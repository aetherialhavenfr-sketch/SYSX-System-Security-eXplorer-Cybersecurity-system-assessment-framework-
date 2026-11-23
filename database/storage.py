"""Persistence layer. The web layer talks only to ``Storage``; it never touches the ORM.

Works with SQLite (default) and PostgreSQL via ``SYSX_DATABASE_URL``.
"""
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import create_engine, delete, event, func, inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool

from core.constants import CLOSED_STATUSES, FINDING_STATUSES, PENDING_STATUSES, SEVERITIES, utcnow
from database.storage_errors import ConflictError
from database.models import (
    AuditLog, Base, Endpoint, Finding, ReconRecord, Scan, Target, TestCredential, User,
)

TARGET_FIELDS = frozenset(c.name for c in Target.__table__.columns) - {"id", "created_at"}
SCAN_FIELDS = frozenset({"status", "current_step", "requests_made", "pages_found", "error", "summary", "started_at", "finished_at"})
ACTIVE_SCAN_STATUSES = ("queued", "running")
FINDING_FIELDS = frozenset(c.name for c in Finding.__table__.columns) - {"id", "created_at"}


class Storage:
    def __init__(self, url: str):
        kwargs: dict[str, Any] = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url:
                kwargs["poolclass"] = StaticPool
            else:
                Path(url.split("///", 1)[1]).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def _enable_foreign_keys(dbapi_connection, _record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        self._sessions = scoped_session(sessionmaker(bind=self.engine, expire_on_commit=False))

    # -- lifecycle ---------------------------------------------------------
    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)
        self._add_missing_columns()

    def _add_missing_columns(self) -> None:
        """Additive in-place upgrade: add columns that newer models have and older databases lack.
        Anything beyond adding columns (renames, type changes) needs a real migration tool."""
        inspector = inspect(self.engine)
        quote = self.engine.dialect.identifier_preparer.quote
        with self.engine.begin() as conn:
            for table in Base.metadata.sorted_tables:
                if not inspector.has_table(table.name):
                    continue
                existing = {c["name"] for c in inspector.get_columns(table.name)}
                for column in table.columns:
                    if column.name not in existing:
                        ddl = column.type.compile(dialect=self.engine.dialect)
                        conn.execute(text(f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(column.name)} {ddl}"))

    def remove_session(self) -> None:
        self._sessions.remove()

    @property
    def _s(self):
        return self._sessions()

    def _commit(self) -> None:
        try:
            self._s.commit()
        except IntegrityError as exc:
            self._s.rollback()
            raise ConflictError(str(exc.orig)) from exc
        except Exception:
            self._s.rollback()
            raise

    # -- users -------------------------------------------------------------
    def count_users(self) -> int:
        return self._s.scalar(select(func.count()).select_from(User)) or 0

    def get_user(self, user_id: int) -> Optional[User]:
        return self._s.get(User, user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        return self._s.scalar(select(User).where(User.username == username))

    def create_user(self, username: str, password_hash: str, role: str = "admin") -> User:
        user = User(username=username, password_hash=password_hash, role=role)
        self._s.add(user)
        self._commit()
        return user

    def set_password(self, user_id: int, password_hash: str) -> None:
        user = self._s.get(User, user_id)
        user.password_hash = password_hash
        self._commit()

    def register_login_success(self, user_id: int, now: datetime) -> None:
        user = self._s.get(User, user_id)
        user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
        self._commit()

    def register_login_failure(self, user_id: int, max_attempts: int, lock_for: timedelta, now: datetime) -> bool:
        """Count a failed login. Returns True when this failure locked the account."""
        user = self._s.get(User, user_id)
        user.failed_logins += 1
        locked = user.failed_logins >= max_attempts
        if locked:
            user.locked_until, user.failed_logins = now + lock_for, 0
        self._commit()
        return locked

    # -- targets -----------------------------------------------------------
    def list_targets(self) -> list[Target]:
        return list(self._s.scalars(select(Target).order_by(Target.name)))

    def get_target(self, target_id: int) -> Optional[Target]:
        return self._s.get(Target, target_id)

    def create_target(self, data: dict[str, Any]) -> Target:
        unknown = set(data) - TARGET_FIELDS
        if unknown:
            raise ValueError(f"Unknown target fields: {sorted(unknown)}")
        target = Target(**data)
        self._s.add(target)
        self._commit()
        return target

    def update_target(self, target_id: int, data: dict[str, Any]) -> Optional[Target]:
        unknown = set(data) - TARGET_FIELDS
        if unknown:
            raise ValueError(f"Unknown target fields: {sorted(unknown)}")
        target = self._s.get(Target, target_id)
        if target is None:
            return None
        for key, value in data.items():
            setattr(target, key, value)
        target.updated_at = utcnow()
        self._commit()
        return target

    def delete_target(self, target_id: int) -> bool:
        target = self._s.get(Target, target_id)
        if target is None:
            return False
        self._s.execute(delete(TestCredential).where(TestCredential.target_id == target_id))
        self._s.delete(target)
        self._commit()
        return True

    # -- test credentials --------------------------------------------------
    def list_credentials(self, target_id: int) -> list[TestCredential]:
        return list(self._s.scalars(
            select(TestCredential).where(TestCredential.target_id == target_id).order_by(TestCredential.id)))

    def add_credential(self, target_id: int, label: str, username: str, secret_enc: str,
                       auth_type: str = "password") -> TestCredential:
        cred = TestCredential(target_id=target_id, label=label, username=username, secret_enc=secret_enc, auth_type=auth_type)
        self._s.add(cred)
        self._commit()
        return cred

    def delete_credential(self, target_id: int, credential_id: int) -> bool:
        cred = self._s.get(TestCredential, credential_id)
        if cred is None or cred.target_id != target_id:
            return False
        self._s.delete(cred)
        self._commit()
        return True

    # -- scans, endpoints, recon records ------------------------------------
    def create_scan(self, target_id: int, intensity: str, created_by: Optional[str], kind: str = "discovery") -> Scan:
        scan = Scan(target_id=target_id, intensity=intensity, created_by=created_by, status="queued", summary={}, pages_found=0,
                    kind=kind)
        self._s.add(scan)
        self._commit()
        return scan

    def get_scan(self, scan_id: int) -> Optional[Scan]:
        return self._s.get(Scan, scan_id)

    def list_scans(self, limit: int = 50, target_id: Optional[int] = None) -> list[Scan]:
        query = select(Scan).order_by(Scan.id.desc()).limit(limit)
        if target_id is not None:
            query = query.where(Scan.target_id == target_id)
        return list(self._s.scalars(query))

    def update_scan(self, scan_id: int, **fields: Any) -> None:
        unknown = set(fields) - SCAN_FIELDS
        if unknown:
            raise ValueError(f"Unknown scan fields: {sorted(unknown)}")
        scan = self._s.get(Scan, scan_id)
        if scan is None:
            return
        for key, value in fields.items():
            setattr(scan, key, value)
        self._commit()

    def fail_stale_scans(self) -> int:
        """Mark scans that were queued or running when the process stopped as failed."""
        result = self._s.execute(update(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES)).values(
            status="failed", error="Interrupted by a restart.", current_step="Failed", finished_at=utcnow()))
        self._commit()
        return result.rowcount or 0

    def add_endpoints(self, scan_id: int, target_id: int, rows: list[dict[str, Any]]) -> None:
        self._s.add_all([Endpoint(scan_id=scan_id, target_id=target_id, **row) for row in rows])
        self._commit()

    def list_endpoints(self, scan_id: int) -> list[Endpoint]:
        return list(self._s.scalars(select(Endpoint).where(Endpoint.scan_id == scan_id).order_by(Endpoint.url, Endpoint.method)))

    def add_recon_records(self, scan_id: int, records: list[tuple[str, Any]]) -> None:
        self._s.add_all([ReconRecord(scan_id=scan_id, kind=kind, data=data) for kind, data in records])
        self._commit()

    def list_recon_records(self, scan_id: int) -> list[ReconRecord]:
        return list(self._s.scalars(select(ReconRecord).where(ReconRecord.scan_id == scan_id).order_by(ReconRecord.id)))

    # -- findings ------------------------------------------------------------
    def add_findings(self, scan_id: int, target_id: int, rows: list[dict[str, Any]]) -> list[int]:
        objs = [Finding(scan_id=scan_id, target_id=target_id, **{k: v for k, v in row.items() if k != "target_id"})
                for row in rows]
        self._s.add_all(objs)
        self._commit()
        for obj in objs:
            self._s.refresh(obj)
        return [obj.id for obj in objs]

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        return self._s.get(Finding, finding_id)

    def list_findings(self, scan_id: Optional[int] = None, target_id: Optional[int] = None,
                       vuln_type: Optional[str] = None, severity: Optional[str] = None,
                       status: Optional[str] = None, min_confidence: Optional[float] = None) -> list[Finding]:
        query = select(Finding).order_by(Finding.id.desc())
        if scan_id is not None:
            query = query.where(Finding.scan_id == scan_id)
        if target_id is not None:
            query = query.where(Finding.target_id == target_id)
        if vuln_type:
            query = query.where(Finding.vuln_type == vuln_type)
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if min_confidence is not None:
            query = query.where(Finding.confidence >= min_confidence)
        return list(self._s.scalars(query))

    def findings_by_fingerprint(self, target_id: int, fingerprints: list[str]) -> dict[str, Finding]:
        """The newest finding of this target for each fingerprint."""
        if not fingerprints:
            return {}
        out: dict[str, Finding] = {}
        for start in range(0, len(fingerprints), 500):
            rows = self._s.scalars(select(Finding).where(Finding.target_id == target_id,
                                                         Finding.fingerprint.in_(fingerprints[start:start + 500]))
                                   .order_by(Finding.id))
            for f in rows:
                out[f.fingerprint] = f  # ascending id, so the newest wins
        return out

    FINDING_UPDATABLE = {"scan_id", "updated_at", "evidence", "confidence", "confidence_detail", "description", "severity",
                         "cvss_score", "cvss_vector", "status"}

    def update_finding_fields(self, finding_id: int, **fields) -> Optional[Finding]:
        if set(fields) - self.FINDING_UPDATABLE:
            raise ValueError("Unknown finding fields")
        if "status" in fields and fields["status"] not in FINDING_STATUSES:
            raise ValueError(f"Unknown finding status: {fields['status']!r}")
        finding = self._s.get(Finding, finding_id)
        if finding is None:
            return None
        for key, value in fields.items():
            setattr(finding, key, value)
        self._commit()
        return finding

    def update_finding_status(self, finding_id: int, status: str) -> Optional[Finding]:
        if status not in FINDING_STATUSES:
            raise ValueError(f"Unknown finding status: {status!r}")
        finding = self._s.get(Finding, finding_id)
        if finding is None:
            return None
        finding.status, finding.updated_at = status, utcnow()
        if status in ("Confirmed", "False Positive", "Fixed") and finding.verified_at is None:
            finding.verified_at = utcnow()
        self._commit()
        return finding

    # -- audit log ---------------------------------------------------------
    def add_audit(self, actor: str, action: str, detail: str = "", level: str = "info",
                  target_id: Optional[int] = None, ip: Optional[str] = None) -> None:
        self._s.add(AuditLog(actor=actor[:64], action=action[:64], detail=detail[:2000], level=level,
                             target_id=target_id, ip=ip))
        self._commit()

    def recent_audit(self, limit: int = 20, only_alerts: bool = False) -> list[AuditLog]:
        query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        if only_alerts:
            query = query.where(AuditLog.level.in_(("warning", "alert")))
        return list(self._s.scalars(query))

    # -- dashboard ---------------------------------------------------------
    def dashboard_stats(self) -> dict[str, Any]:
        s = self._s
        is_open = Finding.status.not_in(CLOSED_STATUSES)
        severity = {name: 0 for name in SEVERITIES}
        for name, count in s.execute(
                select(Finding.severity, func.count()).where(is_open).group_by(Finding.severity)):
            if name in severity:
                severity[name] = count
        recent = s.execute(
            select(Scan.id, Target.name, Scan.status, Scan.created_at, Scan.requests_made)
            .join(Target, Target.id == Scan.target_id).order_by(Scan.id.desc()).limit(8)).all()
        return {
            "targets": s.scalar(select(func.count()).select_from(Target)) or 0,
            "scans": s.scalar(select(func.count()).select_from(Scan)) or 0,
            "severity": severity,
            "confirmed": s.scalar(select(func.count()).select_from(Finding).where(Finding.status == "Confirmed")) or 0,
            "pending": s.scalar(select(func.count()).select_from(Finding)
                                .where(Finding.status.in_(PENDING_STATUSES))) or 0,
            "recent_scans": [dict(id=r[0], target=r[1], status=r[2], created_at=r[3], requests_made=r[4])
                             for r in recent],
        }
