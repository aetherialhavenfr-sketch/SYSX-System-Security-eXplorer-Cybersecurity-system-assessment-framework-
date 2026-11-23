"""SQLAlchemy 2.0 models. Only portable column types are used (SQLite and PostgreSQL).

Every column added after Phase 1 is nullable (or has a default), so existing databases upgrade in
place: ``Storage.create_schema`` adds missing columns automatically. Nothing is ever renamed or retyped.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from core.constants import utcnow


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="admin")
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    base_url: Mapped[str] = mapped_column(String(2048))
    authorization_type: Mapped[str] = mapped_column(String(32))
    authorization_reference: Mapped[str] = mapped_column(Text, default="")
    attested: Mapped[bool] = mapped_column(Boolean, default=False)
    attested_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    attested_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    excluded_paths: Mapped[list] = mapped_column(JSON, default=list)
    max_requests_per_second: Mapped[float] = mapped_column(Float, default=2.0)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    max_total_requests: Mapped[int] = mapped_column(Integer, default=5000)
    scan_intensity: Mapped[str] = mapped_column(String(16), default="safe")
    enabled_modules: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TestCredential(Base):
    """A dedicated test account for a target. The secret is stored Fernet-encrypted."""
    __test__ = False  # not a pytest test class
    __tablename__ = "test_credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(40))
    username: Mapped[str] = mapped_column(String(100))
    secret_enc: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Added in Phase 4: password | basic | bearer | cookie | header (NULL in older rows means password)
    auth_type: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, default="password")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    intensity: Mapped[str] = mapped_column(String(16), default="safe")
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # Added in Phase 2 (all nullable so existing databases upgrade in place)
    current_step: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    pages_found: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    # Added in Phase 5: discovery (crawl + dynamic checks) or source (static analysis). NULL in older rows means discovery.
    kind: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, default="discovery")


class Endpoint(Base):
    """A URL or form target discovered by the crawler. Discovery only: never a verdict about vulnerability."""
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="crawl")
    depth: Mapped[int] = mapped_column(Integer, default=0)
    auth_required: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    params: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class ReconRecord(Base):
    """One reconnaissance result (dns, http, tls, ports, technology, subdomains) for a scan."""
    __tablename__ = "recon_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    vuln_type: Mapped[str] = mapped_column(String(64), index=True)
    technique: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="Unverified", index=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    parameter_location: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # Added in Phases 5 and 6
    origin: Mapped[Optional[str]] = mapped_column(String(12), nullable=True, default="dynamic")  # dynamic | source
    source_file: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    source_line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    confidence_detail: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)


class AuditLog(Base):
    """Append-only record of security-relevant actions. target_id is not a foreign key,
    so history survives target deletion."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    level: Mapped[str] = mapped_column(String(10), default="info")
    detail: Mapped[str] = mapped_column(Text, default="")
    target_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
