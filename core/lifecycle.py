"""Finding identity and lifecycle across scans.

A finding's *fingerprint* identifies the issue itself (what kind, where, which parameter), not one observation of it.
SYSX keeps one row per fingerprint per target: a later scan that sees the same issue refreshes that row instead of
adding a duplicate, a Fixed finding that reappears becomes Reopened, and a False Positive stays dismissed. Which scan
saw which fingerprints is recorded in each scan's summary, which is what scan comparison (Phase 7) reads.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlsplit

from core.confidence import score
from core.constants import utcnow

STATUS_RANK = {"Confirmed": 3, "Potential": 2, "Reopened": 2, "Unverified": 1}
MAX_EVIDENCE = 6
_CODE_LINE = re.compile(r"^\s*(\d+)\s\s(.*)$")


def normalize_endpoint(url: str | None) -> str:
    """scheme://host/path with query parameter *names* (not values) sorted; so ?id=1 and ?id=2 are the same endpoint."""
    if not url:
        return ""
    parts = urlsplit(url)
    names = ",".join(sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}))
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}:{parts.port or ''}{path}" + (f"?{names}" if names else "")


def _source_line_text(row: dict) -> str:
    for item in row.get("evidence") or []:
        for raw in str(item.get("code", "")).splitlines():
            m = _CODE_LINE.match(raw)
            if m and int(m.group(1)) == row.get("source_line"):
                return m.group(2).strip()
    return ""


def fingerprint(row: dict) -> str:
    if (row.get("origin") or "dynamic") == "source":
        # the text of the flagged line, not its number, so inserting code above it does not create a "new" finding
        parts = ["source", row.get("source_file") or "", row.get("rule_id") or "", _source_line_text(row) or str(row.get("source_line") or "")]
    else:
        parts = ["dynamic", row.get("vuln_type") or "", row.get("technique") or "", row.get("method") or "",
                 normalize_endpoint(row.get("endpoint")), row.get("parameter") or ""]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:40]


def _stronger(a: dict, b: dict) -> bool:
    return (STATUS_RANK.get(a["status"], 0), a.get("confidence") or 0) > (STATUS_RANK.get(b["status"], 0), b.get("confidence") or 0)


def merge_duplicates(rows: list[dict]) -> list[dict]:
    """Collapse rows with the same fingerprint inside one scan, keeping the strongest and pooling evidence."""
    by_fp: dict[str, dict] = {}
    order: list[str] = []
    for row in rows:
        fp = row.get("fingerprint") or fingerprint(row)
        row["fingerprint"] = fp
        if fp not in by_fp:
            by_fp[fp] = row
            order.append(fp)
            continue
        keep, other = (row, by_fp[fp]) if _stronger(row, by_fp[fp]) else (by_fp[fp], row)
        pooled = list(keep.get("evidence") or [])
        for item in other.get("evidence") or []:
            if item not in pooled:
                pooled.append(item)
        keep["evidence"] = pooled[:MAX_EVIDENCE]
        by_fp[fp] = keep
    return [by_fp[fp] for fp in order]


def apply_confidence(rows: list[dict], seen_before: dict[str, int] | None = None, corroborated: set[str] | None = None) -> None:
    seen_before, corroborated = seen_before or {}, corroborated or set()
    for row in rows:
        fp = row["fingerprint"]
        row["confidence"], row["confidence_detail"] = score(
            row.get("confidence"), row["status"], len(row.get("evidence") or []), seen_before.get(fp, 0),
            fp in corroborated, source_only=(row.get("origin") == "source" and row["status"] != "Confirmed"))


def corroborated_fingerprints(rows: list[dict]) -> set[str]:
    """Fingerprints of dynamic findings that a second, different technique also reports on the same endpoint and
    parameter. (Static-versus-dynamic corroboration is shown at read time in the Evidence Center.)"""
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        if (row.get("origin") or "dynamic") == "dynamic" and row.get("parameter"):
            groups.setdefault((normalize_endpoint(row.get("endpoint")), row["parameter"]), []).append(row)
    out: set[str] = set()
    for group in groups.values():
        if len({(r["vuln_type"], r.get("technique")) for r in group}) >= 2 and len({r["vuln_type"] for r in group}) >= 2:
            out |= {r["fingerprint"] for r in group}
    return out


def prior_scan_counts(storage, target_id: int, fingerprints: set[str], current_scan_id: int) -> dict[str, int]:
    """For each fingerprint, in how many *earlier* scans of this target it was already recorded."""
    counts: dict[str, int] = {}
    if not fingerprints:
        return counts
    for scan in storage.list_scans(500, target_id):
        if scan.id >= current_scan_id:
            continue
        seen = set((scan.summary or {}).get("fingerprints") or ())
        for fp in fingerprints & seen:
            counts[fp] = counts.get(fp, 0) + 1
    return counts


def finalize_findings(storage, scan_id: int, target_id: int, rows: list[dict]) -> dict:
    """Fingerprint, merge, score and store a scan's findings, refreshing existing findings instead of duplicating them.

    Returns ``{"fingerprints": [...], "new": n, "seen_again": n, "reopened": n, "dismissed_kept": n, "total": n}``.
    """
    rows = merge_duplicates(rows)
    existing = storage.findings_by_fingerprint(target_id, [r["fingerprint"] for r in rows]) if rows else {}
    apply_confidence(rows, prior_scan_counts(storage, target_id, set(existing), scan_id), corroborated_fingerprints(rows))
    stats = dict(new=0, seen_again=0, reopened=0, dismissed_kept=0)
    inserts: list[dict] = []
    for row in rows:
        old = existing.get(row["fingerprint"])
        if old is None:
            inserts.append(row)
            stats["new"] += 1
            continue
        fields = dict(scan_id=scan_id, updated_at=utcnow())
        refresh = dict(evidence=row.get("evidence"), confidence=row["confidence"], confidence_detail=row["confidence_detail"],
                       description=row.get("description"), severity=row["severity"], cvss_score=row.get("cvss_score"),
                       cvss_vector=row.get("cvss_vector"))
        if old.status == "False Positive":
            fields["evidence"] = row.get("evidence")  # the operator's decision stands; only the evidence is refreshed
            stats["dismissed_kept"] += 1
        elif old.status == "Fixed":
            fields.update(refresh, status="Reopened")
            stats["reopened"] += 1
            stats["seen_again"] += 1
        elif STATUS_RANK.get(row["status"], 0) < STATUS_RANK.get(old.status, 0):
            stats["seen_again"] += 1  # keep the stronger verdict; this scan may simply not have repeated the verification
        else:
            fields.update(refresh, status=row["status"] if old.status != "Reopened" else "Reopened")
            stats["seen_again"] += 1
        storage.update_finding_fields(old.id, **fields)
    if inserts:
        storage.add_findings(scan_id, target_id, inserts)
    stats["fingerprints"] = [r["fingerprint"] for r in rows]
    stats["total"] = len(rows)
    return stats
