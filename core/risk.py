"""Risk assessment: ranking and roll-up of open findings. Every number here has a stated formula.

* Base score of a finding: its CVSS 3.1 score when one was calculated, otherwise a fixed value for its severity.
* Finding risk = base x (0.5 + 0.5 x confidence). CVSS says how bad the issue is *if real*; confidence says how likely it
  is to be real, so a 9.8 that is only a guess ranks below a verified 7.5.
* Target risk (0-100) = 100 x (1 - exp(-W / 20)), where W is the sum over open findings of
  severity weight x confidence. It rises steeply with the first serious findings and saturates, so it can be compared over time.
"""
from __future__ import annotations

import math
from urllib.parse import urlsplit

BASE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 0.0}
WEIGHT = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "informational": 0.1}
SEV_ORDER = ("critical", "high", "medium", "low", "informational")
DEFAULT_CONFIDENCE = 0.3
CLOSED = ("False Positive", "Fixed")
BANDS = ((75, "Critical"), (50, "High"), (25, "Medium"), (1, "Low"))


def band(score: int) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "None"


def _conf(f) -> float:
    return f.confidence if f.confidence is not None else DEFAULT_CONFIDENCE


def finding_risk(f) -> dict:
    base = f.cvss_score if f.cvss_score is not None else BASE.get(f.severity, 0.0)
    risk = round(base * (0.5 + 0.5 * _conf(f)), 1)
    return dict(id=f.id, title=f.title, severity=f.severity, status=f.status, vuln_type=f.vuln_type, base=base,
                base_source="CVSS" if f.cvss_score is not None else "severity default", confidence=_conf(f), risk=risk,
                where=location(f))


def location(f) -> str:
    if (getattr(f, "origin", None) or "dynamic") == "source":
        return f"{f.source_file or 'unknown'}" + (f":{f.source_line}" if f.source_line else "")
    if not f.endpoint:
        return "(whole application)"
    parts = urlsplit(f.endpoint)
    return f"{parts.hostname or ''}{':' + str(parts.port) if parts.port else ''}{parts.path.rstrip('/') or '/'}"


def assess(findings: list) -> dict:
    open_rows = [f for f in findings if f.status not in CLOSED]
    ranked = sorted((finding_risk(f) for f in open_rows), key=lambda r: (-r["risk"], SEV_ORDER.index(r["severity"]) if r["severity"] in SEV_ORDER else 9, r["id"]))
    weighted = sum(WEIGHT.get(f.severity, 0.0) * _conf(f) for f in open_rows)
    score = round(100 * (1 - math.exp(-weighted / 20)))
    counts = {s: sum(1 for f in open_rows if f.severity == s) for s in SEV_ORDER}
    by_type: dict[str, dict] = {}
    spots: dict[str, dict] = {}
    for f, r in zip(open_rows, [finding_risk(f) for f in open_rows]):
        t = by_type.setdefault(f.vuln_type, dict(vuln_type=f.vuln_type, count=0, risk=0.0, worst=f.severity))
        t["count"] += 1
        t["risk"] = round(t["risk"] + r["risk"], 1)
        if SEV_ORDER.index(f.severity) < SEV_ORDER.index(t["worst"]):
            t["worst"] = f.severity
        h = spots.setdefault(r["where"], dict(where=r["where"], count=0, risk=0.0))
        h["count"] += 1
        h["risk"] = round(h["risk"] + r["risk"], 1)
    return dict(score=score, rating=band(score), counts=counts, open=len(open_rows), closed=len(findings) - len(open_rows),
                weighted=round(weighted, 1), ranked=ranked,
                by_type=sorted(by_type.values(), key=lambda t: -t["risk"]),
                hotspots=sorted(spots.values(), key=lambda h: -h["risk"])[:10],
                verified=sum(1 for f in open_rows if f.status == "Confirmed"),
                unverified=sum(1 for f in open_rows if f.status != "Confirmed"))
