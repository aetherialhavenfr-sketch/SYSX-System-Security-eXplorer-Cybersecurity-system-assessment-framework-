"""Scan comparison from the fingerprints each scan recorded.

"Not seen again" is deliberately not called "fixed": a later scan may have run fewer modules, a lower intensity, been
cut short by its request budget, or been given different credentials. ``caveats`` lists exactly those differences.
"""
from __future__ import annotations


def comparable_problem(a, b) -> str | None:
    if a.target_id != b.target_id:
        return "These scans belong to different targets."
    if a.id == b.id:
        return "Pick two different scans."
    if (getattr(a, "kind", None) or "discovery") != (getattr(b, "kind", None) or "discovery"):
        return "A discovery scan cannot be compared with a source-code analysis."
    for scan in (a, b):
        if "fingerprints" not in (scan.summary or {}):
            return f"Scan #{scan.id} predates finding fingerprints, so it cannot be compared."
    return None


def compare_scans(storage, older, newer) -> dict:
    """``older`` and ``newer`` are Scan rows of one target (the caller orders them by id)."""
    a, b = set(older.summary["fingerprints"]), set(newer.summary["fingerprints"])
    rows = storage.findings_by_fingerprint(older.target_id, sorted(a | b))
    def pick(fps):
        return sorted((rows[fp] for fp in fps if fp in rows), key=lambda f: -f.id)
    caveats = []
    sa, sb = older.summary or {}, newer.summary or {}
    if newer.status != "completed" or older.status != "completed":
        caveats.append("At least one of the scans did not complete, so its results are partial.")
    for scan, summary in ((older, sa), (newer, sb)):
        if summary.get("budget_exhausted"):
            caveats.append(f"Scan #{scan.id} stopped at its request budget.")
    if sa.get("intensity") and sb.get("intensity") and sa["intensity"] != sb["intensity"]:
        caveats.append(f"The intensity differs ({sa['intensity']} then {sb['intensity']}).")
    if sa.get("modules") is not None and sb.get("modules") is not None and set(sa["modules"]) != set(sb["modules"]):
        diff = sorted(set(sa["modules"]) ^ set(sb["modules"]))
        caveats.append("The enabled modules differ (" + ", ".join(diff) + ").")
    if sa.get("identities", 0) != sb.get("identities", 0):
        caveats.append("The number of test identities differs, which changes access-control results.")
    if sa.get("source_path") != sb.get("source_path"):
        caveats.append("The analysed directory differs.")
    return dict(new=pick(b - a), not_seen=pick(a - b), persistent=pick(a & b), caveats=caveats,
                reopened=[f for f in pick(a & b) if f.status == "Reopened"])
