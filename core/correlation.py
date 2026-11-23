"""Relations between findings, computed when a page is rendered (never stored, so they cannot go stale).

* ``same_parameter``: two or more different vulnerability classes on the same endpoint and parameter.
* ``static_dynamic``: a source-code finding and a running-application finding of the same vulnerability class.
  This is *not* proof they are the same flaw; it tells a reviewer where to look.
"""
from __future__ import annotations

from core.lifecycle import normalize_endpoint

STATIC_DYNAMIC_TYPES = {"sqli", "xss", "ssti", "command_injection", "path_traversal", "ssrf", "open_redirect"}


def correlate(findings: list) -> dict[int, list[dict]]:
    """Map finding id -> list of ``{"kind", "label", "finding_id"}`` relations."""
    open_rows = [f for f in findings if f.status not in ("False Positive", "Fixed")]
    out: dict[int, list[dict]] = {f.id: [] for f in findings}
    groups: dict[tuple, list] = {}
    for f in open_rows:
        if (getattr(f, "origin", None) or "dynamic") == "dynamic" and f.parameter:
            groups.setdefault((normalize_endpoint(f.endpoint), f.parameter), []).append(f)
    for group in groups.values():
        if len({f.vuln_type for f in group}) >= 2:
            for f in group:
                for g in group:
                    if g.id != f.id and g.vuln_type != f.vuln_type:
                        out[f.id].append(dict(kind="same_parameter", finding_id=g.id,
                                              label=f"Also flagged as {g.title} on the same parameter"))
    dynamic = {t: [f for f in open_rows if f.vuln_type == t and (getattr(f, "origin", None) or "dynamic") != "source"] for t in STATIC_DYNAMIC_TYPES}
    for f in open_rows:
        if getattr(f, "origin", None) == "source" and f.vuln_type in STATIC_DYNAMIC_TYPES:
            for d in dynamic[f.vuln_type][:3]:
                out[f.id].append(dict(kind="static_dynamic", finding_id=d.id, label=f"The running application also shows {d.title}"))
                out[d.id].append(dict(kind="static_dynamic", finding_id=f.id,
                                      label=f"Source code has a similar pattern at {f.source_file}:{f.source_line}"))
    for fid, relations in out.items():
        seen, unique = set(), []
        for r in relations:
            if (r["kind"], r["finding_id"]) not in seen:
                seen.add((r["kind"], r["finding_id"]))
                unique.append(r)
        out[fid] = unique[:5]
    return out
