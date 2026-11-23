"""Attack Surface: one correlated view of a target's hosts, endpoints, parameters, technologies, findings and source.

Pure functions over stored rows. Findings are attached to the endpoint with the same scheme, host and path (the query
string is ignored, so ``/item?id=1`` and ``/item?id=2`` are the same endpoint). Findings that belong to a whole host
(missing headers, exposed files) are shown at host level, and source-code findings are listed by file because they have
no URL.
"""
from __future__ import annotations

from urllib.parse import urlsplit

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
OPEN_STATUSES_EXCLUDED = ("False Positive", "Fixed")
MAX_ENDPOINTS_PER_HOST = 400


def _key(url: str | None) -> tuple[str, str, str] | None:
    if not url:
        return None
    p = urlsplit(url)
    if not p.hostname:
        return None
    return (p.scheme.lower(), f"{p.hostname.lower()}:{p.port}" if p.port else p.hostname.lower(), p.path.rstrip("/") or "/")


def _brief(f) -> dict:
    return dict(id=f.id, title=f.title, severity=f.severity, status=f.status, vuln_type=f.vuln_type)


def _worst(items: list[dict]) -> str | None:
    return min((i["severity"] for i in items), key=lambda s: SEV_RANK.get(s, 9), default=None)


def build_surface(endpoints: list, recon: dict, findings: list, include_closed: bool = False) -> dict:
    """``endpoints``: Endpoint-like rows; ``recon``: {kind: data} from the latest discovery scan; ``findings``: Finding rows."""
    live = [f for f in findings if include_closed or f.status not in OPEN_STATUSES_EXCLUDED]
    dynamic = [f for f in live if (getattr(f, "origin", None) or "dynamic") != "source"]
    source = [f for f in live if getattr(f, "origin", None) == "source"]

    by_path: dict[tuple, list] = {}
    by_host: dict[str, list] = {}
    for f in dynamic:
        k = _key(f.endpoint)
        if k:
            by_path.setdefault(k, []).append(f)
            by_host.setdefault(k[1], [])
    hosts: dict[str, dict] = {}
    claimed: set[int] = set()
    for e in endpoints:
        k = _key(e.url)
        if not k:
            continue
        host = hosts.setdefault(k[1], dict(host=k[1], scheme=k[0], endpoints={}, findings=[]))
        row = host["endpoints"].setdefault((k[2], e.method), dict(
            path=k[2], method=e.method, status=e.status, auth_required=e.auth_required, source=e.source, params=[], findings=[]))
        for p in e.params or []:
            if p["name"] not in row["params"]:
                row["params"].append(p["name"])
        for f in by_path.get(k, []):
            if f.id not in claimed and (f.method in (None, e.method) or e.method == "GET"):
                row["findings"].append(_brief(f))
                claimed.add(f.id)
    for f in dynamic:  # findings on paths that were not crawled as endpoints, or host-wide ones
        if f.id in claimed:
            continue
        k = _key(f.endpoint)
        if not k:
            continue
        host = hosts.setdefault(k[1], dict(host=k[1], scheme=k[0], endpoints={}, findings=[]))
        host["findings"].append(_brief(f))
        claimed.add(f.id)

    out_hosts = []
    for host in sorted(hosts.values(), key=lambda h: h["host"]):
        rows = sorted(host["endpoints"].values(), key=lambda r: (r["path"], r["method"]))
        groups: dict[str, list] = {}
        for r in rows[:MAX_ENDPOINTS_PER_HOST]:
            r["findings"].sort(key=lambda x: SEV_RANK.get(x["severity"], 9))
            r["worst"] = _worst(r["findings"])
            segs = [s for s in r["path"].split("/") if s]
            groups.setdefault("/" + segs[0] if len(segs) > 1 else "/", []).append(r)
        host_findings = sorted(host["findings"], key=lambda x: SEV_RANK.get(x["severity"], 9))
        flat = [x for r in rows for x in r["findings"]] + host_findings
        out_hosts.append(dict(host=host["host"], scheme=host["scheme"], endpoint_count=len(rows),
                              param_count=sum(len(r["params"]) for r in rows), finding_count=len(flat),
                              worst=_worst(flat), host_findings=host_findings, truncated=len(rows) > MAX_ENDPOINTS_PER_HOST,
                              groups=[dict(prefix=prefix, endpoints=items, finding_count=sum(len(r["findings"]) for r in items))
                                      for prefix, items in sorted(groups.items())]))
    by_file: dict[str, list] = {}
    for f in source:
        by_file.setdefault(f.source_file or "unknown", []).append(dict(_brief(f), line=f.source_line))
    code = [dict(file=name, findings=sorted(items, key=lambda x: SEV_RANK.get(x["severity"], 9)), worst=_worst(items))
            for name, items in sorted(by_file.items(), key=lambda kv: (SEV_RANK.get(_worst(kv[1]) or "", 9), kv[0]))]
    subs = recon.get("subdomains") or {}
    return dict(
        hosts=out_hosts, code=code,
        technologies=[t for t in (recon.get("technology") or []) if isinstance(t, dict)],
        subdomains=[h for h in (subs.get("hosts") or []) if isinstance(h, dict)] if isinstance(subs, dict) else [],
        totals=dict(hosts=len(out_hosts), endpoints=sum(h["endpoint_count"] for h in out_hosts),
                    parameters=sum(h["param_count"] for h in out_hosts), findings=len(dynamic), source_findings=len(source),
                    technologies=len(recon.get("technology") or []), source_files=len(code)))
