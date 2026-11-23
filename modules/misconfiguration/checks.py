"""Passive security-misconfiguration checks. They read what the crawler already observed and send no requests."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlsplit

from modules.misconfiguration.observe import SESSION_COOKIE
from verification.catalog import build_finding
from verification.evidence import note_item, redact_secrets

HTML_TYPES = ("text/html", "application/xhtml+xml")
_VERSIONED = re.compile(r"[A-Za-z][\w\-. ]*[/ ]v?\d+(?:\.\d+)+")
MAX_PER_KIND = 10


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _result(technique: str, note: str, evidence: list, **extra) -> dict:
    return dict(vuln_type="misconfiguration", technique=technique, status="Confirmed", confidence=0.9, note=note,
                evidence=evidence, **extra)


def _examples(urls: list[str], limit: int = 4) -> str:
    shown = ", ".join(urls[:limit])
    return shown + (f" and {len(urls) - limit} more" if len(urls) > limit else "")


def _header_finding(technique: str, header_label: str, offenders: list[dict], total: int, origin: str, noun: str) -> dict:
    urls = [o["url"] for o in offenders]
    note = (f"{header_label} was missing on {len(offenders)} of {total} {noun} observed on {origin}. "
            f"Examples: {_examples(urls)}.")
    ev = [note_item("Response without the header", offenders[0]["url"], note, offenders[0]["status"], offenders[0]["headers"])]
    return build_finding(_result(technique, note, ev), origin + "/", "GET", None)


def passive_findings(observations: list[dict]) -> list[dict]:
    findings: list[dict] = []
    by_origin: dict[str, list[dict]] = defaultdict(list)
    for obs in observations:
        by_origin[origin_of(obs["url"])].append(obs)
    for origin, group in by_origin.items():
        ok = [o for o in group if 200 <= o["status"] < 300]
        html = [o for o in ok if o["ctype"] in HTML_TYPES]
        https = origin.startswith("https://")
        if https:
            missing = [o for o in ok if "strict-transport-security" not in o["headers"]]
            if missing:
                findings.append(_header_finding("missing_hsts", "Strict-Transport-Security", missing, len(ok), origin, "responses"))
        missing = [o for o in html if "content-security-policy" not in o["headers"]]
        if missing:
            findings.append(_header_finding("missing_csp", "Content-Security-Policy", missing, len(html), origin, "HTML pages"))
        missing = [o for o in ok if o["headers"].get("x-content-type-options", "").lower() != "nosniff"]
        if missing:
            findings.append(_header_finding("missing_nosniff", "X-Content-Type-Options: nosniff", missing, len(ok), origin, "responses"))
        missing = [o for o in html if "x-frame-options" not in o["headers"]
                   and "frame-ancestors" not in o["headers"].get("content-security-policy", "").lower()]
        if missing:
            findings.append(_header_finding("missing_frame_protection", "Clickjacking protection", missing, len(html), origin, "HTML pages"))
        missing = [o for o in html if "referrer-policy" not in o["headers"]]
        if missing:
            findings.append(_header_finding("missing_referrer_policy", "Referrer-Policy", missing, len(html), origin, "HTML pages"))
        findings.extend(_version_disclosure(origin, group))
        findings.extend(_cookie_findings(origin, group, https))
        for o in [o for o in group if o["dir_listing"]][:MAX_PER_KIND]:
            note = f"{o['url']} returns an automatically generated directory index."
            findings.append(build_finding(_result("directory_listing", note, [note_item("Directory index", o["url"], note, o["status"])]),
                                          o["url"], "GET", None))
        for o in [o for o in group if o["stack_trace"]][:MAX_PER_KIND]:
            note = f"{o['url']} returned a page that looks like a {o['stack_trace']}, which exposes internals to visitors."
            findings.append(build_finding(_result("stack_trace", note, [note_item("Verbose error page", o["url"], note, o["status"])]),
                                          o["url"], "GET", None))
    return findings


def _version_disclosure(origin: str, group: list[dict]) -> list[dict]:
    seen: dict[str, str] = {}
    for o in group:
        for header in ("server", "x-powered-by"):
            value = o["headers"].get(header, "")
            if value and _VERSIONED.search(value):
                seen.setdefault(f"{header}: {value}", o["url"])
    if not seen:
        return []
    note = f"Response headers on {origin} reveal software versions: {'; '.join(seen)}."
    first = next(iter(seen.values()))
    return [build_finding(_result("version_disclosure", note, [note_item("Disclosing headers", first, note)]), origin + "/", "GET", None)]


def _cookie_findings(origin: str, group: list[dict], https: bool) -> list[dict]:
    cookies: dict[str, tuple[dict, str]] = {}
    for o in group:
        for c in o["cookies"]:
            cookies.setdefault(c["name"], (c, o["url"]))
    out = []
    for name, (c, url) in sorted(cookies.items()):
        session_like = bool(SESSION_COOKIE.search(name))
        issues = []
        if not c["httponly"]:
            issues.append("HttpOnly")
        if https and not c["secure"]:
            issues.append("Secure")
        if c["samesite"] is None and session_like:
            issues.append("SameSite")
        if c["samesite"] == "none" and not c["secure"]:
            issues.append("Secure (required with SameSite=None)")
        if not issues:
            continue
        note = f"Cookie '{name}' (set by {url}) is missing: {', '.join(issues)}." + ("" if session_like else " It does not look like a session cookie.")
        extra = {} if session_like else {"severity": "informational"}
        out.append(build_finding(_result("cookie_flags", note, [note_item("Set-Cookie attributes", url, note)], parameter=name, **extra),
                                 origin + "/", "GET", "cookie"))
    return out


def tls_findings(tls: dict) -> list[dict]:
    """Findings from one reconnaissance TLS record (the dict produced by ``probe_tls``)."""
    if not tls or not tls.get("supported"):
        return []
    url = f"https://{tls['host']}:{tls['port']}/"
    cert = tls.get("certificate") or {}
    out = []

    def add(technique: str, note: str):
        out.append(build_finding(_result(technique, note, [note_item("TLS handshake", url, note)]), url, "GET", None))

    if cert and cert.get("days_to_expiry", 1) < 0:
        add("tls_expired", f"The certificate expired {-cert['days_to_expiry']} day(s) ago (not after {cert.get('not_after')}).")
    if cert and cert.get("hostname_match") is False:
        add("tls_hostname", f"The certificate names {', '.join(cert.get('names', [])[:5]) or 'no hostnames'}, not {tls['host']}.")
    if cert and cert.get("signature_hash") in ("md5", "sha1"):
        add("tls_weak_signature", f"The certificate is signed with {cert['signature_hash']}.")
    verification = tls.get("verification") or ""
    if cert and cert.get("self_signed"):
        add("tls_self_signed", "The certificate is self-signed, so clients cannot validate it.")
    elif verification.startswith("failed"):
        add("tls_untrusted", f"Certificate verification failed: {redact_secrets(verification)[:200]}.")
    accepted = [p for p, state in (tls.get("legacy_protocols") or {}).items() if state == "accepted"]
    if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
        accepted.append(tls["protocol"])
    if accepted:
        add("tls_weak_protocol", f"The server accepts deprecated protocol version(s): {', '.join(sorted(set(accepted)))}.")
    return out
