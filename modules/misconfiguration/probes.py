"""Small, read-only active probes: a CORS check and a short list of well-known exposed files.

Every request goes through ScopedClient (scope, rate and budget enforced there). A probe that is out of scope,
excluded, or fails at the network level is skipped; only budget exhaustion and cancellation propagate.
"""
from __future__ import annotations

import re
import secrets

from core.http import FetchError, ScopeViolation
from verification.catalog import build_finding
from verification.evidence import evidence_item, redact_secrets

V_HIGH = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V_MED = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
V_CRIT = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# path, signature (regex on text, or bytes prefix), technique, label, optional vector
EXPOSED_FILES = (
    ("/.git/HEAD", re.compile(r"^ref:\s*refs/", re.M), "exposed_sensitive_file", "Git repository (.git/HEAD)", None),
    ("/.git/config", re.compile(r"^\[core\]", re.M), "exposed_sensitive_file", "Git configuration (.git/config)", None),
    ("/.env", re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M), "exposed_sensitive_file", "Environment file (.env)", None),
    ("/.htpasswd", re.compile(r"^[^:\s]+:(?:\$|\{SHA\}|[A-Za-z0-9./]{13})", re.M), "exposed_sensitive_file", "Password file (.htpasswd)", None),
    ("/wp-config.php.bak", re.compile(r"DB_PASSWORD"), "exposed_sensitive_file", "WordPress configuration backup", None),
    ("/config.php.bak", re.compile(r"(?i)(?:password|passwd|secret)\s*[=:>]"), "exposed_sensitive_file", "Configuration backup", None),
    ("/backup.sql", re.compile(r"(?i)\b(?:CREATE TABLE|INSERT INTO)\b"), "exposed_sensitive_file", "Database dump", None),
    ("/actuator/env", re.compile(r'"(?:activeProfiles|propertySources)"'), "exposed_sensitive_file", "Spring Boot actuator /env", None),
    ("/phpinfo.php", re.compile(r"PHP Version|phpinfo\(\)"), "exposed_debug_interface", "phpinfo() page", None),
    ("/info.php", re.compile(r"PHP Version|phpinfo\(\)"), "exposed_debug_interface", "phpinfo() page", None),
    ("/server-status", re.compile(r"Apache Server Status"), "exposed_debug_interface", "Apache server-status", None),
    ("/server-info", re.compile(r"Apache Server Information"), "exposed_debug_interface", "Apache server-info", None),
    ("/actuator", re.compile(r'"_links"'), "exposed_debug_interface", "Spring Boot actuator index", None),
    ("/console", re.compile(r"Werkzeug|Interactive Console"), "exposed_debug_interface", "Interactive debug console", V_CRIT),
    ("/.DS_Store", b"\x00\x00\x00\x01Bud1", "exposed_metadata_file", "macOS directory metadata (.DS_Store)", None),
    ("/composer.json", re.compile(r'"require"'), "exposed_metadata_file", "composer.json", None),
    ("/package.json", re.compile(r'"(?:dependencies|devDependencies|scripts)"'), "exposed_metadata_file", "package.json", None),
)


def cors_probe(client, url: str, token: str | None = None):
    token = token or secrets.token_hex(4)
    origin = f"https://sysx-cors-{token}.invalid"
    try:
        res = client.get(url, headers={"Origin": origin})
    except (ScopeViolation, FetchError):
        return None
    allow = res.headers.get("access-control-allow-origin", "")
    credentials = res.headers.get("access-control-allow-credentials", "").lower() == "true"
    if allow == origin:
        if credentials:
            note = (f"The server reflected an arbitrary Origin ({origin}) in Access-Control-Allow-Origin and also allows "
                    "credentials, so any website can read authenticated responses from this origin.")
            extra: dict = {}
        else:
            note = (f"The server reflected an arbitrary Origin ({origin}) in Access-Control-Allow-Origin. Credentials are not "
                    "allowed, so only unauthenticated content is exposed.")
            extra = {"severity": "low"}
    elif allow == "*" and credentials:
        note = "Access-Control-Allow-Origin: * is combined with Allow-Credentials: true. Browsers reject it, but it shows the policy is not understood."
        extra = {"severity": "low"}
    else:
        return None
    result = dict(vuln_type="misconfiguration", technique="cors", status="Confirmed", confidence=0.9, note=note,
                  evidence=[evidence_item("CORS probe (Origin header only)", "GET", url, res, note)], **extra)
    return build_finding(result, url, "GET", None)


def exposed_file_probe(client, base_url: str, step=lambda s: None, out: list | None = None) -> list[dict]:
    """GET a short list of well-known paths and keep only those whose *content* matches the expected signature.

    Findings are appended to ``out`` as they are found, so a budget stop or cancel keeps what was already confirmed."""
    from urllib.parse import urlsplit
    parts = urlsplit(base_url)
    root = f"{parts.scheme}://{parts.netloc}"
    calibration = None
    try:
        cal = client.get(f"{root}/sysx-{secrets.token_hex(6)}-not-here")
        calibration = cal.body if cal.status < 400 else None
    except (ScopeViolation, FetchError):
        pass
    findings = out if out is not None else []
    seen_labels: set[str] = set()
    for path, signature, technique, label, vector in EXPOSED_FILES:
        step(f"Checking for exposed file {path}")
        url = root + path
        try:
            res = client.get(url, follow_redirects=False)
        except (ScopeViolation, FetchError):
            continue
        if res.status != 200 or not res.body or (calibration is not None and res.body == calibration):
            continue
        if isinstance(signature, bytes):
            matched = res.body.startswith(signature)
        else:
            matched = bool(signature.search(res.text[:200_000]))
        if not matched or label in seen_labels:
            continue
        seen_labels.add(label)
        sensitive = technique == "exposed_sensitive_file"
        snippet = redact_secrets(res.text[:300]) if sensitive else None
        note = (f"{url} is publicly readable and matches the signature of: {label}."
                + (" Values in the stored excerpt are redacted." if sensitive else ""))
        extra = {"cvss_vector": vector} if vector else {}
        result = dict(vuln_type="misconfiguration", technique=technique, status="Confirmed", confidence=0.95, note=note,
                      evidence=[evidence_item("Exposed file", "GET", url, res, note, snippet=snippet if sensitive else
                                              ("(binary content not stored)" if isinstance(signature, bytes) else res.text[:200]))],
                      **extra)
        findings.append(build_finding(result, url, "GET", None))
    return findings
