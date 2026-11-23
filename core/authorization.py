"""Target authorization policy and the gate every scanner must call.

Registering a target is a deliberate act: the operator states how testing is
authorized, records a reference, and attests to it. ``assert_scan_permitted`` is the
single choke point that scanning code must call before sending any request.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from core.scope import (
    Scope, ScopeError, classify_host, normalize_excluded_path, validate_domain_pattern,
)
from modules.registry import MODULE_KEYS


@dataclass(frozen=True)
class AuthType:
    key: str
    label: str
    lab_class: bool
    requires_reference: bool
    help: str


AUTH_TYPES: dict[str, AuthType] = {a.key: a for a in (
    AuthType("owned", "I own this application", False, False,
             "You are the owner or operator of the application."),
    AuthType("written_authorization", "Written authorization from the owner", False, True,
             "Reference the signed scope document, contract, or ticket."),
    AuthType("staging", "Authorized staging or development environment", False, True,
             "Reference the change ticket or approval covering this environment."),
    AuthType("localhost", "Localhost application", True, False,
             "Runs on this machine (localhost, 127.0.0.1, ::1)."),
    AuthType("private_lab", "Private cybersecurity lab", True, False,
             "An isolated network you control."),
    AuthType("ctf", "CTF environment", True, False,
             "A capture-the-flag range that permits testing."),
    AuthType("training_app", "Intentionally vulnerable training app", True, False,
             "DVWA, OWASP Juice Shop, or similar."),
)}

INTENSITIES: dict[str, str] = {
    "safe": "Passive checks and harmless markers only. No disruptive verification. Default.",
    "standard": "Active detection with unique test markers and baseline comparison.",
    "thorough": "Adds time-based and out-of-band verification. Lab-class targets only.",
}

LIMITS = {
    "lab": {"rps": 50.0, "concurrency": 10},
    "production": {"rps": 5.0, "concurrency": 4},
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,79}$")
_SPLIT = re.compile(r"[\s,]+")


class AuthorizationError(PermissionError):
    """A scan or request is not permitted for this target."""


def _tokens(raw: str) -> list[str]:
    return [t for t in _SPLIT.split((raw or "").strip()) if t]


def validate_target_form(form: Mapping[str, Any], module_keys=MODULE_KEYS) -> tuple[dict[str, Any], dict[str, str]]:
    """Validate and normalise target registration input. Returns (clean_data, errors)."""
    errors: dict[str, str] = {}

    def get(key: str) -> str:
        return (form.get(key) or "").strip()

    name = get("name")
    if not NAME_RE.match(name):
        errors["name"] = "Use 1 to 80 characters: letters, digits, spaces, and . _ : -"

    auth_key = get("authorization_type")
    auth = AUTH_TYPES.get(auth_key)
    lab = bool(auth and auth.lab_class)
    if auth is None:
        errors["authorization_type"] = "Choose how testing of this target is authorized."

    reference = get("authorization_reference")
    if len(reference) > 500:
        errors["authorization_reference"] = "Keep the reference under 500 characters."
    elif auth and auth.requires_reference and len(reference) < 8:
        errors["authorization_reference"] = (
            "Record the authorization reference (ticket, contract, or signed scope document), at least 8 characters."
        )

    if form.get("attested") != "on":
        errors["attested"] = "Confirm that you are authorized to test this target."

    base_url = get("base_url")
    domains: list[str] = []
    bad_domains: list[str] = []
    domain_tokens = _tokens(get("allowed_domains"))
    for token in domain_tokens[:50]:
        try:
            domains.append(validate_domain_pattern(token))
        except ScopeError as exc:
            bad_domains.append(f"{token}: {exc}")
    if len(domain_tokens) > 50:
        bad_domains.append("At most 50 domain entries are allowed.")
    if bad_domains:
        errors["allowed_domains"] = " ".join(bad_domains)

    paths: list[str] = []
    bad_paths: list[str] = []
    path_tokens = _tokens(get("excluded_paths"))
    for token in path_tokens[:50]:
        try:
            paths.append(normalize_excluded_path(token))
        except ScopeError as exc:
            bad_paths.append(str(exc))
    if len(path_tokens) > 50:
        bad_paths.append("At most 50 excluded paths are allowed.")
    if bad_paths:
        errors["excluded_paths"] = " ".join(bad_paths)

    try:
        base_scope = Scope(base_url, [], [], lab_class=lab)
    except ScopeError as exc:
        errors["base_url"] = str(exc)
    else:
        if auth and auth.key == "localhost" and classify_host(base_scope.base.host) != "loopback":
            errors["base_url"] = "The 'localhost' authorization type requires a loopback host (localhost, 127.0.0.1 or ::1)."
        elif "allowed_domains" not in errors and "excluded_paths" not in errors:
            try:
                Scope(base_url, domains, paths, lab_class=lab)
            except ScopeError as exc:
                errors["allowed_domains"] = str(exc)

    limits = LIMITS["lab" if lab else "production"]
    rps = _number(get("max_requests_per_second"), float)
    if rps is None or not 0.1 <= rps <= limits["rps"]:
        errors["max_requests_per_second"] = f"Enter a rate between 0.1 and {limits['rps']:g} requests per second."
    conc = _number(get("max_concurrency"), int)
    if conc is None or not 1 <= conc <= limits["concurrency"]:
        errors["max_concurrency"] = f"Enter a whole number between 1 and {limits['concurrency']}."
    budget = _number(get("max_total_requests"), int)
    if budget is None or not 10 <= budget <= 100_000:
        errors["max_total_requests"] = "Enter a whole number between 10 and 100000."

    intensity = get("scan_intensity")
    if intensity not in INTENSITIES:
        errors["scan_intensity"] = "Choose a scan intensity."
    elif intensity == "thorough" and not lab:
        errors["scan_intensity"] = (
            "Thorough scans can run disruptive verification, so they are limited to lab-class targets "
            "(localhost, private lab, CTF, training app)."
        )

    requested = set(form.getlist("enabled_modules")) if hasattr(form, "getlist") else set(form.get("enabled_modules") or [])
    if requested - set(module_keys):
        errors["enabled_modules"] = "Unknown module selected."
    modules = [k for k in module_keys if k in requested]

    data = {
        "name": name,
        "base_url": base_url,
        "authorization_type": auth_key,
        "authorization_reference": reference,
        "allowed_domains": domains,
        "excluded_paths": paths,
        "max_requests_per_second": rps,
        "max_concurrency": conc,
        "max_total_requests": budget,
        "scan_intensity": intensity,
        "enabled_modules": modules,
        "attested": form.get("attested") == "on",
    }
    return data, errors


def _number(raw: str, kind):
    try:
        value = kind(raw)
    except (TypeError, ValueError):
        return None
    if kind is float and not math.isfinite(value):
        return None
    return value


def scope_for_target(target) -> Scope:
    """Build the Scope for a stored target. Fails closed on any inconsistency."""
    auth = AUTH_TYPES.get(getattr(target, "authorization_type", None))
    if auth is None:
        raise AuthorizationError("Target has no valid authorization type.")
    try:
        return Scope(target.base_url, target.allowed_domains or [], target.excluded_paths or [], lab_class=auth.lab_class)
    except ScopeError as exc:
        raise AuthorizationError(f"Target scope is invalid: {exc}") from exc


def assert_scan_permitted(target, url: str) -> Scope:
    """The gate. Call before every outbound request a scanner makes for ``target``."""
    if not getattr(target, "is_active", False):
        raise AuthorizationError("Target is disabled. Re-enable it in Target Manager before scanning.")
    if not getattr(target, "attested", False):
        raise AuthorizationError("Target has no recorded authorization attestation.")
    scope = scope_for_target(target)
    decision = scope.check_url(url)
    if not decision:
        raise AuthorizationError(decision.reason)
    return scope


def assert_source_analysis_permitted(target) -> None:
    """The gate for reading a target's source code: the target must be active and carry an authorization attestation.
    No network request is involved, so scope and rate limits do not apply."""
    if not getattr(target, "is_active", False):
        raise AuthorizationError("Target is disabled. Re-enable it in Target Manager before analysing its source.")
    if not getattr(target, "attested", False):
        raise AuthorizationError("Target has no recorded authorization attestation.")
