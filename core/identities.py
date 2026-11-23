"""Turn stored test credentials into request identities for ScopedClient.

Only credential types that work with GET-only scanning are usable: a ``basic`` login, a ``bearer`` token, a
``cookie`` header string (for example a session cookie copied from a test login) or an arbitrary ``header``.
A plain ``password`` credential would need a login *form* to be submitted, which SYSX never does, so it is
stored but not used. Secrets are decrypted in memory only and are never logged or put in evidence.
"""
from __future__ import annotations

import base64
import re

from core.crypto import VaultError

AUTH_TYPES = {
    "password": "Password (stored only; SYSX cannot submit login forms)",
    "basic": "HTTP Basic (username + password)",
    "bearer": "Bearer token (Authorization header)",
    "cookie": "Cookie header (for example PHPSESSID=...; security=low)",
    "header": "Custom header (username field = header name, secret = value)",
}
USABLE = ("basic", "bearer", "cookie", "header")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9\-]{1,60}$")
_FORBIDDEN = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "user-agent",
              "x-sysx-scan", "origin", "proxy-authorization"}


def _clean(value: str) -> bool:
    return bool(value) and not any(c in value for c in "\r\n\x00")


def headers_for(auth_type: str, username: str, secret: str) -> dict[str, str] | None:
    """Request headers for one credential, or None if it is not usable or is malformed."""
    if not _clean(secret) or (username and not _clean(username)):
        return None
    if auth_type == "basic":
        if ":" in username:
            return None
        return {"Authorization": "Basic " + base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")}
    if auth_type == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    if auth_type == "cookie":
        return {"Cookie": secret}
    if auth_type == "header":
        if not _HEADER_NAME.match(username) or username.lower() in _FORBIDDEN:
            return None
        return {username: secret}
    return None


def load_identities(storage, target_id: int, vault) -> tuple[dict[str, dict[str, str]], dict[str, str], int]:
    """Returns (identity name -> headers, identity name -> label, number of stored credentials that could not be used)."""
    identities: dict[str, dict[str, str]] = {}
    labels: dict[str, str] = {}
    unused = 0
    for cred in sorted(storage.list_credentials(target_id), key=lambda c: c.id):
        auth_type = getattr(cred, "auth_type", None) or "password"
        if auth_type not in USABLE:
            unused += 1
            continue
        try:
            secret = vault.decrypt(cred.secret_enc)
        except VaultError:
            unused += 1
            continue
        headers = headers_for(auth_type, cred.username, secret)
        if headers is None:
            unused += 1
            continue
        name = f"cred:{cred.id}"
        identities[name], labels[name] = headers, cred.label
    return identities, labels, unused
