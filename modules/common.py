"""Small helpers shared by the Phase 4 detectors."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.http import FetchError, ScopeViolation


def set_param(url: str, name: str, value: str) -> str:
    """The URL with query parameter ``name`` set to ``value`` (other parameters are kept)."""
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def safe_get(client, url: str, **kwargs):
    """GET that turns a per-request refusal or network failure into None. Budget and cancel still propagate."""
    try:
        return client.get(url, **kwargs)
    except (ScopeViolation, FetchError):
        return None
