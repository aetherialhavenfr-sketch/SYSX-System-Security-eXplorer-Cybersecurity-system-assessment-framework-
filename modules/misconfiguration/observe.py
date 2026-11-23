"""What the crawler remembers about each response, for passive checks later.

Only metadata is kept: selected response headers, cookie *attributes* (never cookie values), and two body
signals (directory listing, stack trace). No response body is stored.
"""
from __future__ import annotations

import re

KEPT_HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options",
                "referrer-policy", "server", "x-powered-by", "access-control-allow-origin",
                "access-control-allow-credentials", "www-authenticate")
MAX_OBSERVATIONS = 300
_SCAN_CHARS = 200_000

_DIR_LISTING = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /|<title>\s*Directory Listing For", re.I)
_STACK_TRACES = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"(?:Exception in thread|\bat [\w.$]+\([\w$]+\.java:\d+\))")),
    ("PHP error with file path", re.compile(r"(?:Fatal error|Parse error|Uncaught \w*Exception)[^\n]{0,200}\bon line \d+|Stack trace:\s*#0 ")),
    (".NET error page", re.compile(r"Server Error in '/[^']*' Application|System\.\w+Exception:")),
    ("Node.js stack trace", re.compile(r"\bat (?:Object|Module|Function)\.[\w<>.$]+ \([^)\n]*\.js:\d+:\d+\)")),
    ("Django debug page", re.compile(r"You're seeing this error because you have\s*<code>DEBUG = True")),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception")),
    ("Rails error page", re.compile(r"ActionController::RoutingError|Action Controller: Exception caught")),
)
SESSION_COOKIE = re.compile(r"sess|sid$|^sid|jsessionid|phpsessid|connect\.sid|auth|token|login", re.I)


def parse_cookie(raw: str) -> dict:
    """Attributes of one Set-Cookie header. The cookie's value is deliberately dropped."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()[:100]
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip().lower()
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite") or None, "path": attrs.get("path") or "/"}


def body_signals(text: str) -> tuple[bool, str | None]:
    sample = text[:_SCAN_CHARS]
    listing = bool(_DIR_LISTING.search(sample))
    trace = next((name for name, rx in _STACK_TRACES if rx.search(sample)), None)
    return listing, trace


def observe_response(url: str, res, text: str) -> dict:
    listing, trace = body_signals(text) if text else (False, None)
    return {
        "url": url[:500], "status": res.status, "https": url.lower().startswith("https://"),
        "ctype": res.content_type,
        "headers": {h: res.headers.get(h)[:300] for h in KEPT_HEADERS if res.headers.get(h)},
        "cookies": [parse_cookie(c) for c in res.set_cookies[:20]],
        "dir_listing": listing, "stack_trace": trace,
    }
