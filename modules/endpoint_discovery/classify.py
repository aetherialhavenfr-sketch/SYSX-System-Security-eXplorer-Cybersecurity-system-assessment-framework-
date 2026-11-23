"""Parameter intelligence: which checks does this input deserve, and why? Name-based and explainable."""
from __future__ import annotations

import re

REASONS = {
    "xss": "free-text style input that is often rendered back into a page",
    "sqli": "identifier, filter or search style input that often reaches a database query",
    "idor": "object identifier: verify authorization per object",
    "ssrf": "name suggests a URL or host the server may fetch",
    "open_redirect": "name suggests a redirect destination",
    "path_traversal": "name suggests a file, path or template selector",
    "ssti": "name suggests a server-side template or view selector",
    "command_injection": "name suggests input passed to a system command",
    "file_upload": "file upload field",
    "authentication": "password field: authentication endpoint",
}
_TOKENS = {
    "xss": {"q", "s", "query", "search", "keyword", "term", "text", "msg", "message", "comment", "body", "content", "title",
            "subject", "name", "firstname", "lastname", "description", "desc", "feedback", "bio", "note", "notes"},
    "sqli": {"id", "uid", "pid", "oid", "user", "item", "product", "order", "cat", "category", "page", "offset", "limit",
             "sort", "orderby", "year", "month", "filter", "search", "q", "query", "keyword", "term", "name", "num", "number"},
    "idor": {"id", "uid", "pid", "oid", "uuid", "user", "account", "order", "invoice", "doc", "document", "profile", "item"},
    "ssrf": {"url", "uri", "link", "src", "feed", "webhook", "image", "img", "site", "domain", "host", "callback", "dest",
             "destination", "target", "proxy", "fetch", "remote"},
    "open_redirect": {"redirect", "return", "returnto", "next", "continue", "goto", "dest", "destination", "url", "redir",
                      "back", "forward", "callback"},
    "path_traversal": {"file", "filename", "path", "dir", "folder", "doc", "document", "template", "tpl", "include", "inc",
                       "load", "read", "view", "lang", "locale", "page", "download"},
    "ssti": {"template", "tpl", "theme", "layout", "view", "render"},
    "command_injection": {"cmd", "command", "exec", "run", "ping", "ip", "host", "process", "shell", "execute"},
}
SENSITIVE_NAME = re.compile(r"pass|pwd|secret|token|key|auth|session|sig|signature|credential|csrf|xsrf", re.I)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokens(name: str) -> set[str]:
    parts = [p.lower() for p in re.split(r"[^A-Za-z0-9]+", _CAMEL.sub("_", name)) if p]
    return set(parts) | {"".join(parts)}


def classify_param(name: str, sample: str | None = None, input_type: str = "text") -> list[dict]:
    toks = tokens(name)
    checks = [{"check": c, "reason": REASONS[c]} for c, words in _TOKENS.items() if toks & words]
    names = {c["check"] for c in checks}
    if sample is not None and re.fullmatch(r"-?\d{1,18}", sample) and "sqli" not in names:
        checks.append({"check": "sqli", "reason": "numeric value: typical of unquoted SQL parameters"})
    if input_type == "file":
        checks.append({"check": "file_upload", "reason": REASONS["file_upload"]})
    if input_type == "password":
        checks.append({"check": "authentication", "reason": REASONS["authentication"]})
    return checks


def summarize_checks(params: list[dict]) -> list[str]:
    return sorted({c["check"] for p in params for c in p.get("checks", [])})
