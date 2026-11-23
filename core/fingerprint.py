"""Technology fingerprinting from response headers, cookies and page content.

Rule-based and conservative: every result carries a confidence and the evidence that produced it.
Version numbers are only reported when the target itself discloses them.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Iterable, Mapping


@dataclass
class Tech:
    name: str
    category: str
    version: str | None = None
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "category": self.category, "version": self.version,
                "confidence": round(self.confidence, 2), "evidence": self.evidence[:6]}


# (header, regex, name, category, confidence)
HEADER_RULES = (
    ("server", r"nginx(?:/([\d.]+))?", "nginx", "web-server", .9),
    ("server", r"apache(?:/([\d.]+))?", "Apache HTTP Server", "web-server", .9),
    ("server", r"microsoft-iis(?:/([\d.]+))?", "Microsoft IIS", "web-server", .9),
    ("server", r"openresty(?:/([\d.]+))?", "OpenResty", "web-server", .9),
    ("server", r"litespeed", "LiteSpeed", "web-server", .9),
    ("server", r"caddy", "Caddy", "web-server", .9),
    ("server", r"kestrel", "Kestrel", "web-server", .9),
    ("server", r"jetty(?:\(([\d.]+)\))?", "Jetty", "web-server", .9),
    ("server", r"cloudflare", "Cloudflare", "cdn", .9),
    ("server", r"werkzeug(?:/([\d.]+))?", "Werkzeug", "web-server", .9),
    ("server", r"gunicorn(?:/([\d.]+))?", "Gunicorn", "web-server", .9),
    ("server", r"uvicorn", "Uvicorn", "web-server", .9),
    ("server", r"python/([\d.]+)", "Python", "language", .8),
    ("x-powered-by", r"php(?:/([\d.]+))?", "PHP", "language", .9),
    ("x-powered-by", r"express", "Express", "web-framework", .9),
    ("x-powered-by", r"asp\.net", "ASP.NET", "web-framework", .9),
    ("x-powered-by", r"next\.js", "Next.js", "web-framework", .9),
    ("x-aspnet-version", r"([\d.]+)", "ASP.NET", "web-framework", .9),
    ("x-generator", r"drupal(?: ([\d.]+))?", "Drupal", "cms", .9),
)
COOKIE_RULES = {
    "phpsessid": ("PHP", "language"), "jsessionid": ("Java servlet container", "platform"),
    "connect.sid": ("Express", "web-framework"), "csrftoken": ("Django", "web-framework"),
    "laravel_session": ("Laravel", "web-framework"), "asp.net_sessionid": ("ASP.NET", "web-framework"),
    "wordpress_logged_in": ("WordPress", "cms"), "wp-settings": ("WordPress", "cms"),
}
# (regex on body, name, category, confidence); first capture group is a version when present
BODY_RULES = (
    (r"/wp-content/|/wp-includes/", "WordPress", "cms", .85),
    (r"drupal\.settings|/sites/default/files", "Drupal", "cms", .8),
    (r"/_next/static|__NEXT_DATA__", "Next.js", "web-framework", .85),
    (r"/_nuxt/|window\.__NUXT__", "Nuxt", "web-framework", .85),
    (r"ng-version=\"([\d.]+)\"", "Angular", "javascript-framework", .9),
    (r"data-reactroot|react(?:\.production|-dom)(?:\.min)?\.js", "React", "javascript-framework", .6),
    (r"csrfmiddlewaretoken", "Django", "web-framework", .6),
    (r"__viewstate", "ASP.NET WebForms", "web-framework", .8),
    (r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", "jQuery", "javascript-library", .85),
    (r"bootstrap@([\d.]+)|bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap", "javascript-library", .7),
    (r"swagger-ui", "Swagger UI", "api-docs", .8),
    (r"damn vulnerable web application", "DVWA", "training-app", .95),
    (r"owasp juice shop", "OWASP Juice Shop", "training-app", .95),
)
_GENERATOR = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']{1,80})", re.I)


def fingerprint(headers: Mapping[str, str], body: str = "", cookie_names: Iterable[str] = ()) -> list[Tech]:
    found: dict[tuple[str, str], Tech] = {}

    def add(name, category, version, confidence, evidence):
        tech = found.setdefault((name, category), Tech(name, category))
        tech.confidence = max(tech.confidence, confidence)
        tech.version = tech.version or version
        if evidence not in tech.evidence:
            tech.evidence.append(evidence)

    lowered = {k.lower(): v for k, v in headers.items()}
    for header, pattern, name, category, confidence in HEADER_RULES:
        value = lowered.get(header)
        match = re.search(pattern, value, re.I) if value else None
        if match:
            add(name, category, match.group(1) if match.groups() else None, confidence, f"{header}: {value[:80]}")
    for cookie in cookie_names:
        rule = COOKIE_RULES.get(cookie.lower()) or next((v for k, v in COOKIE_RULES.items() if cookie.lower().startswith(k)), None)
        if rule:
            add(rule[0], rule[1], None, .6, f"cookie: {cookie[:40]}")
    sample = body[:300_000]
    lowered_body = sample.lower()
    gen = _GENERATOR.search(sample)
    if gen:
        text = gen.group(1).strip()
        m = re.match(r"([A-Za-z][\w .+-]*?)\s+v?(\d+(?:\.\d+)*)\s*$", text)
        add(m.group(1) if m else text, "generator", m.group(2) if m else None, .9, f"meta generator: {text}")
    for pattern, name, category, confidence in BODY_RULES:
        match = re.search(pattern, lowered_body)
        if match:
            version = match.group(1) if match.groups() and match.group(1) else None
            add(name, category, version, confidence, f"page content matches {name} signature")
    return sorted(found.values(), key=lambda t: (-t.confidence, t.name))


class TechAccumulator:
    """Thread-safe merge of fingerprints from many responses."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], Tech] = {}

    def add(self, techs: Iterable[Tech]) -> None:
        with self._lock:
            for t in techs:
                cur = self._items.setdefault((t.name, t.category), Tech(t.name, t.category))
                cur.confidence = max(cur.confidence, t.confidence)
                cur.version = cur.version or t.version
                for e in t.evidence:
                    if e not in cur.evidence:
                        cur.evidence.append(e)

    def results(self) -> list[dict]:
        with self._lock:
            return [t.as_dict() for t in sorted(self._items.values(), key=lambda t: (-t.confidence, t.name))]
