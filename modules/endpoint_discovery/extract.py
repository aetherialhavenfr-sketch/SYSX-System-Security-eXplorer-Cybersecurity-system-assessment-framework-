"""Pure parsing helpers: HTML pages, forms, and routes referenced from JavaScript. No network access."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin

from bs4 import BeautifulSoup

_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "sms:", "blob:", "about:")
_SKIP_REL = {"stylesheet", "icon", "shortcut", "preload", "prefetch", "dns-prefetch", "preconnect", "apple-touch-icon", "mask-icon"}
_CSRF_NAME = re.compile(r"csrf|xsrf|authenticity|_token$|^token$", re.I)


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list = field(default_factory=list)  # {"name","type","value"}
    has_file: bool = False
    has_password: bool = False
    csrf_field: bool = False
    enctype: str = ""
    submit_fields: list = field(default_factory=list)  # named submit buttons: {"name","value"}


@dataclass
class PageInfo:
    title: str = ""
    links: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    inline_js: list = field(default_factory=list)
    forms: list = field(default_factory=list)


def _clean(base: str, href: str | None) -> str | None:
    href = (href or "").strip()
    if not href or href.lower().startswith(_SKIP_SCHEMES):
        return None
    url, _ = urldefrag(urljoin(base, href))
    return url if url.lower().startswith(("http://", "https://")) else None


def parse_html(page_url: str, html: str) -> PageInfo:
    soup = BeautifulSoup(html, "html.parser")
    info = PageInfo(title=(soup.title.get_text(strip=True)[:200] if soup.title else ""))
    base_tag = soup.find("base", href=True)
    base = urljoin(page_url, base_tag["href"]) if base_tag else page_url
    seen = set()

    def add_link(href):
        url = _clean(base, href)
        if url and url not in seen:
            seen.add(url)
            info.links.append(url)

    for tag in soup.find_all(["a", "area"], href=True):
        add_link(tag["href"])
    for tag in soup.find_all(["iframe", "frame"], src=True):
        add_link(tag["src"])
    for tag in soup.find_all("link", href=True):
        rel = {r.lower() for r in (tag.get("rel") or [])}
        if not rel & _SKIP_REL:
            add_link(tag["href"])
    for tag in soup.find_all("script"):
        if tag.get("src"):
            url = _clean(base, tag["src"])
            if url and url not in info.scripts:
                info.scripts.append(url)
        else:
            text = tag.string or tag.get_text()
            if text and len(info.inline_js) < 20:
                info.inline_js.append(text[:200_000])
    for form in soup.find_all("form"):
        action = _clean(base, form.get("action")) or page_url
        f = FormInfo(action=urldefrag(action)[0], method=(form.get("method") or "GET").upper(),
                     enctype=(form.get("enctype") or "").lower())
        if f.method not in ("GET", "POST"):
            f.method = "POST"
        for el in form.find_all(["input", "select", "textarea", "button"]):
            name = el.get("name")
            if not name:
                continue
            itype = (el.get("type") or ("select" if el.name == "select" else "textarea" if el.name == "textarea" else "text")).lower()
            if itype in ("submit", "button", "image", "reset"):
                if itype == "submit" and len(f.submit_fields) < 3:
                    default = "Submit" if el.name == "input" else ""
                    f.submit_fields.append({"name": name[:100], "value": (el.get("value") or default)[:60]})
                continue
            value = el.get("value")
            if el.name == "select":
                opt = el.find("option")
                value = opt.get("value") if opt and opt.get("value") is not None else (opt.get_text(strip=True) if opt else None)
            if itype in ("hidden", "password", "file"):
                value = None  # never keep hidden/secret values (CSRF tokens, passwords)
            f.fields.append({"name": name[:100], "type": itype, "value": (value or None) and value[:60]})
            f.has_file |= itype == "file"
            f.has_password |= itype == "password"
            f.csrf_field |= itype == "hidden" and bool(_CSRF_NAME.search(name))
        info.forms.append(f)
    return info


# --- JavaScript route extraction ------------------------------------------------------------
_PATH = r"""['"`]((?:https?://[^'"`\s]{1,300}|/[^'"`\s/][^'"`\s]{0,299}))['"`]"""
_JS_RULES = (
    (re.compile(r"fetch\(\s*" + _PATH + r"(?:\s*,\s*\{[^{}]*?method\s*:\s*['\"`]([A-Za-z]+)['\"`])?", re.S), "fetch"),
    (re.compile(r"axios\.(get|post|put|delete|patch|head)\(\s*" + _PATH, re.I), "axios"),
    (re.compile(r"\$\.(get|post|getJSON)\(\s*" + _PATH, re.I), "jquery"),
    (re.compile(r"\.open\(\s*['\"`](GET|POST|PUT|DELETE|PATCH)['\"`]\s*,\s*" + _PATH, re.I), "xhr"),
)
_API_LITERAL = re.compile(r"""['"`](/(?:api|rest|graphql|v\d+)(?:/[A-Za-z0-9_\-.~%${}:\[\]]*)*)['"`]""")
_TEMPLATED = re.compile(r"\$\{|\{[^}]*\}|/:[A-Za-z_]")


def extract_js_routes(js: str) -> list[dict]:
    """Routes referenced from JavaScript: [{"path","method","via","templated"}]."""
    found: dict[tuple[str, str], dict] = {}

    def add(path, method, via):
        method = (method or "GET").upper()
        method = "GET" if method == "GETJSON" else method
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
            return
        found.setdefault((method, path), {"path": path, "method": method, "via": via, "templated": bool(_TEMPLATED.search(path))})

    for pattern, via in _JS_RULES:
        for m in pattern.finditer(js):
            if via == "fetch":
                add(m.group(1), m.group(2), via)
            elif via in ("axios", "jquery"):
                add(m.group(2), m.group(1), via)
            else:
                add(m.group(2), m.group(1), via)
    explicit = {path for (_, path) in found}
    for m in _API_LITERAL.finditer(js):  # bare string literals only fill gaps: never override a known method
        if m.group(1) not in explicit:
            add(m.group(1), "GET", "literal")
    return list(found.values())[:300]
