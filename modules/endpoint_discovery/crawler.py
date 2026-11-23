"""Scope-limited crawler. It only ever sends GET requests, never submits forms, and never fetches
URLs that look state-changing (logout, delete, ...). Every request goes through ScopedClient."""
from __future__ import annotations

import re
import secrets
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.fingerprint import TechAccumulator, fingerprint
from core.http import BudgetExceeded, Cancelled, FetchError, ScopedClient, ScopeViolation
from core.scope import ScopeError, parse_http_url
from modules.endpoint_discovery.classify import SENSITIVE_NAME, classify_param, summarize_checks
from modules.endpoint_discovery.extract import extract_js_routes, parse_html
from modules.misconfiguration.observe import MAX_OBSERVATIONS, observe_response
from modules.xss.dom_indicators import scan_js

ASSET_EXT = frozenset(".png .jpg .jpeg .gif .svg .ico .webp .bmp .css .woff .woff2 .ttf .eot .otf .mp3 .mp4 .webm .avi .mov "
                      ".pdf .zip .gz .tar .7z .rar .exe .dmg .iso .map".split())
STATE_CHANGING = re.compile(r"(^|[/_.-])(logout|logoff|signout|sign-out|log-out|delete|remove|destroy|unsubscribe|purge|wipe|deactivate)($|[/_.?-])", re.I)
LOGIN_HINT = re.compile(r"login|signin|sign-in|log-in|/auth|sso|session/new", re.I)
WELL_KNOWN = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/openapi.json", "/swagger.json", "/api-docs",
              "/api", "/graphql", "/login", "/signin", "/register", "/signup", "/admin", "/dashboard", "/account", "/profile")
HTML_TYPES = ("text/html", "application/xhtml+xml")


@dataclass
class CrawlOptions:
    max_pages: int = 100
    max_depth: int = 3
    max_js_files: int = 30
    max_variants_per_path: int = 3
    probe_wellknown: bool = False


def normalize_url(url: str) -> str | None:
    try:
        parsed = parse_http_url(url)
    except ScopeError:
        return None
    parts = urlsplit(url.strip())
    default = (parts.scheme == "http" and parsed.port == 80) or (parts.scheme == "https" and parsed.port == 443)
    host = f"[{parsed.host}]" if ":" in parsed.host else parsed.host
    netloc = host if default else f"{host}:{parsed.port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = [(k, "REDACTED" if SENSITIVE_NAME.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


class Crawler:
    def __init__(self, client: ScopedClient, options: CrawlOptions, tech: TechAccumulator | None = None, progress=None):
        self.client, self.opt = client, options
        self.tech = tech or TechAccumulator()
        self.progress = progress
        self.endpoints: dict[tuple, dict] = {}
        self.stats: Counter = Counter()
        self.sibling_hosts: set[str] = set()
        self.external_hosts: set[str] = set()
        self.dom_signals: list[dict] = []
        self.observations: list[dict] = []
        self._dom_seen: set[tuple] = set()
        self._seen: set[str] = set()
        self._variants: Counter = Counter()
        self._lock = threading.RLock()
        self._base_host = client.scope.base.host
        self._soft404 = None

    # -- public ------------------------------------------------------------
    def run(self) -> dict:
        base = normalize_url(self.client.base_url)
        frontier: list[tuple] = []
        try:
            self._seed(base, frontier)
            with ThreadPoolExecutor(max_workers=self.client.concurrency, thread_name_prefix="sysx-crawl") as pool:
                while frontier and self.stats["pages_fetched"] < self.opt.max_pages:
                    room = self.opt.max_pages - self.stats["pages_fetched"]
                    batch, frontier = frontier[:room], frontier[room:]
                    for new_items in pool.map(self._process, batch):
                        frontier.extend(new_items)
                    self._report()
        except BudgetExceeded:
            self.stats["budget_exhausted"] = 1
        return self.finalize()

    def finalize(self) -> dict:
        """Snapshot of everything found so far (also used to keep partial results after a cancel)."""
        self.stats["urls_discovered"] = len(self.endpoints)
        rows = sorted(self.endpoints.values(), key=lambda e: (e["url"], e["method"]))
        for row in rows:
            row["meta"]["checks"] = summarize_checks(row["params"])
        return {"endpoints": rows, "stats": dict(self.stats), "sibling_hosts": sorted(self.sibling_hosts),
                "external_hosts": sorted(self.external_hosts)[:100], "denied": list(self.client.denied)[:100],
                "dom_signals": list(self.dom_signals), "observations": list(self.observations)}

    # -- seeding -----------------------------------------------------------
    def _seed(self, base: str, frontier: list) -> None:
        item = self._queue(base, 0, None, "crawl")
        if item:
            frontier.append(item)
        origin = urlsplit(base)
        root = f"{origin.scheme}://{origin.netloc}"
        sitemaps: list[str] = []
        res = self._safe_get(root + "/robots.txt")
        if res is not None and res.status == 200 and "html" not in res.content_type:
            self._record_seed_file(root + "/robots.txt", res)
            for line in res.text.splitlines()[:500]:
                key, _, value = line.partition(":")
                key, value = key.strip().lower(), value.strip()
                if key in ("allow", "disallow") and value.startswith("/") and not re.search(r"[*$?]", value):
                    item = self._queue(root + value, 1, "robots.txt", "robots")
                    if item:
                        frontier.append(item)
                elif key == "sitemap" and value:
                    sitemaps.append(value)
        if not sitemaps:
            sitemaps.append(root + "/sitemap.xml")
        for sm in sitemaps[:3]:
            res = self._safe_get(sm)
            if res is not None and res.status == 200 and "html" not in res.content_type:
                self._record_seed_file(sm, res)
                for loc in re.findall(r"<loc>\s*([^<\s]{1,500})\s*</loc>", res.text)[:200]:
                    item = self._queue(loc, 1, sm, "sitemap")
                    if item:
                        frontier.append(item)
        if self.opt.probe_wellknown:
            self._probe_wellknown(root, frontier)

    def _record_seed_file(self, url: str, res) -> None:
        norm = normalize_url(url)
        if norm and norm not in self._seen:
            self._seen.add(norm)
            self._register(norm, "GET", "wellknown", 0, None)
            self._handle(norm, 0, None, "wellknown", res)

    def _safe_get(self, url):
        if not self.client.scope.check_url(url):
            return None
        try:
            return self.client.get(url)
        except (ScopeViolation, FetchError):
            return None

    def _probe_wellknown(self, root: str, frontier: list) -> None:
        cal = self._safe_get(f"{root}/sysx-probe-{secrets.token_hex(4)}")
        self._soft404 = (cal.status, cal.content_type, len(cal.body)) if cal is not None and cal.status < 400 else None
        for path in WELL_KNOWN:
            url = root + path
            norm = normalize_url(url)
            if norm in self._seen:
                continue
            res = self._safe_get(url)
            if res is None or res.status in (404, 410) or res.status >= 500:
                continue
            if self._soft404 and self._looks_like_soft404(res):
                self.stats["soft404_ignored"] += 1
                continue
            self._seen.add(norm)
            self._register(norm, "GET", "wellknown", 1, None)
            frontier.extend(self._handle(norm, 1, None, "wellknown", res))

    def _looks_like_soft404(self, res) -> bool:
        status, ctype, length = self._soft404
        return (res.status == status and res.content_type == ctype
                and abs(len(res.body) - length) <= max(20, length * 0.02))

    # -- queueing and registration -----------------------------------------
    def _queue(self, url: str, depth: int, found_on: str | None, source: str):
        norm = normalize_url(url)
        if norm is None:
            return None
        host = urlsplit(norm).hostname or ""
        decision = self.client.scope.check_url(norm)
        with self._lock:
            if not decision:
                if not self.client.scope.host_in_scope(host):
                    if len(self.external_hosts) < 200:
                        self.external_hosts.add(host)
                else:
                    self.stats["denied"] += 1
                return None
            if host != self._base_host:
                self.sibling_hosts.add(host)
            if norm in self._seen:
                return None
            path = urlsplit(norm).path.lower()
            is_js = path.endswith(".js")
            if not is_js and any(path.endswith(ext) for ext in ASSET_EXT):
                self.stats["assets_skipped"] += 1
                return None
            if STATE_CHANGING.search(path):
                self._seen.add(norm)
                self._register(norm, "GET", source, depth, found_on, meta={"skipped": "looks state-changing; never requested"})
                self.stats["guarded_skipped"] += 1
                return None
            vkey = (urlsplit(norm).netloc, path)
            if self._variants[vkey] >= self.opt.max_variants_per_path:
                self.stats["variants_skipped"] += 1
                return None
            self._variants[vkey] += 1
            self._seen.add(norm)
            self._register(norm, "GET", source, depth, found_on)
            limit = self.opt.max_depth + (1 if is_js else 0)
            if depth > limit:
                self.endpoints[self._key("GET", norm)]["meta"]["not_fetched"] = "depth limit"
                return None
            return (norm, depth, found_on, source)

    @staticmethod
    def _key(method: str, url: str) -> tuple:
        p = urlsplit(url)
        return (method, p.scheme, p.netloc, p.path or "/", tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})))

    def _register(self, url, method, source, depth, found_on, params=None, meta=None) -> dict:
        key = self._key(method, url)
        with self._lock:
            row = self.endpoints.get(key)
            if row is None:
                if params is None:
                    params = []
                    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)[:30]:
                        sample = None if SENSITIVE_NAME.search(name) else value[:60]
                        params.append({"name": name[:100], "location": "query", "type": "text", "sample": sample,
                                       "checks": classify_param(name, sample)})
                row = {"url": redact_url(url), "method": method, "status": None, "content_type": None, "title": None,
                       "source": source, "depth": depth, "auth_required": None, "params": params,
                       "meta": {"found_on": found_on, **(meta or {})}}
                self.endpoints[key] = row
            elif meta:
                row["meta"].update(meta)
            return row

    # -- processing ----------------------------------------------------------
    def _process(self, item: tuple) -> list:
        url, depth, found_on, source = item
        if self.client.cancel_event.is_set():
            raise Cancelled("Scan cancelled.")
        is_js = urlsplit(url).path.lower().endswith(".js")
        if is_js:
            with self._lock:
                if self.stats["js_fetched"] >= self.opt.max_js_files:
                    self.endpoints[self._key("GET", url)]["meta"]["not_fetched"] = "JavaScript file limit"
                    return []
                self.stats["js_fetched"] += 1
        try:
            res = self.client.get(url)
        except ScopeViolation:
            self.stats["denied"] += 1
            return []
        except FetchError as exc:
            self.stats["errors"] += 1
            self._register(url, "GET", source, depth, found_on, meta={"error": str(exc)})
            return []
        with self._lock:
            if not is_js:
                self.stats["pages_fetched"] += 1
            n = self.stats["pages_fetched"]
        if n and n % 5 == 0:
            self._report()
        return self._handle(url, depth, found_on, source, res)

    def _report(self) -> None:
        if self.progress:
            try:
                self.progress(self.client.requests_made, self.stats["pages_fetched"], len(self.endpoints))
            except Exception:  # progress reporting must never break a scan
                pass

    def _handle(self, url: str, depth: int, found_on, source: str, res) -> list:
        out: list = []
        row = self._register(url, "GET", source, depth, found_on)
        ctype = res.content_type
        is_text = (not ctype) or ctype.startswith("text/") or "json" in ctype or "javascript" in ctype or "xml" in ctype
        text = res.text if is_text else ""
        cookie_names = [c.split("=", 1)[0].strip() for c in res.set_cookies]
        self.tech.add(fingerprint(res.headers, text, cookie_names))
        with self._lock:
            if len(self.observations) < MAX_OBSERVATIONS:
                self.observations.append(observe_response(redact_url(res.url), res, text if is_text else ""))
            row.update(status=res.status, content_type=ctype or None)
            row["meta"]["final_url"] = redact_url(res.url) if res.url != url else None
            if res.blocked_redirect:
                row["meta"]["blocked_redirect"] = res.blocked_redirect
                self.stats["blocked_redirects"] += 1
            if res.status in (401, 403):
                row["auth_required"] = True
            elif res.redirects and LOGIN_HINT.search(urlsplit(res.url).path) and not LOGIN_HINT.search(urlsplit(url).path):
                row["auth_required"] = True
                row["meta"]["redirects_to_login"] = True
            elif res.status < 400:
                row["auth_required"] = False
        if res.redirects and res.url != url:
            item = self._queue(res.url, depth, url, "redirect")
            if item:
                out.append(item)
        nxt = depth + 1
        if ctype in HTML_TYPES or (not ctype and "<html" in text[:2000].lower()):
            page = parse_html(res.url, text)
            row["title"] = page.title or None
            for link in page.links:
                item = self._queue(link, nxt, url, "crawl")
                if item:
                    out.append(item)
            for src in page.scripts:
                item = self._queue(src, nxt, url, "script")
                if item:
                    out.append(item)
            for js in page.inline_js:
                self._note_dom_signal(js, res.url, "inline")
                out.extend(self._js_routes(js, res.url, nxt, url))
            for form in page.forms:
                out.extend(self._form(form, url, nxt))
        elif "javascript" in ctype or urlsplit(url).path.lower().endswith(".js"):
            self._note_dom_signal(text, url, "external")
            out.extend(self._js_routes(text, res.url, nxt, url))
        return out

    def _note_dom_signal(self, js_text: str, url: str, via: str) -> None:
        signal = scan_js(js_text)
        if not signal:
            return
        key = (redact_url(url), tuple(signal["sinks"]), tuple(signal["sources"]))
        with self._lock:
            if key in self._dom_seen or len(self.dom_signals) >= 50:
                return
            self._dom_seen.add(key)
            self.dom_signals.append({"url": redact_url(url), "via": via, **signal})

    def _js_routes(self, js: str, page_url: str, depth: int, found_on: str) -> list:
        from urllib.parse import urljoin
        out = []
        for route in extract_js_routes(js):
            absolute = urljoin(page_url, route["path"])
            norm = normalize_url(absolute) if not route["templated"] else None
            if route["templated"] or route["method"] != "GET":
                target = normalize_url(urljoin(page_url, re.sub(r"\$\{[^}]*\}|\{[^}]*\}", "1", route["path"])))
                if target and self.client.scope.check_url(target):
                    self._register(target, route["method"], "js", depth, found_on,
                                   meta={"via": route["via"], "templated": route["templated"], "not_fetched": "not a plain GET"})
                continue
            item = self._queue(norm, depth, found_on, "js") if norm else None
            if item:
                out.append(item)
        return out

    def _form(self, form, page_url: str, depth: int) -> list:
        norm = normalize_url(form.action)
        if norm is None or not self.client.scope.check_url(norm):
            return []
        params = []
        for f in form.fields:
            params.append({"name": f["name"], "location": "form", "type": f["type"], "sample": f["value"],
                           "checks": classify_param(f["name"], f["value"], f["type"])})
        meta = {"form": True, "enctype": form.enctype or None, "has_file": form.has_file,
                "has_password": form.has_password, "csrf_field": form.csrf_field, "not_fetched": "form target; never submitted"}
        key_url = norm.split("?", 1)[0] if form.method == "GET" else norm
        if form.method == "GET":
            # Named submit buttons ride along as constant, untested parameters: many apps only act when they are present.
            pairs = [f"{p['name']}=" for p in params] + [f"{b['name']}={b['value']}" for b in form.submit_fields]
            key_url = key_url + ("?" + "&".join(pairs) if pairs else "")
        row = self._register(key_url, form.method, "form", depth, page_url, params=params, meta=meta)
        row["auth_required"] = None
        out = []
        if form.method == "GET":  # the bare action URL is a normal page worth crawling
            item = self._queue(norm.split("?", 1)[0], depth, page_url, "form")
            if item:
                out.append(item)
        return out
