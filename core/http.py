"""The only HTTP client scanning modules may use.

Every hop of every request is checked against the target's scope, DNS is re-checked
right before connecting, redirects are followed manually (each hop validated), traffic is
rate-limited, concurrency- and budget-capped, and only safe methods (GET, HEAD) are sent.
"""
from __future__ import annotations

import socket
import threading
import time
from http.cookiejar import DefaultCookiePolicy
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from requests.structures import CaseInsensitiveDict

from core.authorization import assert_scan_permitted
from core.scope import ScopeError, check_resolved_addresses, parse_http_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # TLS is assessed separately

SAFE_METHODS = frozenset({"GET", "HEAD"})
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "SYSX/1.0 (authorized security assessment)"
ANONYMOUS = "anonymous"  # identity name that sends no credentials
_DEFAULT = object()


class ScanAborted(Exception):
    """Base for conditions that stop a scan."""


class ScopeViolation(ScanAborted):
    def __init__(self, url: str, reason: str):
        super().__init__(f"{reason} ({url[:200]})")
        self.url, self.reason = url, reason


class BudgetExceeded(ScanAborted):
    pass


class Cancelled(ScanAborted):
    pass


class FetchError(Exception):
    """Network-level failure for one request (connect error, timeout, TLS failure)."""


@dataclass
class FetchResult:
    requested_url: str
    url: str
    status: int
    headers: CaseInsensitiveDict
    body: bytes
    truncated: bool
    elapsed: float
    set_cookies: list = field(default_factory=list)
    redirects: list = field(default_factory=list)  # (from_url, status, to_url)
    blocked_redirect: str | None = None

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";", 1)[0].strip().lower()

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type") or ""
        if "charset=" in ctype.lower():
            charset = ctype.lower().split("charset=", 1)[1].split(";", 1)[0].strip(" \"'") or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class ScopedClient:
    def __init__(self, target, *, timeout: float = 10.0, max_body: int = 1_000_000, max_redirects: int = 5,
                 cancel_event: threading.Event | None = None, resolver: Callable = socket.getaddrinfo,
                 session: requests.Session | None = None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, scan_id: int | None = None):
        # The gate: refuses disabled or un-attested targets and invalid scopes.
        self.scope = assert_scan_permitted(target, target.base_url)
        self.base_url = target.base_url
        self.rps = float(target.max_requests_per_second)
        self.budget = int(target.max_total_requests)
        self.concurrency = int(target.max_concurrency)
        self.timeout, self.max_body, self.max_redirects = timeout, max_body, max_redirects
        self.cancel_event = cancel_event or threading.Event()
        self.resolver, self._clock, self._sleep = resolver, clock, sleep
        self.session = session or requests.Session()
        self.session.trust_env = False  # never route scan traffic through ambient proxies
        self.headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if scan_id is not None:
            self.headers["X-SYSX-Scan"] = str(scan_id)  # lets the target's operator identify scan traffic
        self.requests_made = 0
        self.denied: list[tuple[str, str]] = []
        self.identities: dict[str, dict[str, str]] = {}
        self.default_identity: str | None = None
        self._base_host = (urlsplit(target.base_url).hostname or "").lower()
        self._lock = threading.Lock()
        self._next_slot = 0.0
        self._gate = threading.BoundedSemaphore(self.concurrency)

    # -- test identities ---------------------------------------------------
    def set_identities(self, identities: dict[str, dict[str, str]], default: str | None = None) -> None:
        """Register authenticated test identities: name -> request headers (Cookie, Authorization, ...).

        The headers are only ever sent to the target's own host, never to another host that happens to be
        in scope and never to a redirect target elsewhere. The cookie jar is switched off so that a session
        cookie the server sets for one identity can never leak into a request made as another.
        """
        self.identities = {name: dict(headers) for name, headers in identities.items()}
        self.default_identity = default
        self.session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        self.session.cookies.clear()

    def _identity_headers(self, identity, url: str) -> dict[str, str]:
        name = self.default_identity if identity is _DEFAULT else identity
        if not name or name == ANONYMOUS or name not in self.identities:
            return {}
        if (urlsplit(url).hostname or "").lower() != self._base_host:
            return {}
        return self.identities[name]

    # -- the choke point -------------------------------------------------
    def authorize(self, url: str) -> tuple[str, ...]:
        """Scope + DNS + cancellation + budget + pacing. Returns the approved IP addresses."""
        if self.cancel_event.is_set():
            raise Cancelled("Scan cancelled.")
        decision = self.scope.check_url(url)
        if not decision:
            self._deny(url, decision.reason)
        try:
            host = parse_http_url(url).host
        except ScopeError as exc:  # pragma: no cover - check_url already parsed it
            self._deny(url, str(exc))
        dns = check_resolved_addresses(host, self.scope.lab_class, self.resolver)
        if not dns:
            self._deny(url, dns.reason)
        self._take_slot()
        return dns.addresses

    def _deny(self, url: str, reason: str):
        with self._lock:
            if len(self.denied) < 200:
                self.denied.append((url[:300], reason))
        raise ScopeViolation(url, reason)

    def _take_slot(self) -> None:
        with self._lock:
            if self.requests_made >= self.budget:
                raise BudgetExceeded(f"Request budget of {self.budget} reached.")
            self.requests_made += 1
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + 1.0 / self.rps
            wait = slot - now
        if wait > 0:
            self._sleep(wait)

    # -- requests ----------------------------------------------------------
    def get(self, url: str, *, method: str = "GET", follow_redirects: bool = True, headers: dict | None = None,
            identity=_DEFAULT) -> FetchResult:
        """``headers`` adds request headers for this call; ``identity`` picks a registered test identity
        (default: the client's default identity; ``ANONYMOUS`` sends no credentials)."""
        if method not in SAFE_METHODS:
            raise ValueError("SYSX only sends GET and HEAD requests.")
        redirects: list[tuple[str, int, str]] = []
        current, last = url, None
        with self._gate:
            while True:
                try:
                    self.authorize(current)
                except ScopeViolation as exc:
                    if last is None:
                        raise
                    last.blocked_redirect = exc.reason
                    last.redirects = redirects
                    return last
                response = self._send(method, current, headers, identity)
                response.requested_url = url
                response.redirects = redirects
                location = response.headers.get("location")
                if not follow_redirects or response.status not in REDIRECT_CODES or not location:
                    return response
                if len(redirects) >= self.max_redirects:
                    response.blocked_redirect = "Too many redirects."
                    return response
                nxt = urljoin(current, location)
                redirects.append((current, response.status, nxt))
                last, current = response, nxt

    def _send(self, method: str, url: str, extra_headers: dict | None = None, identity=_DEFAULT) -> FetchResult:
        start = self._clock()
        secret_headers = self._identity_headers(identity, url)
        headers = {**self.headers, **secret_headers, **(extra_headers or {})}
        # Anonymous requests skip certificate validation so a target with a bad certificate can still be assessed (the
        # certificate itself is reported by the TLS checks). A request that carries a test credential never does: the
        # credential is only sent over a connection whose certificate verifies.
        verify = bool(secret_headers) and url.lower().startswith("https:")
        try:
            resp = self.session.request(method, url, headers=headers, timeout=(self.timeout, self.timeout),
                                        allow_redirects=False, stream=True, verify=verify)
        except requests.RequestException as exc:
            raise FetchError(f"{type(exc).__name__}: {exc}"[:300]) from exc
        try:
            chunks, size, truncated = [], 0, False
            if method != "HEAD":
                try:
                    for chunk in resp.iter_content(65536):
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= self.max_body:
                            truncated = True
                            break
                except requests.RequestException as exc:
                    raise FetchError(f"{type(exc).__name__}: {exc}"[:300]) from exc
            cookies = []
            raw_headers = getattr(resp.raw, "headers", None)
            if raw_headers is not None and hasattr(raw_headers, "getlist"):
                cookies = list(raw_headers.getlist("Set-Cookie"))
            return FetchResult(url, url, resp.status_code, CaseInsensitiveDict(resp.headers), b"".join(chunks)[: self.max_body],
                               truncated, self._clock() - start, cookies)
        finally:
            resp.close()
