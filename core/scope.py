"""Scope enforcement for SYSX.

Every request any scanning module wants to make must pass ``Scope.check_url``.
Design rules:

* Fail closed: anything that cannot be parsed or classified is denied.
* Link-local / cloud-metadata addresses are blocked for every target, always.
* Loopback and private addresses are only reachable for lab-class targets.
* Redirects are never followed blindly: use ``Scope.check_redirect`` on every hop.
* Hostnames can resolve to internal addresses (DNS rebinding), so scanners must also
  call ``check_resolved_addresses`` immediately before connecting.
"""
from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import unquote, urljoin, urlsplit


class ScopeError(ValueError):
    """A URL, hostname, or scope definition is invalid."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    addresses: tuple = ()  # resolved IPs that were approved (set by check_resolved_addresses)

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class ParsedURL:
    scheme: str
    host: str
    port: int
    path: str


_ALWAYS_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.0.0/16",      # link-local, includes AWS/GCP/Azure metadata 169.254.169.254
        "fe80::/10",
        "fd00:ec2::/32",       # AWS IMDS over IPv6
        "100.100.100.200/32",  # Alibaba Cloud metadata
        "0.0.0.0/8",
        "224.0.0.0/4",
        "ff00::/8",
        "::/128",
    )
)
_BLOCKED_HOSTNAMES = frozenset({"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"})
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

BLOCKED_MESSAGE = "Address is in a blocked range (cloud metadata / link-local) and can never be scanned."
PRIVATE_MESSAGE = (
    "Loopback and private addresses can only be targeted with a lab-class authorization "
    "(localhost, private lab, CTF, or training app)."
)


def _as_ip(host: str):
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def classify_host(host: str) -> str:
    """Return 'blocked', 'loopback', 'private' or 'external' (a name or public IP)."""
    ip = _as_ip(host)
    if ip is not None:
        if any(ip in net for net in _ALWAYS_BLOCKED):
            return "blocked"
        if ip.is_loopback:
            return "loopback"
        if not ip.is_global:
            return "private"
        return "external"
    if host in _BLOCKED_HOSTNAMES:
        return "blocked"
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    return "external"


def normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ScopeError("Host is empty.")
    ip = _as_ip(host)
    if ip is not None:
        return str(ip)
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"Invalid hostname: {host!r}.") from exc
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ScopeError(f"Invalid hostname: {host!r}.")
    # Hosts like 2130706433 or 0x7f.1 are resolved as IP addresses by libc. Refuse them.
    if labels[-1].isdigit() or labels[-1].startswith("0x"):
        raise ScopeError("Ambiguous numeric hostname. Use a dotted IP address or a domain name.")
    return host


def parse_http_url(url: str) -> ParsedURL:
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL is empty.")
    url = url.strip()
    if "\\" in url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ScopeError("URL contains whitespace, control characters, or backslashes.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ScopeError("Only http:// and https:// URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("URLs with embedded credentials are not allowed.")
    if not parts.hostname:
        raise ScopeError("URL has no host.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError("URL has an invalid port.") from exc
    host = normalize_host(parts.hostname)
    return ParsedURL(parts.scheme, host, port or (443 if parts.scheme == "https" else 80), parts.path or "/")


def validate_domain_pattern(pattern: str) -> str:
    """Return the normalised pattern: ``host`` or ``*.registrable.domain``."""
    p = (pattern or "").strip().lower()
    wildcard = p.startswith("*.")
    base = p[2:] if wildcard else p
    if "*" in base:
        raise ScopeError("A wildcard is only allowed as a leading '*.' label.")
    host = normalize_host(base)
    if wildcard:
        if _as_ip(host) is not None:
            raise ScopeError("Wildcards cannot be combined with IP addresses.")
        if "." not in host:
            raise ScopeError("A wildcard must cover a registered domain (*.example.com), not a top-level domain.")
        return "*." + host
    return host


def _clean_path(path: str) -> str:
    decoded = unquote(path).replace("\\", "/")
    return posixpath.normpath("/" + decoded.lstrip("/")).lower()


def normalize_excluded_path(prefix: str) -> str:
    prefix = (prefix or "").strip()
    if not prefix.startswith("/"):
        raise ScopeError(f"Excluded path {prefix!r} must start with '/'.")
    if "*" in prefix or "?" in prefix or "#" in prefix:
        raise ScopeError(f"Excluded path {prefix!r} must be a plain path prefix (no wildcards or query strings).")
    cleaned = _clean_path(prefix)
    if cleaned == "/":
        raise ScopeError("Excluding '/' would exclude the whole target.")
    return cleaned


class Scope:
    """The registered scope of one target."""

    def __init__(
        self,
        base_url: str,
        allowed_domains: Iterable[str] = (),
        excluded_paths: Iterable[str] = (),
        lab_class: bool = False,
    ):
        self.base = parse_http_url(base_url)
        self.lab_class = lab_class
        patterns = {self.base.host} | {validate_domain_pattern(d) for d in allowed_domains}
        for pattern in patterns:
            if pattern.startswith("*."):
                continue
            self._reject_forbidden_class(classify_host(pattern))
        self._exact = frozenset(p for p in patterns if not p.startswith("*."))
        self._suffixes = tuple(sorted(p[1:] for p in patterns if p.startswith("*.")))
        self.patterns = tuple(sorted(patterns))
        self.excluded_paths = tuple(sorted({normalize_excluded_path(p) for p in excluded_paths}))
        port = self.base.port
        self.ports = frozenset({port} | ({80, 443} if port in (80, 443) else set()))

    def _reject_forbidden_class(self, cls: str) -> None:
        if cls == "blocked":
            raise ScopeError(BLOCKED_MESSAGE)
        if cls in ("loopback", "private") and not self.lab_class:
            raise ScopeError(PRIVATE_MESSAGE)

    def _host_in_scope(self, host: str) -> bool:
        return host in self._exact or any(host.endswith(suffix) for suffix in self._suffixes)

    def host_in_scope(self, host: str) -> bool:
        try:
            return self._host_in_scope(normalize_host(host))
        except ScopeError:
            return False

    @property
    def wildcard_roots(self) -> tuple[str, ...]:
        """Registered domains covered by a ``*.domain`` entry, e.g. ('example.com',)."""
        return tuple(suffix[1:] for suffix in self._suffixes)

    def check_url(self, url: str) -> ScopeDecision:
        try:
            parsed = parse_http_url(url)
        except ScopeError as exc:
            return ScopeDecision(False, str(exc))
        cls = classify_host(parsed.host)
        if cls == "blocked":
            return ScopeDecision(False, BLOCKED_MESSAGE)
        if not self._host_in_scope(parsed.host):
            return ScopeDecision(False, f"Host {parsed.host} is not in the registered scope.")
        if cls in ("loopback", "private") and not self.lab_class:
            return ScopeDecision(False, PRIVATE_MESSAGE)
        if parsed.port not in self.ports:
            allowed = ", ".join(str(p) for p in sorted(self.ports))
            return ScopeDecision(False, f"Port {parsed.port} is not in the registered scope (allowed: {allowed}).")
        path = _clean_path(parsed.path)
        for prefix in self.excluded_paths:
            if path == prefix or path.startswith(prefix + "/"):
                return ScopeDecision(False, f"Path is under the excluded prefix {prefix}.")
        return ScopeDecision(True, "In scope.")

    def check_redirect(self, current_url: str, location: str) -> ScopeDecision:
        """Validate one redirect hop. Scanners must disable automatic redirects."""
        return self.check_url(urljoin(current_url, location))


Resolver = Callable[..., list]


def check_resolved_addresses(host: str, lab_class: bool, resolver: Resolver = socket.getaddrinfo) -> ScopeDecision:
    """Check where a hostname actually resolves, right before connecting (DNS-rebinding guard)."""
    try:
        infos = resolver(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return ScopeDecision(False, f"Host {host} does not resolve.")
    is_literal = _as_ip(host) is not None
    approved: list[str] = []
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        cls = classify_host(address)
        if cls == "blocked":
            return ScopeDecision(False, f"{host} resolves to {address}. {BLOCKED_MESSAGE}")
        if cls in ("loopback", "private") and not lab_class and not is_literal:
            return ScopeDecision(False, f"{host} resolves to internal address {address}. {PRIVATE_MESSAGE}")
        if address not in approved:
            approved.append(address)
    if not approved:
        return ScopeDecision(False, f"Host {host} does not resolve.")
    return ScopeDecision(True, "Resolved addresses are acceptable.", tuple(approved))
