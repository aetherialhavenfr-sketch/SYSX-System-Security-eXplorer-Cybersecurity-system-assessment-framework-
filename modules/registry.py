"""Registry of scan modules and dashboard sections.

``phase`` is the development phase in which the item becomes real. Anything whose
phase is later than the current build is shown as *planned* in the UI, never as a
working feature.
"""
from __future__ import annotations

from dataclasses import dataclass

CURRENT_PHASE = 7


@dataclass(frozen=True)
class ModuleDef:
    key: str
    label: str
    phase: int
    default_enabled: bool
    summary: str


MODULES = (
    ModuleDef("reconnaissance", "Reconnaissance", 2, True, "Domain, DNS, TLS and technology fingerprinting."),
    ModuleDef("endpoint_discovery", "Crawler and endpoint discovery", 2, True, "Pages, forms, parameters and API routes."),
    ModuleDef("xss", "XSS detection", 3, True, "Reflected XSS with browser verification, plus static DOM-based indicators. Stored XSS is not yet implemented."),
    ModuleDef("sqli", "SQL injection detection", 3, True, "Error, boolean and time-based checks with safe verification."),
    ModuleDef("ssrf", "SSRF detection", 4, False,
              "URL-fetching parameters, confirmed only through your own callback listener (thorough intensity, lab-class targets)."),
    ModuleDef("csrf", "CSRF", 4, True, "Missing anti-CSRF tokens on state-changing forms and state changes over GET (passive)."),
    ModuleDef("idor", "IDOR and access control", 4, False,
              "Compares what different test identities and an anonymous client can fetch (needs two or more stored credentials)."),
    ModuleDef("additional_vulns", "Additional vulnerability checks", 4, False,
              "Path traversal, open redirects, template injection, command injection (thorough only) and upload-form review. XXE is not implemented."),
    ModuleDef("misconfiguration", "Security misconfiguration", 4, True, "Headers, cookies, TLS, CORS, exposed files."),
    ModuleDef("authentication", "Authentication and sessions", 4, True, "Login over HTTP, credentials or session IDs in URLs, Basic auth over HTTP (passive)."),
    ModuleDef("source_analysis", "Source code analysis", 5, False, "Built-in Python/JavaScript rules and secret detection, plus optional Bandit, Semgrep and pip-audit, over an authorized source directory."),
)
MODULE_KEYS = tuple(m.key for m in MODULES)
DEFAULT_MODULES = tuple(m.key for m in MODULES if m.default_enabled)


@dataclass(frozen=True)
class NavItem:
    slug: str
    label: str
    endpoint: str | None  # None means the section is planned and served by the placeholder view
    phase: int
    summary: str = ""
    prefixes: tuple[str, ...] = ()  # extra endpoint prefixes that highlight this item

    @property
    def implemented(self) -> bool:
        return self.endpoint is not None


NAV_GROUPS: tuple[tuple[str, tuple[NavItem, ...]], ...] = (
    ("Operate", (
        NavItem("command-center", "Command Center", "main.index", 1),
        NavItem("targets", "Target Manager", "targets.index", 1, prefixes=("targets.",)),
    )),
    ("Discover", (
        NavItem("reconnaissance", "Reconnaissance", "scans.recon", 2),
        NavItem("attack-surface", "Attack Surface", "evidence.attack_surface", 6),
        NavItem("crawler", "Web Crawler", "scans.crawler", 2, prefixes=("scans.detail", "scans.cancel", "scans.status")),
        NavItem("endpoints", "Endpoint Explorer", "scans.endpoints", 2),
    )),
    ("Assess", (
        NavItem("scanner", "Vulnerability Scanner", "findings.scanner", 3,
                prefixes=("findings.start",)),
        NavItem("xss", "XSS Analyzer", "findings.xss", 3),
        NavItem("sqli", "SQL Injection Analyzer", "findings.sqli", 3),
        NavItem("ssrf", "SSRF Analyzer", "findings.ssrf", 4),
        NavItem("authentication", "Authentication and Access", "findings.authentication", 4),
        NavItem("additional", "Additional Checks", "findings.additional", 4),
        NavItem("source", "Source Code Analyzer", "source.index", 5, prefixes=("source.",)),
        NavItem("misconfiguration", "Security Misconfiguration", "findings.misconfiguration", 4),
    )),
    ("Evidence and output", (
        NavItem("evidence", "Evidence Center", "evidence.center", 6),
        NavItem("risk", "Risk Assessment", "reports.risk", 7),
        NavItem("reports", "Reports", "reports.index", 7, prefixes=("reports.html_report", "reports.json_report", "reports.pdf_report")),
        NavItem("history", "Scan History", "reports.history", 7, prefixes=("reports.compare",)),
    )),
    ("System", (
        NavItem("settings", "Settings", "main.settings", 1, prefixes=("main.settings",)),
    )),
)


def find_nav_item(slug: str) -> NavItem | None:
    for _, items in NAV_GROUPS:
        for item in items:
            if item.slug == slug:
                return item
    return None
