"""The security-assessment phase of a scan: everything that runs after the crawl.

Order matters. Passive checks (no requests) run first so their findings survive anything that happens later. Then
cheap probes, then per-parameter testing, then identity-based access checks. If the request budget runs out or the
scan is cancelled at any point, the findings gathered so far are kept and the remaining steps are skipped.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.http import BudgetExceeded, Cancelled
from core.vuln_runner import dom_indicator_findings, run_vulnerability_checks
from modules.additional_vulns.upload import upload_findings
from modules.authentication.checks import auth_findings
from modules.csrf.checks import csrf_findings
from modules.idor.checks import access_findings
from modules.misconfiguration.checks import passive_findings, tls_findings
from modules.misconfiguration.probes import cors_probe, exposed_file_probe
from verification.browser import BrowserVerifier

PARAMETER_MODULES = {"xss", "sqli", "additional_vulns", "ssrf"}


@dataclass
class Assessment:
    findings: list = field(default_factory=list)
    parameters_tested: int = 0
    stop_reason: str | None = None  # None, "budget" or "cancelled"
    notes: dict = field(default_factory=dict)


def run_assessment(scan_id: int, target, client, crawl: dict, records: list, modules: set, intensity: str, step, *,
                   callback=None, labels: dict | None = None, browser_factory=BrowserVerifier) -> Assessment:
    endpoints, observations = crawl["endpoints"], crawl.get("observations", [])
    labels = labels or {}
    out = Assessment(findings=dom_indicator_findings(crawl.get("dom_signals", [])))
    findings = out.findings

    # 1. passive: no requests
    if "misconfiguration" in modules:
        findings += passive_findings(observations)
        for kind, data in records:
            if kind == "tls" and isinstance(data, dict):
                findings += tls_findings(data)
    if "csrf" in modules:
        findings += csrf_findings(endpoints, observations, authenticated=bool(labels))
    if "authentication" in modules:
        findings += auth_findings(endpoints, observations, client.scope.lab_class)
    if "additional_vulns" in modules:
        findings += upload_findings(endpoints)

    try:
        # 2. cheap active probes
        if "misconfiguration" in modules:
            step("Checking CORS policy")
            cors = cors_probe(client, client.base_url)
            if cors:
                findings.append(cors)
            if intensity != "safe":
                exposed_file_probe(client, client.base_url, step, out=findings)
        # 3. per-parameter testing
        if modules & PARAMETER_MODULES:
            step("Vulnerability testing")
            browser = browser_factory()
            try:
                found, out.parameters_tested, stop = run_vulnerability_checks(
                    scan_id, target.id, client, endpoints, modules, intensity, browser, step, callback=callback, notes=out.notes)
            finally:
                browser.close()
            findings += found
            if stop:
                out.stop_reason = stop
        # 4. identity-based access checks
        if "idor" in modules and out.stop_reason is None:
            if labels:
                access_findings(client, endpoints, labels, intensity, step, out=findings)
            else:
                out.notes["idor_skipped"] = ("Access-control checks need a stored test credential of type basic, bearer, "
                                             "cookie or header on this target.")
    except BudgetExceeded:
        out.stop_reason = "budget"
    except Cancelled:
        out.stop_reason = "cancelled"
    return out
