"""Orchestrates parameter-level testing across a scan's discovered GET endpoints.

Depth scales with the target's scan intensity, matching ``core.authorization.INTENSITIES``: "safe" is
reflection and error-signature checks only; "standard" adds boolean-based blind SQL injection; "thorough"
adds time-based blind SQL injection, OS-command-injection markers and out-of-band (SSRF callback)
verification. XSS probing is inherently lightweight (single alternate GET requests) so it runs at full
depth at every intensity.

Which parameters a module sees is decided by ``modules.endpoint_discovery.classify`` (name-based and
explainable): path traversal only for file-like names, open redirect only for redirect-like names, and so on.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from core.http import BudgetExceeded, Cancelled
from modules.additional_vulns import cmdi, redirect, ssti, traversal
from modules.sqli import detector as sqli_detector
from modules.ssrf import detector as ssrf_detector
from modules.xss import detector as xss_detector
from verification.catalog import IMPACT, REMEDIATION, build_finding, title_for

PROFILES = {
    "safe": dict(max_param_tests=20, xss_deep=True, sqli_boolean=False, sqli_time=False, cmdi=False, ssrf=False),
    "standard": dict(max_param_tests=60, xss_deep=True, sqli_boolean=True, sqli_time=False, cmdi=False, ssrf=False),
    "thorough": dict(max_param_tests=150, xss_deep=True, sqli_boolean=True, sqli_time=True, cmdi=True, ssrf=True),
}


def _finalize(result: dict, scan_id: int, target_id: int, endpoint: str, method: str) -> dict:
    return build_finding(result, endpoint, method, "query")


def testable_endpoints(endpoints: list[dict]) -> list[dict]:
    """GET form rows are never fetched themselves (their action URL carries empty values). When the bare action page
    was fetched successfully, the form row inherits that status so its fields can be tested."""
    fetched = {e["url"]: e["status"] for e in endpoints
               if e["method"] == "GET" and e.get("status") and not urlsplit(e["url"]).query}
    out = []
    for e in endpoints:
        if e["method"] == "GET" and not e.get("status") and (e.get("meta") or {}).get("form"):
            status = fetched.get(e["url"].split("?", 1)[0])
            if status:
                e = {**e, "status": status}
        out.append(e)
    return out


def dom_indicator_findings(dom_signals: list[dict]) -> list[dict]:
    out = []
    for sig in dom_signals:
        where = "inline on this page" if sig["via"] == "inline" else "in a script this page loads"
        description = (f"Dangerous sink(s) {', '.join(sig['sinks'])} appear together with user-controllable "
                       f"source(s) {', '.join(sig['sources'])} {where}. This is a static code pattern; it has "
                       "not been exercised against the running application and may be a false positive.")
        out.append(dict(vuln_type="xss", technique="dom_indicator", title=title_for("xss", "dom_indicator"),
                        severity="low", status="Unverified", confidence=0.2, cvss_score=None, cvss_vector=None,
                        endpoint=sig["url"], method="GET", parameter=None, parameter_location=None,
                        description=description, impact=IMPACT["xss"], remediation=REMEDIATION["xss"], evidence=[],
                        origin="dynamic", source_file=None, source_line=None, rule_id=None))
    return out


def _checks_of(param: dict) -> set[str]:
    return {c["check"] for c in param.get("checks", [])}


def run_vulnerability_checks(scan_id: int, target_id: int, client, endpoints: list[dict], enabled_modules: set,
                             intensity: str, browser, step, callback=None, notes: dict | None = None,
                             ) -> tuple[list[dict], int, str | None]:
    """Returns (finding dicts, parameters tested, stop reason). stop reason is None, "budget" or "cancelled"."""
    profile = PROFILES.get(intensity, PROFILES["safe"])
    notes = notes if notes is not None else {}
    candidates = [e for e in testable_endpoints(endpoints) if e["method"] == "GET" and e["params"] and e.get("status") and e["status"] < 400]
    total = min(profile["max_param_tests"], sum(len(e["params"]) for e in candidates))
    use_ssrf = "ssrf" in enabled_modules
    if use_ssrf and not (profile["ssrf"] and callback is not None and callback.configured):
        use_ssrf = False
        notes["ssrf_skipped"] = "SSRF testing needs the 'thorough' intensity (lab-class targets) and SYSX_CALLBACK_URL to be set."
    if use_ssrf:
        try:
            callback.start()
        except Exception as exc:  # a callback that cannot listen must not break the scan
            use_ssrf = False
            notes["ssrf_skipped"] = f"The callback listener could not start: {exc}"[:200]
    findings: list[dict] = []
    tested = 0
    seen_leaks: set[tuple] = set()
    stop_reason = None
    try:
        for endpoint in candidates:
            if tested >= profile["max_param_tests"]:
                break
            for param in endpoint["params"]:
                if tested >= profile["max_param_tests"]:
                    break
                tested += 1
                step(f"Testing parameter {tested}/{total}: {param['name']}")
                if "xss" in enabled_modules:
                    result = xss_detector.test_parameter(client, endpoint["url"], param["name"], browser,
                                                          deep=profile["xss_deep"])
                    if result:
                        findings.append(_finalize(result, scan_id, target_id, endpoint["url"], "GET"))
                if "sqli" in enabled_modules:
                    sample = param.get("sample") or "1"
                    result = sqli_detector.test_parameter(client, endpoint["url"], param["name"], sample,
                                                          boolean_blind=profile["sqli_boolean"],
                                                          time_blind=profile["sqli_time"])
                    if result:
                        key = (endpoint["url"], result["technique"], result.get("parameter"))
                        if result["technique"] == "information_disclosure" and key in seen_leaks:
                            continue
                        seen_leaks.add(key)
                        findings.append(_finalize(result, scan_id, target_id, endpoint["url"], "GET"))
                checks = _checks_of(param)
                results = []
                if "additional_vulns" in enabled_modules:
                    if "path_traversal" in checks:
                        results.append(traversal.check_parameter(client, endpoint["url"], param["name"], param.get("sample")))
                    if "open_redirect" in checks:
                        results.append(redirect.check_parameter(client, endpoint["url"], param["name"]))
                    if checks & {"ssti", "xss"}:
                        results.append(ssti.check_parameter(client, endpoint["url"], param["name"]))
                    if profile["cmdi"] and "command_injection" in checks:
                        results.append(cmdi.check_parameter(client, endpoint["url"], param["name"], param.get("sample")))
                if use_ssrf and "ssrf" in checks:
                    results.append(ssrf_detector.check_parameter(client, endpoint["url"], param["name"], callback))
                for result in results:
                    if result:
                        findings.append(_finalize(result, scan_id, target_id, endpoint["url"], "GET"))
    except BudgetExceeded:
        stop_reason = "budget"
    except Cancelled:
        stop_reason = "cancelled"
    return findings, tested, stop_reason
