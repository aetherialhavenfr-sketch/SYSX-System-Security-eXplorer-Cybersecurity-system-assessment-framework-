"""SQL injection detection: error-based, boolean-based blind, and time-based blind.

Every technique is checked against a baseline response first. The blind techniques are
reproduced a second time before being reported "Confirmed"; a result that does not
reproduce is still reported, as "Potential", rather than discarded.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.http import FetchError, ScopeViolation
from modules.endpoint_discovery.classify import SENSITIVE_NAME
from modules.sqli.signatures import find_db_error
from verification.evidence import evidence_item

TIME_PAYLOADS = (("MySQL/MariaDB", "SLEEP({n})"), ("PostgreSQL", "pg_sleep({n})"),
                 ("Microsoft SQL Server", "WAITFOR DELAY '0:0:{n}'"))
# (true-condition template, false-condition template) with {v} as the placeholder value
_BOOL_TEMPLATES = ("' AND '1'='{v}", '" AND "1"="{v}', " AND 1={v}")
DEFAULT_DELAY = 4.0
DEFAULT_TOLERANCE = 2.0


def _set_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def _get(client, url):
    try:
        return client.get(url)
    except (ScopeViolation, FetchError):
        return None


def _differs(a, b) -> bool:
    return a.status != b.status or abs(len(a.body) - len(b.body)) > max(20, 0.02 * len(b.body))


def check_baseline_leak(baseline, endpoint_url: str) -> dict | None:
    """Zero extra requests: a target that already shows a DB error on ordinary input."""
    engine, excerpt = find_db_error(baseline.text)
    if not engine:
        return None
    return {"vuln_type": "sqli", "technique": "information_disclosure", "status": "Confirmed", "confidence": 0.7,
            "parameter": None, "note": f"The page already shows a {engine} error on unmodified input.",
            "evidence": [evidence_item("Baseline response", "GET", endpoint_url, baseline, snippet_around=excerpt)]}


def test_parameter(client, endpoint_url: str, param_name: str, sample: str, *, boolean_blind: bool, time_blind: bool,
                   delay: float = DEFAULT_DELAY, tolerance: float = DEFAULT_TOLERANCE) -> dict | None:
    if SENSITIVE_NAME.search(param_name):
        return None
    sample = sample if sample not in (None, "") else "1"
    baseline = _get(client, _set_param(endpoint_url, param_name, sample))
    if baseline is None:
        return None

    leak = check_baseline_leak(baseline, endpoint_url)
    if leak:
        leak["parameter"] = param_name
        return leak

    finding = _error_based(client, endpoint_url, param_name, sample, baseline)
    if finding:
        return finding
    if boolean_blind:
        finding = _boolean_blind(client, endpoint_url, param_name, sample, baseline)
        if finding:
            return finding
    if time_blind:
        finding = _time_blind(client, endpoint_url, param_name, sample, baseline, delay, tolerance)
        if finding:
            return finding
    return None


def _error_based(client, endpoint_url, param_name, sample, baseline):
    base_engine, _ = find_db_error(baseline.text)
    probe = _get(client, _set_param(endpoint_url, param_name, sample + "'"))
    if probe is None:
        return None
    engine, excerpt = find_db_error(probe.text)
    if not engine or engine == base_engine:
        return None
    control = _get(client, _set_param(endpoint_url, param_name, sample + "''"))  # a "closed" quote should not error
    control_engine = find_db_error(control.text)[0] if control is not None else None
    confidence = 0.9 if control is not None and not control_engine else 0.65
    evidence = [evidence_item("Baseline (unmodified value)", "GET", endpoint_url, baseline),
                evidence_item("Single quote", "GET", probe.requested_url, probe, snippet_around=excerpt)]
    if control is not None:
        evidence.append(evidence_item("Two single quotes (control)", "GET", control.requested_url, control))
    return {"vuln_type": "sqli", "technique": "error_based", "confidence": confidence, "parameter": param_name,
            "status": "Confirmed" if confidence >= 0.8 else "Potential",
            "note": f"A {engine} error appears only when a single quote is added to the value.", "evidence": evidence}


def _boolean_blind(client, endpoint_url, param_name, sample, baseline):
    for template in _BOOL_TEMPLATES:
        true_url = _set_param(endpoint_url, param_name, sample + template.format(v=1))
        false_url = _set_param(endpoint_url, param_name, sample + template.format(v=2))
        true_res, false_res = _get(client, true_url), _get(client, false_url)
        if true_res is None or false_res is None:
            continue
        if _differs(true_res, baseline) or not _differs(false_res, baseline) or not _differs(true_res, false_res):
            continue  # TRUE must resemble the baseline; FALSE must not; the two must differ from each other
        true2, false2 = _get(client, true_url), _get(client, false_url)
        reproduced = (true2 is not None and false2 is not None
                      and not _differs(true2, baseline) and _differs(false2, baseline))
        status, confidence = ("Confirmed", 0.85) if reproduced else ("Potential", 0.5)
        return {"vuln_type": "sqli", "technique": "boolean_blind", "status": status, "confidence": confidence,
                "parameter": param_name,
                "note": "A logically-true condition reproduces the baseline response; a logically-false one changes it.",
                "evidence": [evidence_item("Baseline", "GET", endpoint_url, baseline),
                            evidence_item("TRUE condition", "GET", true_res.requested_url, true_res),
                            evidence_item("FALSE condition", "GET", false_res.requested_url, false_res)]}
    return None


def _time_blind(client, endpoint_url, param_name, sample, baseline, delay, tolerance):
    for engine, template in TIME_PAYLOADS:
        url = _set_param(endpoint_url, param_name, sample + f"' OR {template.format(n=delay)}-- -")
        delays, last = [], None
        for _ in range(2):
            last = _get(client, url)
            if last is None:
                break
            delays.append(last.elapsed)
        if len(delays) < 2 or any(d < delay - tolerance for d in delays):
            continue
        control = _get(client, _set_param(endpoint_url, param_name, sample + f"' OR {template.format(n=0)}-- -"))
        if control is not None and control.elapsed >= delay - tolerance:
            continue  # the zero-second control was slow too: the delay isn't coming from our payload
        evidence = [evidence_item("Baseline", "GET", endpoint_url, baseline)]
        if control is not None:
            evidence.append(evidence_item("0-second control", "GET", control.requested_url, control))
        times = ", ".join(f"{d:.1f}s" for d in delays)
        evidence.append(evidence_item(f"{delay:g}-second payload (sent twice: {times})", "GET", last.requested_url, last))
        return {"vuln_type": "sqli", "technique": "time_blind", "status": "Confirmed", "confidence": 0.8,
                "parameter": param_name, "note": f"The response is consistently delayed by a {engine}-style sleep payload.",
                "evidence": evidence}
    return None


# Not a pytest test, despite the name: stops pytest collecting it when a test module imports it.
test_parameter.__test__ = False
