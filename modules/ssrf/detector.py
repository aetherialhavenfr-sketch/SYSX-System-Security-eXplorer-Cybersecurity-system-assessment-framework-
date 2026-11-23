"""SSRF detection by controlled callback only.

The target is handed a one-time URL on SYSX's own callback listener. If that listener sees the request, the
server fetched an attacker-supplied URL: confirmed. Nothing else is ever supplied as a destination (no cloud
metadata addresses, no internal hosts, no third parties).
"""
from __future__ import annotations

from modules.common import safe_get, set_param
from modules.endpoint_discovery.classify import SENSITIVE_NAME
from verification.evidence import evidence_item


def check_parameter(client, endpoint_url: str, param_name: str, callback, *, wait: float = 4.0) -> dict | None:
    if SENSITIVE_NAME.search(param_name):
        return None
    token = callback.new_token()
    callback_url = callback.url_for(token)
    probe_url = set_param(endpoint_url, param_name, callback_url)
    res = safe_get(client, probe_url)
    if res is None:
        return None
    hits = callback.wait_for(token, timeout=wait, cancelled=client.cancel_event.is_set)
    if not hits:
        return None
    first = hits[0]
    note = (f"Parameter '{param_name}' was set to a one-time URL on this SYSX instance's callback listener, and the "
            f"listener then received a request for it from {first['addr']}. The application fetched a URL supplied by the client.")
    evidence = [
        evidence_item("Request carrying the callback URL", "GET", probe_url, res, note),
        {"label": "Callback received", "request": {"method": "GET", "url": callback_url},
         "note": f"Seen {len(hits)} time(s). First from {first['addr']}, User-Agent '{first['user_agent'] or 'none'}'."},
    ]
    return dict(vuln_type="ssrf", technique="out_of_band", status="Confirmed", confidence=0.95, parameter=param_name,
                note=note, evidence=evidence)
