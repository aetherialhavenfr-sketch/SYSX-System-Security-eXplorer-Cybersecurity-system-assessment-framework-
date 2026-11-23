"""Discovery scan orchestrator: reconnaissance, crawl, security assessment, then subdomain/technology roll-up."""
from __future__ import annotations

import logging
import shutil
import socket
import time

from core.assessment import run_assessment
from core.authorization import AuthorizationError
from core.constants import utcnow
from core.fingerprint import TechAccumulator
from core.http import BudgetExceeded, Cancelled, ScopedClient, ScopeViolation
from core.identities import load_identities
from core.lifecycle import finalize_findings
from core.tools import run_tool
from modules.endpoint_discovery.crawler import CrawlOptions, Crawler
from modules.reconnaissance.dns_info import dns_records, resolve_host
from modules.reconnaissance.http_probe import probe_http_surface
from modules.reconnaissance.nmap_probe import probe_ports
from modules.reconnaissance.subdomains import discover_subdomains
from modules.reconnaissance.tls import probe_tls

log = logging.getLogger("sysx.scan")

PROFILES = {
    "safe": dict(max_pages=100, max_depth=3, wellknown=False, tls_weak=False, nmap=False),
    "standard": dict(max_pages=300, max_depth=4, wellknown=True, tls_weak=True, nmap=True),
    "thorough": dict(max_pages=1000, max_depth=6, wellknown=True, tls_weak=True, nmap=True),
}


def run_discovery_scan(storage, scan_id: int, cancel_event, *, resolver=socket.getaddrinfo, tool_runner=run_tool,
                       which=shutil.which, client_kwargs: dict | None = None, vault=None, callback=None) -> None:
    scan = storage.get_scan(scan_id)
    if scan is None:
        return
    status, error, summary = "completed", None, {}
    records: list[tuple[str, object]] = []
    crawler, client, saved_endpoints, tech = None, None, False, TechAccumulator()
    storage.update_scan(scan_id, status="running", started_at=utcnow(), current_step="Authorizing")
    try:
        if cancel_event.is_set():
            raise Cancelled("Scan cancelled before it started.")
        target = storage.get_target(scan.target_id)
        if target is None:
            raise AuthorizationError("Target no longer exists.")
        client = ScopedClient(target, cancel_event=cancel_event, resolver=resolver, scan_id=scan_id, **(client_kwargs or {}))
        profile = PROFILES.get(target.scan_intensity, PROFILES["safe"])
        modules = set(target.enabled_modules or [])
        summary["modules"] = sorted(modules)
        summary["intensity"] = target.scan_intensity
        base = client.scope.base
        labels: dict[str, str] = {}
        if vault is not None:
            identities, labels, unused = load_identities(storage, target.id, vault)
            if identities:
                first = next(iter(identities))
                client.set_identities(identities, default=first)  # the scan runs as the first usable test credential
                summary["authenticated_as"] = labels[first]
                summary["identities"] = len(identities)
            if unused:
                summary["credentials_unused"] = unused

        def step(text: str) -> None:
            storage.update_scan(scan_id, current_step=text[:120], requests_made=client.requests_made)

        def guarded(kind: str, fn):
            try:
                records.append((kind, fn()))
            except (Cancelled, BudgetExceeded):
                raise
            except ScopeViolation as exc:
                records.append((kind, {"error": f"blocked by scope: {exc.reason}"}))
            except Exception as exc:  # one failing probe must not abort the whole scan
                log.exception("recon step failed", extra={"scan_id": scan_id, "step": kind})
                records.append((kind, {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}))

        if "reconnaissance" in modules:
            step("DNS and addresses")
            guarded("dns", lambda: {**resolve_host(base.host, client.scope.lab_class, resolver), "records": dns_records(base.host)})
            step("HTTP and HTTPS discovery")
            guarded("http", lambda: probe_http_surface(client))
            tls_ports = [p for p in sorted(client.scope.ports) if p == 443 or (client.base_url.lower().startswith("https") and p == base.port)]
            for port in tls_ports[:2]:
                step(f"TLS assessment (port {port})")
                guarded("tls", lambda port=port: probe_tls(client, base.host, port, weak_probe=profile["tls_weak"]))
            if profile["nmap"]:
                step("Service detection (nmap)")
                guarded("ports", lambda: probe_ports(client, base.host, runner=tool_runner, which=which))
        if "endpoint_discovery" in modules:
            step("Crawling")
            crawler = Crawler(
                client, CrawlOptions(max_pages=profile["max_pages"], max_depth=profile["max_depth"], probe_wellknown=profile["wellknown"]),
                tech, progress=lambda req, pages, urls: storage.update_scan(
                    scan_id, requests_made=req, pages_found=pages, current_step=f"Crawling: {pages} pages, {urls} URLs found"))
            result = crawler.run()
            storage.add_endpoints(scan_id, target.id, result["endpoints"])
            saved_endpoints = True
            summary.update(result["stats"])
            summary["external_hosts"] = result["external_hosts"]
            summary["denied_requests"] = result["denied"]  # the list; summary["denied"] stays the count
            assessment = run_assessment(scan_id, target, client, result, records, modules, target.scan_intensity, step,
                                        callback=callback, labels=labels)
            summary.update(assessment.notes)
            if assessment.parameters_tested:
                summary["parameters_tested"] = assessment.parameters_tested
            if assessment.stop_reason == "budget":
                summary["budget_exhausted"] = 1
            stats = finalize_findings(storage, scan_id, target.id, assessment.findings)
            summary.update(findings=stats["total"], findings_new=stats["new"], findings_reopened=stats["reopened"],
                           fingerprints=stats["fingerprints"])
            if assessment.stop_reason == "cancelled" or client.cancel_event.is_set():
                raise Cancelled("Scan cancelled during vulnerability testing.")
        if "reconnaissance" in modules:
            step("Subdomains")
            guarded("subdomains", lambda: discover_subdomains(
                client, crawler.sibling_hosts if crawler else (), runner=tool_runner, which=which))
    except Cancelled:
        status = "cancelled"
    except (AuthorizationError, ScopeViolation) as exc:
        status, error = "failed", str(exc)
    except BudgetExceeded:
        summary["budget_exhausted"] = 1
    except Exception as exc:
        log.exception("scan crashed", extra={"scan_id": scan_id})
        status, error = "failed", f"Internal error ({type(exc).__name__}). See the SYSX log."
    finally:
        try:
            if crawler is not None and not saved_endpoints:  # keep partial results after cancel/budget/failure
                result = crawler.finalize()
                storage.add_endpoints(scan_id, scan.target_id, result["endpoints"])
                summary.update(result["stats"])
            records.append(("technology", tech.results()))
            storage.add_recon_records(scan_id, records)
        except Exception:
            log.exception("could not save scan results", extra={"scan_id": scan_id})
        summary["technologies"] = len(tech.results())
        storage.update_scan(scan_id, status=status, error=error, summary=summary, finished_at=utcnow(),
                            current_step={"completed": "Done", "cancelled": "Cancelled", "failed": "Failed"}[status],
                            requests_made=client.requests_made if client else 0)
