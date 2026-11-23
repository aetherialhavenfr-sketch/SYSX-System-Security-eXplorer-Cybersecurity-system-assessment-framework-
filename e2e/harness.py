"""End-to-end harness: drives SYSX through its own web interface, exactly as an operator would.

Register a target, add test credentials, run a scan, check the findings against a profile, run it again to check
stability, and open every results page and report. Only the *target* is external; SYSX itself runs in-process.

Profiles (``e2e/profiles/*.json``) hold three lists:
  must      findings that have to be present                        -> a miss fails the run
  must_not  findings that must not be present (safe twins)          -> a hit fails the run
  may       findings a good scan usually produces                   -> reported, never fail
Each entry may use: vuln_type, technique, endpoint_contains, source_contains, status_in.
"""
from __future__ import annotations

import json
import re
import tempfile
import time
from pathlib import Path
from typing import Callable

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
TERMINAL = ("completed", "failed", "cancelled")
PROFILE_DIR = Path(__file__).parent / "profiles"
PAGES = ("/", "/scanner", "/xss", "/sqli", "/ssrf", "/authentication", "/additional", "/misconfiguration", "/evidence",
         "/attack-surface", "/risk", "/reports", "/history", "/crawler", "/endpoints", "/recon")


class HarnessError(RuntimeError):
    pass


def load_profile(name_or_path: str) -> dict:
    path = Path(name_or_path)
    if not path.exists():
        path = PROFILE_DIR / f"{name_or_path}.json"
    if not path.exists():
        raise HarnessError(f"No such profile: {name_or_path}")
    return json.loads(path.read_text(encoding="utf-8"))


def matches(finding, spec: dict) -> bool:
    if spec.get("vuln_type") and finding.vuln_type != spec["vuln_type"]:
        return False
    if spec.get("technique") and finding.technique != spec["technique"]:
        return False
    if spec.get("endpoint_contains") and spec["endpoint_contains"] not in (finding.endpoint or ""):
        return False
    if spec.get("source_contains") and spec["source_contains"] not in (finding.source_file or ""):
        return False
    if spec.get("status_in") and finding.status not in spec["status_in"]:
        return False
    return True


def _describe(spec: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in spec.items())


class Run:
    def __init__(self, profile: dict, base_url: str, *, secrets: dict | None = None, storage=None, callback_url: str = "",
                 log: Callable[[str], None] = print, scan_timeout: float = 900.0, rescan: bool = True, config: dict | None = None):
        self.profile, self.base_url, self.secrets = profile, base_url.rstrip("/"), secrets or {}
        self.log, self.scan_timeout, self.rescan = log, scan_timeout, rescan
        self.checks: list[dict] = []
        self._tmp = None
        from app import create_app
        if storage is None:
            from database.storage import Storage
            self._tmp = tempfile.TemporaryDirectory(prefix="sysx-e2e-")
            storage = Storage(f"sqlite:///{self._tmp.name}/e2e.db")
            storage.create_schema()
        self.storage = storage
        self.app = create_app({"TESTING": True, "SECRET_KEY": "e2e", "SYSX_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                               "SYSX_LOG_TO_FILE": False, "SYSX_LOG_LEVEL": "CRITICAL", "SYSX_CALLBACK_URL": callback_url,
                               "SYSX_CALLBACK_BIND": "127.0.0.1", **(config or {})}, storage=storage)
        self.client = self.app.test_client()
        self.scheduler = self.app.config["SYSX_SCHEDULER"]

    # -- plumbing -------------------------------------------------------------
    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(dict(name=name, ok=bool(ok), detail=detail))
        self.log(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail and not ok else ""))
        return bool(ok)

    def token(self, path: str) -> str:
        match = CSRF.search(self.client.get(path).get_data(as_text=True))
        if not match:
            raise HarnessError(f"No CSRF token on {path}")
        return match.group(1)

    def post(self, path: str, data: dict, page: str):
        return self.client.post(path, data={**data, "csrf_token": self.token(page)})

    # -- steps ------------------------------------------------------------------
    def sign_in(self) -> None:
        password = "e2e-" + Fernet.generate_key().decode()[:24]
        self.storage.create_user("e2e", generate_password_hash(password))
        response = self.client.post("/login", data={"username": "e2e", "password": password, "csrf_token": self.token("/login")})
        if response.status_code != 302:
            raise HarnessError("Could not sign in to the in-process SYSX instance.")

    def register_target(self) -> int:
        p = self.profile
        form = {"name": f"e2e {p['name']}", "base_url": self.base_url + p.get("start_path", "/"),
                "authorization_type": p.get("authorization_type", "training_app"),
                "authorization_reference": "end-to-end harness against a lab or training application",
                "allowed_domains": "\n".join(p.get("allowed_domains", [])), "excluded_paths": "\n".join(p.get("excluded_paths", ["/logout"])),
                "max_requests_per_second": str(p.get("rps", 20)), "max_concurrency": str(p.get("concurrency", 4)),
                "max_total_requests": str(p.get("budget", 3000)), "scan_intensity": p.get("intensity", "standard"),
                "attested": "on", "enabled_modules": p["modules"]}
        response = self.post("/targets/new", form, "/targets/new")
        if response.status_code != 302:
            raise HarnessError("The target form was rejected: " + re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", response.get_data(as_text=True)))[:300])
        target_id = int(response.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        for cred in p.get("credentials", []):
            secret = self.secrets.get(cred["label"], cred.get("secret"))
            if not secret:
                self.log(f"  (skipping credential '{cred['label']}': no secret supplied)")
                continue
            self.post(f"/targets/{target_id}/credentials", dict(label=cred["label"], auth_type=cred["auth_type"],
                                                               username=cred.get("username", "x"), secret=secret), f"/targets/{target_id}")
        return target_id

    def run_scan(self, target_id: int) -> object:
        response = self.post("/scans/start", {"target_id": target_id}, "/crawler")
        if response.status_code != 302 or "/scans/" not in response.headers["Location"]:
            raise HarnessError("The scan was not accepted (see the flash message on /crawler).")
        scan_id = int(response.headers["Location"].rsplit("/", 1)[-1])
        deadline = time.monotonic() + self.scan_timeout
        while time.monotonic() < deadline:
            state = self.client.get(f"/scans/{scan_id}/status.json").get_json()
            if state["status"] in TERMINAL:
                return self.storage.get_scan(scan_id)
            time.sleep(0.5)
        self.client.post(f"/scans/{scan_id}/cancel", data={"csrf_token": self.token("/crawler")})
        raise HarnessError(f"Scan #{scan_id} did not finish within {self.scan_timeout:.0f}s and was cancelled.")

    def evaluate(self, target_id: int) -> None:
        findings = self.storage.list_findings(target_id=target_id)
        for spec in self.profile.get("must", []):
            hits = [f for f in findings if matches(f, spec)]
            self.check(f"must find: {_describe(spec)}", hits, "no matching finding")
        for spec in self.profile.get("must_not", []):
            hits = [f for f in findings if matches(f, spec)]
            self.check(f"must not find: {_describe(spec)}", not hits, f"{len(hits)} unexpected finding(s), e.g. #{hits[0].id} {hits[0].title}" if hits else "")
        for spec in self.profile.get("may", []):
            found = any(matches(f, spec) for f in findings)
            self.log(f"  [{'found' if found else 'absent'}] optional: {_describe(spec)}")
        floor = self.profile.get("min_findings")
        if floor is not None:
            self.check(f"at least {floor} findings", len(findings) >= floor, f"only {len(findings)}")

    def check_pages(self, target_id: int) -> None:
        bad = []
        for path in PAGES:
            if self.client.get(f"{path}?target_id={target_id}").status_code != 200:
                bad.append(path)
        self.check("all results pages render", not bad, ", ".join(bad))
        for kind, mimetype in (("html", "text/html"), ("json", "application/json"), ("pdf", "application/pdf")):
            response = self.client.get(f"/reports/{target_id}/report.{kind}")
            if kind == "pdf" and response.status_code == 302:
                self.log("  (PDF report skipped: reportlab is not installed)")
                continue
            self.check(f"{kind.upper()} report", response.status_code == 200 and response.mimetype == mimetype, f"HTTP {response.status_code}")

    def execute(self) -> dict:
        started = time.monotonic()
        self.log(f"Profile '{self.profile['name']}' against {self.base_url}")
        try:
            self.sign_in()
            target_id = self.register_target()
            self.log("Scan 1")
            first = self.run_scan(target_id)
            self.check("scan 1 completed", first.status == "completed", f"{first.status}: {first.error}")
            if first.status == "completed":
                self.evaluate(target_id)
                self.check_pages(target_id)
                if self.rescan:
                    self.log("Scan 2 (stability)")
                    second = self.run_scan(target_id)
                    self.check("scan 2 completed", second.status == "completed", f"{second.status}: {second.error}")
                    if second.status == "completed":
                        a, b = set(first.summary["fingerprints"]), set(second.summary["fingerprints"])
                        if self.profile.get("stable", False):
                            self.check("re-scan finds the same issues", a == b, f"{len(a - b)} disappeared, {len(b - a)} appeared")
                            self.check("re-scan creates no duplicate rows",
                                       len(self.storage.list_findings(target_id=target_id)) == len(a), "duplicates were stored")
                        else:
                            self.log(f"  re-scan: {len(a & b)} unchanged, {len(b - a)} new, {len(a - b)} not seen again")
                        self.check("comparison page renders", self.client.get(f"/history/compare?a={first.id}&b={second.id}").status_code == 200)
        except HarnessError as exc:
            self.check("harness", False, str(exc))
        finally:
            self.scheduler.shutdown()
            if self._tmp:
                self._tmp.cleanup()
        failed = [c for c in self.checks if not c["ok"]]
        return dict(profile=self.profile["name"], base_url=self.base_url, passed=not failed, checks=self.checks,
                    seconds=round(time.monotonic() - started, 1))
