"""In-process background scan scheduler (thread pool). Needs no Redis or external broker.

Scan state lives in the database, so the dashboard stays responsive and progress survives page reloads.
Scans interrupted by a restart are marked failed on startup. The interface is small on purpose so that a
Celery-backed scheduler can replace it later without touching the web layer.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor

from core.scan_runner import run_scan

log = logging.getLogger("sysx.scheduler")


class ScanScheduler:
    def __init__(self, storage, *, max_workers: int = 2, runner=run_scan, **runner_kwargs):
        self.storage, self.runner, self.runner_kwargs = storage, runner, runner_kwargs
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="sysx-scan")
        self._jobs: dict[int, tuple[int, threading.Event, Future]] = {}
        self._lock = threading.Lock()

    def mark_interrupted(self) -> int:
        return self.storage.fail_stale_scans()

    def submit(self, scan_id: int, target_id: int) -> None:
        event = threading.Event()
        with self._lock:
            self._jobs[scan_id] = (target_id, event, self._pool.submit(self._run, scan_id, event))

    def _run(self, scan_id: int, event: threading.Event) -> None:
        try:
            self.runner(self.storage, scan_id, event, **self.runner_kwargs)
        except Exception:
            log.exception("scan runner crashed", extra={"scan_id": scan_id})
            try:
                self.storage.update_scan(scan_id, status="failed", error="Internal error. See the SYSX log.")
            except Exception:
                pass
        finally:
            self.storage.remove_session()
            with self._lock:
                self._jobs.pop(scan_id, None)

    def is_active(self, scan_id: int) -> bool:
        with self._lock:
            return scan_id in self._jobs

    def cancel(self, scan_id: int) -> bool:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job:
            job[1].set()
        return job is not None

    def cancel_for_target(self, target_id: int) -> int:
        with self._lock:
            jobs = [j for j in self._jobs.values() if j[0] == target_id]
        for _, event, _ in jobs:
            event.set()
        return len(jobs)

    def wait(self, scan_id: int, timeout: float = 30.0) -> bool:
        """Block until the scan finishes (used by tests). Returns False on timeout."""
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is None:
            return True
        try:
            job[2].result(timeout=timeout)
        except TimeoutError:
            return False
        except Exception:
            pass
        return True

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
