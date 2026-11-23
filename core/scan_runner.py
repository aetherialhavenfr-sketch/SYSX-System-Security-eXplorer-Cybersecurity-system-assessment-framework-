"""Dispatches a queued scan to the right runner by its kind: ``discovery`` (default) or ``source``."""
from __future__ import annotations

import shutil

from core.scanner import run_discovery_scan
from core.source_scan import run_source_scan
from core.tools import run_tool


def run_scan(storage, scan_id: int, cancel_event, *, source_roots=(), semgrep_config: str = "", **kwargs) -> None:
    scan = storage.get_scan(scan_id)
    if scan is not None and getattr(scan, "kind", None) == "source":
        run_source_scan(storage, scan_id, cancel_event, source_roots=source_roots, semgrep_config=semgrep_config,
                        tool_runner=kwargs.get("tool_runner", run_tool), which=kwargs.get("which", shutil.which))
    else:
        run_discovery_scan(storage, scan_id, cancel_event, **kwargs)
