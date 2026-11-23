"""Source-code analysis run: the Phase 5 counterpart of the discovery scan, dispatched by ``scan.kind == "source"``."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

from core.authorization import AuthorizationError, assert_source_analysis_permitted
from core.constants import utcnow
from core.http import Cancelled
from core.lifecycle import finalize_findings
from core.tools import run_tool
from modules.source_analysis.analyzer import analyze_tree
from modules.source_analysis.walker import SourcePathError, resolve_source_path

log = logging.getLogger("sysx.source")


def run_source_scan(storage, scan_id: int, cancel_event, *, source_roots=(), tool_runner=run_tool, which=shutil.which,
                    semgrep_config: str = "") -> None:
    scan = storage.get_scan(scan_id)
    if scan is None:
        return
    summary = dict(scan.summary or {})
    status, error = "completed", None
    storage.update_scan(scan_id, status="running", started_at=utcnow(), current_step="Authorizing")

    def step(text: str) -> None:
        storage.update_scan(scan_id, current_step=text[:120])

    try:
        if cancel_event.is_set():
            raise Cancelled("Cancelled before it started.")
        target = storage.get_target(scan.target_id)
        if target is None:
            raise AuthorizationError("Target no longer exists.")
        assert_source_analysis_permitted(target)
        root = resolve_source_path(list(source_roots), str(summary.get("source_path", "")))
        summary["source_path"] = str(root)
        summary["modules"] = ["source_analysis"]
        report = analyze_tree(Path(root), tool_runner=tool_runner, which=which, semgrep_config=semgrep_config,
                              cancelled=cancel_event.is_set, step=step)
        stats = finalize_findings(storage, scan_id, target.id, report.findings)
        summary.update(files_scanned=report.files_scanned, files_unparsed=report.files_unparsed, findings=stats["total"],
                       findings_new=stats["new"], findings_reopened=stats["reopened"], fingerprints=stats["fingerprints"],
                       tools_used=report.tools_used, tools_missing=report.tools_missing)
        if report.truncated:
            summary["truncated"] = 1
        if cancel_event.is_set():
            raise Cancelled("Cancelled during analysis.")
    except Cancelled:
        status = "cancelled"
    except (AuthorizationError, SourcePathError) as exc:
        status, error = "failed", str(exc)
    except Exception as exc:
        log.exception("source scan crashed", extra={"scan_id": scan_id})
        status, error = "failed", f"Internal error ({type(exc).__name__}). See the SYSX log."
    finally:
        storage.update_scan(scan_id, status=status, error=error, summary=summary, finished_at=utcnow(),
                            current_step={"completed": "Done", "cancelled": "Cancelled", "failed": "Failed"}[status])
