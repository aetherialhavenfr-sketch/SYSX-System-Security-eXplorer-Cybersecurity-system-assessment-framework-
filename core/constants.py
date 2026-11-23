"""Shared constants and tiny helpers. Pure Python: no third-party imports."""
from __future__ import annotations

from datetime import datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "informational")

FINDING_STATUSES = ("Confirmed", "Potential", "Unverified", "False Positive", "Fixed", "Reopened")
# A finding no longer counts as "open" once it is a false positive or fixed.
CLOSED_STATUSES = ("False Positive", "Fixed")
PENDING_STATUSES = ("Potential", "Unverified")

SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")

AUDIT_LEVELS = ("info", "warning", "alert")


def utcnow() -> datetime:
    """Naive UTC timestamp. SYSX stores every datetime as naive UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
