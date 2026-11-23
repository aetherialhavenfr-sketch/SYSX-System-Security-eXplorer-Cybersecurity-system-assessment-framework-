"""Explainable confidence scoring.

Every finding carries a list of factors, each with a signed delta and a plain-language reason, so a reviewer can see
exactly why the number is what it is. The detector supplies the starting value; the engine only adjusts it for facts
that are visible in the data: the finding's status, how much evidence backs it, whether it was seen again in a later
scan, and whether an independent detector or the source code points at the same place.

Ceilings keep the number honest: an issue that no active check confirmed can never score like one that was.
"""
from __future__ import annotations

CEILING = {"Confirmed": 0.99, "Potential": 0.80, "Unverified": 0.35, "Reopened": 0.80, "False Positive": 0.10, "Fixed": 0.10}
CONFIRMED_FLOOR = 0.85
EVIDENCE_BONUS = 0.05
RECURRENCE_BONUS = 0.05
CORROBORATION_BONUS = 0.10
MIN_CONFIDENCE = 0.05


def clamp(value: float, low: float = MIN_CONFIDENCE, high: float = 0.99) -> float:
    return max(low, min(high, value))


def score(base: float | None, status: str, evidence_count: int = 0, seen_before: int = 0, corroborated: bool = False,
          source_only: bool = False) -> tuple[float, list[dict]]:
    """Returns (confidence rounded to 2 places, factors). ``seen_before`` is the number of earlier scans that also found it."""
    start = clamp(base if base is not None else 0.3)
    factors = [dict(factor="detector", delta=round(start, 2), reason="Starting value from the check that produced this finding.")]
    value = start

    def add(name: str, delta: float, reason: str) -> None:
        nonlocal value
        if abs(delta) < 0.005:
            return
        value += delta
        factors.append(dict(factor=name, delta=round(delta, 2), reason=reason))

    if evidence_count >= 2:
        add("evidence", EVIDENCE_BONUS, f"{evidence_count} separate pieces of evidence were captured.")
    if seen_before:
        add("recurrence", min(2, seen_before) * RECURRENCE_BONUS, f"Found again in {seen_before} earlier scan(s); it is stable, not a one-off.")
    if corroborated:
        add("corroboration", CORROBORATION_BONUS,
            "An independent check (a different detector, or the source code) points at the same place.")
    if status == "Confirmed" and value < CONFIRMED_FLOOR:
        add("verified", CONFIRMED_FLOOR - value, "An active check reproduced the behaviour (status Confirmed).")
    ceiling = CEILING.get(status, 0.8)
    if source_only:
        ceiling = min(ceiling, 0.7)
    if value > ceiling:
        add("ceiling", ceiling - value,
            f"Capped at {ceiling:.2f}: " + ("a static code pattern has not been exercised." if source_only
                                           else f"status '{status}' has not been verified by an active check."))
    final = round(clamp(value), 2)
    return final, factors
