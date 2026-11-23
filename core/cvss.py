"""CVSS v3.1 base-score calculator (FIRST specification, section 7). Pure Python, no dependencies.

SYSX records a CVSS vector per finding type and computes the score from it, instead of keeping
hand-typed scores. ``parse_vector`` is strict: a vector with a missing, repeated or unknown
metric is rejected rather than guessed at.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

VERSION = "3.1"
_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VALID = {**{k: set(v) for k, v in _WEIGHTS.items()}, "PR": {"N", "L", "H"}, "S": {"U", "C"}}


class CvssError(ValueError):
    """The vector is not a valid CVSS v3.x base vector."""


@dataclass(frozen=True)
class CvssResult:
    vector: str
    score: float
    severity: str
    impact: float
    exploitability: float


def roundup(value: float) -> float:
    """The CVSS 3.1 Roundup function: smallest number, to one decimal, that is >= value (float-safe)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def rating(score: float) -> str:
    """Qualitative severity. 'informational' stands in for CVSS 'None' so it matches SYSX severities."""
    if score <= 0:
        return "informational"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse_vector(vector: str) -> dict[str, str]:
    if not isinstance(vector, str):
        raise CvssError("Vector must be a string.")
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise CvssError("Vector must start with CVSS:3.1 (or 3.0).")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key not in _VALID:
            raise CvssError(f"Unknown or malformed metric: {part!r}")
        if key in metrics:
            raise CvssError(f"Metric {key} appears twice.")
        if value not in _VALID[key]:
            raise CvssError(f"Invalid value {value!r} for metric {key}.")
        metrics[key] = value
    missing = [k for k in _ORDER if k not in metrics]
    if missing:
        raise CvssError(f"Missing base metrics: {', '.join(missing)}")
    return metrics


def build_vector(**metrics: str) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in _ORDER)


def calculate(vector: str) -> CvssResult:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * _WEIGHTS["AV"][m["AV"]] * _WEIGHTS["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _WEIGHTS["UI"][m["UI"]]
    if impact <= 0:
        score = 0.0
    elif changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))
    canonical = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _ORDER)
    return CvssResult(canonical, score, rating(score), round(impact, 1), round(exploitability, 1))


def score_for(vector: str | None) -> float | None:
    """Score for a stored vector, or None when there is no (valid) vector."""
    if not vector:
        return None
    try:
        return calculate(vector).score
    except CvssError:
        return None
