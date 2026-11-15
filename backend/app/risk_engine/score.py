"""Deterministic 0-100 incident risk score. No LLM or model output can change it.

score = w_sev * severity + w_corr * correlation + w_ti * threat_intel + w_asset * asset  (each part 0-100)
Missing parts are dropped and the remaining weights renormalized, never silently treated as zero.
"""
from dataclasses import dataclass

SEVERITY_POINTS = {"low": 25, "medium": 50, "high": 75, "critical": 100}
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Weights:
    severity: float = 0.4
    correlation: float = 0.3
    threat_intel: float = 0.2
    asset: float = 0.1


def correlation_points(distinct_rules: int) -> float:
    """1 detection = 0, each further distinct detection on related activity adds 33.3, capped at 100 (4+ rules)."""
    return min(1.0, max(0, distinct_rules - 1) / 3) * 100


def asset_points(criticality: int | None) -> float | None:
    """Asset criticality 1..5 mapped linearly to 0..100; unknown stays unknown."""
    return None if criticality is None else (min(5, max(1, criticality)) - 1) / 4 * 100


def risk_score(severity: str, distinct_rules: int, asset_criticality: int | None, ti_score: float | None,
               w: Weights = Weights()) -> tuple[int, dict]:
    parts = {
        "severity": (float(SEVERITY_POINTS[severity]), w.severity),
        "correlation": (correlation_points(distinct_rules), w.correlation),
        "threat_intel": (None if ti_score is None else min(100.0, max(0.0, ti_score)), w.threat_intel),
        "asset": (asset_points(asset_criticality), w.asset),
    }
    used: dict[str, tuple[float, float]] = {}
    for k, (val, wt) in parts.items():
        if val is not None and wt > 0:
            used[k] = (val, wt)
    total_w = sum(wt for _, wt in used.values())
    raw = sum(val * wt for val, wt in used.values()) / total_w if total_w else 0.0
    score = min(100, max(0, int(raw + 0.5)))  # round half up
    breakdown = {
        "score": score,
        "components": {k: {"value": None if v is None else round(v, 1), "weight": wt, "used": k in used} for k, (v, wt) in parts.items()},
        "missing": [k for k, (v, _) in parts.items() if v is None],
        "effective_weights": {k: round(wt / total_w, 4) for k, (_, wt) in used.items()} if total_w else {},
    }
    return score, breakdown
