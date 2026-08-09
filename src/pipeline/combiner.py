"""
Risk combiner (docs.md §Risk Combiner + Side Notes §Problem 2 / Solution B).

Blends the live signals into a 0–100 score and routes to allow/hold/block.

Key design point from the side notes: signals that are cold (anomaly during a
fresh demo) or not built yet (threat intel) are passed as None and EXCLUDED from
the weighting, with the weights renormalized across whatever is present. So a
missing signal never silently drags the score toward zero — the attack still
blocks on injection + drift alone.
"""
from typing import Optional

from src.pipeline.config import (
    ALLOW_MAX,
    HOLD_MAX,
    INJECTION_OVERRIDE_THRESHOLD,
    WEIGHTS,
)


def combine_risk(
    injection_score: float,
    drift_score: float,
    anomaly_score: Optional[float] = None,
    threat_score: Optional[float] = None,
) -> tuple[float, str]:
    """Return (final_risk_score, decision)."""
    contributions = {"injection": injection_score, "drift": drift_score}
    if anomaly_score is not None:
        contributions["anomaly"] = anomaly_score
    if threat_score is not None:
        contributions["threat"] = threat_score

    total_weight = sum(WEIGHTS[k] for k in contributions)
    risk = sum(WEIGHTS[k] * v for k, v in contributions.items()) / total_weight
    risk = round(risk, 1)

    # Override: an unambiguous injection always blocks (docs.md §Override rules).
    # Floor the risk to the injection level so a block driven by a near-certain
    # injection isn't reported with a misleadingly low blended score.
    if injection_score > INJECTION_OVERRIDE_THRESHOLD:
        return max(risk, injection_score), "block"
    if risk > HOLD_MAX:
        return risk, "block"
    if risk > ALLOW_MAX:
        return risk, "hold"
    return risk, "allow"
