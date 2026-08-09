"""
Pipeline orchestrator (docs.md §Pipeline Orchestrator).

Runs the components with the right parallelism and turns their results into the
public AnalysisResponse. Every component is wrapped so a single failure or
timeout degrades to a conservative default instead of crashing the pipeline —
the proxy's own fail-safe handles a total pipeline outage.

Phase 1 stages:
  Stage 1 (parallel):  intent extraction + injection detection
  Stage 2:             drift scoring (needs the intent from Stage 1)
  Stage 3:             threat intel — GARNISH, skipped
  Stage 4:             combine -> decision -> counterfactual (if not allow)
"""
import asyncio
import time
from typing import Awaitable, TypeVar

from src.models import AnalysisResponse, AnomalySignals, ToolCallRequest
from src.pipeline.combiner import combine_risk
from src.pipeline.config import DEFAULT_DRIFT_NO_INTENT, STAGE_TIMEOUT_SECONDS
from src.pipeline.counterfactual import generate_counterfactual
from src.pipeline.drift import score_drift
from src.pipeline.injection import detect_injection
from src.pipeline.intent import extract_or_retrieve_intent
from src.pipeline.schemas import DriftResult, InjectionResult

T = TypeVar("T")


async def _safe(coro: Awaitable[T], default: T, label: str, timeout: float = STAGE_TIMEOUT_SECONDS) -> T:
    """Await a component with a timeout; on timeout/error return its default."""
    try:
        return await asyncio.wait_for(coro, timeout)
    except Exception as e:  # noqa: BLE001 — includes asyncio.TimeoutError
        print(f"[orchestrator] {label} failed/timed out -> default: {e}")
        return default


async def analyze(request: ToolCallRequest) -> AnalysisResponse:
    start = time.time()

    # Stage 1 — independent, run in parallel.
    intent, injection = await asyncio.gather(
        _safe(extract_or_retrieve_intent(request), None, "intent"),
        _safe(
            detect_injection(request.message_context, request.trigger_source),
            InjectionResult(score=0.0, detected=False),
            "injection",
        ),
    )

    # Stage 2 — drift depends on the intent from Stage 1.
    drift = await _safe(
        score_drift(request, intent),
        DriftResult(score=DEFAULT_DRIFT_NO_INTENT, reasoning="Drift scorer unavailable."),
        "drift",
    )

    # Stage 4 — combine. Anomaly (Phase 2) and threat (Phase 3) are absent, so
    # they're passed as None and the combiner reweights across injection + drift.
    risk_score, decision = combine_risk(injection.score, drift.score)

    counterfactual = None
    if decision != "allow":
        counterfactual = await _safe(
            generate_counterfactual(request, injection, drift, decision, risk_score),
            None,
            "counterfactual",
        )

    elapsed_ms = int((time.time() - start) * 1000)

    return AnalysisResponse(
        risk_score=risk_score,
        decision=decision,
        drift_score=drift.score,
        injection_score=injection.score,
        injection_detected=injection.detected,
        suspicious_text=injection.suspicious_text,
        anomaly_score=0.0,                 # cold in Phase 1 (no baseline yet)
        anomaly_signals=AnomalySignals(),
        threat_match=False,
        threat_pattern=None,
        counterfactual=counterfactual,
        tokens_used=[],                    # tokenization vault is GARNISH
        processing_time_ms=elapsed_ms,
    )
