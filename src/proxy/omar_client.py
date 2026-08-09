"""
HTTP client the proxy uses to call the AI reasoning engine (src/pipeline).

Fail-safe by design: if the pipeline is slow or unreachable, retry once with a
shorter timeout, then default to BLOCK. A broken brain is treated as a high-risk
signal, never as a green light (docs.md §Layer 3).
"""
import os

import httpx

from src.models import AnalysisResponse, ToolCallRequest

PIPELINE_URL = os.getenv("OMAR_PIPELINE_URL", "http://localhost:8001")
TIMEOUT_SECONDS = 4.0
RETRY_TIMEOUT_SECONDS = 2.0


async def analyze(request: ToolCallRequest) -> AnalysisResponse:
    payload = request.model_dump(mode="json")

    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        try:
            resp = await client.post(f"{PIPELINE_URL}/analyze", json=payload)
            resp.raise_for_status()
            return AnalysisResponse(**resp.json())
        except (httpx.TimeoutException, httpx.RequestError):
            # Retry once with a shorter timeout before giving up.
            try:
                async with httpx.AsyncClient(timeout=RETRY_TIMEOUT_SECONDS) as retry_client:
                    resp = await retry_client.post(f"{PIPELINE_URL}/analyze", json=payload)
                    resp.raise_for_status()
                    return AnalysisResponse(**resp.json())
            except Exception:
                return _fail_safe_block(request)
        except Exception:
            return _fail_safe_block(request)


def _fail_safe_block(request: ToolCallRequest) -> AnalysisResponse:
    """Pipeline unreachable — default to BLOCK. A broken brain is a red flag."""
    return AnalysisResponse(
        risk_score=100.0,
        decision="block",
        drift_score=100.0,
        injection_score=100.0,
        injection_detected=False,
        anomaly_score=100.0,
        counterfactual=(
            f"Analysis pipeline unreachable. Tool call {request.tool_name} blocked as a "
            "precaution. Investigate pipeline health before resuming agent operations."
        ),
        processing_time_ms=0,
    )
