"""
AI Reasoning Engine service — the real "brain" the proxy calls.

Runs as its own service (separate from the proxy) so the heavy, LLM-bound
pipeline is isolated from the proxy's always-fast healthcheck + fail-safe path,
exactly as docs.md describes. Deploy with:

    uvicorn src.pipeline.app:pipeline_api --host 0.0.0.0 --port 8001

The proxy reaches it at OMAR_PIPELINE_URL (default http://localhost:8001).
Contract: POST /analyze takes a ToolCallRequest, returns an AnalysisResponse
(both defined in src/models.py — the shared contract with the proxy).
"""
from dotenv import load_dotenv

load_dotenv()

import src.pipeline.bootstrap  # noqa: F401 — trust OS cert store before any TLS call

import asyncio

from fastapi import FastAPI
from pydantic import BaseModel

from src.models import AnalysisResponse, InterceptDecision, ToolCallRequest
from src.pipeline.injection import detect_injection, regex_scan
from src.pipeline.orchestrator import analyze

pipeline_api = FastAPI(title="Agent Firewall — Reasoning Engine")


class ScanItem(BaseModel):
    name: str
    text: str


class ScanRequest(BaseModel):
    """Tool descriptions to scan for injected instructions (tool-poisoning)."""
    items: list[ScanItem]
    source: str = "unknown"


class ScanResult(BaseModel):
    name: str
    flagged: bool = False
    suspicious_text: str | None = None


@pipeline_api.get("/health")
async def health():
    """No dependencies — always 200 so the platform healthcheck passes."""
    return {"status": "ok", "service": "agent-firewall-pipeline"}


@pipeline_api.post("/analyze", response_model=AnalysisResponse)
async def analyze_endpoint(request: ToolCallRequest) -> AnalysisResponse:
    """
    Score one intercepted tool call. PURE: never blocks/parks — evals and the
    smoke check depend on this returning promptly. The hold path lives in
    /intercept. If the pipeline raises (it shouldn't — components degrade
    internally), FastAPI returns 500 and the proxy fail-safe BLOCKs.
    """
    return await analyze(request)


@pipeline_api.post("/intercept", response_model=InterceptDecision)
async def intercept_endpoint(request: ToolCallRequest) -> InterceptDecision:
    """
    The proxy's gate. Scores one tool call and returns a decision the proxy acts
    on. Phase 1b: score + return. Phase 2a (Tue) adds audit logging and parks a
    'hold' on a human-approval Event before returning allow/block. /analyze stays
    the pure scoring path so evals never park here.
    """
    analysis = await analyze(request)
    return InterceptDecision(
        decision=analysis.decision,
        risk_score=analysis.risk_score,
        hold_id=None,  # set in Phase 2a once the hold registry exists
        counterfactual=analysis.counterfactual,
        message=f"{analysis.decision}: risk {analysis.risk_score:.0f}/100",
    )


# Descriptions shorter than this and without a regex hit skip the (paid, slower)
# Claude pass — real tool descriptions are short; poisoning payloads are wordy.
_SCAN_CLAUDE_MIN_CHARS = 200


@pipeline_api.post("/scan", response_model=list[ScanResult])
async def scan_endpoint(request: ScanRequest) -> list[ScanResult]:
    """
    Scan tool descriptions for tool-poisoning (instructions hidden in a server's
    own tool metadata). Regex on every description (instant); Claude only on the
    long ones a regex missed, run concurrently.
    """
    async def scan_one(item: ScanItem) -> ScanResult:
        hit = regex_scan(item.text)
        if hit is not None:
            return ScanResult(name=item.name, flagged=True, suspicious_text=hit)
        if len(item.text) >= _SCAN_CLAUDE_MIN_CHARS:
            verdict = await detect_injection(item.text, request.source)
            if verdict.detected:
                return ScanResult(name=item.name, flagged=True,
                                  suspicious_text=verdict.suspicious_text)
        return ScanResult(name=item.name, flagged=False)

    return list(await asyncio.gather(*(scan_one(item) for item in request.items)))
