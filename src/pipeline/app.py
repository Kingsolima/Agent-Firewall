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

from fastapi import FastAPI
from pydantic import BaseModel

from src.models import AnalysisResponse, InterceptDecision, ToolCallRequest
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
    The proxy's gate. STUB (Phase 0): always allow so transparent passthrough
    can be verified before the real analyze -> audit -> hold-park wiring lands
    (Tue, Phase 2a).
    """
    return InterceptDecision(
        decision="allow",
        risk_score=0.0,
        message="stub: allow (Phase 0 — /intercept not yet wired to analyze)",
    )


@pipeline_api.post("/scan", response_model=list[ScanResult])
async def scan_endpoint(request: ScanRequest) -> list[ScanResult]:
    """
    Scan tool descriptions for tool-poisoning. STUB (Phase 0): flag nothing.
    Real impl (Mon, Phase 1c) runs regex_scan on all, Claude only on suspicious.
    """
    return [ScanResult(name=item.name) for item in request.items]
