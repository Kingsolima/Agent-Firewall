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

from src.models import AnalysisResponse, ToolCallRequest
from src.pipeline.orchestrator import analyze

pipeline_api = FastAPI(title="Agent Firewall — Reasoning Engine")


@pipeline_api.get("/health")
async def health():
    """No dependencies — always 200 so the platform healthcheck passes."""
    return {"status": "ok", "service": "agent-firewall-pipeline"}


@pipeline_api.post("/analyze", response_model=AnalysisResponse)
async def analyze_endpoint(request: ToolCallRequest) -> AnalysisResponse:
    """
    Score one intercepted tool call. If the pipeline raises (it shouldn't —
    components degrade internally), FastAPI returns 500 and the proxy fail-safe
    BLOCKs, which is the correct conservative outcome.
    """
    return await analyze(request)
