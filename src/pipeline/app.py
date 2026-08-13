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
import os
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.dashboard.events import build_record, feed
from src.dashboard.holds import holds
from src.dashboard.routes import router as dashboard_router
from src.db.client import update_admin_action, write_audit_record
from src.models import AnalysisResponse, InterceptDecision, ToolCallRequest
from src.pipeline.injection import detect_injection, regex_scan
from src.pipeline.orchestrator import analyze

pipeline_api = FastAPI(title="Agent Firewall — Reasoning Engine")
pipeline_api.include_router(dashboard_router)

# How long a held call parks awaiting a human decision before failing closed.
# Kept under the MCP host's own tools/call timeout (~60s) so the host doesn't
# cancel first. Timeout -> block (see /intercept).
DASH_HOLD_TIMEOUT = float(os.getenv("DASH_HOLD_TIMEOUT", "55"))


async def _write_audit_best_effort(request: ToolCallRequest,
                                   analysis: AnalysisResponse,
                                   record_id: str) -> None:
    """
    Persist the decision off the event loop. Best-effort: the audit trail is a
    side record, not the gate. A Supabase outage must not turn a clean ALLOW
    into a 500 (which the proxy would fail-safe BLOCK) — log and move on.
    """
    try:
        await asyncio.to_thread(write_audit_record, request, analysis, record_id)
    except Exception as exc:  # noqa: BLE001
        print(f"[intercept] audit write failed ({type(exc).__name__}): {exc}")


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
    The proxy's gate. Scores one tool call, logs it, and returns a decision the
    proxy acts on. On a HOLD it PARKS: the response stays open until a human
    approves/denies in the dashboard (holds.resolve) or DASH_HOLD_TIMEOUT expires
    — timeout fails closed to block. /analyze stays the pure scoring path so evals
    never park here.
    """
    analysis = await analyze(request)
    record_id = str(uuid.uuid4())
    await _write_audit_best_effort(request, analysis, record_id)

    if analysis.decision != "hold":
        # Publish AFTER scoring so the feed never sits on the decision path.
        feed.publish(build_record(request, analysis))
        return InterceptDecision(
            decision=analysis.decision,
            risk_score=analysis.risk_score,
            hold_id=None,
            counterfactual=analysis.counterfactual,
            message=f"{analysis.decision}: risk {analysis.risk_score:.0f}/100",
        )

    # HOLD: surface the parked call immediately (it shows in the feed + holds
    # panel while a human decides), then block on the decision (or time out).
    holds.register(record_id)
    feed.publish(build_record(request, analysis, hold_id=record_id))
    resolution = await holds.wait(record_id, DASH_HOLD_TIMEOUT)
    final = "allow" if resolution == "approved" else "block"

    if resolution in ("approved", "denied"):
        try:
            await asyncio.to_thread(update_admin_action, record_id, resolution, "dashboard")
        except Exception as exc:  # noqa: BLE001
            print(f"[intercept] admin-action write failed ({type(exc).__name__}): {exc}")

    # Publish the resolution so the held card updates to its final outcome.
    feed.publish(build_record(request, analysis, hold_id=record_id,
                              event="resolved", final_decision=final))

    reason = {"approved": "approved by reviewer", "denied": "denied by reviewer",
              "timeout": "no reviewer decision before timeout — failed closed"}[resolution]
    return InterceptDecision(
        decision=final,
        risk_score=analysis.risk_score,
        hold_id=record_id,
        counterfactual=analysis.counterfactual,
        message=f"hold {resolution}: {reason}",
    )


@pipeline_api.get("/holds")
async def holds_endpoint() -> dict:
    """Hold ids currently parked in-process awaiting a human decision."""
    return {"active": holds.active()}


@pipeline_api.post("/holds/{hold_id}/approve", response_model=InterceptDecision)
async def approve_hold(hold_id: str) -> InterceptDecision:
    return _resolve_hold(hold_id, "approved")


@pipeline_api.post("/holds/{hold_id}/deny", response_model=InterceptDecision)
async def deny_hold(hold_id: str) -> InterceptDecision:
    return _resolve_hold(hold_id, "denied")


def _resolve_hold(hold_id: str, action: str) -> InterceptDecision:
    """Release a parked /intercept waiter. 404 if the hold is unknown/expired."""
    if not holds.resolve(hold_id, action):
        raise HTTPException(status_code=404, detail="hold not found or already resolved")
    decision = "allow" if action == "approved" else "block"
    return InterceptDecision(
        decision=decision,
        risk_score=0.0,
        hold_id=hold_id,
        message=f"hold {hold_id} {action}",
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
