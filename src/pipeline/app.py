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
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.dashboard.events import build_record, feed
from src.dashboard.holds import holds
from src.dashboard.routes import router as dashboard_router
from src.db.client import update_admin_action, write_audit_record
from src.models import AnalysisResponse, InterceptDecision, ToolCallRequest
from src.pipeline import intent_store
from src.pipeline.injection import detect_injection, regex_scan
from src.pipeline.orchestrator import analyze

pipeline_api = FastAPI(title="Agent Firewall — Reasoning Engine")

# The clearance board is deployed separately (Vercel) and polls this engine from
# another origin when a developer points it at their own machine. The engine is
# a localhost-bound developer tool, so the permissive origin is scoped to the
# read/resolve surface the board actually uses, not to the proxy's gate.
pipeline_api.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("FIREWALL_CORS_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

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


def taint_summary(request: ToolCallRequest, analysis: AnalysisResponse,
                  decision: str) -> str:
    """
    The DERIVED fact we persist about one call — never raw tool output, file
    contents, or secret values. It records that a tool ran, how it was judged,
    and (when the detector fired) a short excerpt of the *injected instruction*
    that triggered it. That excerpt is a security finding, not user data, and
    it's what lets a restarted proxy re-detect poison it already ingested.
    """
    line = (f"Tool '{request.tool_name}' was {decision.upper()} "
            f"(risk {analysis.risk_score:.0f}/100).")
    if analysis.injection_detected and analysis.suspicious_text:
        excerpt = analysis.suspicious_text[:200].replace("\n", " ")
        line += f" Injected instruction detected in ingested content: \"{excerpt}\""
    return line


async def _write_taint_memory(request: ToolCallRequest, analysis: AnalysisResponse,
                              decision: str) -> None:
    """
    Fire-and-forget durable memory of what this session has ingested. Runs AFTER
    the decision has been returned, so Backboard is never on the scoring path and
    can never delay or gate a tool call.
    """
    try:
        from src.pipeline import backboard_client as bb
        if not bb.available():
            return
        await bb.add_memory(taint_summary(request, analysis, decision), {
            "session_id": request.session_id,
            "kind": bb.KIND_TAINT,
            "tool": request.tool_name,
            "decision": decision,
            "risk": round(analysis.risk_score, 1),
        })
    except Exception as exc:  # noqa: BLE001 — additive, never load-bearing
        print(f"[intercept] taint memory write failed ({type(exc).__name__}): {exc}")


def _spawn_taint_write(request: ToolCallRequest, analysis: AnalysisResponse,
                       decision: str) -> None:
    """Schedule the taint write without awaiting it (keeps the hot path clean)."""
    asyncio.create_task(_write_taint_memory(request, analysis, decision))


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
        _spawn_taint_write(request, analysis, analysis.decision)
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
    _spawn_taint_write(request, analysis, final)

    reason = {"approved": "approved by reviewer", "denied": "denied by reviewer",
              "timeout": "no reviewer decision before timeout — failed closed"}[resolution]
    return InterceptDecision(
        decision=final,
        risk_score=analysis.risk_score,
        hold_id=record_id,
        counterfactual=analysis.counterfactual,
        message=f"hold {resolution}: {reason}",
    )


@pipeline_api.get("/session/{session_id}/context")
async def session_context(session_id: str) -> dict:
    """
    Durable context for a session — what it was asked to do and what it has
    already ingested. A restarting proxy calls this to REHYDRATE its in-process
    taint buffer, so poison read before the restart is still in view when the
    action it induced is scored afterwards. Empty when Backboard is unconfigured
    (the firewall then behaves exactly as it did before this existed).
    """
    intent_goal = None
    taint: list[str] = []
    try:
        from src.pipeline import backboard_client as bb
        if bb.available():
            existing = await asyncio.to_thread(intent_store.get_intent, session_id)
            if existing:
                intent_goal = existing.goal
            rows = await bb.get_memories(session_id, kind=bb.KIND_TAINT, limit=20)
            taint = [str(r.get("content") or "") for r in rows if r.get("content")]
    except Exception as exc:  # noqa: BLE001
        print(f"[context] rehydration read failed ({type(exc).__name__}): {exc}")
    return {"session_id": session_id, "intent": intent_goal, "taint": taint}


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
