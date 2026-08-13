"""
HTTP client the MCP proxy uses to reach the reasoning engine.

Same fail-safe philosophy as src/proxy/omar_client.py — if the engine is
unreachable, default to BLOCK; a broken brain is a red flag, never a green
light. Two differences from omar_client:

  1. It calls POST /intercept (not /analyze). /intercept adds audit logging and
     can PARK the response for a human hold; /analyze stays pure for evals.
  2. The read timeout is long (outwaits a hold) while the connect timeout is
     short (fail-fast on a genuinely dead engine). A hold that the human never
     resolves is bounded engine-side by the hold timeout, after which /intercept
     returns block on its own — so read=130 only ever waits for a real decision.
"""
from __future__ import annotations

import httpx

from src.models import InterceptDecision, ToolCallRequest

# connect fails fast (dead engine); read outwaits an engine-side human hold.
TIMEOUTS = httpx.Timeout(connect=3.0, read=130.0, write=5.0, pool=5.0)
_SCAN_TIMEOUTS = httpx.Timeout(connect=3.0, read=10.0, write=5.0, pool=5.0)


async def intercept(request: ToolCallRequest, engine_url: str) -> InterceptDecision:
    """Score + (if held) await resolution for one tool call. Fail-safe -> block."""
    payload = request.model_dump(mode="json")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUTS) as client:
            resp = await client.post(f"{engine_url}/intercept", json=payload)
            resp.raise_for_status()
            return InterceptDecision(**resp.json())
    except Exception as exc:  # noqa: BLE001 — includes timeout, connect error, HTTP status
        return _fail_safe_block(request, exc)


async def scan_tools(items: list[dict], source: str, engine_url: str) -> list[dict]:
    """
    Scan tool descriptions for injected instructions (tool-poisoning).

    ``items`` = ``[{"name": str, "text": str}, ...]``. Returns one verdict per
    item: ``[{"name", "flagged": bool, "suspicious_text": str|None}, ...]``.
    Fail-OPEN here (return no flags) — a scan outage must not corrupt the tool
    list the host depends on; the per-call /intercept path is the real gate.
    """
    if not items:
        return []
    payload = {"items": items, "source": source}
    try:
        async with httpx.AsyncClient(timeout=_SCAN_TIMEOUTS) as client:
            resp = await client.post(f"{engine_url}/scan", json=payload)
            resp.raise_for_status()
            return resp.json()
    except Exception:  # noqa: BLE001
        return [{"name": it.get("name", ""), "flagged": False, "suspicious_text": None}
                for it in items]


async def register_session(session_id: str, agent: str, workspace: str, engine_url: str) -> None:
    """
    Announce this session to the dashboard so a human can arm it with intent.
    Fire-and-forget: a missing engine must never delay or fail proxy startup.
    """
    try:
        async with httpx.AsyncClient(timeout=_SCAN_TIMEOUTS) as client:
            await client.post(f"{engine_url}/session/register",
                              json={"session_id": session_id, "agent": agent,
                                    "workspace": workspace})
    except Exception:  # noqa: BLE001
        pass


def _fail_safe_block(request: ToolCallRequest, exc: Exception) -> InterceptDecision:
    """Engine unreachable — block. Mirrors omar_client._fail_safe_block."""
    return InterceptDecision(
        decision="block",
        risk_score=100.0,
        counterfactual=(
            f"Analysis engine unreachable ({type(exc).__name__}). Tool call "
            f"'{request.tool_name}' was blocked as a precaution. Investigate "
            "firewall engine health before resuming agent operations."
        ),
        message="blocked: analysis engine unreachable",
    )
