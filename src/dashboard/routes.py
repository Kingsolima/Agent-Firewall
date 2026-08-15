"""
Dashboard HTTP surface — an APIRouter mounted into the engine. Serves the JSON
feed the clearance board polls plus the arm-session endpoints. The approve/deny
and /holds endpoints live in app.py and the board calls them directly.

The engine serves no HTML. The board is the static site in web/, deployed
separately (see vercel.json) and pointed at an engine via its Connect control,
so this router is a pure JSON API and needs the CORS middleware in app.py.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from src.dashboard.events import feed
from src.dashboard.sessions import sessions
from src.pipeline import intent_store
from src.pipeline.schemas import IntentObject

router = APIRouter()

_REPO = Path(__file__).resolve().parents[2]
_demo_proc: subprocess.Popen | None = None


class RegisterBody(BaseModel):
    session_id: str
    agent: str = ""
    workspace: str = "default"


class ArmBody(BaseModel):
    session_id: str
    intent: str


@router.get("/")
async def index() -> dict:
    """
    Not a UI. Landing here usually means someone expected the board on the
    engine's port, so say plainly what this is and where the board lives.
    """
    return {
        "service": "agent-firewall-engine",
        "ui": "none — the clearance board is the static site in web/",
        "connect": "open the board and enter this origin in its Live engine field",
        "endpoints": ["/health", "/events", "/feed", "/sessions",
                      "/session/register", "/session/arm",
                      "/analyze", "/intercept", "/scan", "/holds"],
    }


@router.get("/events")
async def events(since: int = 0) -> dict:
    """Feed records newer than ``since`` (incremental poll)."""
    return {"records": feed.since(since), "latest_seq": feed.latest_seq()}


@router.get("/feed")
async def full_feed() -> dict:
    """The whole current buffer — initial page hydration."""
    return {"records": feed.all(), "latest_seq": feed.latest_seq()}


@router.get("/sessions")
async def list_sessions() -> dict:
    return {"sessions": sessions.list()}


@router.post("/session/register")
async def register_session(body: RegisterBody) -> dict:
    entry = sessions.register(body.session_id, body.agent, body.workspace)
    return {"ok": True, "session": entry}


@router.post("/session/arm")
async def arm_session(body: ArmBody) -> dict:
    """
    Attach the user's intent to a session and seed the intent store, so the very
    next tool call is scored against it. Written through the same backend seam
    scoring reads from (memory | supabase | backboard).
    """
    entry = sessions.arm(body.session_id, body.intent)
    intent = IntentObject(
        session_id=body.session_id,
        goal=body.intent,
        scope="",
        permitted_action_types=[],
        prohibited_action_types=[],
        expected_tool_types=[],
        risk_tolerance="low",
    )
    try:
        intent_store.save_intent(intent, entry.get("agent", ""), entry.get("workspace", "default"))
    except Exception as exc:  # noqa: BLE001 — arming the UI must not 500 on a backend hiccup
        print(f"[arm] intent save failed ({type(exc).__name__}): {exc}")
    return {"ok": True, "session": entry}


@router.post("/demo/run")
async def run_demo() -> dict:
    """
    Fire the scripted benign+attack demo (demo/run_demo.py) so the feed lights up
    on camera without juggling a second terminal. Best-effort and single-flight.
    """
    global _demo_proc
    if _demo_proc is not None and _demo_proc.poll() is None:
        return {"ok": True, "status": "already running"}
    script = _REPO / "demo" / "run_demo.py"
    if not script.exists():
        return {"ok": False, "status": "demo script not found"}
    try:
        _demo_proc = subprocess.Popen([sys.executable, str(script)], cwd=str(_REPO))
        return {"ok": True, "status": "started"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": f"{type(exc).__name__}: {exc}"}
