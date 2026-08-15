"""
Intent persistence behind a pluggable backend seam.

The one importer is src/pipeline/intent.py; the surface is two functions,
``get_intent(session_id) -> IntentObject | None`` and ``save_intent(...)``.
Defining the seam in terms of IntentObject (not a Supabase row) is what lets a
new backend be a drop-in implementation instead of a refactor.

Backends, selected by ``FIREWALL_MEMORY_BACKEND``:
  memory   (default) — in-process dict. Always works, no external dependency;
                       the demo runs on this even with Supabase paused.
  supabase           — the intent_store table (24h TTL). Durable, shared.
  backboard          — Thursday: durable session memory + derived-fact writes,
                       off the scoring hot path.

The dashboard's arm-session writes through this same seam, so scoring picks the
armed intent up on the very next call.
"""
from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.pipeline.config import INTENT_TTL_HOURS
from src.pipeline.schemas import IntentObject

_BACKEND = os.getenv("FIREWALL_MEMORY_BACKEND", "memory").lower()


def _run_sync(coro):
    """
    Run an async adapter call from this synchronous seam, safely from any thread.

    Normally we're on a worker thread (intent.py wraps these calls in
    asyncio.to_thread), where asyncio.run is correct. The dashboard's arm route
    can call in from inside a running loop, where asyncio.run would raise — so
    fall back to a short-lived thread with its own loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    box: dict = {}

    def runner() -> None:
        box["value"] = asyncio.run(coro)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    return box.get("value")


# --------------------------------------------------------------------- memory
class _MemoryBackend:
    """In-process intent store. No TTL — fine for a single-run demo/session."""

    def __init__(self) -> None:
        self._store: dict[str, IntentObject] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> Optional[IntentObject]:
        with self._lock:
            return self._store.get(session_id)

    def save(self, intent: IntentObject, agent_id: str, workspace_id: str) -> None:
        with self._lock:
            self._store[intent.session_id] = intent


# ------------------------------------------------------------------- supabase
class _SupabaseBackend:
    """The intent_store table via the shared client (lazy — imported on use)."""

    def get(self, session_id: str) -> Optional[IntentObject]:
        from src.db.client import get_client
        result = (
            get_client().table("intent_store")
            .select("*")
            .eq("session_id", session_id)
            .gt("expires_at", datetime.now(timezone.utc).isoformat())
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return _row_to_intent(rows[0]) if rows else None

    def save(self, intent: IntentObject, agent_id: str, workspace_id: str) -> None:
        from src.db.client import get_client
        now = datetime.now(timezone.utc)
        row = {
            "session_id": intent.session_id,
            "agent_id": agent_id,
            "workspace_id": workspace_id,
            "goal": intent.goal,
            "scope": intent.scope,
            "permitted_action_types": intent.permitted_action_types,
            "prohibited_action_types": intent.prohibited_action_types,
            "expected_tool_types": intent.expected_tool_types,
            "risk_tolerance": intent.risk_tolerance,
            "extracted_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=INTENT_TTL_HOURS)).isoformat(),
        }
        get_client().table("intent_store").upsert(row, on_conflict="session_id").execute()


def _row_to_intent(row: dict) -> IntentObject:
    return IntentObject(
        goal=row["goal"],
        scope=row.get("scope") or "",
        permitted_action_types=row.get("permitted_action_types") or [],
        prohibited_action_types=row.get("prohibited_action_types") or [],
        expected_tool_types=row.get("expected_tool_types") or [],
        risk_tolerance=row.get("risk_tolerance") or "low",
        session_id=row["session_id"],
    )


# ------------------------------------------------------------------ backboard
class _BackboardBackend:
    """
    Durable session memory in Backboard, with a local cache in front.

    The cache is what keeps this off the hot path: intent is read on every scored
    call, but only the FIRST read of a session (typically after a restart) goes
    to the network. Writes are small and infrequent (once per arm/extract).

    Falls back to in-process storage whenever Backboard is unconfigured or a call
    fails, so selecting this backend can never break scoring.
    """

    def __init__(self) -> None:
        self._cache: dict[str, IntentObject] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> Optional[IntentObject]:
        with self._lock:
            cached = self._cache.get(session_id)
        if cached is not None:
            return cached

        from src.pipeline import backboard_client as bb
        if not bb.available():
            return None

        rows = _run_sync(bb.get_memories(session_id, kind=bb.KIND_INTENT, limit=10)) or []
        if not rows:
            return None

        # Newest intent wins; content is the goal text we wrote in save().
        goal = str(rows[0].get("content") or "").strip()
        if not goal:
            return None
        intent = IntentObject(session_id=session_id, goal=goal, scope="")
        with self._lock:
            self._cache[session_id] = intent
        print(f"[intent_store] rehydrated intent for {session_id} from Backboard")
        return intent

    def save(self, intent: IntentObject, agent_id: str, workspace_id: str) -> None:
        with self._lock:
            self._cache[intent.session_id] = intent

        from src.pipeline import backboard_client as bb
        if not bb.available():
            return
        _run_sync(bb.add_memory(intent.goal, {
            "session_id": intent.session_id,
            "kind": bb.KIND_INTENT,
            "agent_id": agent_id,
            "workspace_id": workspace_id,
        }))
        _run_sync(bb.record_thread_message(
            intent.session_id, f"Session intent captured: {intent.goal}"))


def _select_backend():
    if _BACKEND == "supabase":
        return _SupabaseBackend()
    if _BACKEND == "backboard":
        return _BackboardBackend()
    return _MemoryBackend()


_backend = _select_backend()


def get_intent(session_id: str) -> Optional[IntentObject]:
    """Return the session's intent object, or None if absent/expired."""
    return _backend.get(session_id)


def save_intent(intent: IntentObject, agent_id: str, workspace_id: str) -> None:
    """Persist (or overwrite) the intent for a session."""
    _backend.save(intent, agent_id, workspace_id)
