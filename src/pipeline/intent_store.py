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

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.pipeline.config import INTENT_TTL_HOURS
from src.pipeline.schemas import IntentObject

_BACKEND = os.getenv("FIREWALL_MEMORY_BACKEND", "memory").lower()


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


def _select_backend():
    if _BACKEND == "supabase":
        return _SupabaseBackend()
    if _BACKEND == "backboard":
        # Thursday: BackboardBackend drops in here. Until then, memory keeps the
        # app functional rather than failing selection.
        print("[intent_store] backboard backend not yet built — using memory")
        return _MemoryBackend()
    return _MemoryBackend()


_backend = _select_backend()


def get_intent(session_id: str) -> Optional[IntentObject]:
    """Return the session's intent object, or None if absent/expired."""
    return _backend.get(session_id)


def save_intent(intent: IntentObject, agent_id: str, workspace_id: str) -> None:
    """Persist (or overwrite) the intent for a session."""
    _backend.save(intent, agent_id, workspace_id)
