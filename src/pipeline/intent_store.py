"""
Persistence for intent objects in Supabase `intent_store` (table created by
Ahmed's migration — we only read/write it). 24h TTL per docs.md.

Reuses the shared Supabase client from src/db/client.py so there's one
connection/credential path for the whole app.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.db.client import get_client
from src.pipeline.config import INTENT_TTL_HOURS
from src.pipeline.schemas import IntentObject


def get_intent(session_id: str) -> Optional[dict]:
    """Return the stored intent row for a session if present and not expired."""
    db = get_client()
    result = (
        db.table("intent_store")
        .select("*")
        .eq("session_id", session_id)
        .gt("expires_at", datetime.now(timezone.utc).isoformat())
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None


def save_intent(intent: IntentObject, agent_id: str, workspace_id: str) -> None:
    """Upsert an intent object keyed by session_id with a fresh TTL."""
    db = get_client()
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
    db.table("intent_store").upsert(row, on_conflict="session_id").execute()


def row_to_intent(row: dict) -> IntentObject:
    return IntentObject(
        goal=row["goal"],
        scope=row["scope"],
        permitted_action_types=row.get("permitted_action_types") or [],
        prohibited_action_types=row.get("prohibited_action_types") or [],
        expected_tool_types=row.get("expected_tool_types") or [],
        risk_tolerance=row.get("risk_tolerance") or "low",
        session_id=row["session_id"],
    )
