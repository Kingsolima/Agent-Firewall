"""
Backboard adapter — the ONLY file that knows Backboard's wire format.

Backboard is the firewall's durable session memory: it remembers what a session
was originally asked to do (intent) and what it has since ingested (derived
taint facts), so that state survives a proxy restart instead of dying with the
process. It is deliberately NOT part of scoring — reasoning stays local (Claude
via claude_client) and every call here is either cache-backed or fire-and-forget.

Two rules this file enforces:

  1. ADDITIVE, NEVER LOAD-BEARING. Every method degrades to None/[] on any
     failure and never raises into the caller. If Backboard is down, slow, or
     unconfigured, the firewall keeps working on the `memory` backend.
  2. DERIVED FACTS ONLY. Callers store intent text and short derived summaries
     (tool, decision, risk, a truncated suspicious excerpt) — never raw tool
     results, file contents, or secret values. See src/pipeline/app.py.

Memory in Backboard is ASSISTANT-scoped (memories written under one assistant
are visible across all of its threads), so every record carries a session_id in
its metadata and reads filter on it client-side. That filtering is what keeps
two concurrent firewall sessions from seeing each other's state.

Endpoint paths are centralized in _PATHS below: the docs describe the surface
(base https://app.backboard.io/api, X-API-Key auth, assistants/threads/memories)
but exact field names are confirmed at the sponsor workshop — when they drift,
this block is the only thing that changes.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx

BASE_URL = os.getenv("BACKBOARD_BASE_URL", "https://app.backboard.io/api")
API_KEY = os.getenv("BACKBOARD_API_KEY", "")
ASSISTANT_ID = os.getenv("BACKBOARD_ASSISTANT_ID", "")

# Assistant profile created on first use when no id is configured.
ASSISTANT_NAME = os.getenv("BACKBOARD_ASSISTANT_NAME", "agent-firewall-session-memory")
ASSISTANT_INSTRUCTIONS = (
    "You are the durable memory of Agent Firewall, an MCP security proxy. You "
    "store each session's original user intent and short derived facts about what "
    "the agent has ingested and which actions were allowed, held, or blocked. You "
    "never store raw tool output or secret values."
)

# Short timeouts: this is never on the decision path, so waiting is pointless.
_TIMEOUT = httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=5.0)

# --- Wire surface. Confirm at the workshop; nothing else in the repo hardcodes these.
_PATHS = {
    "create_assistant": "/assistants",
    "add_memory": "/assistants/{assistant_id}/memories",
    "list_memories": "/assistants/{assistant_id}/memories",
    "search_memories": "/assistants/{assistant_id}/memories/search",
    "thread_message": "/threads/messages",
}

# Metadata keys we set on every record (used for client-side session filtering).
KIND_INTENT = "intent"
KIND_TAINT = "taint"

_assistant_id_cache: Optional[str] = None


def available() -> bool:
    """True when an API key is configured. Callers skip Backboard entirely if not."""
    return bool(API_KEY)


def _headers() -> dict:
    return {"X-API-Key": API_KEY, "Content-Type": "application/json"}


async def _request(method: str, path: str, **kwargs) -> Optional[Any]:
    """One HTTP call. Returns parsed JSON, or None on ANY failure (never raises)."""
    if not available():
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.request(method, f"{BASE_URL}{path}",
                                        headers=_headers(), **kwargs)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
    except Exception as exc:  # noqa: BLE001 — additive, never load-bearing
        print(f"[backboard] {method} {path} failed ({type(exc).__name__}): {exc}")
        return None


async def ensure_assistant() -> Optional[str]:
    """
    Return the assistant id that owns firewall memories, creating it on first use.
    Cached per process; set BACKBOARD_ASSISTANT_ID to pin an existing one.
    """
    global _assistant_id_cache
    if _assistant_id_cache:
        return _assistant_id_cache
    if ASSISTANT_ID:
        _assistant_id_cache = ASSISTANT_ID
        return _assistant_id_cache

    try:
        data = await _request("POST", _PATHS["create_assistant"], json={
            "name": ASSISTANT_NAME,
            "instructions": ASSISTANT_INSTRUCTIONS,
        })
    except Exception as exc:  # noqa: BLE001 — rule 1: never raise into the caller
        print(f"[backboard] ensure_assistant failed ({type(exc).__name__}): {exc}")
        return None

    if isinstance(data, dict):
        # Tolerate {id}, {assistant_id}, or {assistant: {id}} response shapes.
        found = (data.get("id") or data.get("assistant_id")
                 or (data.get("assistant") or {}).get("id"))
        if found:
            _assistant_id_cache = str(found)
            print(f"[backboard] using assistant {_assistant_id_cache}")
    return _assistant_id_cache


async def add_memory(content: str, metadata: dict) -> bool:
    """
    Store one derived fact. Callers MUST pass metadata containing session_id and
    kind. Returns True on success; False means the caller carries on regardless.
    """
    try:
        assistant_id = await ensure_assistant()
        if not assistant_id:
            return False
        path = _PATHS["add_memory"].format(assistant_id=assistant_id)
        result = await _request("POST", path,
                                json={"content": content, "metadata": metadata})
        return result is not None
    except Exception as exc:  # noqa: BLE001
        print(f"[backboard] add_memory failed ({type(exc).__name__}): {exc}")
        return False


async def get_memories(session_id: str, kind: Optional[str] = None,
                       limit: int = 50) -> list[dict]:
    """
    Memories for one session, newest first. Memory is assistant-scoped, so the
    session filter is applied client-side on metadata — this is what keeps two
    concurrent sessions isolated.
    """
    try:
        assistant_id = await ensure_assistant()
        if not assistant_id:
            return []
        path = _PATHS["list_memories"].format(assistant_id=assistant_id)
        data = await _request("GET", path, params={"page": 1, "page_size": limit})
        return _filter_session(data, session_id, kind)
    except Exception as exc:  # noqa: BLE001
        print(f"[backboard] get_memories failed ({type(exc).__name__}): {exc}")
        return []


def _filter_session(data: Any, session_id: str, kind: Optional[str]) -> list[dict]:
    """Extract the memory list from any documented envelope, then filter."""
    if isinstance(data, dict):
        rows = data.get("memories") or data.get("data") or data.get("items") or []
    elif isinstance(data, list):
        rows = data
    else:
        rows = []

    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        meta = row.get("metadata") or {}
        if meta.get("session_id") != session_id:
            continue
        if kind is not None and meta.get("kind") != kind:
            continue
        out.append(row)
    return out


async def record_thread_message(session_id: str, content: str) -> bool:
    """
    Append a human-readable line to the session's Backboard thread — the audit
    narrative a judge can scroll in Backboard's own dashboard. Best-effort; the
    memory records above are the load-bearing half.
    """
    try:
        payload = {"content": content, "memory": "Auto",
                   "metadata": {"session_id": session_id}}
        assistant_id = await ensure_assistant()
        if assistant_id:
            payload["assistant_id"] = assistant_id
        return await _request("POST", _PATHS["thread_message"], json=payload) is not None
    except Exception as exc:  # noqa: BLE001
        print(f"[backboard] record_thread_message failed ({type(exc).__name__}): {exc}")
        return False


def reset_cache() -> None:
    """Test hook — drop the cached assistant id."""
    global _assistant_id_cache
    _assistant_id_cache = None
