"""
Session registry — the arm-session mechanism.

The MCP channel carries tool calls, never the user's chat, so the firewall has
no way to know the user's intent from the wire. The proxy therefore announces
its session on startup (POST /session/register) and a human arms it with the
intent string (POST /session/arm) — "review PR #42, post the summary to #eng".
That armed intent is what every later tool call is scored against, and it's what
makes the dashboard's intent line real instead of a hardcoded placeholder.

In-process and unauthenticated — this is a local firewall console, not a
multi-tenant service.
"""
from __future__ import annotations

import threading
import time


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def register(self, session_id: str, agent: str, workspace: str) -> dict:
        """Record a session the proxy just opened (idempotent — keeps any intent)."""
        with self._lock:
            existing = self._sessions.get(session_id, {})
            self._sessions[session_id] = {
                "session_id": session_id,
                "agent": agent,
                "workspace": workspace,
                "intent": existing.get("intent"),
                "armed": existing.get("armed", False),
                "registered_at": existing.get("registered_at") or time.time(),
            }
            return self._sessions[session_id]

    def arm(self, session_id: str, intent: str, agent: str = "", workspace: str = "") -> dict:
        """Attach the user's intent to a session (auto-registers if unseen)."""
        with self._lock:
            entry = self._sessions.get(session_id) or {
                "session_id": session_id, "agent": agent, "workspace": workspace,
                "registered_at": time.time(),
            }
            entry["intent"] = intent
            entry["armed"] = True
            self._sessions[session_id] = entry
            return entry

    def list(self) -> list[dict]:
        with self._lock:
            return sorted(self._sessions.values(),
                          key=lambda s: s["registered_at"], reverse=True)


# Process-wide singleton shared by the dashboard routes and (indirectly) scoring.
sessions = SessionRegistry()
