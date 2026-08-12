"""
Hold registry — the wait/resolve rendezvous behind a HOLD decision.

When /intercept scores a call in the hold band it must PARK: keep the HTTP
response open (the proxy is waiting on it, the agent's tool call is suspended)
until a human clicks approve/deny in the dashboard, or a timeout expires. The
registry is the synchronization point. It lives in the SAME process as both the
/intercept endpoint and the approve/deny routes, so resolving a hold is just
``event.set()`` on an in-memory ``asyncio.Event`` — no polling, no broker.

Fail-closed by construction: an unresolved hold that times out returns
``"timeout"``, which /intercept maps to BLOCK. A human who never answers is
treated as "no", never as tacit yes.
"""
from __future__ import annotations

import asyncio
from typing import Literal

Resolution = Literal["approved", "denied", "timeout"]


class HoldRegistry:
    def __init__(self) -> None:
        self._events: dict[str, asyncio.Event] = {}
        self._resolutions: dict[str, str] = {}

    def register(self, hold_id: str) -> asyncio.Event:
        """Create (or return) the Event a waiter blocks on for this hold."""
        event = self._events.get(hold_id)
        if event is None:
            event = asyncio.Event()
            self._events[hold_id] = event
        return event

    async def wait(self, hold_id: str, timeout: float) -> Resolution:
        """
        Block until the hold is resolved or ``timeout`` seconds pass. Timeout ->
        "timeout" (caller blocks). Always cleans up its own registry entries.
        """
        event = self.register(hold_id)
        try:
            await asyncio.wait_for(event.wait(), timeout)
        except asyncio.TimeoutError:
            return "timeout"
        finally:
            self._events.pop(hold_id, None)
        resolution = self._resolutions.pop(hold_id, None)
        # A set Event always has a resolution; default to denied (fail-closed).
        return resolution if resolution in ("approved", "denied") else "denied"

    def resolve(self, hold_id: str, action: str) -> bool:
        """
        Release a parked waiter with approved/denied. Returns False if no waiter
        is registered (already resolved, timed out, or never held).
        """
        event = self._events.get(hold_id)
        if event is None:
            return False
        self._resolutions[hold_id] = "approved" if action == "approved" else "denied"
        event.set()
        return True

    def active(self) -> list[str]:
        """Hold ids currently parked and awaiting a human decision."""
        return [hid for hid, ev in self._events.items() if not ev.is_set()]


# Process-wide singleton shared by /intercept and the approve/deny routes.
holds = HoldRegistry()
