"""
Offline tests for the hold registry (no network, no API keys).

The registry is the rendezvous behind a HOLD: /intercept parks on wait(), the
dashboard releases it with resolve(), and an unanswered hold times out to a
fail-closed default.
"""
import asyncio

import pytest

from src.dashboard.holds import HoldRegistry


async def test_wait_returns_approved_when_resolved():
    reg = HoldRegistry()
    reg.register("h1")

    async def approve_soon():
        await asyncio.sleep(0.01)
        assert reg.resolve("h1", "approved") is True

    task = asyncio.create_task(approve_soon())
    result = await reg.wait("h1", timeout=2.0)
    await task
    assert result == "approved"
    assert reg.active() == []          # cleaned up after resolution


async def test_wait_returns_denied_when_denied():
    reg = HoldRegistry()
    reg.register("h2")
    asyncio.get_running_loop().call_later(0.01, lambda: reg.resolve("h2", "denied"))
    assert await reg.wait("h2", timeout=2.0) == "denied"


async def test_wait_times_out_to_fail_closed():
    reg = HoldRegistry()
    reg.register("h3")
    # No resolution -> timeout, which the caller (/intercept) maps to block.
    assert await reg.wait("h3", timeout=0.02) == "timeout"
    assert reg.active() == []


async def test_resolve_unknown_hold_is_false():
    reg = HoldRegistry()
    assert reg.resolve("nope", "approved") is False


async def test_active_lists_only_parked_holds():
    reg = HoldRegistry()
    reg.register("a")
    reg.register("b")
    assert set(reg.active()) == {"a", "b"}
    reg.resolve("a", "approved")
    # 'a' is set (resolved) and no longer counts as actively parked.
    assert reg.active() == ["b"]
