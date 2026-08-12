"""
Offline tests for the /intercept endpoint (no network, no API keys).

Covers the three decision paths and proves two safety properties:
  * a Supabase outage on the audit write must NOT change a clean ALLOW into an
    error (audit is best-effort, not the gate);
  * a HOLD parks until the dashboard resolves it, mapping approve->allow and
    timeout->block (fail closed).
"""
import asyncio

import pytest

from src.models import AnalysisResponse, ToolCallRequest
from src.pipeline import app as appmod


def _analysis(decision: str, risk: float) -> AnalysisResponse:
    return AnalysisResponse(
        risk_score=risk, decision=decision, drift_score=risk,
        injection_score=0.0, injection_detected=False, anomaly_score=0.0,
        counterfactual=("would exfiltrate" if decision != "allow" else None),
    )


def _fake_analyze(decision: str, risk: float):
    async def _inner(_request):
        return _analysis(decision, risk)
    return _inner


def _request(tool="database_read") -> ToolCallRequest:
    return ToolCallRequest(
        tool_name=tool, tool_input={"x": 1}, session_id="s1", agent_id="a1",
        workspace_id="w1", trigger_source="internal", message_context="do a thing",
    )


async def test_allow_survives_audit_outage(monkeypatch):
    monkeypatch.setattr(appmod, "analyze", _fake_analyze("allow", 5.0))

    def _boom(*_a, **_k):
        raise RuntimeError("supabase down")

    monkeypatch.setattr(appmod, "write_audit_record", _boom)   # audit fails hard...
    decision = await appmod.intercept_endpoint(_request())     # ...ALLOW still returned
    assert decision.decision == "allow"
    assert decision.hold_id is None


async def test_block_is_returned_with_counterfactual(monkeypatch):
    monkeypatch.setattr(appmod, "analyze", _fake_analyze("block", 95.0))
    monkeypatch.setattr(appmod, "write_audit_record", lambda *a, **k: None)
    decision = await appmod.intercept_endpoint(_request("http_post"))
    assert decision.decision == "block"
    assert decision.counterfactual == "would exfiltrate"


async def test_hold_parks_then_approve_maps_to_allow(monkeypatch):
    monkeypatch.setattr(appmod, "analyze", _fake_analyze("hold", 55.0))
    monkeypatch.setattr(appmod, "write_audit_record", lambda *a, **k: None)
    monkeypatch.setattr(appmod, "update_admin_action", lambda *a, **k: None)
    monkeypatch.setattr(appmod.uuid, "uuid4", lambda: "fixed-hold-id")

    async def approve_when_parked():
        for _ in range(200):
            if "fixed-hold-id" in appmod.holds.active():
                break
            await asyncio.sleep(0.005)
        appmod.holds.resolve("fixed-hold-id", "approved")

    task = asyncio.create_task(approve_when_parked())
    decision = await appmod.intercept_endpoint(_request())
    await task
    assert decision.decision == "allow"
    assert decision.hold_id == "fixed-hold-id"


async def test_hold_times_out_to_block(monkeypatch):
    monkeypatch.setattr(appmod, "analyze", _fake_analyze("hold", 55.0))
    monkeypatch.setattr(appmod, "write_audit_record", lambda *a, **k: None)
    monkeypatch.setattr(appmod, "update_admin_action", lambda *a, **k: None)
    monkeypatch.setattr(appmod, "DASH_HOLD_TIMEOUT", 0.02)   # no one answers
    decision = await appmod.intercept_endpoint(_request())
    assert decision.decision == "block"
