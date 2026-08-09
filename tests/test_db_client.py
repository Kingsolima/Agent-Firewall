"""Supabase query construction tests for the audit-log helper."""
from datetime import datetime, timezone
from types import SimpleNamespace

import src.db.client as db_client


class FakeQuery:
    def __init__(self):
        self.calls = []

    def _record(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        return self

    def select(self, *args, **kwargs):
        return self._record("select", *args, **kwargs)

    def order(self, *args, **kwargs):
        return self._record("order", *args, **kwargs)

    def limit(self, *args, **kwargs):
        return self._record("limit", *args, **kwargs)

    def offset(self, *args, **kwargs):
        return self._record("offset", *args, **kwargs)

    def eq(self, *args, **kwargs):
        return self._record("eq", *args, **kwargs)

    def gt(self, *args, **kwargs):
        return self._record("gt", *args, **kwargs)

    def gte(self, *args, **kwargs):
        return self._record("gte", *args, **kwargs)

    def lt(self, *args, **kwargs):
        return self._record("lt", *args, **kwargs)

    def range(self, *args, **kwargs):
        return self._record("range", *args, **kwargs)

    def execute(self):
        return SimpleNamespace(data=[{"id": "one"}])


class FakeClient:
    def __init__(self, query):
        self.query = query

    def table(self, name):
        assert name == "audit_log"
        return self.query


def test_get_audit_records_applies_filters_and_bounds(monkeypatch):
    query = FakeQuery()
    monkeypatch.setattr(db_client, "get_client", lambda: FakeClient(query))
    since = datetime(2026, 7, 1, tzinfo=timezone.utc)

    result = db_client.get_audit_records(
        decision="block",
        agent_id="support-agent",
        score_above=70,
        since=since,
        limit=500,
        offset=-5,
    )

    assert result == [{"id": "one"}]
    assert ("limit", (50,), {}) in query.calls
    assert ("offset", (0,), {}) in query.calls
    assert ("eq", ("decision", "block"), {}) in query.calls
    assert ("eq", ("agent_id", "support-agent"), {}) in query.calls
    assert ("gt", ("final_risk_score", 70.0), {}) in query.calls
    assert ("gte", ("timestamp", since.isoformat()), {}) in query.calls


def test_recent_conspiracy_records_use_bounded_time_query(monkeypatch):
    query = FakeQuery()
    monkeypatch.setattr(db_client, "get_client", lambda: FakeClient(query))

    result = db_client.get_recent_audit_records_for_conspiracy(minutes=60)

    assert result == [{"id": "one"}]
    assert any(call[0] == "gte" and call[1][0] == "timestamp" for call in query.calls)
    assert ("order", ("timestamp",), {"desc": True}) in query.calls
    assert ("limit", (500,), {}) in query.calls


def test_export_query_uses_safe_fields_and_half_open_range(monkeypatch):
    query = FakeQuery()
    monkeypatch.setattr(db_client, "get_client", lambda: FakeClient(query))
    since = datetime(2026, 7, 6, tzinfo=timezone.utc)
    until = datetime(2026, 7, 13, tzinfo=timezone.utc)

    result = db_client.get_audit_records_for_export(since, until)

    assert result == [{"id": "one"}]
    select_call = next(call for call in query.calls if call[0] == "select")
    selected = select_call[1][0]
    assert "tool_input_tokenized" not in selected
    assert "tokens_used" not in selected
    assert ("gte", ("timestamp", since.isoformat()), {}) in query.calls
    assert ("lt", ("timestamp", until.isoformat()), {}) in query.calls
    assert ("range", (0, 499), {}) in query.calls


def test_weekly_report_query_uses_bounded_interval(monkeypatch):
    query = FakeQuery()
    monkeypatch.setattr(db_client, "get_client", lambda: FakeClient(query))
    start = datetime(2026, 7, 6, tzinfo=timezone.utc)
    end = datetime(2026, 7, 13, tzinfo=timezone.utc)

    result = db_client.get_audit_records_between(start, end, limit=9000)

    assert result == [{"id": "one"}]
    assert ("gte", ("timestamp", start.isoformat()), {}) in query.calls
    assert ("lt", ("timestamp", end.isoformat()), {}) in query.calls
    assert ("limit", (5000,), {}) in query.calls


def test_get_audit_summary_calculates_recent_metrics(monkeypatch):
    records = [
        {
            "id": "new",
            "timestamp": "2026-07-12T15:00:00+00:00",
            "agent_id": "agent-1",
            "tool_name": "fast_tool",
            "final_risk_score": 20,
            "processing_time_ms": 40,
        },
        {
            "id": "slow",
            "timestamp": "2026-07-12T14:00:00+00:00",
            "agent_id": "agent-2",
            "tool_name": "slow_tool",
            "final_risk_score": 80,
            "processing_time_ms": 160,
        },
    ]
    query = FakeQuery()
    query.execute = lambda: SimpleNamespace(data=records)
    monkeypatch.setattr(db_client, "get_client", lambda: FakeClient(query))

    counts = iter([7, 2, 1, 4, 9, 20])
    monkeypatch.setattr(db_client, "_get_audit_count", lambda **_filters: next(counts))
    monkeypatch.setattr(db_client, "_get_pending_hold_count", lambda: 3)
    summary = db_client.get_audit_summary(
        now=datetime(2026, 7, 12, 16, 0, tzinfo=timezone.utc)
    )

    assert summary["by_decision"] == {"allow": 7, "hold": 2, "block": 1}
    assert summary["total_today"] == 4
    assert summary["total_week"] == 9
    assert summary["total_all_time"] == 20
    assert summary["active_holds"] == 3
    assert summary["average_final_risk_score"] == 50
    assert summary["average_processing_time_ms"] == 100
    assert summary["slowest_recent"]["id"] == "slow"
    assert summary["most_recent_timestamp"] == records[0]["timestamp"]


def test_agent_baseline_summary_degrades_gracefully(monkeypatch):
    class BrokenClient:
        def table(self, _name):
            raise RuntimeError("table unavailable")

    monkeypatch.setattr(db_client, "get_client", lambda: BrokenClient())
    assert db_client.get_agent_baseline_summary() == {
        "available": False,
        "agents": [],
    }


def test_calculate_agent_health_metrics():
    now = datetime(2026, 7, 12, 16, 0, tzinfo=timezone.utc)
    records = [
        {"agent_id": "agent-1", "timestamp": "2026-07-12T12:00:00+00:00", "tool_name": "http", "trigger_source": "external", "decision": "hold", "final_risk_score": 80, "anomaly_score": 60},
        {"agent_id": "agent-1", "timestamp": "2026-07-11T12:00:00+00:00", "tool_name": "http", "trigger_source": "external", "decision": "block", "final_risk_score": 40, "anomaly_score": 20},
        {"agent_id": "agent-1", "timestamp": "2026-06-01T12:00:00+00:00", "tool_name": "email", "trigger_source": "internal", "decision": "allow", "final_risk_score": 10, "anomaly_score": 5},
        {"agent_id": "other", "timestamp": "2026-07-12T12:00:00+00:00", "tool_name": "ignored", "decision": "block", "final_risk_score": 100},
    ]
    health = db_client.calculate_agent_health(
        records, "agent-1", now, baseline={"baseline_phase": "active"}
    )
    assert health["total_call_count"] == 3
    assert health["calls_last_7_days"] == 2
    assert health["average_risk_score_7_days"] == 60
    assert health["highest_risk_score_7_days"] == 80
    assert health["most_common_tools"] == [("http", 2)]
    assert health["most_common_trigger_sources"] == [("external", 2)]
    assert health["average_anomaly_score"] == 40
    assert health["hold_rate"] == 1 / 3
    assert health["block_rate"] == 1 / 3
    assert health["baseline_phase"] == "active"
