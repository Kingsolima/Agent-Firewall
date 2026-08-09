"""Tests for visibility-only cross-agent conspiracy detection."""
from src.visibility.conspiracy import detect_conspiracies


def audit_row(record_id, timestamp, session, agent, tool, **extra):
    return {
        "id": record_id,
        "timestamp": timestamp,
        "session_id": session,
        "agent_id": agent,
        "tool_name": tool,
        **extra,
    }


def test_detects_sensitive_read_followed_by_external_write():
    records = [
        audit_row(
            "read-1", "2026-07-12T15:00:00Z", "session-1", "research-agent",
            "customer_lookup", tool_input_tokenized="customer email and account data",
        ),
        audit_row(
            "write-1", "2026-07-12T15:05:00Z", "session-1", "outreach-agent",
            "email_send", counterfactual="customer records would be sent externally",
        ),
    ]

    alerts = detect_conspiracies(records)

    assert len(alerts) == 1
    assert alerts[0]["session_id"] == "session-1"
    assert alerts[0]["source_agent"] == "research-agent"
    assert alerts[0]["target_agent"] == "outreach-agent"
    assert alerts[0]["source_record_id"] == "read-1"
    assert alerts[0]["target_record_id"] == "write-1"
    assert 0 <= alerts[0]["conspiracy_score"] <= 100
    assert alerts[0]["conspiracy_score"] >= 80
    assert "same session" in alerts[0]["reason"]
    assert "sensitive indicators" in alerts[0]["reason"]


def test_excludes_same_agent_other_session_and_out_of_window():
    source = audit_row(
        "read", "2026-07-12T15:00:00Z", "session-1", "agent-a", "db_read"
    )
    records = [
        source,
        audit_row("same", "2026-07-12T15:02:00Z", "session-1", "agent-a", "db_export"),
        audit_row("other", "2026-07-12T15:03:00Z", "session-2", "agent-b", "http_post"),
        audit_row("late", "2026-07-12T15:16:00Z", "session-1", "agent-b", "email_send"),
    ]

    assert detect_conspiracies(records) == []


def test_configurable_window_and_timing_affect_score():
    records = [
        audit_row("read", "2026-07-12T15:00:00Z", "s", "a", "search"),
        audit_row("write", "2026-07-12T15:20:00Z", "s", "b", "http_post"),
    ]
    assert detect_conspiracies(records) == []
    alerts = detect_conspiracies(records, window_minutes=30)
    assert len(alerts) == 1
    assert alerts[0]["conspiracy_score"] == 55.0
