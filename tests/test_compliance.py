"""Tests for secret-safe compliance export construction."""
from datetime import datetime, timezone

from src.visibility.compliance import build_compliance_export


def test_build_compliance_export_calculates_summary_and_projects_fields():
    records = [
        {
            "timestamp": "2026-07-12T10:00:00Z",
            "agent_id": "agent-a",
            "session_id": "session-1",
            "tool_name": "db_read",
            "decision": "allow",
            "final_risk_score": 20,
            "processing_time_ms": 50,
            "drift_score": 10,
            "injection_score": 0,
            "anomaly_score": 5,
            "threat_match": False,
            "counterfactual": None,
            "admin_action": None,
            "tool_input_tokenized": "SECRET-MUST-NOT-EXPORT",
            "api_key": "also-secret",
        },
        {
            "timestamp": "2026-07-12T11:00:00Z",
            "agent_id": "agent-b",
            "session_id": "session-1",
            "tool_name": "http_post",
            "decision": "block",
            "final_risk_score": 80,
            "processing_time_ms": 150,
            "drift_score": 50,
            "injection_score": 90,
            "anomaly_score": 70,
            "threat_match": True,
            "counterfactual": "Data transfer prevented.",
            "admin_action": "denied",
        },
    ]
    since = datetime(2026, 7, 12, tzinfo=timezone.utc)
    until = datetime(2026, 7, 13, tzinfo=timezone.utc)

    export = build_compliance_export(records, since, until)

    assert export["summary"] == {
        "total_calls": 2,
        "allow_count": 1,
        "hold_count": 0,
        "block_count": 1,
        "average_risk_score": 50.0,
        "average_processing_time_ms": 100.0,
    }
    assert export["time_range"]["until_exclusive"] is True
    assert export["controls"]["audit_logging"] is True
    assert "SOC 2 CC6" in export["compliance_mapping"]
    assert "tool_input_tokenized" not in export["incidents"][0]
    assert "api_key" not in export["incidents"][0]
    assert export["incidents"][1]["admin_action"] == "denied"
