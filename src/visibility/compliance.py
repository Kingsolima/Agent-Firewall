"""Pure JSON construction for compliance-oriented audit exports."""
from __future__ import annotations

from datetime import datetime, timezone


INCIDENT_FIELDS = (
    "timestamp",
    "agent_id",
    "session_id",
    "tool_name",
    "decision",
    "final_risk_score",
    "drift_score",
    "injection_score",
    "anomaly_score",
    "threat_match",
    "counterfactual",
    "admin_action",
)


def _iso(value: datetime | str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def build_compliance_export(
    records: list[dict],
    since: datetime | str,
    until: datetime | str,
) -> dict:
    """Build a secret-safe, JSON-serializable compliance export."""
    decisions = {"allow": 0, "hold": 0, "block": 0}
    risks = []
    processing_times = []
    incidents = []
    for row in records:
        decision = str(row.get("decision") or "").lower()
        if decision in decisions:
            decisions[decision] += 1
        if row.get("final_risk_score") is not None:
            risks.append(float(row["final_risk_score"]))
        if row.get("processing_time_ms") is not None:
            processing_times.append(float(row["processing_time_ms"]))
        incidents.append({field: row.get(field) for field in INCIDENT_FIELDS})

    return {
        "export_generated_at": datetime.now(timezone.utc).isoformat(),
        "time_range": {
            "since": _iso(since),
            "until": _iso(until),
            "until_exclusive": True,
        },
        "summary": {
            "total_calls": len(records),
            "allow_count": decisions["allow"],
            "hold_count": decisions["hold"],
            "block_count": decisions["block"],
            "average_risk_score": round(sum(risks) / len(risks), 2) if risks else None,
            "average_processing_time_ms": (
                round(sum(processing_times) / len(processing_times), 2)
                if processing_times else None
            ),
        },
        "controls": {
            "intent_verification": True,
            "prompt_injection_detection": True,
            "audit_logging": True,
            "admin_review_for_holds": True,
        },
        "incidents": incidents,
        "compliance_mapping": {
            "SOC 2 CC6": "Access controls",
            "SOC 2 CC7": "System operations and monitoring",
            "ISO 27001": "Logging and monitoring",
        },
    }
