"""
Supabase client — audit logging and hold state management.
Uses service role key for full table access (never expose this client-side).
"""
import os
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional
from supabase import create_client, Client
from src.models import AuditRecord, AnalysisResponse, ToolCallRequest

_client: Optional[Client] = None


def get_client() -> Client:
    global _client
    if _client is None:
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
        _client = create_client(url, key)
    return _client


def write_audit_record(
    request: ToolCallRequest,
    analysis: AnalysisResponse,
    record_id: str,
) -> None:
    db = get_client()
    row = {
        "id": record_id,
        "timestamp": datetime.utcnow().isoformat(),
        "session_id": request.session_id,
        "agent_id": request.agent_id,
        "workspace_id": request.workspace_id,
        "tool_name": request.tool_name,
        "tool_input_tokenized": json.dumps(request.tool_input),
        "trigger_source": request.trigger_source,
        "trigger_user_id": request.trigger_user_id,
        "drift_score": analysis.drift_score,
        "injection_score": analysis.injection_score,
        "injection_detected": analysis.injection_detected,
        "suspicious_text": analysis.suspicious_text,
        "anomaly_score": analysis.anomaly_score,
        "anomaly_signals": analysis.anomaly_signals.model_dump(),
        "threat_match": analysis.threat_match,
        "threat_pattern": analysis.threat_pattern,
        "final_risk_score": analysis.risk_score,
        "decision": analysis.decision,
        "counterfactual": analysis.counterfactual,
        "tokens_used": analysis.tokens_used,
        "processing_time_ms": analysis.processing_time_ms,
    }
    db.table("audit_log").insert(row).execute()


def update_admin_action(
    record_id: str,
    action: str,  # approved | denied
    admin_user_id: str,
) -> None:
    db = get_client()
    db.table("audit_log").update({
        "admin_action": action,
        "admin_user_id": admin_user_id,
        "admin_action_timestamp": datetime.utcnow().isoformat(),
    }).eq("id", record_id).execute()


def get_audit_records(
    decision: Optional[str] = None,
    agent_id: Optional[str] = None,
    score_above: Optional[float] = None,
    since: Optional[datetime | str] = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Return audit records using server-side Supabase filters.

    ``since`` may be an ISO-8601 string or a datetime. Limits are deliberately
    bounded here as well as in the Slack command so every caller respects the
    audit-log read cap.
    """
    db = get_client()
    safe_limit = max(1, min(int(limit), 50))
    safe_offset = max(0, int(offset))
    query = (
        db.table("audit_log")
        .select("*")
        .order("timestamp", desc=True)
        .limit(safe_limit)
        .offset(safe_offset)
    )
    if decision:
        query = query.eq("decision", decision)
    if agent_id:
        query = query.eq("agent_id", agent_id)
    if score_above is not None:
        query = query.gt("final_risk_score", float(score_above))
    if since is not None:
        since_value = since.isoformat() if isinstance(since, datetime) else since
        query = query.gte("timestamp", since_value)
    result = query.execute()
    return result.data or []


def get_audit_record_by_id(record_id: str) -> Optional[dict]:
    db = get_client()
    result = db.table("audit_log").select("*").eq("id", record_id).single().execute()
    return result.data


def get_recent_audit_records_for_conspiracy(minutes: int = 60) -> list[dict]:
    """Return a bounded recent audit window for visibility-only correlation."""
    safe_minutes = max(1, min(int(minutes), 24 * 60))
    since = datetime.now(timezone.utc) - timedelta(minutes=safe_minutes)
    result = (
        get_client().table("audit_log")
        .select(
            "id,timestamp,session_id,agent_id,tool_name,tool_input_tokenized,"
            "tokens_used,suspicious_text,counterfactual"
        )
        .gte("timestamp", since.isoformat())
        .order("timestamp", desc=True)
        .limit(500)
        .execute()
    )
    return result.data or []


def get_audit_records_for_export(
    since: datetime,
    until: datetime,
    max_records: int = 5000,
) -> list[dict]:
    """Return approved compliance fields within a UTC half-open time range."""
    safe_max = max(1, min(int(max_records), 5000))
    page_size = 500
    records: list[dict] = []
    selected_fields = (
        "timestamp,agent_id,session_id,tool_name,decision,final_risk_score,"
        "drift_score,injection_score,anomaly_score,threat_match,counterfactual,"
        "admin_action,processing_time_ms"
    )
    while len(records) < safe_max:
        end = min(len(records) + page_size, safe_max) - 1
        result = (
            get_client().table("audit_log")
            .select(selected_fields)
            .gte("timestamp", since.isoformat())
            .lt("timestamp", until.isoformat())
            .order("timestamp")
            .range(len(records), end)
            .execute()
        )
        page = result.data or []
        records.extend(page)
        if len(page) < page_size:
            break
    return records


def get_audit_records_between(
    start_datetime: datetime,
    end_datetime: datetime,
    limit: int = 1000,
) -> list[dict]:
    """Return a bounded audit interval for scheduled visibility reports."""
    safe_limit = max(1, min(int(limit), 5000))
    result = (
        get_client().table("audit_log")
        .select(
            "id,timestamp,agent_id,session_id,tool_name,decision,final_risk_score,"
            "anomaly_score,suspicious_text,threat_pattern,counterfactual"
        )
        .gte("timestamp", start_datetime.isoformat())
        .lt("timestamp", end_datetime.isoformat())
        .order("timestamp", desc=True)
        .limit(safe_limit)
        .execute()
    )
    return result.data or []


def _get_audit_count(**filters) -> int:
    """Return an exact audit-log count without transferring matching rows."""
    query = get_client().table("audit_log").select("id", count="exact").limit(1)
    for column, value in filters.items():
        query = query.gte(column, value) if column == "timestamp" else query.eq(column, value)
    result = query.execute()
    return int(result.count or 0)


def _get_pending_hold_count() -> int:
    """Return the exact number of unresolved HOLD records."""
    result = (
        get_client().table("audit_log")
        .select("id", count="exact")
        .eq("decision", "hold")
        .is_("admin_action", "null")
        .limit(1)
        .execute()
    )
    return int(result.count or 0)


def get_audit_summary(now: Optional[datetime] = None, recent_limit: int = 200) -> dict:
    """Return exact audit counts plus metrics from a bounded recent window."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    today_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = current - timedelta(days=7)

    by_decision = {
        decision: _get_audit_count(decision=decision)
        for decision in ("allow", "hold", "block")
    }
    safe_limit = max(1, min(int(recent_limit), 500))
    result = (
        get_client().table("audit_log")
        .select("id,timestamp,agent_id,tool_name,decision,final_risk_score,processing_time_ms")
        .order("timestamp", desc=True)
        .limit(safe_limit)
        .execute()
    )
    records = result.data or []
    risks = [float(row["final_risk_score"]) for row in records if row.get("final_risk_score") is not None]
    latencies = [float(row["processing_time_ms"]) for row in records if row.get("processing_time_ms") is not None]
    timed = [row for row in records if row.get("processing_time_ms") is not None]

    return {
        "total_today": _get_audit_count(timestamp=today_start.isoformat()),
        "total_week": _get_audit_count(timestamp=week_start.isoformat()),
        "total_all_time": _get_audit_count(),
        "active_holds": _get_pending_hold_count(),
        "by_decision": by_decision,
        "average_final_risk_score": sum(risks) / len(risks) if risks else None,
        "average_processing_time_ms": sum(latencies) / len(latencies) if latencies else None,
        "slowest_recent": max(timed, key=lambda row: float(row["processing_time_ms"]), default=None),
        "most_recent_timestamp": records[0].get("timestamp") if records else None,
        "metrics_sample_size": len(records),
    }


def get_pending_holds(limit: int = 10) -> list[dict]:
    """Return unresolved HOLD records awaiting an administrator decision."""
    safe_limit = max(1, min(int(limit), 50))
    result = (
        get_client().table("audit_log")
        .select("id,timestamp,agent_id,tool_name,final_risk_score")
        .eq("decision", "hold")
        .is_("admin_action", "null")
        .order("timestamp", desc=True)
        .limit(safe_limit)
        .execute()
    )
    return result.data or []


def get_agent_baseline_summary(limit: int = 50) -> dict:
    """Return bounded baseline status, or an unavailable state on query errors."""
    try:
        safe_limit = max(1, min(int(limit), 100))
        result = (
            get_client().table("agent_baselines")
            .select("agent_id,call_count,baseline_phase,last_updated")
            .order("agent_id")
            .limit(safe_limit)
            .execute()
        )
        return {"available": True, "agents": result.data or []}
    except Exception:
        return {"available": False, "agents": []}


def get_agent_baseline(agent_id: str) -> dict:
    """Return one agent baseline, degrading gracefully when unavailable."""
    try:
        result = (
            get_client().table("agent_baselines")
            .select("agent_id,call_count,baseline_phase,last_updated")
            .eq("agent_id", agent_id)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return {"available": True, "baseline": rows[0] if rows else None}
    except Exception:
        return {"available": False, "baseline": None}


def calculate_agent_health(
    records: list[dict],
    agent_id: str,
    now: Optional[datetime] = None,
    *,
    total_call_count: Optional[int] = None,
    calls_last_7_days: Optional[int] = None,
    decision_counts: Optional[dict] = None,
    baseline: Optional[dict] = None,
) -> dict:
    """Calculate per-agent health metrics without performing database I/O."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    week_start = current - timedelta(days=7)
    agent_records = [row for row in records if row.get("agent_id") == agent_id]

    def is_recent(row: dict) -> bool:
        value = row.get("timestamp")
        if not value:
            return False
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc) >= week_start

    recent = [row for row in agent_records if is_recent(row)]
    risks = [float(row["final_risk_score"]) for row in recent if row.get("final_risk_score") is not None]
    anomalies = [float(row["anomaly_score"]) for row in recent if row.get("anomaly_score") is not None]
    tools = Counter(str(row["tool_name"]) for row in recent if row.get("tool_name"))
    sources = Counter(str(row["trigger_source"]) for row in recent if row.get("trigger_source"))
    total = len(agent_records) if total_call_count is None else int(total_call_count)
    decisions = decision_counts or Counter(
        str(row.get("decision", "")).lower() for row in agent_records
    )

    return {
        "agent_id": agent_id,
        "has_records": total > 0,
        "baseline_available": baseline is not None,
        "baseline_phase": baseline.get("baseline_phase") if baseline else None,
        "total_call_count": total,
        "calls_last_7_days": len(recent) if calls_last_7_days is None else int(calls_last_7_days),
        "average_risk_score_7_days": sum(risks) / len(risks) if risks else None,
        "highest_risk_score_7_days": max(risks, default=None),
        "most_common_tools": tools.most_common(5),
        "most_common_trigger_sources": sources.most_common(5),
        "average_anomaly_score": sum(anomalies) / len(anomalies) if anomalies else None,
        "hold_rate": int(decisions.get("hold", 0)) / total if total else 0.0,
        "block_rate": int(decisions.get("block", 0)) / total if total else 0.0,
    }


def get_agent_health(
    agent_id: str,
    now: Optional[datetime] = None,
    recent_limit: int = 500,
) -> dict:
    """Return a bounded, audit-log-backed health summary for one agent."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    since = current - timedelta(days=7)
    safe_limit = max(1, min(int(recent_limit), 500))
    result = (
        get_client().table("audit_log")
        .select("timestamp,agent_id,tool_name,trigger_source,decision,final_risk_score,anomaly_score")
        .eq("agent_id", agent_id)
        .gte("timestamp", since.isoformat())
        .order("timestamp", desc=True)
        .limit(safe_limit)
        .execute()
    )
    records = result.data or []
    total = _get_audit_count(agent_id=agent_id)
    recent_count = _get_audit_count(agent_id=agent_id, timestamp=since.isoformat())
    decisions = {
        decision: _get_audit_count(agent_id=agent_id, decision=decision)
        for decision in ("hold", "block")
    }

    baseline_result = get_agent_baseline(agent_id)
    baseline = baseline_result.get("baseline") if baseline_result.get("available") else None
    return calculate_agent_health(
        records,
        agent_id,
        current,
        total_call_count=total,
        calls_last_7_days=recent_count,
        decision_counts=decisions,
        baseline=baseline,
    )
