"""Visibility-only cross-agent suspicious relationship detection."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import networkx as nx


READ_TOOL_MARKERS = (
    "read", "search", "lookup", "find", "query", "select", "fetch", "get",
)
EXTERNAL_WRITE_TOOL_MARKERS = (
    "http_post", "post", "external_write", "export", "email_send", "send_email",
    "upload", "publish", "webhook",
)
SENSITIVE_INDICATORS = (
    "customer", "email", "phone", "address", "ssn", "social security", "credit card",
    "account", "credential", "secret", "token", "api key", "password", "private",
    "confidential", "pii", "personal data",
)


def _timestamp(record: dict) -> datetime | None:
    value = record.get("timestamp")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalized_tool(record: dict) -> str:
    return str(record.get("tool_name") or "").strip().lower().replace("-", "_")


def _is_sensitive_read(record: dict) -> bool:
    tool = _normalized_tool(record)
    return any(marker in tool for marker in READ_TOOL_MARKERS)


def _is_external_write(record: dict) -> bool:
    tool = _normalized_tool(record)
    return any(marker in tool for marker in EXTERNAL_WRITE_TOOL_MARKERS)


def _sensitive_matches(source: dict, target: dict) -> list[str]:
    fields = ("tool_input_tokenized", "tokens_used", "suspicious_text", "counterfactual")
    text = " ".join(
        str(record.get(field) or "")
        for record in (source, target)
        for field in fields
    ).lower()
    return [indicator for indicator in SENSITIVE_INDICATORS if indicator in text]


def _score_pair(
    source: dict,
    target: dict,
    elapsed_seconds: float,
    window_seconds: float,
) -> tuple[float, list[str]]:
    timing_score = 30.0 * max(0.0, 1.0 - elapsed_seconds / window_seconds)
    indicators = _sensitive_matches(source, target)
    sensitive_score = min(25.0, len(indicators) * 5.0)
    score = min(100.0, timing_score + 25.0 + sensitive_score + 20.0)
    reason = [
        f"sensitive read followed by external write in {elapsed_seconds / 60:.1f} minutes",
        "same session",
    ]
    if indicators:
        reason.append("sensitive indicators: " + ", ".join(indicators[:5]))
    reason.append(f"external write tool: {target.get('tool_name', 'unknown')}")
    return round(score, 1), reason


def detect_conspiracies(
    records: list[dict],
    window_minutes: int = 15,
) -> list[dict]:
    """Detect cross-agent read-to-external-write relationships in audit rows."""
    safe_window = max(1, int(window_minutes))
    window_seconds = float(safe_window * 60)
    graph = nx.DiGraph()
    sessions: dict[str, list[tuple[datetime, dict[str, Any]]]] = {}

    for record in records:
        agent_id = record.get("agent_id")
        session_id = record.get("session_id")
        timestamp = _timestamp(record)
        if not agent_id or not session_id or timestamp is None:
            continue
        graph.add_node(str(agent_id))
        sessions.setdefault(str(session_id), []).append((timestamp, record))

    results = []
    for session_id, events in sessions.items():
        events.sort(key=lambda item: item[0])
        for source_index, (source_time, source) in enumerate(events):
            if not _is_sensitive_read(source):
                continue
            for target_time, target in events[source_index + 1:]:
                elapsed = (target_time - source_time).total_seconds()
                if elapsed > window_seconds:
                    break
                if source.get("agent_id") == target.get("agent_id") or not _is_external_write(target):
                    continue
                score, reasons = _score_pair(source, target, elapsed, window_seconds)
                graph.add_edge(
                    str(source["agent_id"]), str(target["agent_id"]),
                    session_id=session_id, conspiracy_score=score,
                )
                results.append({
                    "session_id": session_id,
                    "source_agent": source["agent_id"],
                    "target_agent": target["agent_id"],
                    "source_record_id": source.get("id"),
                    "target_record_id": target.get("id"),
                    "conspiracy_score": score,
                    "reason": "; ".join(reasons),
                })

    return sorted(results, key=lambda item: item["conspiracy_score"], reverse=True)
