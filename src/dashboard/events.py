"""
Decision feed — an in-process ring buffer the dashboard polls.

Every /intercept decision (and every hold resolution) is published here AFTER
the decision is made, so the feed never sits on the scoring path. The browser
polls GET /events?since=<seq> for records newer than the last it saw. Being
in-process, the live feed needs no database — it works even when Supabase is
paused; only the historical audit view depends on the DB.

Eviction is handled by monotonic ``seq`` (independent of buffer position): a
client whose ``since`` predates the oldest buffered record simply receives the
whole current buffer (every record's seq exceeds an old since), never nothing.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any


class DecisionFeed:
    def __init__(self, maxlen: int = 200) -> None:
        self._buf: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = threading.Lock()

    def publish(self, record: dict) -> dict:
        """Stamp a record with the next seq + a timestamp and append it."""
        with self._lock:
            self._seq += 1
            stamped = {**record, "seq": self._seq, "ts": record.get("ts") or time.time()}
            self._buf.append(stamped)
            return stamped

    def since(self, seq: int) -> list[dict]:
        """Records newer than ``seq`` (all of them if seq predates the buffer)."""
        with self._lock:
            return [r for r in self._buf if r["seq"] > seq]

    def all(self) -> list[dict]:
        with self._lock:
            return list(self._buf)

    def latest_seq(self) -> int:
        with self._lock:
            return self._seq


# Process-wide singleton shared by /intercept and the dashboard routes.
feed = DecisionFeed()


def build_record(request: Any, analysis: Any, *, hold_id: str | None = None,
                 event: str = "decision", final_decision: str | None = None) -> dict:
    """
    Shape one feed record from a ToolCallRequest + AnalysisResponse.

    provenance is derived structurally (not parsed from counterfactual prose):
    an injection hit names its suspicious text; a non-allow with no injection is
    attributed to intent drift; an allow is "consistent with intent".
    tainted reflects the proxy having ingested external/tool content before this
    call (trigger_source ages to external_dm once the taint buffer is non-empty).
    anomaly_active is False until the anomaly detector is wired into scoring.
    """
    decision = final_decision or analysis.decision
    tainted = request.trigger_source == "external_dm"

    if analysis.injection_detected and analysis.suspicious_text:
        provenance = f"injected text: {analysis.suspicious_text[:120]}"
    elif decision != "allow":
        provenance = "intent drift from the original request"
    else:
        provenance = "consistent with intent"

    return {
        "event": event,                       # "decision" | "resolved"
        "hold_id": hold_id,
        "agent": request.agent_id,
        "tool": request.tool_name,
        "decision": decision,
        "risk_score": round(analysis.risk_score, 1),
        "injection_score": round(analysis.injection_score, 1),
        "drift_score": round(analysis.drift_score, 1),
        "anomaly_score": round(analysis.anomaly_score, 1),
        "anomaly_active": False,              # detector not wired into scoring yet
        "tainted": tainted,
        "counterfactual": analysis.counterfactual,
        "provenance": provenance,
        "latency_ms": analysis.processing_time_ms,
    }
