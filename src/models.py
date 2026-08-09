from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid


class ToolCallRequest(BaseModel):
    """What the proxy receives when intercepting a tool call."""
    tool_name: str
    tool_input: dict
    session_id: str
    agent_id: str
    workspace_id: str
    trigger_source: str  # internal | external_dm | unknown
    trigger_user_id: Optional[str] = None
    message_context: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AnomalySignals(BaseModel):
    call_frequency: float = 0.0
    tool_distribution: float = 0.0
    data_volume: float = 0.0
    trigger_source: float = 0.0
    call_sequence: float = 0.0


class AnalysisResponse(BaseModel):
    """What the reasoning engine returns to the proxy."""
    risk_score: float
    decision: str  # allow | hold | block
    drift_score: float
    injection_score: float
    injection_detected: bool
    suspicious_text: Optional[str] = None
    anomaly_score: float
    anomaly_signals: AnomalySignals = Field(default_factory=AnomalySignals)
    threat_match: bool = False
    threat_pattern: Optional[str] = None
    counterfactual: Optional[str] = None
    tokens_used: list[str] = Field(default_factory=list)
    processing_time_ms: int = 0


class InterceptDecision(BaseModel):
    """Returned to the agent after interception."""
    decision: str       # allow | hold | block
    risk_score: float
    hold_id: Optional[str] = None   # set when decision=hold, for admin approve/deny
    counterfactual: Optional[str] = None
    message: str


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str
    agent_id: str
    workspace_id: str
    tool_name: str
    tool_input_tokenized: str
    trigger_source: str
    trigger_user_id: Optional[str] = None
    drift_score: Optional[float] = None
    injection_score: Optional[float] = None
    injection_detected: bool = False
    suspicious_text: Optional[str] = None
    anomaly_score: Optional[float] = None
    anomaly_signals: Optional[dict] = None
    threat_match: bool = False
    threat_pattern: Optional[str] = None
    final_risk_score: float
    decision: str
    counterfactual: Optional[str] = None
    tokens_used: list[str] = Field(default_factory=list)
    processing_time_ms: int = 0
    admin_action: Optional[str] = None
    admin_user_id: Optional[str] = None
    admin_action_timestamp: Optional[datetime] = None
