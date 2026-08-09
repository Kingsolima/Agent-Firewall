"""
Internal types for the reasoning engine.

These are distinct from the public contract in src/models.py (ToolCallRequest /
AnalysisResponse). The orchestrator assembles these component results into the
public AnalysisResponse the proxy consumes.
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class IntentObject(BaseModel):
    """What the user originally wanted — the reference point for drift scoring."""
    goal: str
    scope: str
    permitted_action_types: list[str] = Field(default_factory=list)
    prohibited_action_types: list[str] = Field(default_factory=list)
    expected_tool_types: list[str] = Field(default_factory=list)
    risk_tolerance: str = "low"  # low | medium | high
    session_id: str
    extracted_at: datetime = Field(default_factory=datetime.utcnow)


class InjectionResult(BaseModel):
    score: float = 0.0           # 0–100 after source-trust adjustment
    detected: bool = False
    suspicious_text: Optional[str] = None


class DriftResult(BaseModel):
    score: float                 # 0–100, higher = more inconsistent with intent
    reasoning: Optional[str] = None
