"""
Counterfactual explainer (docs.md §Counterfactual Explainer).

Translates the technical signals into a clear, specific, non-alarmist
explanation for a non-technical admin deciding in 30 seconds. Only generated for
hold/block decisions.
"""
import json

from src.models import ToolCallRequest
from src.pipeline.claude_client import complete_text
from src.pipeline.schemas import DriftResult, InjectionResult

_SYSTEM = (
    "You write a short admin alert explaining why an AI agent's action was held "
    "or blocked. Be specific and concrete (name what data/endpoint was involved "
    "and what would have happened), plain-English, and non-alarmist. 2-4 "
    "sentences. Cover: what the agent attempted, what would have happened if not "
    "stopped, and why it was flagged. No preamble, no markdown."
)


async def generate_counterfactual(
    request: ToolCallRequest,
    injection: InjectionResult,
    drift: DriftResult,
    decision: str,
    risk_score: float,
) -> str:
    user = (
        f"Decision: {decision.upper()} (risk {risk_score}/100)\n"
        f"Agent: {request.agent_id}\n"
        f"Tool: {request.tool_name}\n"
        f"Tool input: {json.dumps(request.tool_input)[:400]}\n"
        f"Trigger source: {request.trigger_source}\n"
        f"Triggering message: {request.message_context[:400]}\n"
        f"Injection detected: {injection.detected} "
        f"(score {injection.score}, suspicious text: {injection.suspicious_text!r})\n"
        f"Drift score: {drift.score}/100 ({drift.reasoning})"
    )
    return await complete_text(_SYSTEM, user, max_tokens=400)
