"""
Thin async wrapper around the Anthropic SDK.

We use plain `messages.create` + strict-JSON prompting + Pydantic validation
(with one retry) rather than SDK-version-specific helpers, so the pipeline runs
on any reasonably recent `anthropic` release. docs.md §Intent Extraction
prescribes exactly this: validate with Pydantic, retry once on malformed JSON.
"""
import json
import re
from typing import Optional, Type, TypeVar

from anthropic import AsyncAnthropic
from pydantic import BaseModel, ValidationError

from src.pipeline.config import MODEL

T = TypeVar("T", bound=BaseModel)

_client: Optional[AsyncAnthropic] = None

# Matches a ```json ... ``` (or bare ```) fence so we can strip it if the model
# wraps its JSON despite being told not to.
_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def get_client() -> AsyncAnthropic:
    """Lazy singleton — importing this module never requires ANTHROPIC_API_KEY."""
    global _client
    if _client is None:
        _client = AsyncAnthropic()  # reads ANTHROPIC_API_KEY from env
    return _client


def _extract_text(message) -> str:
    return "".join(block.text for block in message.content if block.type == "text").strip()


def _strip_fence(text: str) -> str:
    return _FENCE_RE.sub("", text).strip()


async def complete_text(system: str, user: str, max_tokens: int = 512) -> str:
    """Free-form text completion (used for the counterfactual)."""
    message = await get_client().messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return _extract_text(message)


async def complete_json(
    system: str,
    user: str,
    schema: Type[T],
    max_tokens: int = 1024,
) -> T:
    """
    Ask Claude for a JSON object matching `schema`, validate it, and return the
    typed model. Retries once with a stricter instruction if the first response
    is malformed. Raises on the second failure — the caller decides the fallback.
    """
    instruction = (
        "Respond with ONLY a single JSON object and nothing else — "
        "no markdown, no code fences, no commentary."
    )
    last_error: Optional[Exception] = None

    for attempt in range(2):
        sys_prompt = system if attempt == 0 else f"{system}\n\n{instruction}"
        raw = await complete_text(sys_prompt, user, max_tokens=max_tokens)
        try:
            return schema.model_validate(json.loads(_strip_fence(raw)))
        except (json.JSONDecodeError, ValidationError) as e:
            last_error = e

    raise ValueError(f"Claude returned invalid JSON for {schema.__name__}: {last_error}")
