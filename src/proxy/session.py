"""
Per-session state carried across tool calls — the thing that makes multi-step
attacks visible.

The reference attack is two calls: read a poisoned file (turn 1), then send its
contents to an external channel (turn 2). The malicious *instruction* arrives in
a tool RESULT; the malicious *action* is a later call. A stateless scanner
looking only at the second call sees an innocent `slack_send` and nothing else.

SessionState keeps a small rolling buffer of recent tool-result text. When the
next tool call is scored, ``build_message_context`` folds that recent result
text in alongside the current arguments, so the poisoned content the agent just
ingested is on the table when the engine judges the action it triggered.

This is the proxy-side taint buffer. The engine's own session memory (intent /
the Backboard session-brain, Thu) is the deeper version; this is what makes the
single-process demo fire without depending on it.
"""
from __future__ import annotations

from collections import deque

# How many recent tool-result texts to remember, and the char cap per entry.
# Small on purpose: we want the *recently ingested* content, not the whole
# session, and we must stay well under the engine's prompt budget.
_MAX_RESULTS = 6
_PER_RESULT_CHARS = 4000
_CONTEXT_CHARS = 8000


class SessionState:
    """Rolling record of what a session has read, keyed implicitly per proxy."""

    def __init__(self) -> None:
        self._results: deque[str] = deque(maxlen=_MAX_RESULTS)
        # True once we've ingested external/tool content — used to age the
        # trigger_source from "internal" (user-initiated) to "post-ingest".
        self.ingested = False

    def add_result_text(self, text: str) -> None:
        """Record the text of a tool result the agent just received."""
        if not text:
            return
        self._results.append(text[:_PER_RESULT_CHARS])
        self.ingested = True

    def recent_results_text(self) -> str:
        """The buffered result text, newest last, capped to the context budget."""
        if not self._results:
            return ""
        joined = "\n---\n".join(self._results)
        return joined[-_CONTEXT_CHARS:]

    def build_message_context(self, tool_input: dict) -> str:
        """
        The text the engine scores this call against: recently ingested tool
        results + the current call's arguments. Injection detection runs over
        this, so poison read on a prior turn is in view for the action it drives.
        """
        recent = self.recent_results_text()
        args = _stringify_args(tool_input)
        if recent and args:
            return (
                "Recently ingested content (from prior tool results):\n"
                f"{recent}\n\n"
                f"Current tool call arguments:\n{args}"
            )
        if recent:
            return (
                "Recently ingested content (from prior tool results):\n"
                f"{recent}"
            )
        return args


def _stringify_args(tool_input: dict) -> str:
    if not tool_input:
        return ""
    parts = []
    for key, value in tool_input.items():
        parts.append(f"{key}={value}")
    return " ".join(parts)[:_CONTEXT_CHARS]
