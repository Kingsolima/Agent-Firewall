"""
MCP stdio proxy — the in-line firewall.

An MCP host (Claude Desktop, Kiro) launches THIS as if it were the target
server. The proxy spawns the real server as a child, then pipes JSON-RPC 2.0
messages between the host and the child, watching the stream:

  * ``tools/call`` (host -> child) is INTERCEPTED: held back, scored by the
    reasoning engine (POST /intercept), and only forwarded on ALLOW. On BLOCK /
    HOLD the child never sees it and the host gets a synthetic result carrying a
    plain-English counterfactual (isError:true, so it lands in the agent's chat).
  * ``tools/call`` RESULTS (child -> host) are captured into SessionState so the
    content the agent just ingested is in view when the *next* call is scored —
    this is what makes read-poison -> later-exfil visible (cross-turn taint).
  * ``tools/list`` results are scanned for tool-poisoning (POST /scan) and a
    flagged description is rewritten to a warning; the list is never dropped.
  * everything else (initialize, notifications, ping, sampling/*, resources/*,
    prompts/*) is pure passthrough, byte-for-byte.

    python -m src.proxy.mcp_proxy --name filesystem \\
        -- npx -y @modelcontextprotocol/server-filesystem C:\\demo

Transport facts (MCP stdio spec): newline-delimited UTF-8 JSON, one message per
line, no embedded '\\n'; stdout is protocol-only, stderr is free-form (we log
there); a message with method+id is a request, method+no-id a notification,
result/error+no-method a response (see ``classify``).

Windows/Proactor (Windows-first repo, Python 3.13): subprocess pipes need the
Proactor loop (set in ``main``); console stdin can't be wrapped as an async
transport, so a blocking daemon thread reads it and bridges via
``loop.call_soon_threadsafe``; one writer coroutine per output stream gives
whole-line atomicity; flush every line or the host hangs on ``initialize``.
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
from typing import Any, Literal, Optional

import src.pipeline.bootstrap  # noqa: F401 — trust the OS cert store before any TLS call

from src.models import ToolCallRequest
from src.proxy.config import ArgError, ProxyConfig, parse_args
from src.proxy.mcp_engine_client import (
    fetch_session_context,
    intercept,
    register_session,
    scan_tools,
)
from src.proxy.session import SessionState

# Generous read buffer: a tool result (e.g. a file's contents) is a single line
# and the StreamReader default (64 KiB) would raise on a large one.
_STREAM_LIMIT = 16 * 1024 * 1024

# Sentinel enqueued to tell a writer coroutine to stop.
_STOP = object()


def _log(message: str) -> None:
    """Proxy logs go to stderr (inherited by the host); stdout is protocol-only."""
    print(f"[mcp_proxy] {message}", file=sys.stderr, flush=True)


def classify(msg: dict) -> Literal["request", "notification", "response"]:
    """
    JSON-RPC 2.0 discrimination. Server-initiated requests (sampling/createMessage,
    roots/list, elicitation/create) carry a ``method`` so they classify as
    "request"; a bare result/error is a "response".
    """
    has_method = "method" in msg
    has_id = msg.get("id") is not None
    if has_method and has_id:
        return "request"
    if has_method:
        return "notification"
    return "response"


def make_block_result(request_id: Any, text: str) -> bytes:
    """
    Synthesize the host's answer for a blocked/held call. isError:true makes it a
    *successful* JSON-RPC response whose content the model reads (MCP feeds tool
    errors back into context) — so the counterfactual lands in the agent's chat,
    unlike a JSON-RPC error which the host would hide as a transport fault.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"isError": True, "content": [{"type": "text", "text": text}]},
    }
    return (json.dumps(payload) + "\n").encode("utf-8")


def _result_text(msg: dict) -> str:
    """Concatenate the text blocks of a CallToolResult, for the taint buffer."""
    result = msg.get("result")
    if not isinstance(result, dict):
        return ""
    parts = []
    for block in result.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "\n".join(parts)


def _decision_text(decision) -> str:
    """The human-facing message the agent sees for a non-allow decision."""
    counterfactual = decision.counterfactual or decision.message or ""
    if decision.decision == "hold":
        return (
            "⏸️ Held for human approval — this action is awaiting review in the "
            "Agent Firewall dashboard.\n\n" + counterfactual
        )
    return "🛑 Blocked by Agent Firewall.\n\n" + counterfactual


async def run_proxy(cfg: ProxyConfig) -> int:
    loop = asyncio.get_running_loop()
    session = SessionState()
    # request id -> method, for requests we forwarded to the child and whose
    # response we want to treat specially (capture tools/call results, scan
    # tools/list). Only touched on the loop thread, so no lock needed.
    pending: dict[Any, str] = {}
    # request id -> the in-flight handle_tool_call task, so a host
    # notifications/cancelled (or shutdown) can cancel a call still being scored
    # before the child ever sees it.
    handlers: dict[Any, asyncio.Task] = {}

    _log(f"starting: name={cfg.name} session={cfg.session_id} "
         f"engine={cfg.engine_url} child={cfg.command} {' '.join(cfg.args)}")

    child = await asyncio.create_subprocess_exec(
        cfg.command,
        *cfg.args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,          # inherit: child logs flow straight to the host
        limit=_STREAM_LIMIT,
    )
    assert child.stdin is not None and child.stdout is not None

    host_out_q: asyncio.Queue = asyncio.Queue()   # -> our stdout (to host)
    child_in_q: asyncio.Queue = asyncio.Queue()   # -> child stdin

    # In-flight interception tasks (handle_tool_call / handle_tools_list). We must
    # let these finish and flush their replies before tearing down on shutdown,
    # or a blocked call's synthetic result is lost when the child exits.
    tasks: set[asyncio.Task] = set()

    def spawn(coro, rid: Any = None) -> None:
        task = asyncio.create_task(coro)
        tasks.add(task)
        if rid is not None:
            handlers[rid] = task
        task.add_done_callback(lambda t: _on_task_done(t, rid))

    def _on_task_done(task: asyncio.Task, rid: Any = None) -> None:
        tasks.discard(task)
        if rid is not None:
            handlers.pop(rid, None)
        if not task.cancelled() and task.exception() is not None:
            _log(f"handler task error: {task.exception()!r}")

    # ------------------------------------------------------------------ writers
    async def write_host_out() -> None:
        while True:
            line = await host_out_q.get()
            if line is _STOP:
                return
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def write_child_in() -> None:
        while True:
            line = await child_in_q.get()
            if line is _STOP:
                if not child.stdin.is_closing():
                    child.stdin.close()
                return
            child.stdin.write(line)
            await child.stdin.drain()

    # ------------------------------------------------------- interception tasks
    async def handle_tool_call(msg: dict, raw: bytes) -> None:
        """Score one tools/call; forward on allow, answer the host on block/hold."""
        rid = msg.get("id")
        params = msg.get("params") or {}
        tool_name = params.get("name", "")
        tool_input = params.get("arguments") or {}

        request = ToolCallRequest(
            tool_name=tool_name,
            tool_input=tool_input if isinstance(tool_input, dict) else {"_": tool_input},
            session_id=cfg.session_id,
            agent_id=cfg.name,
            workspace_id=cfg.workspace_id,
            # Once the agent has ingested external/tool content, treat its actions
            # as the untrusted surface; before that, the configured trust default.
            trigger_source="external_dm" if session.ingested else cfg.trust,
            message_context=session.build_message_context(
                tool_input if isinstance(tool_input, dict) else {}),
        )

        decision = await intercept(request, cfg.engine_url)
        _log(f"tools/call name={tool_name} -> {decision.decision} "
             f"risk={decision.risk_score}")

        if decision.decision == "allow":
            pending[rid] = "tools/call"      # expect a real result to capture
            child_in_q.put_nowait(raw)       # forward the original bytes
        else:
            host_out_q.put_nowait(make_block_result(rid, _decision_text(decision)))

    async def handle_tools_list(msg: dict, raw: bytes) -> None:
        """Scan tool descriptions for injected instructions; rewrite flagged ones."""
        tools = (msg.get("result") or {}).get("tools") or []
        items = [{"name": t.get("name", ""), "text": t.get("description", "")}
                 for t in tools if isinstance(t, dict)]
        verdicts = await scan_tools(items, cfg.trust, cfg.engine_url)
        flagged = {v["name"]: v for v in verdicts if v.get("flagged")}

        if not flagged:
            host_out_q.put_nowait(raw)        # nothing to change -> byte-identical
            return

        for tool in tools:
            name = tool.get("name", "")
            if name in flagged:
                suspicious = flagged[name].get("suspicious_text") or "hidden instructions"
                _log(f"tool-poisoning flagged in '{name}': {suspicious!r}")
                tool["description"] = (
                    "⚠️ Agent Firewall: this tool's description contained injected "
                    f"instructions and was sanitized. Original flagged text: {suspicious!r}"
                )
        host_out_q.put_nowait((json.dumps(msg) + "\n").encode("utf-8"))

    # ----------------------------------------------------------- dispatch (loop)
    def handle_host_line(raw: bytes) -> None:
        """Host -> child."""
        msg = _try_parse(raw)
        if msg is not None:
            kind = classify(msg)
            if kind == "request":
                if msg.get("method") == "tools/call":
                    rid = msg.get("id")
                    spawn(handle_tool_call(msg, raw), rid=rid)
                    return                    # handler decides allow/block/hold
                pending[msg.get("id")] = msg.get("method")   # e.g. tools/list
            elif kind == "notification" and msg.get("method") == "notifications/cancelled":
                cid = (msg.get("params") or {}).get("requestId")
                task = handlers.get(cid)
                if task is not None:
                    # Still being scored — the child never saw this call, so cancel
                    # the handler and swallow the cancellation (nothing to forward).
                    task.cancel()
                    _log(f"host cancelled in-flight tools/call id={cid}")
                    return
                # Not ours (or already forwarded on ALLOW) -> let the child hear it.
        child_in_q.put_nowait(raw)

    def handle_child_line(raw: bytes) -> None:
        """Child -> host."""
        msg = _try_parse(raw)
        if msg is not None and classify(msg) == "response":
            method = pending.pop(msg.get("id"), None)
            if method == "tools/list":
                spawn(handle_tools_list(msg, raw))
                return                        # handler forwards (maybe modified)
            if method == "tools/call":
                session.add_result_text(_result_text(msg))
        host_out_q.put_nowait(raw)

    # -------------------------------------------------------------- child reader
    async def read_child_out() -> None:
        while True:
            try:
                raw = await child.stdout.readline()
            except (asyncio.LimitOverrunError, ValueError):
                _log("child produced a line over the stream limit; skipping")
                continue
            if not raw:                      # child closed stdout / exited
                break
            handle_child_line(raw)
        # NB: do not stop the host writer here — outstanding interception tasks
        # may still owe it a reply. run_proxy drains them first (below).

    # --------------------------------------------------------- host stdin thread
    def stdin_reader() -> None:
        """Blocking readline on our own stdin, bridged onto the loop (daemon)."""
        buffer = sys.stdin.buffer
        while True:
            raw = buffer.readline()
            if not raw:                      # host closed stdin -> begin shutdown
                loop.call_soon_threadsafe(child_in_q.put_nowait, _STOP)
                return
            loop.call_soon_threadsafe(handle_host_line, raw)

    async def announce_and_rehydrate() -> None:
        """
        Tell the dashboard this session exists, then restore what it already
        ingested. Rehydration is what makes durable memory real: after a restart
        the taint buffer would otherwise be empty, and poison read before the
        restart would be invisible to the call it induced afterwards.
        """
        await register_session(cfg.session_id, cfg.name, cfg.workspace_id, cfg.engine_url)
        prior = await fetch_session_context(cfg.session_id, cfg.engine_url)
        for summary in prior:
            session.add_result_text(summary)
        if prior:
            _log(f"rehydrated {len(prior)} prior taint records for {cfg.session_id}")

    threading.Thread(target=stdin_reader, name="host-stdin", daemon=True).start()
    spawn(announce_and_rehydrate())
    writers = [asyncio.create_task(write_host_out()),
               asyncio.create_task(write_child_in())]
    reader = asyncio.create_task(read_child_out())

    # The child's stdout closing (reader completing) is the natural end of life.
    await reader
    # Let outstanding interception tasks flush their replies BEFORE we stop the
    # host writer — otherwise a blocked call's synthetic result races the teardown.
    if tasks:
        await asyncio.gather(*list(tasks), return_exceptions=True)
    host_out_q.put_nowait(_STOP)
    await child.wait()
    child_in_q.put_nowait(_STOP)
    for task in writers:
        await task
    _log(f"child exited rc={child.returncode}")
    return child.returncode or 0


def _try_parse(raw: bytes) -> Optional[dict]:
    """Parse a line for classification only; never used to re-serialize output."""
    try:
        msg = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return msg if isinstance(msg, dict) else None


def main(argv: Optional[list[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        cfg = parse_args(raw_argv)
    except ArgError as exc:
        _log(f"arg error: {exc}")
        _log("usage: python -m src.proxy.mcp_proxy --name NAME [--trust internal|external|unknown] "
             "[--engine-url URL] [--hold-timeout S] -- COMMAND [ARGS...]")
        return 2

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        return asyncio.run(run_proxy(cfg))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
