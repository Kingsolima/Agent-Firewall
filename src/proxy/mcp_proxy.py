"""
MCP stdio proxy — the in-line firewall.

An MCP host (Claude Desktop, Kiro) launches THIS as if it were the target
server. The proxy spawns the real server as a child, then pipes JSON-RPC 2.0
messages between the host and the child, watching the stream. In Phase 1a it is
a pure passthrough: every byte the host sends reaches the child and vice-versa,
untouched. Interception of ``tools/call`` (Phase 1b) and ``tools/list``
scanning (Phase 1c) hook into the two dispatch points marked SEAM below.

    python -m src.proxy.mcp_proxy --name filesystem \\
        -- npx -y @modelcontextprotocol/server-filesystem C:\\demo

Transport facts this relies on (MCP stdio spec):
  * newline-delimited UTF-8 JSON, exactly one message per line, no embedded '\\n'
  * stdout carries ONLY protocol messages; stderr is free-form and we log there
  * a message with method+id is a request, method+no-id a notification,
    result/error+no-method a response (see ``classify``)

Windows/Proactor notes (this is a Windows-first repo, Python 3.13):
  * subprocess pipes require the Proactor loop — set explicitly in ``main``
  * console stdin can't be wrapped as an async transport reliably on Proactor,
    so we read it with a blocking daemon thread and bridge via
    ``loop.call_soon_threadsafe``
  * each output stream has exactly ONE writer coroutine draining a queue, which
    serializes concurrent producers and guarantees whole-line atomicity
  * flush after every line or the host hangs waiting for ``initialize``
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
from typing import Literal, Optional

from src.proxy.config import ArgError, ProxyConfig, parse_args

# Generous read buffer: tool results (e.g. a file's contents) are a single line
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


async def run_proxy(cfg: ProxyConfig) -> int:
    loop = asyncio.get_running_loop()

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

    # ----------------------------------------------------------- dispatch (SEAM)
    def handle_host_line(raw: bytes) -> None:
        """Host -> child. Runs on the loop thread. Phase 1a: pure passthrough."""
        msg = _try_parse(raw)
        # SEAM (Phase 1b): if msg and classify(msg)=="request" and
        # msg.get("method")=="tools/call": spawn handle_tool_call(...) and RETURN
        # (do not forward here — the handler decides allow/block).
        child_in_q.put_nowait(raw)

    def handle_child_line(raw: bytes) -> None:
        """Child -> host. Phase 1a: pure passthrough."""
        msg = _try_parse(raw)
        # SEAM (Phase 1b/1c): if msg is a response to a tools/call, capture its
        # content text into SessionState before forwarding; if it's a tools/list
        # response, spawn handle_tools_list(...) to scan descriptions.
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
        host_out_q.put_nowait(_STOP)         # let the host writer drain and stop

    # --------------------------------------------------------- host stdin thread
    def stdin_reader() -> None:
        """
        Blocking readline on our own stdin, bridged onto the loop. Daemon thread:
        it dies with the process, and readline() can't be cleanly interrupted.
        """
        buffer = sys.stdin.buffer
        while True:
            raw = buffer.readline()
            if not raw:                      # host closed stdin -> begin shutdown
                loop.call_soon_threadsafe(child_in_q.put_nowait, _STOP)
                return
            loop.call_soon_threadsafe(handle_host_line, raw)

    threading.Thread(target=stdin_reader, name="host-stdin", daemon=True).start()
    writers = [asyncio.create_task(write_host_out()),
               asyncio.create_task(write_child_in())]
    reader = asyncio.create_task(read_child_out())

    # The child's stdout closing (reader completing) is the natural end of life.
    await reader
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
