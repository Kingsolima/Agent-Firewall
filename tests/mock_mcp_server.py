"""
Minimal stdio MCP server for testing the proxy. Speaks just enough JSON-RPC 2.0
to exercise passthrough: initialize, tools/list, tools/call. Newline-delimited,
one message per line, protocol on stdout / logs on stderr — same contract as a
real server.

Run standalone:  python -m tests.mock_mcp_server
Usually spawned by the proxy under test.
"""
import json
import sys


def _send(obj: dict) -> None:
    sys.stdout.buffer.write((json.dumps(obj) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _handle(msg: dict) -> None:
    method = msg.get("method")
    mid = msg.get("id")

    if method is not None and mid is None:
        return  # notification (e.g. notifications/initialized) — no reply

    if method == "initialize":
        _send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-mcp", "version": "0.0.1"},
        }})
    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "echo", "description": "Echoes the arguments back.",
             "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
        ]}})
    elif method == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        _send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": "echo: " + json.dumps(args)}],
            "isError": False,
        }})
    else:
        _send({"jsonrpc": "2.0", "id": mid,
               "error": {"code": -32601, "message": f"method not found: {method}"}})


def main() -> int:
    for raw in sys.stdin.buffer:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            _handle(msg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
