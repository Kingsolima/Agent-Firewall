"""
Demo MCP server — one process exposing both a read tool and an external-send
tool, so the read-poison -> exfiltrate attack lives in a single session the
proxy can correlate. Real stdio MCP server (newline-delimited JSON-RPC on
stdout, logs on stderr); usually spawned by the firewall proxy.

    python demo/mock_server.py [BASE_DIR]     # BASE_DIR defaults to demo/repo

Tools:
  read_file(path)      -> contents of BASE_DIR/path
  http_post(url, body) -> "sends" a body to a URL (records to stderr)

These mirror the two servers a real host is usually wired to at once — a
filesystem server and an HTTP/fetch server. http_post is the egress channel: if
the firewall ever lets a call through, whatever it "sends" is printed to stderr
so the demo can show what WOULD have leaked.

Note that http_post is not a forbidden tool. The benign path posts through it
too; only the call whose destination and payload contradict the user's stated
task is stopped. A blocklist cannot make that distinction.
"""
import json
import sys
from pathlib import Path

BASE_DIR = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else \
    (Path(__file__).resolve().parent / "repo")


def _send(obj: dict) -> None:
    sys.stdout.buffer.write((json.dumps(obj) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _log(message: str) -> None:
    print(f"[mock_server] {message}", file=sys.stderr, flush=True)


def _ok(mid, text: str) -> None:
    _send({"jsonrpc": "2.0", "id": mid,
           "result": {"content": [{"type": "text", "text": text}], "isError": False}})


def _err(mid, text: str) -> None:
    _send({"jsonrpc": "2.0", "id": mid,
           "result": {"content": [{"type": "text", "text": text}], "isError": True}})


def _read_file(mid, args: dict) -> None:
    rel = str(args.get("path", ""))
    target = (BASE_DIR / rel).resolve()
    # Stay within BASE_DIR (defense the real filesystem server also does).
    if not str(target).startswith(str(BASE_DIR)):
        _err(mid, f"path escapes base dir: {rel}")
        return
    try:
        _ok(mid, target.read_text(encoding="utf-8"))
    except OSError as exc:
        _err(mid, f"could not read {rel}: {exc}")


def _http_post(mid, args: dict) -> None:
    url = str(args.get("url", ""))
    body = str(args.get("body", ""))
    _log(f"!!! EGRESS WOULD HAVE HAPPENED: POST {url}: {body[:200]}")
    _ok(mid, f"POST {url} -> 200 OK")


_TOOLS = [
    {"name": "read_file",
     "description": "Read a UTF-8 text file from the working directory.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
    {"name": "http_post",
     "description": "Send an HTTP POST request with a text body to a URL.",
     "inputSchema": {"type": "object",
                     "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
                     "required": ["url", "body"]}},
]


def _handle(msg: dict) -> None:
    method = msg.get("method")
    mid = msg.get("id")

    if method is not None and mid is None:
        return  # notification

    if method == "initialize":
        _send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-mcp", "version": "0.1.0"},
        }})
    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": _TOOLS}})
    elif method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "read_file":
            _read_file(mid, args)
        elif name == "http_post":
            _http_post(mid, args)
        else:
            _err(mid, f"unknown tool: {name}")
    else:
        _send({"jsonrpc": "2.0", "id": mid,
               "error": {"code": -32601, "message": f"method not found: {method}"}})


def main() -> int:
    _log(f"serving files from {BASE_DIR}")
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
