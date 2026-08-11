"""
Regression guards for the MCP proxy.

Protocol integrity is the whole ballgame: if the proxy ever corrupts, drops, or
reorders non-intercepted messages, every downstream feature is worthless. And
tools/call MUST be intercepted, failing CLOSED (block) when the engine is
unreachable. Both are checked here by pointing the proxy at a deliberately dead
engine port, so no reasoning engine is required. Pure subprocess (no asyncio),
so it runs the same on the Windows Proactor loop and on Linux CI.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MOCK_SERVER = REPO / "tests" / "mock_mcp_server.py"
DEAD_ENGINE = "http://127.0.0.1:9"   # port 9 (discard) refuses fast -> fail-safe block


def _run_through_proxy(messages: list[dict], timeout: float = 30.0) -> dict:
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.proxy.mcp_proxy", "--name", "mock",
         "--engine-url", DEAD_ENGINE, "--", sys.executable, str(MOCK_SERVER)],
        cwd=str(REPO),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    payload = "".join(json.dumps(m) + "\n" for m in messages).encode("utf-8")
    out, _err = proc.communicate(input=payload, timeout=timeout)
    responses = {}
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("id") is not None:
            responses[obj["id"]] = obj
    return responses


def test_non_intercepted_traffic_round_trips():
    responses = _run_through_proxy([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ])

    assert responses[1]["result"]["serverInfo"]["name"] == "mock-mcp"
    # tools/list passes through untouched when nothing is flagged.
    assert responses[2]["result"]["tools"][0]["name"] == "echo"
    # The notification (no id) must not have produced a response of its own.
    assert set(responses) == {1, 2}


def test_tools_call_is_intercepted_and_fails_closed():
    responses = _run_through_proxy([
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "hello firewall"}}},
    ])

    # Engine unreachable -> the proxy must BLOCK, not silently forward. The block
    # is a synthetic isError:true result carrying an explanation (never the echo).
    result = responses[3]["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "hello firewall" not in text
    assert "Blocked" in text or "unreachable" in text.lower()
