"""
Regression guard for the MCP proxy's transparent passthrough.

Protocol integrity is the whole ballgame: if the proxy ever corrupts, drops, or
reorders messages, every downstream feature is worthless. This spawns the proxy
wrapping a minimal mock MCP server (tests/mock_mcp_server.py) and asserts that
initialize / tools/list / tools/call round-trip and that a notification draws no
reply. Pure subprocess (no asyncio), so it runs the same on the Windows Proactor
loop and on Linux CI.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MOCK_SERVER = REPO / "tests" / "mock_mcp_server.py"


def _run_through_proxy(messages: list[dict], timeout: float = 30.0) -> dict:
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.proxy.mcp_proxy", "--name", "mock",
         "--", sys.executable, str(MOCK_SERVER)],
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


def test_passthrough_round_trips_all_message_kinds():
    responses = _run_through_proxy([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "hello firewall"}}},
    ])

    assert responses[1]["result"]["serverInfo"]["name"] == "mock-mcp"
    assert responses[2]["result"]["tools"][0]["name"] == "echo"
    assert "hello firewall" in responses[3]["result"]["content"][0]["text"]
    # isError must survive as a real boolean, not be dropped or stringified.
    assert responses[3]["result"]["isError"] is False
    # The notification (no id) must not have produced a response of its own.
    assert set(responses) == {1, 2, 3}
