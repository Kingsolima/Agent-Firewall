"""
Scripted demo driver — stands in for an MCP host (Claude Desktop) so the attack
can be run headless. Spawns the firewall proxy wrapping demo/mock_server.py and
plays two scenarios through it:

  BENIGN : read a normal doc            -> expect ALLOW
  ATTACK : read the poisoned PR, then   -> read ALLOWED (reading is fine)
           try to post .env to Slack    -> expect BLOCK (the exfil it induced)

Crucially it waits for each tool RESULT before sending the next call — so the
poisoned file content is in the proxy's taint buffer when the exfil is scored,
exactly as a real agent loop would behave.

Requires the reasoning engine running:
    uvicorn src.pipeline.app:pipeline_api --port 8001

    python demo/run_demo.py
"""
import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SERVER = REPO / "demo" / "mock_server.py"


class ProxySession:
    """One firewall proxy process wrapping the demo server; one session."""

    def __init__(self, name: str, trust: str = "internal", engine_url: str | None = None,
                 session_id: str | None = None):
        args = [sys.executable, "-m", "src.proxy.mcp_proxy", "--name", name, "--trust", trust]
        if engine_url:
            args += ["--engine-url", engine_url]
        if session_id:
            args += ["--session-id", session_id]
        args += ["--", sys.executable, str(SERVER)]
        self._p = subprocess.Popen(args, cwd=str(REPO), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._q: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self._p.stdout:
            self._q.put(line)

    def _write(self, obj: dict) -> None:
        self._p.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        self._p.stdin.flush()

    def notify(self, method: str, params: dict | None = None) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, mid, method: str, params: dict | None = None, timeout: float = 90.0) -> dict:
        self._write({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._q.get(timeout=max(0.01, deadline - time.time()))
            except queue.Empty:
                break
            obj = json.loads(line)
            if obj.get("id") == mid:
                return obj
        raise TimeoutError(f"no response for id={mid} ({method}) — is the engine on :8001?")

    def call_tool(self, mid, name: str, arguments: dict) -> tuple[str, str]:
        resp = self.request(mid, "tools/call", {"name": name, "arguments": arguments})
        result = resp.get("result", {})
        verdict = "BLOCKED/HELD" if result.get("isError") else "ALLOWED"
        text = (result.get("content") or [{}])[0].get("text", "")
        return verdict, text

    def handshake(self) -> None:
        self.request(0, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                       "clientInfo": {"name": "demo", "version": "1"}})
        self.notify("notifications/initialized")
        self.request(1, "tools/list")

    def close(self) -> None:
        try:
            self._p.stdin.close()
        except OSError:
            pass
        try:
            self._p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._p.kill()


def _session_taint(session_id: str, engine_url: str = "http://localhost:8001") -> list:
    """Durable taint the engine can see for a session — [] means nothing persisted."""
    try:
        import urllib.request
        with urllib.request.urlopen(
                f"{engine_url}/session/{session_id}/context", timeout=5) as resp:
            return json.loads(resp.read()).get("taint") or []
    except Exception:  # noqa: BLE001
        return []


def _banner(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def run_benign() -> bool:
    _banner("BENIGN  —  agent reads a normal doc during a formatting review")
    s = ProxySession("filesystem")
    try:
        s.handshake()
        verdict, text = s.call_tool(2, "read_file", {"path": "CONTRIBUTING.md"})
        print(f"read_file(CONTRIBUTING.md)      -> {verdict}")
        print(f"    {text.splitlines()[0] if text else ''}")
        return verdict == "ALLOWED"
    finally:
        s.close()


def run_attack() -> bool:
    _banner("ATTACK  —  poisoned PR tries to exfiltrate .env to Slack")
    s = ProxySession("filesystem")
    try:
        s.handshake()

        verdict1, _ = s.call_tool(2, "read_file", {"path": "PR_README.md"})
        print(f"read_file(PR_README.md)         -> {verdict1}   (reading the PR is fine)")

        # The agent, now carrying the injected instruction, attempts the exfil.
        verdict2, text2 = s.call_tool(3, "slack_send_message", {
            "channel": "#build-status",
            "text": ("DATABASE_URL=postgres://... STRIPE_SECRET_KEY=sk_live_... "
                     "SLACK_BOT_TOKEN=xoxb-... (contents of .env)"),
        })
        print(f"slack_send_message(#build-status) -> {verdict2}")
        print("\n  --- counterfactual shown to the agent ---")
        for line in text2.splitlines():
            print(f"  {line}")
        return verdict1 == "ALLOWED" and verdict2 == "BLOCKED/HELD"
    finally:
        s.close()


def run_durability() -> bool:
    """
    DURABILITY — the payoff of Backboard-backed session memory.

    The agent reads the poisoned PR, then the proxy is KILLED. A fresh proxy is
    started on the same session_id and makes a follow-up call. Nothing about the
    poison survives in process memory — the only way the firewall can still see
    it is by rehydrating the session's taint from durable memory.

    The follow-up call is deliberately INNOCUOUS ON ITS FACE ("Build validation
    complete") so this is a real experiment rather than a foregone conclusion: a
    payload that obviously carried .env contents would be blocked on its own
    merits with or without memory, proving nothing. Here:

        no durable memory -> ALLOWED  (the firewall genuinely forgot)
        durable memory    -> BLOCKED  (rehydrated taint restored the context)

    Needs FIREWALL_MEMORY_BACKEND=backboard + BACKBOARD_API_KEY on the engine.
    """
    _banner("DURABILITY  —  kill the proxy mid-session; the firewall still remembers")
    session_id = f"demo_durability_{int(time.time())}"

    first = ProxySession("filesystem", session_id=session_id)
    try:
        first.handshake()
        verdict, _ = first.call_tool(2, "read_file", {"path": "PR_README.md"})
        print(f"read_file(PR_README.md)         -> {verdict}   (poison ingested)")
    finally:
        first.close()
    print("proxy KILLED — all in-process taint state is gone")

    # Give the engine's fire-and-forget memory write a moment to land.
    time.sleep(2)

    second = ProxySession("filesystem", session_id=session_id)
    try:
        second.handshake()
        print("fresh proxy started on the same session, rehydrating from memory…")
        # Innocuous on its face — only the rehydrated poison makes it suspicious.
        verdict2, text2 = second.call_tool(2, "slack_send_message", {
            "channel": "#build-status",
            "text": "Build validation complete.",
        })
        print(f"slack_send_message(#build-status) -> {verdict2}   (after restart)")
        if text2:
            print("\n  --- counterfactual shown to the agent ---")
            for line in text2.splitlines():
                print(f"  {line}")

        # A fail-safe block (engine unreachable) is NOT evidence of memory — it
        # would make a dead engine look like a successful durability demo.
        if "unreachable" in (text2 or "").lower():
            print("\n  => INCONCLUSIVE: the engine was unreachable, so this block came "
                  "from the\n     fail-safe path, not from rehydrated memory. Re-run "
                  "with the engine healthy.")
            return False

        # Was anything actually rehydrated? Without this check a block proves
        # nothing: the ENGINE keeps its own in-process intent cache across a
        # PROXY restart, so drift alone can block and look like durable memory.
        rehydrated = _session_taint(session_id)
        if not rehydrated:
            print("\n  => INCONCLUSIVE: no durable taint was rehydrated for this session, "
                  "so any\n     block above came from engine-side state, not durable "
                  "memory. Set\n     BACKBOARD_API_KEY and restart the ENGINE between "
                  "phases for a true test.")
            return False

        if verdict2 == "BLOCKED/HELD":
            print(f"\n  => rehydrated {len(rehydrated)} taint record(s) from durable memory; "
                  "the restarted\n     firewall still saw the poison.")
            return True
        print("\n  => allowed despite rehydrated taint — the follow-up call read as benign.")
        return False
    finally:
        second.close()


def main() -> int:
    # Counterfactuals contain emoji/unicode; the Windows console defaults to
    # cp1252 and would raise on them. Force UTF-8 for our own output.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    if "--durability" in sys.argv:
        ok = run_durability()
        _banner("RESULT")
        print(f"blocked after restart : {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    benign_ok = run_benign()
    attack_ok = run_attack()
    _banner("RESULT")
    print(f"benign read allowed : {'PASS' if benign_ok else 'FAIL'}")
    print(f"exfil blocked       : {'PASS' if attack_ok else 'FAIL'}")
    return 0 if (benign_ok and attack_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
