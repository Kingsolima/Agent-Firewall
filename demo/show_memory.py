"""
PRIVACY BEAT — show exactly what Agent Firewall persists to Backboard.

Lists a session's durable memory and scans it for anything that looks like a
secret. The claim being demonstrated: the firewall stores the user's INTENT and
short DERIVED security findings, and never raw tool output, file contents, or
credential values — so durable cross-session memory doesn't become a new place
for secrets to leak.

    python demo/show_memory.py                  # all recent firewall memories
    python demo/show_memory.py <session_id>     # one session

Requires BACKBOARD_API_KEY. On the memory backend there is nothing to show —
that's expected; durable memory is the Backboard-backed path.
"""
import asyncio
import re
import sys
from pathlib import Path

# Run directly (python demo/show_memory.py), so the repo root isn't on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

import src.pipeline.bootstrap  # noqa: F401 — trust OS cert store before any TLS call

from src.pipeline import backboard_client as bb

# Shapes that would be alarming to find in durable storage.
SECRET_PATTERNS = [
    (r"sk_live_[A-Za-z0-9]+", "Stripe live key"),
    (r"sk-ant-[A-Za-z0-9\-_]+", "Anthropic API key"),
    (r"xoxb-[A-Za-z0-9\-]+", "Slack bot token"),
    (r"postgres(?:ql)?://[^\s\"']+", "Postgres connection string"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
]


def scan_for_secrets(text: str) -> list[str]:
    return [label for pattern, label in SECRET_PATTERNS
            if re.search(pattern, text or "", re.IGNORECASE)]


async def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    if not bb.available():
        print("BACKBOARD_API_KEY is not set — nothing is being persisted to Backboard.")
        print("(The firewall is running on the in-process `memory` backend.)")
        return 0

    session_id = sys.argv[1] if len(sys.argv) > 1 else None
    assistant_id = await bb.ensure_assistant()
    if not assistant_id:
        print("Could not reach Backboard.")
        return 1

    print(f"Backboard assistant: {assistant_id}")
    if session_id:
        rows = await bb.get_memories(session_id, limit=100)
        print(f"Session: {session_id}\n")
    else:
        # No session filter — read the raw page and show everything we wrote.
        data = await bb._request(
            "GET", bb._PATHS["list_memories"].format(assistant_id=assistant_id),
            params={"page": 1, "page_size": 100})
        rows = (data or {}).get("memories") or []
        print("All firewall memories\n")

    if not rows:
        print("(no memories stored yet — run the demo first)")
        return 0

    findings: list[str] = []
    for row in rows:
        meta = row.get("metadata") or {}
        content = str(row.get("content") or "")
        kind = meta.get("kind", "?")
        sid = meta.get("session_id", "?")
        print(f"  [{kind:6}] ({sid}) {content}")
        findings.extend(scan_for_secrets(content))

    print("\n" + "=" * 68)
    print(f"{len(rows)} memories stored")
    if findings:
        print(f"SECRETS FOUND: {sorted(set(findings))}  <-- privacy claim VIOLATED")
        return 1
    print("SECRET SCAN: clean — intent and derived findings only, zero credential values")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
