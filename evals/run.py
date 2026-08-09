"""
Eval runner. Runs each case through the real pipeline and reports pass/fail
against the docs.md criteria.

    python -m evals.run          # run everything
    python -m evals.run clean    # run one category

PII cases are reported BLOCKED (tokenization pipeline not built in Phase 1).
"""
import asyncio
import sys
import time

from dotenv import load_dotenv

load_dotenv()

import src.pipeline.bootstrap  # noqa: F401 — trust OS cert store before any TLS call

from evals.cases import ALL_CASES, passes
from src.pipeline.orchestrator import analyze


async def _warmup() -> None:
    from src.pipeline.claude_client import complete_text
    print("warming up connection...\n")
    try:
        await complete_text("You are a warmup.", "Reply OK.", max_tokens=5)
    except Exception as e:  # noqa: BLE001
        print(f"[warmup failed: {e}]\n")


async def main() -> None:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    cases = [c for c in ALL_CASES if (only is None or c.category == only)]

    await _warmup()

    results = []  # (case, score, decision, ms, status)
    slowest = 0

    for c in cases:
        if c.blocked:
            print(f"[{c.category:9}] {c.id:10} BLOCKED (tokenization not built)")
            results.append((c, None, None, 0, "BLOCKED"))
            continue

        r = await analyze(c.request())
        slowest = max(slowest, r.processing_time_ms)
        ok = passes(c.category, r.risk_score)
        status = "PASS" if ok else "FAIL"
        print(
            f"[{c.category:9}] {c.id:10} score={r.risk_score:5.1f} "
            f"decision={r.decision:5} inj={r.injection_score:5.1f} "
            f"drift={r.drift_score:5.1f} {r.processing_time_ms:5}ms  {status}"
        )
        results.append((c, r.risk_score, r.decision, r.processing_time_ms, status))

    # ---- summary ----
    print("\n" + "=" * 60)
    for cat in ("clean", "attack", "ambiguous", "pii"):
        rows = [x for x in results if x[0].category == cat]
        if not rows:
            continue
        if cat == "pii":
            print(f"{cat:9}: {len(rows)} BLOCKED (tokenization = deferred GARNISH)")
            continue
        p = sum(1 for x in rows if x[4] == "PASS")
        print(f"{cat:9}: {p}/{len(rows)} pass")

    runnable = [x for x in results if x[4] != "BLOCKED"]
    total_pass = sum(1 for x in runnable if x[4] == "PASS")
    print("-" * 60)
    print(f"RUNNABLE: {total_pass}/{len(runnable)} pass   (5 pii blocked)")
    print(f"LATENCY: slowest {slowest}ms (target <3000; local network adds ~1s/req)")


if __name__ == "__main__":
    asyncio.run(main())
