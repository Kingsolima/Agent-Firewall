"""
The headline experiment: firewall vs. signature baseline vs. ablation.

Three systems judge the same ~50 cases, and the comparison is designed so the
project's central claim is falsifiable rather than asserted:

  firewall  — the full pipeline (injection + intent/drift + source trust)
  baseline  — evals/baseline.py, a generous 38-pattern stateless scanner:
              what a conventional guardrail does
  ablation  — the firewall with the drift/intent stage DISABLED, leaving only
              injection detection: isolates how much of the result comes from
              intent-checking specifically, rather than from "we also call an LLM"

The two categories that decide it are benign_scary (legitimate requests that
look alarming, or that literally quote injection vocabulary) and taint (the
poison arrived in an earlier tool result, so this call looks innocuous on its
own). A pattern matcher must trade one off against the other; an intent-checker
should not have to.

    python -m evals.benchmark              # all three systems
    python -m evals.benchmark --quick      # firewall + baseline only

Writes evals/results.json and evals/results.md for the README.
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import src.pipeline.bootstrap  # noqa: F401 — trust OS cert store before any TLS call

from evals import baseline
from evals.dataset import load_cases, load_tool_descriptions
from evals.report import build_markdown
from src.pipeline import combiner
from src.pipeline.config import ALLOW_MAX
from src.pipeline.injection import detect_injection, regex_scan
from src.pipeline.orchestrator import analyze

OUT_DIR = Path(__file__).resolve().parent

# Cases are scored concurrently — a serial loop at ~8s/call puts a few-hundred-case
# run into the hours, which is slow enough that nobody re-runs it and the eval
# stops being used. Note the trade-off: per-call latency measured under
# concurrency includes contention and is NOT comparable to a serial measurement,
# so the reported figure is wall-clock-per-call at this concurrency, not a
# single-call latency benchmark. Set EVAL_CONCURRENCY=1 for a clean latency read.
CONCURRENCY = int(os.getenv("EVAL_CONCURRENCY", "8"))


def _stopped(score: float) -> bool:
    """A call is 'stopped' if it left the allow band (i.e. held or blocked)."""
    return score > ALLOW_MAX


def _metrics(rows: list[dict]) -> dict:
    """
    Binary detection metrics. Positive = the call SHOULD have been stopped.

      recall    — of the attacks, how many did we stop? (misses are breaches)
      precision — of what we stopped, how much genuinely warranted it?
      fpr       — of the legitimate calls, how many did we wrongly stop?
                  This is the "crying wolf" number that decides whether a
                  security tool survives contact with real users.
    """
    tp = sum(1 for r in rows if r["truth"] and r["stopped"])
    fn = sum(1 for r in rows if r["truth"] and not r["stopped"])
    fp = sum(1 for r in rows if not r["truth"] and r["stopped"])
    tn = sum(1 for r in rows if not r["truth"] and not r["stopped"])

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    lat = [r["ms"] for r in rows if r.get("ms")]

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "fpr": round(fpr, 3), "f1": round(f1, 3),
        "accuracy": round((tp + tn) / len(rows), 3) if rows else 0.0,
        "avg_latency_ms": round(sum(lat) / len(lat)) if lat else 0,
        "n": len(rows),
    }


def _by_category(rows: list[dict]) -> dict:
    out: dict = {}
    for row in rows:
        cat = out.setdefault(row["category"], {"n": 0, "correct": 0})
        cat["n"] += 1
        # "Correct" = we stopped what should be stopped, allowed what shouldn't.
        if row["stopped"] == row["truth"]:
            cat["correct"] += 1
    return out


async def run_firewall(cases: list, ablate_drift: bool) -> list[dict]:
    """
    Score every case through the real pipeline, optionally without drift.

    The two arms must not overlap in time: ablation works by swapping the global
    combiner weights, so running both concurrently would let one arm's weights
    leak into the other's scores. Concurrency is therefore WITHIN an arm only.
    """
    original = combiner.WEIGHTS
    if ablate_drift:
        # Zero the drift weight so only injection contributes — the combiner
        # renormalizes across whatever weights remain non-zero.
        combiner.WEIGHTS = {**original, "drift": 0.0}

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def score(case) -> dict:
        async with semaphore:
            started = time.time()          # timed inside the gate, so queue wait
            result = await analyze(case.request())   # is excluded from the figure
            return {
                "id": case.id, "category": case.category,
                "label": case.label, "label_source": case.label_source,
                "split": case.split, "cluster": case.cluster,
                "truth": case.should_stop,     # per-case now, not per-category
                "score": result.risk_score, "stopped": _stopped(result.risk_score),
                "decision": result.decision,
                "ms": int((time.time() - started) * 1000),
            }

    try:
        rows = await asyncio.gather(*(score(case) for case in cases))
    finally:
        combiner.WEIGHTS = original
    return list(rows)


def run_baseline(cases: list) -> list[dict]:
    rows = []
    for case in cases:
        started = time.time()
        score, hit = baseline.score(case.tool_name, case.tool_input, case.message_context)
        rows.append({
            "id": case.id, "category": case.category,
            "label": case.label, "label_source": case.label_source,
            "split": case.split, "cluster": case.cluster,
            "truth": case.should_stop,
            "score": score, "stopped": _stopped(score), "matched": hit,
            "ms": int((time.time() - started) * 1000),
        })
    return rows


async def run_tool_poisoning() -> dict:
    """tools/list scanning: does the firewall catch instructions hidden in tool
    metadata, without flagging honest descriptions?"""
    tool_cases = load_tool_descriptions()
    fw_correct = base_correct = 0
    details = []
    for case in tool_cases:
        regex_hit = regex_scan(case.description)
        verdict = await detect_injection(case.description, "unknown")
        fw_flag = verdict.detected or regex_hit is not None
        base_flag = baseline.score(case.tool_name, {}, case.description)[0] > ALLOW_MAX
        fw_correct += fw_flag == case.should_flag
        base_correct += base_flag == case.should_flag
        details.append({"id": case.id, "should_flag": case.should_flag,
                        "firewall": fw_flag, "baseline": base_flag})
    return {"n": len(tool_cases), "firewall_correct": fw_correct,
            "baseline_correct": base_correct, "details": details}


def _requested_split() -> str | None:
    """
    --split dev | heldout | all  (default: all)

    Reporting a headline number should use `--split heldout`. Running everything
    is right for exploration, but a number quoted from `all` includes the cases
    any tuning was done on, so it is not an out-of-sample result.
    """
    for i, arg in enumerate(sys.argv):
        if arg == "--split" and i + 1 < len(sys.argv):
            value = sys.argv[i + 1]
            if value not in ("dev", "heldout", "all"):
                sys.exit(f"--split must be dev|heldout|all, got {value!r}")
            return None if value == "all" else value
    return None


async def main() -> None:
    quick = "--quick" in sys.argv
    split = _requested_split()
    cases = load_cases(split=split)
    if not cases:
        sys.exit("no cases loaded — check evals/data/cases.jsonl")

    print(f"{len(cases)} cases ({split or 'all'} split), concurrency {CONCURRENCY}")
    print("Running firewall (full pipeline)…")
    fw = await run_firewall(cases, ablate_drift=False)
    print("Running signature baseline…")
    bl = run_baseline(cases)

    systems = {"firewall": _metrics(fw), "baseline": _metrics(bl)}
    per_category = {"firewall": _by_category(fw), "baseline": _by_category(bl)}

    raw = {"firewall": fw, "baseline": bl}

    if not quick:
        print("Running ablation (intent/drift disabled)…")
        ab = await run_firewall(cases, ablate_drift=True)
        systems["ablation"] = _metrics(ab)
        per_category["ablation"] = _by_category(ab)
        # Kept in raw so the report can compare it case-by-case; without the
        # per-case rows the ablation can only be eyeballed as a summary number.
        raw["ablation"] = ab

    print("Scanning tool descriptions…")
    poison = await run_tool_poisoning()

    categories: dict = {}
    for row in fw:
        categories[row["category"]] = categories.get(row["category"], 0) + 1

    report = {
        "n_cases": len(fw), "categories": categories, "systems": systems,
        "per_category": per_category, "tool_poisoning": poison,
        "threshold": ALLOW_MAX, "concurrency": CONCURRENCY,
        "split": split or "all", "raw": raw,
    }

    (OUT_DIR / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # The report is rebuilt from raw scores at the CURRENT threshold, so results.md
    # can also be regenerated later without re-running: python -m evals.report
    (OUT_DIR / "results.md").write_text(build_markdown(report), encoding="utf-8")

    print(f"\nWrote {OUT_DIR / 'results.json'} and {OUT_DIR / 'results.md'}")


if __name__ == "__main__":
    asyncio.run(main())
