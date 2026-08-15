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
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import src.pipeline.bootstrap  # noqa: F401 — trust OS cert store before any TLS call

from evals import baseline
from evals.cases import ALL_CASES, SHOULD_STOP, TOOL_POISONING
from src.pipeline import combiner
from src.pipeline.config import ALLOW_MAX
from src.pipeline.injection import detect_injection, regex_scan
from src.pipeline.orchestrator import analyze

OUT_DIR = Path(__file__).resolve().parent


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


async def run_firewall(ablate_drift: bool) -> list[dict]:
    """Score every case through the real pipeline, optionally without drift."""
    rows = []
    original = combiner.WEIGHTS
    if ablate_drift:
        # Zero the drift weight so only injection contributes — the combiner
        # renormalizes across whatever weights remain non-zero.
        combiner.WEIGHTS = {**original, "drift": 0.0}
    try:
        for case in ALL_CASES:
            if case.blocked:          # pii — tokenization not built
                continue
            started = time.time()
            result = await analyze(case.request())
            rows.append({
                "id": case.id, "category": case.category,
                "truth": SHOULD_STOP.get(case.category, True),
                "score": result.risk_score, "stopped": _stopped(result.risk_score),
                "decision": result.decision,
                "ms": int((time.time() - started) * 1000),
            })
    finally:
        combiner.WEIGHTS = original
    return rows


def run_baseline() -> list[dict]:
    rows = []
    for case in ALL_CASES:
        if case.blocked:
            continue
        started = time.time()
        score, hit = baseline.score(case.tool_name, case.tool_input, case.message_context)
        rows.append({
            "id": case.id, "category": case.category,
            "truth": SHOULD_STOP.get(case.category, True),
            "score": score, "stopped": _stopped(score), "matched": hit,
            "ms": int((time.time() - started) * 1000),
        })
    return rows


async def run_tool_poisoning() -> dict:
    """tools/list scanning: does the firewall catch instructions hidden in tool
    metadata, without flagging honest descriptions?"""
    fw_correct = base_correct = 0
    details = []
    for case in TOOL_POISONING:
        regex_hit = regex_scan(case.description)
        verdict = await detect_injection(case.description, "unknown")
        fw_flag = verdict.detected or regex_hit is not None
        base_flag = baseline.score(case.tool_name, {}, case.description)[0] > ALLOW_MAX
        fw_correct += fw_flag == case.should_flag
        base_correct += base_flag == case.should_flag
        details.append({"id": case.id, "should_flag": case.should_flag,
                        "firewall": fw_flag, "baseline": base_flag})
    return {"n": len(TOOL_POISONING), "firewall_correct": fw_correct,
            "baseline_correct": base_correct, "details": details}


def _markdown(report: dict) -> str:
    systems = report["systems"]
    lines = [
        "# Evaluation results",
        "",
        f"{report['n_cases']} tool calls across {len(report['categories'])} categories. "
        "A call counts as *stopped* when it leaves the allow band (held or blocked). "
        "**FPR** is the share of legitimate calls wrongly stopped — the number that "
        "decides whether a security tool is usable in practice.",
        "",
        "| System | Precision | Recall | FPR | F1 | Accuracy | Avg latency |",
        "|---|---|---|---|---|---|---|",
    ]
    label = {"firewall": "**Agent Firewall**",
             "baseline": f"Signature baseline ({baseline.PATTERN_COUNT} patterns)",
             "ablation": "Ablation (no intent/drift)"}
    for key, metrics in systems.items():
        lines.append(
            f"| {label.get(key, key)} | {metrics['precision']:.2f} | {metrics['recall']:.2f} "
            f"| {metrics['fpr']:.2f} | {metrics['f1']:.2f} | {metrics['accuracy']:.2f} "
            f"| {metrics['avg_latency_ms']} ms |")

    lines += ["", "## Per-category accuracy", "",
              "| Category | n | " + " | ".join(label.get(k, k) for k in systems) + " |",
              "|---" * (len(systems) + 2) + "|"]
    for cat in report["categories"]:
        row = [cat, str(report["categories"][cat])]
        for key in systems:
            per = report["per_category"][key].get(cat, {"n": 0, "correct": 0})
            row.append(f"{per['correct']}/{per['n']}")
        lines.append("| " + " | ".join(row) + " |")

    poison = report.get("tool_poisoning")
    if poison:
        lines += ["", "## Tool-description poisoning (tools/list)", "",
                  f"Firewall {poison['firewall_correct']}/{poison['n']} correct · "
                  f"baseline {poison['baseline_correct']}/{poison['n']} correct."]

    lines += ["", "---", "",
              "_Generated by `python -m evals.benchmark`._"]
    return "\n".join(lines)


async def main() -> None:
    quick = "--quick" in sys.argv
    print("Running firewall (full pipeline)…")
    fw = await run_firewall(ablate_drift=False)
    print("Running signature baseline…")
    bl = run_baseline()

    systems = {"firewall": _metrics(fw), "baseline": _metrics(bl)}
    per_category = {"firewall": _by_category(fw), "baseline": _by_category(bl)}

    if not quick:
        print("Running ablation (intent/drift disabled)…")
        ab = await run_firewall(ablate_drift=True)
        systems["ablation"] = _metrics(ab)
        per_category["ablation"] = _by_category(ab)

    print("Scanning tool descriptions…")
    poison = await run_tool_poisoning()

    categories: dict = {}
    for row in fw:
        categories[row["category"]] = categories.get(row["category"], 0) + 1

    report = {
        "n_cases": len(fw), "categories": categories, "systems": systems,
        "per_category": per_category, "tool_poisoning": poison,
        "raw": {"firewall": fw, "baseline": bl},
    }

    (OUT_DIR / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown = _markdown(report)
    (OUT_DIR / "results.md").write_text(markdown, encoding="utf-8")

    print("\n" + markdown)
    print(f"\nWrote {OUT_DIR / 'results.json'} and {OUT_DIR / 'results.md'}")


if __name__ == "__main__":
    asyncio.run(main())
