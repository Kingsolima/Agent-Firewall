"""
Turn a benchmark run into an honest report.

Split out of benchmark.py for one practical reason: rebuilding the writeup no
longer costs a full re-run. `python -m evals.report` regenerates results.md from
the scores already in results.json — no API calls, no waiting — so the wording
and the statistics can be iterated on freely.

Everything here is recomputed from the RAW PER-CASE SCORES at the current
config.ALLOW_MAX, never from the summary metrics stored alongside them. Those
summaries were computed at whatever threshold was in force when the benchmark
ran, and silently reporting them after the threshold moves is how a results
table ends up contradicting the code it describes.

What this adds over a plain metrics table:

  * confidence intervals on every rate, so the reader can see how much of the
    apparent difference between systems is measurement noise;
  * a paired (McNemar) comparison, which counts the cases where two systems
    actually disagreed instead of subtracting their summary scores;
  * a threshold-sensitivity section, because a metric quoted at one operating
    point hides whether that point is even on the efficient frontier;
  * an explicit limitations section, on the principle that a benchmark which
    does not state its own weaknesses is advertising rather than evidence.

    python -m evals.report
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from evals import baseline
from evals.stats import (
    clustered_interval,
    fmt_clustered,
    mcnemar,
    significance_note,
)
from evals.threshold_sweep import confusion, metrics, sweep
from src.pipeline.config import ALLOW_MAX

OUT_DIR = Path(__file__).resolve().parent
RESULTS_JSON = OUT_DIR / "results.json"
RESULTS_MD = OUT_DIR / "results.md"

LABELS = {
    "firewall": "**Agent Firewall**",
    "baseline": f"Signature baseline ({baseline.PATTERN_COUNT} patterns)",
    "ablation": "Ablation (no intent/drift)",
}
ORDER = ("firewall", "baseline", "ablation")


def metrics_from_raw(rows: list[dict]) -> dict:
    """Full metric set for one system, evaluated at the CURRENT threshold."""
    tp, fn, fp, tn = confusion(rows, ALLOW_MAX)
    rates = {k: round(v, 3) for k, v in metrics(tp, fn, fp, tn).items()}
    latencies = [r["ms"] for r in rows if r.get("ms")]
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "n": len(rows), **rates,
            "avg_latency_ms": round(sum(latencies) / len(latencies)) if latencies else 0}


def per_category_from_raw(rows: list[dict]) -> dict:
    out: dict = {}
    for row in rows:
        cat = out.setdefault(row["category"], {"n": 0, "correct": 0})
        cat["n"] += 1
        if (row["score"] > ALLOW_MAX) == row["truth"]:
            cat["correct"] += 1
    return out


def _correctness(rows: list[dict]) -> list[bool]:
    """Per-case correctness ordered by case id, so two systems line up pairwise."""
    return [(r["score"] > ALLOW_MAX) == r["truth"]
            for r in sorted(rows, key=lambda r: r["id"])]


def _stopped(row: dict) -> bool:
    return row["score"] > ALLOW_MAX


def _rate(rows: list[dict], subset, outcome) -> dict:
    """Clustered rate over the rows matching `subset`, scoring each by `outcome`."""
    by_cluster: dict[str, list[bool]] = {}
    for row in rows:
        if subset(row):
            key = row.get("cluster") or row["id"]
            by_cluster.setdefault(key, []).append(bool(outcome(row)))
    return clustered_interval(by_cluster)


def _headline_table(raw: dict) -> list[str]:
    lines = [
        "| System | Recall | FPR | Precision | Accuracy | Latency |",
        "|---|---|---|---|---|---|",
    ]
    for key, rows in raw.items():
        recall = _rate(rows, lambda r: r["truth"], _stopped)
        fpr = _rate(rows, lambda r: not r["truth"], _stopped)
        precision = _rate(rows, _stopped, lambda r: r["truth"])
        accuracy = _rate(rows, lambda r: True, lambda r: _stopped(r) == r["truth"])
        latencies = [r["ms"] for r in rows if r.get("ms")]
        avg_latency = round(sum(latencies) / len(latencies)) if latencies else 0
        lines.append(
            f"| {LABELS.get(key, key)} | {fmt_clustered(recall)} | {fmt_clustered(fpr)} "
            f"| {fmt_clustered(precision)} | {fmt_clustered(accuracy)} | {avg_latency} ms |")
    return lines + [
        "",
        "Rates are **clustered**: the dataset expands each scenario into several "
        "near-duplicate variants, so the unit of observation is the scenario, not the "
        "row. `k` is the number of scenarios behind each rate — the honest sample "
        "size. Row counts are larger and would produce intervals roughly "
        "`sqrt(variants-per-scenario)` too narrow.",
        "",
    ]


def _negatives_section(raw: dict) -> list[str]:
    """
    FPR split by how hard the negative is.

    An average over all negatives can be dragged down by easy cases — a set full
    of "search the refund policy" makes any system look calibrated. The category
    that decides real-world usability is `benign_scary`: legitimate work that
    looks alarming, or that quotes attack vocabulary because the user is doing
    security work. Reporting the two separately stops one hiding the other.
    """
    if "firewall" not in raw:
        return []

    categories = sorted({r["category"] for r in raw["firewall"] if not r["truth"]})
    if len(categories) < 2:
        return []

    lines = [
        "## False positives, by how hard the negative is",
        "",
        "`clean` is ordinary agent work. `benign_scary` is legitimate work that *looks* "
        "dangerous — GDPR exports, deleting build artefacts, posting to approved "
        "external services, or a security engineer whose query is itself full of "
        "injection vocabulary. The second number is the one that decides whether the "
        "tool survives contact with users.",
        "",
        "| System | " + " | ".join(f"FPR on `{c}`" for c in categories) + " |",
        "|---" * (len(categories) + 1) + "|",
    ]
    for key, rows in raw.items():
        cells = []
        for category in categories:
            rate = _rate(rows,
                         lambda r, c=category: not r["truth"] and r["category"] == c,
                         _stopped)
            cells.append(fmt_clustered(rate))
        lines.append(f"| {LABELS.get(key, key)} | " + " | ".join(cells) + " |")
    return lines + [""]


def _paired_section(raw: dict) -> list[str]:
    """McNemar for every pair we have per-case results for."""
    if "firewall" not in raw:
        return []

    lines = [
        "## Is the difference real? (paired comparison)",
        "",
        "Subtracting summary scores overstates how much evidence there is. McNemar's "
        "test looks only at the cases where two systems **disagreed** — cases both got "
        "right, or both got wrong, say nothing about which is better. The "
        "*disagreeing cases* column is the honest sample size behind each comparison.",
        "",
        "| Comparison | Firewall-only wins | Other-only wins | Disagreeing cases | Reading |",
        "|---|---|---|---|---|",
    ]
    firewall = _correctness(raw["firewall"])
    for other in ORDER:
        if other == "firewall" or other not in raw:
            continue
        result = mcnemar(firewall, _correctness(raw[other]))
        lines.append(
            f"| Firewall vs {LABELS.get(other, other)} | {result['a_wins']} "
            f"| {result['b_wins']} | {result['n_discordant']} "
            f"| {significance_note(result)} |")
    return lines + [""]


def _per_category_section(systems: dict, per_category: dict) -> list[str]:
    keys = list(systems)
    categories: dict = {}
    for cat, counts in per_category[keys[0]].items():
        categories[cat] = counts["n"]

    lines = ["## Per-category accuracy", "",
             "| Category | n | " + " | ".join(LABELS.get(k, k) for k in keys) + " |",
             "|---" * (len(keys) + 2) + "|"]
    for cat, n in categories.items():
        row = [cat, str(n)]
        for key in keys:
            per = per_category[key].get(cat, {"n": 0, "correct": 0})
            row.append(f"{per['correct']}/{per['n']}")
        lines.append("| " + " | ".join(row) + " |")
    return lines + [""]


def _threshold_section(raw: dict) -> list[str]:
    if "firewall" not in raw:
        return []

    bands = sweep(raw["firewall"])
    current = next(b for b in bands if b["lo"] <= ALLOW_MAX <= b["hi"])
    best_accuracy = max(bands, key=lambda b: b["accuracy"])
    best_fpr = min(bands, key=lambda b: (b["fpr"], -b["recall"]))
    best_recall = max(bands, key=lambda b: (b["recall"], -b["fpr"]))

    lines = [
        "## Threshold sensitivity",
        "",
        f"`ALLOW_MAX` is currently **{ALLOW_MAX:g}**. Every number above is a property of "
        "that choice as much as of the model, so here is what other choices would have "
        "done to the same scores:",
        "",
        "| Threshold band | Recall | FPR | Accuracy | |",
        "|---|---|---|---|---|",
    ]
    # One band can win on several criteria at once (max recall AND max accuracy);
    # collect the notes per band so it appears as a single row.
    notes: dict[tuple[int, int], list[str]] = {}
    bands_by_key: dict[tuple[int, int], dict] = {}
    for band, note in ((best_recall, "max recall"), (current, "**current**"),
                       (best_accuracy, "max accuracy"), (best_fpr, "min FPR")):
        key = (band["lo"], band["hi"])
        bands_by_key[key] = band
        if note not in notes.setdefault(key, []):
            notes[key].append(note)

    for key in sorted(bands_by_key, key=lambda k: k[0]):
        band = bands_by_key[key]
        lines.append(f"| {band['lo']}-{band['hi']} | {band['recall']:.2f} "
                     f"| {band['fpr']:.2f} | {band['accuracy']:.2f} "
                     f"| {', '.join(notes[key])} |")

    width = best_fpr["hi"] - best_fpr["lo"] + 1
    lines += [
        "",
        f"The lowest-FPR band is only **{width} points wide**, and it was located by "
        "looking at these very cases. Adopting it would be fitting the threshold to the "
        "test set, so it is recorded as a hypothesis for the held-out set rather than a "
        "setting to ship. Full curve: `python -m evals.threshold_sweep`.",
        "",
    ]
    return lines


def _limitations(raw: dict, split: str) -> list[str]:
    rows = raw.get("firewall", [])
    negatives = [r for r in rows if not r["truth"]]
    positives = [r for r in rows if r["truth"]]
    neg_clusters = len({r.get("cluster") or r["id"] for r in negatives})
    pos_clusters = len({r.get("cluster") or r["id"] for r in positives})
    # Synthetic rows are the expanded ones, identifiable by their "<seed>_<nn>"
    # ids; authored one-offs have a single underscore ("clean_01").
    synthetic = sum(1 for r in rows if str(r.get("id", "")).count("_") >= 2)
    category_labelled = sum(1 for r in rows if r.get("label_source") == "category")

    lines = [
        "## Limitations",
        "",
        "Stated plainly, because a benchmark that hides these is marketing:",
        "",
        f"1. **Effective sample size is scenarios, not rows.** {len(negatives)} negative "
        f"rows come from {neg_clusters} distinct scenarios, and {len(positives)} positive "
        f"rows from {pos_clusters}. Every interval above is computed on the scenario "
        "count. Quoting the row count as the sample size would overstate the precision "
        f"by roughly {(len(rows) / max(1, neg_clusters + pos_clusters)) ** 0.5:.1f}x.",
        f"2. **{synthetic} of {len(rows)} cases are synthetic.** No real tool traffic was "
        "available — the `audit_log` table has never been created in this project — so "
        "those cases are invented, and they encode the author's guess about what agents "
        "do rather than a measurement of it. Harvested traffic would be strictly better "
        "evidence and would move these numbers in unknown directions.",
        "3. **The cases were written by the author of the system**, so they are shaped by "
        "what it was built to catch. An independent source — a public benchmark, or a "
        "second person writing cases blind — would test something this set cannot.",
    ]
    if category_labelled:
        lines.append(
            f"4. **{category_labelled} cases carry category-inherited labels** rather than "
            "a per-case judgement, so accuracy on those measures agreement with the "
            "author's taxonomy as much as correctness.")
    lines += [
        f"{5 if category_labelled else 4}. **Class balance is unrealistic.** "
        f"{len(positives)} of {len(rows)} rows are attacks; real tool traffic is "
        "overwhelmingly benign. Precision measured here will be far higher than in "
        "deployment, where even a small FPR is multiplied across thousands of legitimate "
        "calls. FPR, not precision, is the number that transfers.",
    ]
    if split != "heldout":
        lines.append(
            f"{6 if category_labelled else 5}. **This run used the `{split}` split.** "
            "Any threshold or weight tuned against these same cases makes the numbers "
            "in-sample. Report from `python -m evals.benchmark --split heldout`.")
    return lines + [""]


def _staleness_banner(n_cases: int, split: str) -> list[str]:
    """
    Warn when results.json was produced from a smaller dataset than exists now.

    Adding cases without re-running leaves a results file that is not wrong about
    what it measured, but IS wrong as an answer to "how does the system score" —
    and nothing in the numbers themselves reveals the gap. Checking the current
    dataset on every render makes that failure loud instead of silent.
    """
    try:
        from evals.dataset import load_cases
        available = len(load_cases(split=None if split == "all" else split))
    except Exception:  # noqa: BLE001 — a report must still render without the dataset
        return []

    if available <= n_cases:
        return []

    return [
        f"> **These numbers are out of date.** They were produced from {n_cases} cases, "
        f"but the `{split}` split now holds {available}. Re-run "
        f"`python -m evals.benchmark --split {split}` to refresh.",
        "",
    ]


def build_markdown(report: dict) -> str:
    raw = {k: report["raw"][k] for k in ORDER if k in report.get("raw", {})}
    if not raw:
        raise ValueError("results.json has no per-case rows; re-run `python -m evals.benchmark`")

    systems = {k: metrics_from_raw(v) for k, v in raw.items()}
    per_category = {k: per_category_from_raw(v) for k, v in raw.items()}
    n_cases = systems["firewall"]["n"] if "firewall" in systems else len(next(iter(raw.values())))

    split = str(report.get("split", "all"))
    first = raw[next(iter(raw))]
    n_clusters = len({r.get("cluster") or r["id"] for r in first})

    lines = [
        "# Evaluation results",
        "",
        *_staleness_banner(n_cases, split),
        f"{n_cases} tool calls from {n_clusters} distinct scenarios, across "
        f"{len(per_category[next(iter(raw))])} categories, on the **{split}** split. "
        f"A call counts as *stopped* when it leaves the allow band (score > "
        f"`ALLOW_MAX` = {ALLOW_MAX:g}). **FPR** is the share of legitimate calls "
        "wrongly stopped.",
        "",
        "Every rate carries a 95% confidence interval. Read the intervals before the "
        "point estimates: a gap between two systems that is narrower than the intervals "
        "around it has not been measured, only observed.",
        "",
    ]
    lines += _headline_table(raw)
    lines += _negatives_section(raw)
    lines += _paired_section(raw)
    lines += _per_category_section(systems, per_category)
    lines += _threshold_section(raw)

    poison = report.get("tool_poisoning")
    if poison:
        lines += ["## Tool-description poisoning (tools/list)", "",
                  f"Firewall {poison['firewall_correct']}/{poison['n']} correct, "
                  f"baseline {poison['baseline_correct']}/{poison['n']} correct. "
                  "Six cases — a smoke test, not a measurement.", ""]

    lines += _limitations(raw, str(report.get("split", "all")))
    lines += ["---", "", "_Generated by `python -m evals.report` from `results.json`._"]
    return "\n".join(lines)


def _filter_split(report: dict, split: str) -> dict:
    """
    Narrow an existing run to one split.

    Lets a single (expensive) benchmark over every case produce both the dev view
    and the held-out view, without re-scoring anything. The rows already carry
    their split, so this is pure bookkeeping.
    """
    filtered = {k: [r for r in rows if r.get("split") == split]
                for k, rows in report.get("raw", {}).items()}
    missing = [k for k, rows in filtered.items() if not rows]
    if missing:
        raise SystemExit(f"no rows in split {split!r} for: {', '.join(missing)}")
    return {**report, "raw": filtered, "split": split,
            "n_cases": len(next(iter(filtered.values())))}


def main() -> None:
    report = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))

    out_path = RESULTS_MD
    for i, arg in enumerate(sys.argv):
        if arg == "--split" and i + 1 < len(sys.argv):
            split = sys.argv[i + 1]
            if split not in ("dev", "heldout"):
                raise SystemExit("--split must be dev or heldout")
            report = _filter_split(report, split)
            out_path = OUT_DIR / f"results-{split}.md"

    markdown = build_markdown(report)
    out_path.write_text(markdown, encoding="utf-8")
    # Deliberately not echoing the markdown: Windows consoles default to cp1252
    # and would mangle the en-dashes that are written correctly to the file.
    print(f"Wrote {out_path} ({len(markdown.splitlines())} lines)")


if __name__ == "__main__":
    main()
