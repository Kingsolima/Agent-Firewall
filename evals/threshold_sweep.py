"""
Threshold sweep — is ALLOW_MAX in the right place?

The pipeline scores every call 0-100, and config.ALLOW_MAX draws a line on that
scale: above it we stop the call, below it we let it through. That line is a
CHOICE. This script asks what every other choice would have done.

It re-reads the scores already saved in results.json — no API calls, no
re-running the pipeline. Each candidate threshold is replayed against the same
42 cases to produce a full confusion matrix, so you can see the precision /
recall / FPR trade-off the current setting is buying you.

Two things to look for in the output:

  1. Is the current line on the efficient frontier at all? A threshold is
     DOMINATED if some other threshold beats it on every metric at once. A
     dominated setting is a straightforward bug: you are giving up accuracy
     and getting nothing for it.

  2. How WIDE is the winning band? If the best threshold sits in a 5-point gap
     that happens to be empty in 42 samples, you have not found the right
     threshold — you have found a gap in a small sample. The width of that band
     is a direct readout of how much you can trust the answer, and the honest
     response to a narrow one is to collect more data, not to ship the number.

    python -m evals.threshold_sweep
"""
from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.config import ALLOW_MAX

RESULTS = Path(__file__).resolve().parent / "results.json"


def confusion(rows: list[dict], threshold: float) -> tuple[int, int, int, int]:
    """
    Replay one threshold against every case.

    A case is 'stopped' if its score is above the line. It is a true positive
    when we stopped something that deserved it, a false positive when we
    stopped something legitimate, and so on.
    """
    tp = fn = fp = tn = 0
    for row in rows:
        stopped = row["score"] > threshold
        if row["truth"] and stopped:
            tp += 1
        elif row["truth"] and not stopped:
            fn += 1
        elif not row["truth"] and stopped:
            fp += 1
        else:
            tn += 1
    return tp, fn, fp, tn


def metrics(tp: int, fn: int, fp: int, tn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fn + fp + tn)
    return {"precision": precision, "recall": recall, "fpr": fpr,
            "f1": f1, "accuracy": accuracy}


def sweep(rows: list[dict]) -> list[dict]:
    """
    Walk the threshold from 0 to 100 and collapse runs that behave identically.

    Most thresholds change nothing — moving the line from 50 to 51 only matters
    if some case scored between them. Collapsing gives one row per DISTINCT
    behaviour, and the 'lo-hi' range on that row is the band of thresholds that
    all produce it. A wide band is a robust choice; a narrow one is a coincidence.
    """
    bands: list[dict] = []
    for threshold in range(0, 101):
        counts = confusion(rows, float(threshold))
        if bands and bands[-1]["counts"] == counts:
            bands[-1]["hi"] = threshold          # same behaviour, extend the band
        else:
            bands.append({"lo": threshold, "hi": threshold, "counts": counts,
                          **metrics(*counts)})
    return bands


def print_table(name: str, rows: list[dict]) -> None:
    bands = sweep(rows)

    # The reference points we want flagged in the output.
    best_accuracy = max(bands, key=lambda b: b["accuracy"])
    # Lowest FPR, breaking ties toward the band that keeps the most recall.
    best_fpr = min(bands, key=lambda b: (b["fpr"], -b["recall"]))
    current = next(b for b in bands if b["lo"] <= ALLOW_MAX <= b["hi"])

    print(f"\n{'=' * 78}\n{name}\n{'=' * 78}")
    print(f"{'threshold':>12}  {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3}  "
          f"{'prec':>5} {'recall':>6} {'FPR':>5} {'F1':>5} {'acc':>5}")

    for band in bands:
        tp, fn, fp, tn = band["counts"]
        span = f"{band['lo']:>3}" if band["lo"] == band["hi"] else f"{band['lo']:>3}-{band['hi']:<3}"
        notes = []
        if band is current:
            notes.append("<- CURRENT")
        if band is best_accuracy:
            notes.append("best accuracy")
        if band is best_fpr:
            notes.append("best FPR")
        print(f"{span:>12}  {tp:>3} {fn:>3} {fp:>3} {tn:>3}  "
              f"{band['precision']:>5.2f} {band['recall']:>6.2f} {band['fpr']:>5.2f} "
              f"{band['f1']:>5.2f} {band['accuracy']:>5.2f}  {'  '.join(notes)}")

    # A threshold is dominated if another one is at least as good on every
    # metric and strictly better on one. That is a free win being left unclaimed.
    dominators = [
        b for b in bands
        if b is not current
        and b["accuracy"] >= current["accuracy"]
        and b["fpr"] <= current["fpr"]
        and b["recall"] >= current["recall"]
        and (b["accuracy"] > current["accuracy"] or b["fpr"] < current["fpr"]
             or b["recall"] > current["recall"])
    ]

    print(f"\n  Current ALLOW_MAX = {ALLOW_MAX:g}  ->  band {current['lo']}-{current['hi']}, "
          f"FPR {current['fpr']:.2f}, recall {current['recall']:.2f}, "
          f"accuracy {current['accuracy']:.2f}")
    if dominators:
        best = max(dominators, key=lambda b: b["accuracy"])
        print(f"  DOMINATED: threshold {best['lo']}-{best['hi']} is at least as good on "
              f"every metric\n             (FPR {best['fpr']:.2f}, recall {best['recall']:.2f}, "
              f"accuracy {best['accuracy']:.2f}).")
    else:
        print("  Not dominated - the current setting is a real trade-off, not a free loss.")

    width = best_fpr["hi"] - best_fpr["lo"] + 1
    print(f"  Lowest-FPR band is {width} point(s) wide ({best_fpr['lo']}-{best_fpr['hi']}), "
          f"chosen on {len(rows)} cases.")
    if width <= 10:
        print("  WARNING: that band is narrow. On a sample this small it may be an empty "
              "gap rather\n           than a real separation - treat it as a hypothesis to "
              "test on held-out\n           data, not a setting to ship.")


def main() -> None:
    report = json.loads(RESULTS.read_text(encoding="utf-8"))
    print_table("FIREWALL (full pipeline)", report["raw"]["firewall"])
    print_table("SIGNATURE BASELINE", report["raw"]["baseline"])


if __name__ == "__main__":
    main()
