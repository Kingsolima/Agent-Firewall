"""
The eval dataset: storage, labels, and the dev/held-out split.

Cases used to live as Python literals in cases.py. That caps the dataset at
whatever one person will type into a source file, and it made the labels a
property of the CATEGORY rather than of the case. Both limits are lifted here.

Three ideas are worth understanding before touching this file.

**Labels are per case, and they name a decision, not a class.**
Each case carries ``label`` in {allow, hold, block} — what the pipeline SHOULD
have decided. This matters most for the ambiguous cases: they were previously
lumped in as "should stop", which conflated "hold this for a human" with "block
this outright". A narrow-intent/broad-action mismatch with no injection is a
HOLD; treating it as a block overstates what the system is claiming.

Two metrics fall out, and they answer different questions:
  * ``should_stop``  — did the call leave the allow band at all? The binary
                       detection question, comparable against a signature scanner.
  * exact band match — did it land in the RIGHT band? Stricter, and the one that
                       reflects what a user actually experiences.

**``label_source`` records how a label was arrived at.**
``category`` means it was inherited from the case's group — convenient, but it
makes "accuracy on this category" partly a measure of agreement with the
author's own taxonomy. ``per_case`` means someone judged this specific case.
Keeping the distinction in the DATA means the limitation shows up in the report
automatically instead of relying on anyone remembering it.

**The split is deterministic, never random.**
``split`` is computed from a hash of the case id alone, so it is stable across
runs and machines with no seed to record, and — because each case is assigned
independently of every other — appending new cases never reshuffles the existing
ones. That stability is the property that matters: a split that moves when the
dataset grows silently leaks held-out cases into dev over time.

The cost is that balance across categories is only APPROXIMATE. Each category
lands near DEV_FRACTION in expectation, but at a few cases per category the
variance is visible (check it any time with ``python -m evals.dataset``, which
prints the per-category split). It tightens as the dataset grows. If a category
is ever badly skewed, the fix is to add cases, not to re-roll the split.

Tune on ``dev``; touch ``heldout`` only to report. A threshold chosen by looking
at held-out scores has silently converted the held-out set into another dev set.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Literal

from src.models import ToolCallRequest

DATA_DIR = Path(__file__).resolve().parent / "data"
CASES_FILE = DATA_DIR / "cases.jsonl"
TOOL_DESC_FILE = DATA_DIR / "tool_descriptions.jsonl"

Label = Literal["allow", "hold", "block"]
Split = Literal["dev", "heldout"]

# Fraction of each category routed to dev. The rest is held out.
DEV_FRACTION = 0.6


@dataclass
class EvalCase:
    id: str
    category: str
    tool_name: str
    tool_input: dict
    message_context: str
    label: Label = "allow"
    trigger_source: str = "internal"
    # How the label was arrived at: "per_case" (judged individually) or
    # "category" (inherited from the group). Surfaced in the report.
    label_source: str = "per_case"
    # Where the case came from: "authored", "synthetic", "harvested".
    source: str = "authored"
    # Which generator seed produced this case, for synthetic rows.
    #
    # This is the field that keeps the statistics honest. Expanding one scenario
    # into six variants gives six ROWS but nowhere near six independent
    # observations — if the pipeline misjudges the scenario it usually misjudges
    # every variant of it, so the errors arrive in clumps. Treating them as
    # independent would shrink the confidence intervals by roughly sqrt(variants)
    # and manufacture precision that was never measured. Recording the seed lets
    # the report cluster by it and report an effective sample size.
    #
    # Authored one-off cases leave this empty and are each their own cluster.
    seed_id: str = ""
    # Free-text justification. Worth writing for anything non-obvious — it is
    # what a second labeller needs in order to agree or disagree with you.
    rationale: str = ""
    blocked: bool = False        # feature not built (pii) -> excluded from runs
    _split: str | None = field(default=None, repr=False)

    @property
    def should_stop(self) -> bool:
        """Binary detection ground truth: should this have left the allow band?"""
        return self.label != "allow"

    @property
    def split(self) -> Split:
        """
        Deterministic assignment, hashed on the CLUSTER rather than the case id.

        Hashing per case would scatter variants of one seed across both sides of
        the split — and since those variants are near-duplicates, a threshold
        tuned on the dev copy is effectively tuned on the held-out copy too. That
        is leakage, and it is invisible in the metrics: the held-out score just
        comes out flatteringly high. Assigning by cluster keeps every variant of
        a scenario on the same side.

        Hashing (rather than shuffling with a seed) keeps the split reproducible
        anywhere with no state to record, and keeps it stable under append: a new
        seed lands on one side without moving anything already assigned.
        """
        if self._split:
            return self._split  # type: ignore[return-value]
        digest = hashlib.sha256(self.cluster.encode()).hexdigest()
        return "dev" if (int(digest[:8], 16) % 100) < DEV_FRACTION * 100 else "heldout"

    def request(self) -> ToolCallRequest:
        return ToolCallRequest(
            tool_name=self.tool_name,
            tool_input=self.tool_input,
            session_id=f"eval_{self.id}",
            agent_id="support-agent-1",
            workspace_id="T0EVAL",
            trigger_source=self.trigger_source,
            trigger_user_id="U_eval",
            message_context=self.message_context,
        )

    def to_json(self) -> dict:
        """Stable field order; optional fields omitted when at their default."""
        record = {
            "id": self.id,
            "category": self.category,
            "label": self.label,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "message_context": self.message_context,
            "trigger_source": self.trigger_source,
            "label_source": self.label_source,
            "source": self.source,
        }
        if self.seed_id:
            record["seed_id"] = self.seed_id
        if self.rationale:
            record["rationale"] = self.rationale
        if self.blocked:
            record["blocked"] = True
        return record

    @property
    def cluster(self) -> str:
        """
        The unit of independent observation.

        Variants of one seed share a cluster; an authored one-off is its own.
        Metrics should be aggregated over clusters, not rows — see seed_id.
        """
        return self.seed_id or self.id


@dataclass
class ToolDescCase:
    """A tools/list description, scored by the /scan path rather than /analyze."""
    id: str
    tool_name: str
    description: str
    should_flag: bool
    source: str = "authored"
    rationale: str = ""


def _read_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name} line {line_no}: {exc}") from exc


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_cases(split: Split | None = None, include_blocked: bool = False) -> list[EvalCase]:
    """
    Load cases, optionally restricted to one split.

    split=None returns everything — correct for exploratory work, WRONG for
    reporting a headline number, which should come from "heldout" alone.
    """
    cases = [EvalCase(**record) for record in _read_jsonl(CASES_FILE)]
    if not include_blocked:
        cases = [c for c in cases if not c.blocked]
    if split:
        cases = [c for c in cases if c.split == split]
    return cases


def load_tool_descriptions() -> list[ToolDescCase]:
    return [ToolDescCase(**record) for record in _read_jsonl(TOOL_DESC_FILE)]


def summarise(cases: list[EvalCase]) -> dict:
    """Counts by category, label, split and label_source — for sanity-checking."""
    def tally(key) -> dict:
        out: dict = {}
        for case in cases:
            out[key(case)] = out.get(key(case), 0) + 1
        return dict(sorted(out.items()))

    # Per-category split, so the approximate balance is inspectable rather than
    # assumed — see the note on the split in this module's docstring.
    split_by_category: dict = {}
    for case in cases:
        entry = split_by_category.setdefault(case.category, {"dev": 0, "heldout": 0})
        entry[case.split] += 1

    return {
        "total": len(cases),
        "by_category": tally(lambda c: c.category),
        "by_label": tally(lambda c: c.label),
        "by_split": tally(lambda c: c.split),
        "by_label_source": tally(lambda c: c.label_source),
        "by_source": tally(lambda c: c.source),
        "split_by_category": dict(sorted(split_by_category.items())),
        "positives": sum(1 for c in cases if c.should_stop),
        "negatives": sum(1 for c in cases if not c.should_stop),
    }


if __name__ == "__main__":
    print(json.dumps(summarise(load_cases()), indent=2))
