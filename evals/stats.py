"""
The two statistics that decide whether an eval result means anything.

Summary metrics like "FPR 0.21" invite a precision the sample size does not
support. These two functions put that back in the open:

  wilson_interval — the range a rate could plausibly be, given how few samples
                    it was measured on. 4/19 is not "21%"; it is "somewhere
                    between 8% and 44%, probably".

  mcnemar         — whether system A really beats system B, by looking only at
                    the cases where they DISAGREE. Cases both got right (or both
                    got wrong) carry no information about which is better, and
                    including them in a comparison hides how thin the evidence is.

Both are deliberately small and dependency-free; neither needs scipy.
"""
from __future__ import annotations

import math

# 1.959964 = the z-score for 95% coverage under a normal approximation.
Z_95 = 1.959964


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """
    95% confidence interval for a proportion, by Wilson's method.

    Why Wilson and not the textbook p +/- 1.96*sqrt(p(1-p)/n): the textbook
    ("Wald") interval breaks down at exactly the sizes we care about. With 0
    failures out of 19 it reports the interval [0, 0] — claiming certainty from
    19 samples. Wilson stays sensible at small n and at rates near 0 or 1, which
    is the entire regime this eval lives in.

    Returns (low, high), each clamped to [0, 1].
    """
    if n == 0:
        return (0.0, 1.0)          # no data == no information, not zero risk

    p = successes / n
    denominator = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denominator
    half_width = (z / denominator) * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2))
    return (max(0.0, centre - half_width), min(1.0, centre + half_width))


def fmt_ci(successes: int, n: int, decimals: int = 2) -> str:
    """Render a rate with its interval, e.g. '0.21 (0.08-0.44)'."""
    if n == 0:
        return "n/a"
    low, high = wilson_interval(successes, n)
    rate = successes / n
    return f"{rate:.{decimals}f} ({low:.{decimals}f}-{high:.{decimals}f})"


def clustered_interval(outcomes_by_cluster: dict[str, list[bool]]) -> dict:
    """
    A rate and 95% interval where the unit of observation is the CLUSTER.

    Needed because the dataset expands each scenario into several variants. Those
    variants are near-duplicates: if the pipeline misjudges the scenario it
    usually misjudges every variant, so errors arrive in clumps rather than
    independently. Treating 462 rows as 462 observations would shrink the
    interval by roughly sqrt(variants-per-seed) and report a precision that was
    never measured.

    Two things follow from clustering, and both matter:

      * The POINT ESTIMATE is the mean of the per-cluster rates, not the raw row
        proportion. Row-weighting would let a scenario with six variants count
        six times as much as one with three, which is an artefact of generation,
        not evidence.
      * The INTERVAL uses the spread BETWEEN cluster means with n = number of
        clusters, so it reflects how much scenarios disagree with each other.

    Returns rate, low, high, and k (clusters) — k is the honest sample size and
    belongs in the report next to the number.
    """
    clusters = [c for c in outcomes_by_cluster.values() if c]
    k = len(clusters)
    if k == 0:
        return {"rate": 0.0, "low": 0.0, "high": 1.0, "k": 0, "n_rows": 0}

    n_rows = sum(len(c) for c in clusters)
    means = [sum(outcomes) / len(outcomes) for outcomes in clusters]
    rate = sum(means) / k

    if k == 1:
        # One cluster carries no information about between-scenario spread; fall
        # back to the row-level interval rather than implying certainty.
        low, high = wilson_interval(round(rate * n_rows), n_rows)
        return {"rate": rate, "low": low, "high": high, "k": k, "n_rows": n_rows}

    variance = sum((m - rate) ** 2 for m in means) / (k - 1)
    standard_error = math.sqrt(variance / k)
    return {"rate": rate,
            "low": max(0.0, rate - Z_95 * standard_error),
            "high": min(1.0, rate + Z_95 * standard_error),
            "k": k, "n_rows": n_rows}


def fmt_clustered(result: dict, decimals: int = 2) -> str:
    """Render a clustered rate, e.g. '0.07 (0.03-0.11, k=79)'."""
    if result["k"] == 0:
        return "n/a"
    return (f"{result['rate']:.{decimals}f} "
            f"({result['low']:.{decimals}f}-{result['high']:.{decimals}f}, "
            f"k={result['k']})")


def mcnemar(a_correct: list[bool], b_correct: list[bool]) -> dict:
    """
    Paired comparison of two systems judged on the SAME cases.

    Build the two disagreement counts:
        b_only = cases A got right and B got wrong  (A's wins)
        c_only = cases A got wrong and B got right  (B's wins)

    Cases where both agree are discarded — they tell you the cases were easy or
    hard, not which system is better. The test then asks a simple question: if
    the two systems were equally good, each disagreement would fall either way
    like a coin flip. How surprising is the split we actually observed?

    Uses the EXACT binomial test rather than the chi-square approximation,
    because at these counts (single digits) the approximation is not valid.

    Returns the counts, the p-value, and the number of informative cases. A
    small n_discordant is the real message: it says the comparison rests on a
    handful of cases no matter how the p-value lands.
    """
    if len(a_correct) != len(b_correct):
        raise ValueError("paired comparison needs the same cases in the same order")

    a_wins = sum(1 for a, b in zip(a_correct, b_correct) if a and not b)
    b_wins = sum(1 for a, b in zip(a_correct, b_correct) if b and not a)
    n = a_wins + b_wins

    if n == 0:
        p_value = 1.0            # the systems never disagreed; nothing to test
    else:
        # Two-sided exact test: probability of a split at least this lopsided.
        tail = sum(math.comb(n, k) for k in range(0, min(a_wins, b_wins) + 1))
        p_value = min(1.0, 2 * tail / (2**n))

    return {"a_wins": a_wins, "b_wins": b_wins, "n_discordant": n,
            "p_value": round(p_value, 4)}


def significance_note(result: dict) -> str:
    """A plain-language reading of a McNemar result, for the report."""
    n, p = result["n_discordant"], result["p_value"]
    if n == 0:
        return "the systems never disagreed"
    if p < 0.05:
        verdict = "unlikely to be chance"
    elif p < 0.20:
        verdict = "suggestive, not conclusive"
    else:
        verdict = "indistinguishable from chance"
    return f"{verdict} (p={p:.3f}, on {n} disagreeing case{'s' if n != 1 else ''})"
