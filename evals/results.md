# Evaluation results

> **These numbers are out of date.** They were produced from 42 cases, but the `all` split now holds 504. Re-run `python -m evals.benchmark --split all` to refresh.

42 tool calls from 42 distinct scenarios, across 5 categories, on the **all** split. A call counts as *stopped* when it leaves the allow band (score > `ALLOW_MAX` = 20). **FPR** is the share of legitimate calls wrongly stopped.

Every rate carries a 95% confidence interval. Read the intervals before the point estimates: a gap between two systems that is narrower than the intervals around it has not been measured, only observed.

| System | Recall | FPR | Precision | Accuracy | Latency |
|---|---|---|---|---|---|
| **Agent Firewall** | 0.96 (0.87-1.00, k=23) | 0.21 (0.02-0.40, k=19) | 0.85 (0.70-0.99, k=26) | 0.88 (0.78-0.98, k=42) | 8412 ms |
| Signature baseline (39 patterns) | 0.61 (0.40-0.81, k=23) | 0.16 (0.00-0.33, k=19) | 0.82 (0.64-1.00, k=17) | 0.71 (0.58-0.85, k=42) | 0 ms |

Rates are **clustered**: the dataset expands each scenario into several near-duplicate variants, so the unit of observation is the scenario, not the row. `k` is the number of scenarios behind each rate — the honest sample size. Row counts are larger and would produce intervals roughly `sqrt(variants-per-scenario)` too narrow.

## False positives, by how hard the negative is

`clean` is ordinary agent work. `benign_scary` is legitimate work that *looks* dangerous — GDPR exports, deleting build artefacts, posting to approved external services, or a security engineer whose query is itself full of injection vocabulary. The second number is the one that decides whether the tool survives contact with users.

| System | FPR on `benign_scary` | FPR on `clean` |
|---|---|---|
| **Agent Firewall** | 0.33 (0.01-0.66, k=9) | 0.10 (0.00-0.30, k=10) |
| Signature baseline (39 patterns) | 0.33 (0.01-0.66, k=9) | 0.00 (0.00-0.00, k=10) |

## Is the difference real? (paired comparison)

Subtracting summary scores overstates how much evidence there is. McNemar's test looks only at the cases where two systems **disagreed** — cases both got right, or both got wrong, say nothing about which is better. The *disagreeing cases* column is the honest sample size behind each comparison.

| Comparison | Firewall-only wins | Other-only wins | Disagreeing cases | Reading |
|---|---|---|---|---|
| Firewall vs Signature baseline (39 patterns) | 8 | 1 | 9 | unlikely to be chance (p=0.039, on 9 disagreeing cases) |

## Per-category accuracy

| Category | n | **Agent Firewall** | Signature baseline (39 patterns) |
|---|---|---|---|
| clean | 10 | 9/10 | 10/10 |
| attack | 8 | 8/8 | 8/8 |
| ambiguous | 7 | 6/7 | 0/7 |
| benign_scary | 9 | 6/9 | 6/9 |
| taint | 8 | 8/8 | 6/8 |

## Threshold sensitivity

`ALLOW_MAX` is currently **20**. Every number above is a property of that choice as much as of the model, so here is what other choices would have done to the same scores:

| Threshold band | Recall | FPR | Accuracy | |
|---|---|---|---|---|
| 9-16 | 1.00 | 0.26 | 0.88 | max recall, max accuracy |
| 18-20 | 0.96 | 0.21 | 0.88 | **current** |
| 35-39 | 0.78 | 0.00 | 0.88 | min FPR |

The lowest-FPR band is only **5 points wide**, and it was located by looking at these very cases. Adopting it would be fitting the threshold to the test set, so it is recorded as a hypothesis for the held-out set rather than a setting to ship. Full curve: `python -m evals.threshold_sweep`.

## Tool-description poisoning (tools/list)

Firewall 6/6 correct, baseline 6/6 correct. Six cases — a smoke test, not a measurement.

## Limitations

Stated plainly, because a benchmark that hides these is marketing:

1. **Effective sample size is scenarios, not rows.** 19 negative rows come from 19 distinct scenarios, and 23 positive rows from 23. Every interval above is computed on the scenario count. Quoting the row count as the sample size would overstate the precision by roughly 1.0x.
2. **0 of 42 cases are synthetic.** No real tool traffic was available — the `audit_log` table has never been created in this project — so those cases are invented, and they encode the author's guess about what agents do rather than a measurement of it. Harvested traffic would be strictly better evidence and would move these numbers in unknown directions.
3. **The cases were written by the author of the system**, so they are shaped by what it was built to catch. An independent source — a public benchmark, or a second person writing cases blind — would test something this set cannot.
4. **Class balance is unrealistic.** 23 of 42 rows are attacks; real tool traffic is overwhelmingly benign. Precision measured here will be far higher than in deployment, where even a small FPR is multiplied across thousands of legitimate calls. FPR, not precision, is the number that transfers.
5. **This run used the `all` split.** Any threshold or weight tuned against these same cases makes the numbers in-sample. Report from `python -m evals.benchmark --split heldout`.

---

_Generated by `python -m evals.report` from `results.json`._