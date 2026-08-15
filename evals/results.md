# Evaluation results

504 tool calls from 146 distinct scenarios, across 5 categories, on the **all** split. A call counts as *stopped* when it leaves the allow band (score > `ALLOW_MAX` = 30). **FPR** is the share of legitimate calls wrongly stopped.

Every rate carries a 95% confidence interval. Read the intervals before the point estimates: a gap between two systems that is narrower than the intervals around it has not been measured, only observed.

| System | Recall | FPR | Precision | Accuracy | Latency |
|---|---|---|---|---|---|
| **Agent Firewall** | 0.87 (0.79-0.94, k=67) | 0.12 (0.06-0.18, k=79) | 0.79 (0.70-0.88, k=77) | 0.87 (0.83-0.92, k=146) | 7708 ms |
| Signature baseline (39 patterns) | 0.50 (0.38-0.62, k=67) | 0.13 (0.05-0.20, k=79) | 0.77 (0.65-0.90, k=44) | 0.70 (0.63-0.78, k=146) | 0 ms |
| Ablation (no intent/drift) | 0.66 (0.55-0.78, k=67) | 0.06 (0.01-0.11, k=79) | 0.87 (0.77-0.96, k=52) | 0.81 (0.75-0.87, k=146) | 6797 ms |

Rates are **clustered**: the dataset expands each scenario into several near-duplicate variants, so the unit of observation is the scenario, not the row. `k` is the number of scenarios behind each rate — the honest sample size. Row counts are larger and would produce intervals roughly `sqrt(variants-per-scenario)` too narrow.

## False positives, by how hard the negative is

`clean` is ordinary agent work. `benign_scary` is legitimate work that *looks* dangerous — GDPR exports, deleting build artefacts, posting to approved external services, or a security engineer whose query is itself full of injection vocabulary. The second number is the one that decides whether the tool survives contact with users.

| System | FPR on `benign_scary` | FPR on `clean` |
|---|---|---|
| **Agent Firewall** | 0.23 (0.11-0.34, k=39) | 0.02 (0.00-0.04, k=40) |
| Signature baseline (39 patterns) | 0.26 (0.12-0.40, k=39) | 0.00 (0.00-0.00, k=40) |
| Ablation (no intent/drift) | 0.12 (0.03-0.22, k=39) | 0.01 (0.00-0.01, k=40) |

## Is the difference real? (paired comparison)

Subtracting summary scores overstates how much evidence there is. McNemar's test looks only at the cases where two systems **disagreed** — cases both got right, or both got wrong, say nothing about which is better. The *disagreeing cases* column is the honest sample size behind each comparison.

| Comparison | Firewall-only wins | Other-only wins | Disagreeing cases | Reading |
|---|---|---|---|---|
| Firewall vs Signature baseline (39 patterns) | 101 | 23 | 124 | unlikely to be chance (p=0.000, on 124 disagreeing cases) |
| Firewall vs Ablation (no intent/drift) | 37 | 23 | 60 | suggestive, not conclusive (p=0.092, on 60 disagreeing cases) |

## Per-category accuracy

| Category | n | **Agent Firewall** | Signature baseline (39 patterns) | Ablation (no intent/drift) |
|---|---|---|---|---|
| clean | 160 | 157/160 | 160/160 | 159/160 |
| attack | 50 | 50/50 | 46/50 | 50/50 |
| ambiguous | 63 | 35/63 | 0/63 | 0/63 |
| benign_scary | 159 | 127/159 | 121/159 | 147/159 |
| taint | 72 | 70/72 | 34/72 | 69/72 |

## Threshold sensitivity

`ALLOW_MAX` is currently **30**. Every number above is a property of that choice as much as of the model, so here is what other choices would have done to the same scores:

| Threshold band | Recall | FPR | Accuracy | |
|---|---|---|---|---|
| 5-6 | 1.00 | 0.45 | 0.71 | max recall |
| 30-30 | 0.84 | 0.11 | 0.87 | **current** |
| 41-41 | 0.75 | 0.01 | 0.90 | max accuracy |
| 45-45 | 0.62 | 0.00 | 0.86 | min FPR |

The lowest-FPR band is only **1 points wide**, and it was located by looking at these very cases. Adopting it would be fitting the threshold to the test set, so it is recorded as a hypothesis for the held-out set rather than a setting to ship. Full curve: `python -m evals.threshold_sweep`.

## Tool-description poisoning (tools/list)

Firewall 6/6 correct, baseline 6/6 correct. Six cases — a smoke test, not a measurement.

## Limitations

Stated plainly, because a benchmark that hides these is marketing:

1. **Effective sample size is scenarios, not rows.** 319 negative rows come from 79 distinct scenarios, and 185 positive rows from 67. Every interval above is computed on the scenario count. Quoting the row count as the sample size would overstate the precision by roughly 1.9x.
2. **462 of 504 cases are synthetic.** No real tool traffic was available — the `audit_log` table has never been created in this project — so those cases are invented, and they encode the author's guess about what agents do rather than a measurement of it. Harvested traffic would be strictly better evidence and would move these numbers in unknown directions.
3. **The cases were written by the author of the system**, so they are shaped by what it was built to catch. An independent source — a public benchmark, or a second person writing cases blind — would test something this set cannot.
4. **42 cases carry category-inherited labels** rather than a per-case judgement, so accuracy on those measures agreement with the author's taxonomy as much as correctness.
5. **Class balance is unrealistic.** 185 of 504 rows are attacks; real tool traffic is overwhelmingly benign. Precision measured here will be far higher than in deployment, where even a small FPR is multiplied across thousands of legitimate calls. FPR, not precision, is the number that transfers.
6. **This run used the `all` split.** Any threshold or weight tuned against these same cases makes the numbers in-sample. Report from `python -m evals.benchmark --split heldout`.

---

_Generated by `python -m evals.report` from `results.json`._