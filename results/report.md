# Active ACH matched-state test: results

- Model: claude-sonnet-5-5
- Run started (UTC): 2026-10-21T04:59:39.689560+00:00
- Repetitions per state: 5; thinking: between_tools; temperature: model default; cost-weighted EIG: True
- State-reps completed: 60 of 60; failed: 0; stopped for budget: False
- Spent: $2.72 (cap $4.50)
- Scenario file SHA-256: bfcda443c4aeb8000dbb72e3ddced20fe10c18c31d020bf604d2cb225b7b5809

## Nonredundant diagnostic rate by scenario

| Scenario | Truth | State-reps | Chance | A2 (LLM selects) | A3 (controller) | A3 âˆ’ A2 | Same pick | A2 invalid | Calibration log-loss |
|---|---|---|---|---|---|---|---|---|---|
| SC-01 | malicious | 10 | 0.30 | 1.00 | 1.00 | +0.00 | 0.70 | 0 | 0.48 |
| SC-02 | benign | 10 | 0.45 | 0.80 | 0.60 | -0.20 | 0.60 | 0 | 0.72 |
| SC-03 | malicious | 10 | 0.45 | 0.50 | 0.50 | +0.00 | 1.00 | 0 | 0.50 |
| SC-04 | benign | 10 | 0.62 | 1.00 | 1.00 | +0.00 | 0.60 | 0 | 0.49 |
| SC-05 | malicious | 10 | 0.60 | 1.00 | 1.00 | +0.00 | 0.50 | 0 | 0.46 |
| SC-06 | benign | 10 | 0.62 | 1.00 | 1.00 | +0.00 | 0.40 | 0 | 0.57 |

## Across scenarios (scenario is the unit)

- Scenarios where A3 > A2: 0; equal: 5; A3 < A2: 1
- Mean scenario-level diagnostic rate: A2 0.88, A3 0.85, chance 0.51
- Mean change in probability of the true label after the selected query: A2 0.342, A3 0.339
- Share of state-reps where the model generated a hypothesis with the true label: 1.00
- Mean A3 minus A2 in better-calibrated scenarios (log-loss at or below median 0.49): 0.00 (n = 3)
- Mean A3 minus A2 in worse-calibrated scenarios: -0.07 (n = 3)

## How to read this

- Results are descriptive. With few scenarios, no significance tests are reported.
- 'Chance' is the share of candidate queries that are nonredundant-diagnostic, i.e. what random selection would score.
- Calibration is the mean log-loss (bits) of the reference outcomes under the model's true-label hypotheses; lower means the model predicted the evidence better. DP1 expects the controller to help most when calibration is good.
- Full prompts and raw model outputs for every call are in runs.jsonl.
