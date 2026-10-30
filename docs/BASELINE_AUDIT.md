# Baseline audit (Phase A)

Written 2026-10-25 before any COVER code was added. Everything original is preserved, byte for byte, in `legacy/`.

## Architecture inventory (what was supplied)

| File | SHA-256 | What it is |
|---|---|---|
| `legacy/active_ach_experiment.py` | `528750ab…c2b32ccea` | Single-file harness. Matched-state A2 (LLM selects) vs A3 (cost-weighted EIG). Embeds six scenarios. Default model Sonnet 5.5. |
| `legacy/scenarios.json` | `9fc05d54…0f50955e` | An older/alternative version of the same six scenarios. |
| `legacy/requirements.txt` | `7e20c18a…a9234379` | `anthropic` |
| `docs_spec.md` | `6e965445…ac169d9` | The COVER v3 specification this revision implements. |

Per scenario: an alert, two initial evidence lines, 5–8 catalog queries (description, outcome set, cost) and two decision states (`s0` empty, `s1` with one query already observed). Hidden fields: `truth`, `reference_outcome`, `diagnostic`, `redundant_with`.

Pipeline: one generation call (hypotheses + outcome distributions per query × hypothesis), one A2 selection call, A3 computed from the same predictions, both scored against the hidden map. The legacy offline dry run (`run --fake`) completes (60 state-reps).

## Not present (spec items that could not be audited)

- No original raw runs (`runs.jsonl`), so the paper's 53/60, 51/60 and 38/60 **cannot be reproduced or audited**.
- No record of which model or which scenario version produced the paper's numbers.
- No human investigation workbook (12 investigations, 6 analysts). Nothing in this package is human data.
- No telemetry, SQL/Sigma queries, schemas or log data. Evidence checks are catalog items; "execution" is a **simulated replay** of the researcher's reference outcome.
- No A1 (generic LLM) or "B" arm code, no git history, no tests, no held-out scenarios.

## Findings

| # | Finding | Consequence / action |
|---|---|---|
| F1 | Two scenario versions disagree: the embedded set adds 1–2 decoy queries per scenario (SC-01: Q6, Q7; SC-05: Q7, Q8; others: Q7). Shared queries and states are identical. | Chance rates differ (e.g. SC-05 s0: 0.62 embedded vs 0.83 JSON). COVER v3 uses the embedded set (`scenarios/dev_master.json`), the legacy default. Which set the paper used is unknown. |
| F2 | The embedded set is marked `validated: true` for all six scenarios; the JSON is `false`. The instructions read "change `\"validated\": true` to `\"validated\": true`", which suggests a find-and-replace rather than a recorded coder review. | Flags copied as found. **Researcher action:** confirm a two-coder review happened; if not, set them to `false` in `scenarios/dev_master.json` and re-split. |
| F3 | In all six scenarios the diagnostic queries are the low IDs (Q1–Q4, plus Q6 in SC-05) and the decoys are the highest IDs. | The spec's "stable sort by query_id" tie-break would systematically favour the correct answer. COVER v3 breaks ties by `sha256(case_id|query_id)` (label-blind, fixed). Prompts list candidates in the same order for every arm. Legacy prompts listed Q1..Qn, so A2's historical results may include position effects. |
| F4 | Legacy A2/A3 fill missing predictions with uniform distributions silently. | Kept in the legacy baseline only. COVER treats missing predictions as unknown and counts them. |
| F5 | The legacy select prompt asks the model to weigh cost; COVER does not use cost to rank. | Cost is reported descriptively only (spec permits). A2's cost instruction is kept verbatim so S0/A2 stays the original condition. |
| F6 | Legacy targets Sonnet 5.5 with `tool_choice: auto` + `between_tools` thinking. Haiku 5.5 supports forced `tool_choice` and does not document `between_tools`. | Model adapter has per-model profiles. Haiku: forced tool call, no thinking parameter, no temperature. |
| F7 | `calibration` and `delta_p_true` use the scorer's key and the model's predictions together. | Kept as scorer-side measures (scoring/reference_judge.py), never fed back to any arm. |

## Can valid contrast cards be built from matched-state data without regenerating?

Partly. The legacy generation output (hypotheses with labels and priors, per-query outcome distributions) contains everything a contrast card needs. But there are no saved legacy runs, so E1 **regenerates** with Haiku 5.5. Within the new E1 run every arm (A2, A3, C0, C1, C3, C2, C3h) uses the *same* generation call for each state-rep, which is the matched-state property the spec requires.

## Gap list → what was built

| Spec item | Status |
|---|---|
| Rival registry, hunch shield, contrast cards, feasibility gate, rule-based recommender, traces | Built (`cover/`) |
| Scorer-only key with separate loading path, fail-closed leak guard | Built (`scenarios/*.key.json`, `scoring/`, `cover/view.py`) |
| E1 matched-state + hunch experiment + flat/mask stress tests | Built (`experiments/e1_matched.py`) |
| E2 sequential with S0, S1, C1, C3, C1x_wrong, C2_wrong | Built (`experiments/e2_sequential.py`) |
| 14 acceptance tests | Built (`tests/`, 40 tests) |
| Held-out split | **Not available.** Two DRAFT scenarios (SC-07 non-exclusive, SC-08 benign lookalike) need researcher validation. |
| Reproduction of paper numbers | **NOT REPRODUCIBLE** (inputs missing) |
| E3 human study, presentation-only test | **NOT RUN** (needs participants) |
| Literature-verified novelty matrix | **Scaffold only** (see NOVELTY_MATRIX.md) |
