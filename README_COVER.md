# COVER v3 — Counterfactual and Competing-Hypothesis Evidence Recommender

Theory-driven revision of the Active ACH experiment (spec: `docs_spec.md`). COVER is a **rule-based** evidence recommender: it shows the analyst a check that could count against the leading explanation, says what each rival predicts, and defers when its predictions cannot separate the rivals. It has no utility score, EIG objective or learned policy; the original EIG controller is kept only as a baseline.

Default model: **Claude Haiku 5.5** (`claude-haiku-5-5`).

## Install

```bash
pip install -r requirements.txt          # anthropic, pydantic, pytest, matplotlib
export ANTHROPIC_API_KEY=...             # or you will be asked with hidden input; never written to disk
```

## Run (in this order)

```bash
python -m pytest -q                                              # 48 tests, offline
python run_cover.py validate                                     # scenario check + cost estimate
python run_cover.py all --fake  --out results/cover_v3/dryrun    # offline, free, numbers meaningless
python run_cover.py all --pilot --out results/cover_v3/pilot     # 1 rep, $0.50 cap per episode
python run_cover.py all --overwrite --out results/cover_v3/main  # full run, replacing earlier results in that folder
#   or separately:
python run_cover.py e1 --overwrite --out results/cover_v3/main   # E1: 60 state-reps, cap $2
python run_cover.py e2 --overwrite --out results/cover_v3/main   # E2: 108 episodes, cap $3
python run_cover.py report --out results/cover_v3/main
python run_cover.py coding-sheet --out results/cover_v3/main     # blinded sheet for two coders
python run_cover.py kappa --sheet results/cover_v3/main/tables/coding_sheet.csv
```

### Held-out test on 20 real AIT alerts (run once, after the dev runs)

```bash
python run_cover.py validate --dataset ait
python run_cover.py e1 --dataset ait --reps 3 --overwrite --out results/cover_v3/ait
python run_cover.py e2 --dataset ait --reps 2 --max-cost 4 --overwrite --out results/cover_v3/ait
```
About $3 in total. The hypotheses are fixed in docs/EVALUATION_PROTOCOL.md. Do not change the design after this run.

Add `--resume` to continue an interrupted run. Use `--scenario SC-01 SC-02` to limit scenarios, `--model claude-sonnet-5-5` to switch models.

**Estimated API use (Haiku 5.5):** about $1.20 for E1 + E2 at default reps, scaled from the pilot ($0.28 at 1 rep) plus the small v3.1 verifier calls. `validate` prints a deliberately cautious figure. Hard caps stop the run before any call that could exceed them. Prompts stay far below the 100k-token threshold where Haiku 5.5's price rises 5x. No cache is used.

## What is where

| Path | Contents |
|---|---|
| `legacy/` | Original script, scenarios and requirements, **unchanged** |
| `scenarios/dev_master.json` | Researcher master (extracted from the legacy script). Re-split after edits: `python tools/split_scenarios.py scenarios/dev_master.json scenarios/dev` |
| `scenarios/dev.visible.json` / `dev.key.json` | Agent-visible view / scorer-only key |
| `scenarios/heldout_draft_*` | Two **unvalidated** draft scenarios (non-exclusive, benign lookalike) |
| `cover/` | Runtime: view + leak guard, contrast cards, recommender, hunch shield, rival registry, beliefs, traces, Haiku adapter, legacy EIG baseline |
| `scoring/` | Scorer-only: key loader, judge, simulated replay |
| `experiments/` | E1 matched-state (+ hunch, stress), E2 sequential |
| `analysis/` | Report, tables, figures, manifest, blinded coding sheet + κ |
| `config/cover.json` | Frozen thresholds, reps, arms, budgets |
| `prompts/` | Prompt templates (hashed into every run's metadata) |
| `schemas/` | JSON Schemas exported from the Pydantic models |
| `docs/` | Audit, traceability, protocol, decisions, novelty scaffold, negative results |

Each run folder holds `e1/` and `e2/` (`raw_runs.jsonl` agent-side only, `scored_runs.jsonl` scorer-side, `trace.jsonl`, `failures.jsonl`, `run_meta.json`), plus `report.md` (labelled COMPLETE / PARTIAL / NOT RUN), `manifest.json`, `tables/*.csv` and `figures/*.png`.

## Arms

| Arm | Episode | What differs from its pair |
|---|---|---|
| A2 / S0 | E1 / E2 | LLM picks the query (legacy structured ACH) |
| A3 / S1 | E1 / E2 | Legacy cost-weighted EIG picks (baseline only) |
| C0 | E1 | First feasible checks in fixed order, no contrast use |
| C1v30 | E1 | Pre-registered v3.0 rule: first qualifying challenge (kept for comparison) |
| C1 | E1, E2 | v3.1: contrast cards, challenges ranked by ACH tier, independent verifier gate (vs C0, C1v30) |
| C1x_* | E1, E2 | Analyst hunch exposed to the rival generator |
| C2_* | E1, E2 | Hunch hidden from the generator, used only to pick the leader (vs C1x) |
| C3 / C3h_* | E1, E2 | C2 + warnings + deferral unless the verifier supports the top challenge (vs C2) |

## Honest limits

No telemetry was supplied, so "executing" a check returns the researcher's reference outcome (simulated replay). The paper's numbers cannot be reproduced (raw runs missing). No human data; E3 is not run. All diagnostic/disconfirming labels are automated proxies until two coders apply the rubric. See `docs/BASELINE_AUDIT.md` and `docs/NEGATIVE_RESULTS.md`.
