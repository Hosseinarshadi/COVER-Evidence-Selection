# Evaluation protocol (v3.0 pre-specified 2026-10-25 before any real run; v3.1 amended after the pilot)

> v3.1 amendment: after the pilot, the belief wording was fixed, COVER arms gained ACH tiers and an independent
> verifier, and C3's restraint now depends on the verifier. The pre-registered v3.0 rule stays as arm C1v30.
> Primary E1 comparison is now C1 (v3.1) vs A2 and A3, with C1v30 reported alongside. Because the pilot used the
> same six scenarios, results on them are development results; confirmatory claims need a held-out set.

Changing anything below after seeing real results requires a dated entry in RESEARCH_DECISIONS.md and a new config version.

## Data

- Development set: the six scenarios in `scenarios/dev_master.json` (SC-01…SC-06). These are development history, not novel test cases; prompts and rules were written with them in view.
- Held-out set: none exists yet. `scenarios/heldout_draft_master.json` (SC-07 non-exclusive, SC-08 benign lookalike) are unvalidated drafts. A real held-out split must be written and validated by the researcher, then frozen (hash recorded here) before it is run.
- All scenarios are constructed, not real incidents.

## Model and settings

`claude-haiku-5-5`; forced tool call; no temperature; no thinking parameter; `max_tokens` 12000; 3 attempts per call; strict tools with logged fallback. Hard caps: E1 $2, E2 $3, pilot $0.50 per episode.

## E1 (matched state)

12 states × 5 reps = 60 state-reps; 4 large model calls each (G0, A2, G-exposed-correct, G-exposed-wrong) plus 3–4 small verifier calls.

- **Primary:** nonredundant diagnostic rate of the top-1 pick, scenario-level, for C1 vs A2 and C1 vs A3. Abstentions count as non-diagnostic.
- **Mechanism:** C1 vs C0 (contrast use) on challenge rate and diagnostic rate; C3 vs C2 on abstention.
- **Secondary:** false-contrast count, contradiction realized, delta-p(true), agreement between arms, candidate-ceiling strata (bins: chance < 0.40 low, > 0.60 high).
- **Shielding:** wrong-hunch prior mass exposed − shielded (positive = anchoring); opposite-label rival count; top-1 diagnostic for C1x vs C2.
- **Stress (simulated):** flat forecasts (expect C1 fallback, C3 abstain); masked telemetry (every diagnostic query unavailable: any claimed challenge is false certainty).

## E2 (sequential)

6 scenarios × 6 arms × 3 reps, budget 3 queries, start at s0. Arms diverge after the first pick.

- **Primary (co-primary):** disconfirming share = nonredundant diagnostic executed / executed; rival coverage = ran ≥ 1 nonredundant diagnostic check.
- **Secondary:** first useful step (right-censored), redundancy, invalid picks, verdict accuracy, unresolved (incl. deferred), wrong verdicts, wrong-hunch endorsement (C1x_wrong vs C2_wrong), rival-persistence violations.
- **Verdict rule:** label with ≥ 0.70 of the model's self-reported prior mass after the last observation; otherwise unresolved. C3 deferral = unresolved.

## Analysis

- Unit: scenario. Average within scenario first, then across scenarios.
- Uncertainty: 95% cluster bootstrap over scenarios (2000 draws, seed 20261025). No p-values. With six scenarios, intervals are rough and are described as such.
- Report counts and denominators. Never drop abstentions, failures or adverse cases. The adverse trajectory is mandatory (report §6a, chosen by a fixed rule).
- Every "diagnostic/disconfirming/contradiction" label is an automated proxy from the evidence map. Two coders apply the blinded rubric (`run_cover.py coding-sheet`, then `kappa`) to a stratified sample (3 items per scenario × arm cell); report κ and disagreements. Until then the labels are provisional.

## Claims allowed

- Selection-process differences, if any, and only those. No claims about analysts' cognition, trust, control or burden without E3.
- No generalisation beyond these constructed scenarios.


## Held-out test on real alerts (AIT) — frozen 2026-10-25, before any model saw these cases

**Data.** 20 cases built by `tools/build_ait_cases.py` (rules in its header) from the AIT Alert Data Set
(Landauer, Skopik & Wurzenberger 2024; CC BY 4.0): 10 attack alerts (distinct attack steps) and 10 harmless lookalike
alerts (alert types that also occur in attacks; half from inside attack windows), across all eight AIT scenarios.
Truth = the dataset authors' per-event labels. Evidence map = fixed likelihood-ratio rule (LR ≥ 2 toward the truth,
leave-one-scenario-out). Fingerprints:
- `scenarios/ait.visible.json` sha256 `344c0ce47364a96c91352954732b75485d6752074bff45905d1ca1d61582b8cb`
- `scenarios/ait.key.json` sha256 `a5a0337be7ee333f95e915d61c7f5eda2e2d5058c928b54ff2ad6ad3012f3eca`
- `data/ait/alerts_csv.zip` sha256 `2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3`

**Design under test.** COVER v3.1 exactly as in `config/cover.json` (version cover-v3.1). No change to prompts, rules
or thresholds after this point. Run ONCE: E1 with 3 reps, E2 with 2 reps, all eight E2 arms.

**Pre-registered hypotheses (directional; scenario = AIT case is the unit; 95% cluster-bootstrap intervals)**
- **H1 Non-inferior selection (E1).** C1's nonredundant diagnostic rate is at least A2's minus 0.10.
  Supported if the lower bound of (C1 − A2) > −0.10. Superiority claimed only if the lower bound > 0.
- **H2 Robustness to a wrong hunch (E2).** C2_wrong reaches the correct verdict more often than S0_wrong and
  S1_wrong. Supported if (C2_wrong − S0_wrong) accuracy difference has a lower bound > 0.
- **H3 Less false certainty under missing telemetry (E1 mask).** C3's false-certainty rate is lower than A2's
  (A2 may answer NONE) and A3's. Supported if the upper bound of (C3 − A2) < 0.
- Secondary: E2 accuracy and wrong-verdict rate for C1 vs S0/S1; verifier vs evidence map (§3c); C3 deferral cost.

All results are reported whatever their direction, including any hypothesis that fails.
