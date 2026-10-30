# Negative and adverse results

No real (non-fake) COVER run has been made yet, so there are no empirical results to record. This file lists, in advance, what must be written here after the run, whatever the direction.

## Known before any run (design-level limits)

1. **The original null result stands.** The paper found A3 (EIG) no better than A2 (LLM). COVER does not revisit that with a better optimiser; it changes what the recommendation shows and when it abstains.
2. **COVER's quality is bounded by the model's predictions.** Every challenge is defined on predicted outcome distributions. If the predictions are wrong, a "challenge" is a false contrast. The failure taxonomy counts these against the evidence map.
3. **Restraint trades coverage for caution.** C3 abstentions count as non-diagnostic and as unresolved. C3 can look worse on every rate while being the more honest design. Report both.
4. **C0 is one fixed draw per state.** Its diagnostic rate swings between 0 and 1 per scenario in small samples. Do not read C1 − C0 without the chance column.
5. **Simulation is not analyst behaviour.** Nothing here measures trust, control, understanding or burden (P2 and the human side of DP4 are untested).
6. **Six constructed scenarios, two states each.** Bootstrap intervals over six clusters are rough.

## Pilot findings (development data, v3.0, Haiku 5.5, 1 rep — not evidence)

1. **v3.0 COVER underperformed both baselines** on E1: nonredundant diagnostic rate C1 0.50 vs A2 0.92 and A3 0.83
   (scenario means; C1 − A2 = −0.42). Mechanism: taking the first qualifying challenge without any ordering let
   generic checks with fluent but spurious predicted contrasts through (6 false contrasts in SC-01, SC-03, SC-06).
2. **Restraint did not engage.** C3 never deferred in normal states and claimed challenges under masked telemetry in
   4 of 6 scenarios: restraint keyed on the generator's confidence inherits its overconfidence.
3. **No hunch anchoring** at generation (exposed − shielded = 0.00); the shield had nothing to prevent.
4. **E2 verdicts were invalid** because of a prompt-wording bug (fixed in v3.1); E2 pilot numbers must not be used.

These motivated v3.1 (docs/RESEARCH_DECISIONS.md). Report them in the paper as the design iteration they are.

## To fill after the run (do not skip any row)

| Item | Result | Scenarios affected |
|---|---|---|
| Scenarios where C1 < A2 (E1) | | |
| Scenarios where C1 (v3.1) < C1v30 (v3.0) | | |
| Verifier rejected diagnostic checks (cost of restraint, report §3c) | | |
| Scenarios where C1 < S0 on disconfirming share (E2) | | |
| Shielding increased wrong-hunch endorsement or reduced credible rivals | | |
| C3 failed to defer under mask or flat stress | | |
| C1 claimed challenges under mask (false certainty) | | |
| False contrasts (count, by arm) | | |
| Wrong verdicts reached with ≥ 0.70 self-reported mass (unwarranted conviction) | | |
| Rival-persistence violations | | |
| Coder disagreement with automated labels (κ) | | |
