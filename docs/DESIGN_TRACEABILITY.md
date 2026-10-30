# Design traceability: theory → mechanism → DP → software → measure → test

| Theory | Problem mechanism | DP | Software function (file) | Outcome proxy (where reported) | Arm contrast | Acceptance test |
|---|---|---|---|---|---|---|
| Confirmation bias; ACH (Nickerson 1998; Heuer 1999) | An initial hunch shapes which rivals are generated | DP1 rival-space preservation | `cover/hunch_shield.py` (hunch withheld at generation), `cover/rivals.py` (registry, no silent deletion) | Prior mass on wrong hunch, opposite-label rival count (report §5); final wrong-hunch endorsement (§6) | C1x vs C2 (E1, E2) | 2, 5 |
| ACH; falsification | Search drifts to confirming checks | DP2 falsification-oriented recommendation | `cover/recommender.py` rule 2 (challenge first), `cover/contrast.py` `challenges()` | Challenge rate, disconfirming share, first useful step (§3b, §6) | C0 vs C1; C1 vs S0/S1 | 3 |
| OIPT (Galbraith 1974; Daft & Lengel 1986) | Ambiguity needs interpretation of rivals, not more data | DP3 counterfactual interpretability | `cover/contrast.py` cards: if-leader / if-rival predictions, what would count against the leader, limitations | Contrast quality: false contrast, contradiction realized (§3b, §7) | C0 vs C1 | 3 |
| Human–AI delegation (Baird & Maruping 2021); automation levels (Parasuraman et al. 2000) | Delegating "what to look at" moves decision authority | DP4 contestability | Top-k bundle with distinct purposes, rejected list, rule trace; `human_choice` slot kept empty | Alternatives offered per bundle; human accept/modify/reject **only in E3 (not run)** | — | 7 |
| DSR (Hevner et al. 2004; Gregor & Jones 2007; Gregor & Hevner 2013; Venable et al. 2016) | Contribution must be traceable design knowledge | DP5 epistemic traceability | `cover/trace.py`, `cover/belief.py` reason records; predicted / observed / reference stored separately | Complete audit chains (e2/trace.jsonl) | all | 12 |
| Appropriate reliance (Lee & See 2004) | Fluent output invites unwarranted confidence | DP6 safe restraint | C3 rule 6 (defer when top item is low-confidence or nondiscriminating), warnings, `feasibility.py` | Abstention, false certainty under flat/mask stress (§4), unresolved and deferred episodes (§6) | C2 vs C3 | 8, 9 |

## Propositions → evidence in this package

| Proposition | Test here | What would count against it |
|---|---|---|
| P1 challenge-oriented recommendations raise disconfirming evidence-seeking | E1 C1 vs A2/A3/C0; E2 C1 vs S0/S1 | C1 ≤ baselines on disconfirming share or diagnostic rate; high false-contrast counts |
| P2 contrast explanations raise inspectability | Card completeness is structural; the human side needs E3 | **Untested** for humans; machine runs can only show the cards exist |
| P3 shielding reduces wrong-hunch endorsement | E1 exposed vs shielded hunch mass; E2 C1x_wrong vs C2_wrong final endorsement | Shielded ≥ exposed endorsement, or fewer credible rivals when shielded |
| P4 advantage shrinks when candidates cannot discriminate or telemetry is missing | Candidate-ceiling bins (§3a); flat and mask stress (§4) | C3 fails to defer under mask/flat, or C1 claims challenges under mask |
