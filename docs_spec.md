# Coding Agent Specification — COVER v3 (Theory-Driven IS Revision)

**Research project:** COVER — *Counterfactual and Competing-Hypothesis Evidence Recommender* for AI-Augmented Threat Hunting  
**Target:** ECIS 2027 Short Research Paper (Information Systems / Design Science Research)  
**Status:** Implementation and evaluation instructions, **not** a claim that COVER is novel or effective  
**Supersedes:** `AGENT_SPEC_COVER_Evidence_Recommender_ECIS2027.md` wherever the earlier version calls for decision-value optimization, a cost-minimizing utility policy, a learned policy, or mathematical optimality. Preserve original data, experiments and runnable code.

---

## 0. Assignment to coding agent

**Modify the existing repository rather than creating an unrelated demo.** First inspect the code, experiment files, tests, scenarios, candidate pools, prompts, model adapters, telemetry queries, human-investigation workbook, saved predictions, and manuscript results. Identify actual paths and current behavior. Do not assume the repository layout matches the proposals in this document. Write an architecture inventory and a gap list to `docs/BASELINE_AUDIT.md` before editing.

### Core instruction

Reframe and implement COVER as a **theory-driven, context-aware recommendation and justification mechanism** that helps threat hunters maintain competing explanations, encounter potentially disconfirming evidence, and retain control over investigative decisions. The key explanatory object is **how AI recommendations structure the analyst's evidence attention and belief revision**, not whether an algorithm maximizes mathematical information gain or decision utility.

Build code to test the *mechanisms*, report favorable and unfavorable findings, and generate auditable traces. Do **not** tune the recommender to guarantee superiority. If the concept proves ineffective, produce a valid negative result and a mechanistic explanation.

### Explicitly out of scope for the principal contribution

- No new mathematical optimization objective, expected-value-of-information maximization, reward maximization, cost-loss matrix, regret bound, reinforcement-learning policy, or contextual bandit.
- No invented recommendations inferred from retrospective ground truth.
- No assertion that ranking three items constitutes a novel algorithm.
- No claim that COVER, competing hypotheses, counterfactual reasoning, or disconfirming evidence is new in isolation.
- No automatic intervention in live systems; read-only investigative evidence acquisition only.
- No post-hoc labeling of algorithmic simulations as human evaluation.

**Permitted:** deterministic, interpretable ordering rules; transparent qualitative diagnosticity rubric; safety/feasibility checks; fixed query budgets for fair comparisons; descriptive cost measurement (not cost optimization); optional legacy EIG as a **baseline**, not COVER's objective.

---

## 1. IS problem, theory and contribution

### 1.1 Research problem (use consistently in code comments, documentation, reports, and later manuscript)

Organizational investigators facing ambiguous security events must reason across malicious and benign explanations while deciding what evidence to seek. AI assistants increasingly mediate this *evidence-selection stage*: by recommending which logs, records, and queries deserve attention, they influence what information enters the analyst's subsequent judgment. This creates an IS design problem of **epistemic dependence and delegated evidence attention**. Fluent AI recommendations may amplify an initial hunch, obscure feasible rival explanations, or appear authoritative without demonstrating how an observation would challenge the dominant account. Yet transferring query selection from an LLM to an explicit EIG controller did not improve binary diagnostic query selection in the project's initial experiment. The problem is therefore not only selecting a high-scoring query, but designing **contestable, theory-grounded recommendations** that expose rival explanations, provide a reason to test them, and preserve accountable analyst judgment.

### 1.2 Research questions

- **RQ1 — Design:** How can a hypothesis-aware recommender make competing explanations and potentially falsifying evidence actionable and contestable in AI-augmented threat hunting?
- **RQ2 — Mechanism:** Compared with conventional AI and structured ACH, how do counterfactual challenge explanations, rival-preservation prompts, and recommendation transparency affect *which evidence is sought* and *how beliefs change*?
- **RQ3 — Boundary conditions:** Under which conditions—incorrect analyst hunches, limited telemetry, weakly discriminatory candidate queries, or uncertain model predictions—does this design help, fail, or create excessive burden?

**Scope:** RQ1/RQ2 can be explored in controlled computational studies; credible claims about analysts' understanding, trust, perceived control, and reliance require a new balanced human study. Existing human investigation records are formative, descriptive evidence only.

### 1.3 Theoretical grounding → implemented mechanism → observable test

| Theory / literature stream | Problem mechanism | COVER design feature | Test or observation |
|---|---|---|---|
| Organizational Information Processing Theory (Galbraith, 1974; Daft & Lengel, 1986) | Ambiguity is not solved by acquiring more data; actors need decision-relevant interpretation of competing explanations | Context cards linking rival hypotheses to available evidence and explicit missing observations | Rival coverage, proportion of recommendations with feasible evidence paths, time/query budget until meaningful rival tested; interpret as process outcomes, not organizational effectiveness |
| Human–AI delegation (Baird & Maruping, 2021) / automation levels (Parasuraman et al., 2000) | Delegating what to seek changes the distribution of decision authority | Analyst-facing top-k recommendations, ability to accept, revise, skip, or request alternative; autonomy mode only for software evaluation | Exposure of alternatives, override events, adoption/contestability in actual human study; autonomous-agent simulation is **not** user behavior |
| Confirmation bias / ACH (Nickerson, 1998; Heuer, 1999) | Initial hunch anchors information search | Protect initial rival generation from analyst hunch; show falsifying tests alongside confirming ones | Wrong-hunch endorsement, disconfirming-query share, neglected benign rivals, time to first disconfirming test |
| Appropriate reliance (Lee & See, 2004) | Explanations can trigger inappropriate trust or false confidence | Explicit forecast limitations, evidence provenance, “what would change the recommendation?” notes; abstention when inadequate evidence | False-certainty warnings, unsupported claims, appropriate overrides (human study), qualitative error taxonomy |
| DSR / design theory (Hevner et al., 2004; Gregor & Jones, 2007; Gregor & Hevner, 2013; Venable et al., 2016) | Artifact contribution must be expressed as transferable design knowledge, not only system accuracy | Traceable design requirements, mechanisms and evaluation episodes | Theory→DP→feature→measurement traceability; supported/unsupported design propositions |

**Novelty discipline:** literature review must examine existing ACH, threat-hunting agents, counterfactual explanations, next-best-evidence recommendation, active diagnosis, diagnostic reasoning, human-AI contestability, and IS recommender systems. Keep a `docs/NOVELTY_MATRIX.md` with sources, what each prior work already did, and *verified* differentiators. Record search date and scope; never claim “first” without comprehensive evidence.

### 1.4 Design principles (hypotheses, not established findings)

- **DP1 Rival-space preservation:** Generate and preserve plausible malicious and benign rivals before exposing an analyst's preferred explanation where experimentally appropriate.
- **DP2 Falsification-oriented recommendation:** Recommend at least one feasible observation that could *undermine* the leading explanation, not just confirm it.
- **DP3 Counterfactual interpretability:** Describe what distinct possible query outcomes would imply for the rivals, while marking predictions as fallible.
- **DP4 Recommendation contestability:** Present alternative feasible queries and why each differs; enable human accept/modify/reject without hiding provenance.
- **DP5 Epistemic traceability:** Track initial hunch, hypotheses, suggested and executed evidence, observed outcomes, interpretation, revised confidence, and final judgment independently.
- **DP6 Context sensitivity and safe restraint:** When available telemetry cannot distinguish rivals, communicate unresolved ambiguity and request analyst review instead of projecting certainty.

**Propositions for empirical testing:**

- **P1:** Challenge-oriented recommendations increase the *share and coverage of meaningful disconfirming evidence-seeking* versus structured ACH when a credible alternative is available.
- **P2:** Counterfactual explanations increase the *inspectability* of evidence-seeking rationales; whether they improve judgment or create additional confidence is an open question.
- **P3:** Hunch shielding reduces endorsement of a wrong initial hypothesis, contingent on the rival generator's capacity to produce credible alternatives.
- **P4:** When candidate queries cannot discriminate rival explanations or telemetry is missing, COVER's advantage diminishes; transparent deferral may increase unresolved cases.

Treat these as conditional hypotheses and look for counterexamples, not just confirmatory stories.

---

## 2. Define COVER precisely

**COVER = Counterfactual and Competing-Hypothesis Evidence Recommender.** “Counterfactual” here means *explicit contrasting predictions about evidence outcomes under rival explanations*, not causal counterfactual identification or access to unrealized outcomes. A recommendation is a supported suggestion to the **analyst** for what to check next and how the result could challenge a leading explanation; it is not an autonomous final verdict.

### 2.1 Recommender entities

- **Recipient:** threat hunter / investigator; role and available access are context, not inferred psychology.
- **Item:** read-only, valid Sigma/SQL/log query or an analyst-review request.
- **Context:** alert, rival hypotheses, investigation history, telemetry/schema, visibility restrictions, remaining query budget, displayed hunch (experimental condition).
- **Recommendation:** up to 3 candidate evidence checks, reason for each, rival challenged, predicted contrasting outcomes, execution feasibility, observed evidence if run, limitations, and accept/modify/reject affordance.
- **Feedback:** recommendation offered, chosen/modified/skipped, observed outcome, affected hypotheses, final judgment; record human choices only when an actual human participated.

This is a **knowledge-based, context-aware evidence recommender**. Do not claim collaborative filtering, personalized preference learning, or optimized sequential decisions.

### 2.2 Architecture

```text
Alert + current case history + telemetry schema
     |
Rival generation (explicit malicious AND benign hypotheses)
     |                   [hunch-shielded condition masks stated preference here]
Candidate evidence generation (SQL / Sigma / existing read-only check)
     |
Validate feasibility (safe SQL, available fields, duplicate check)
     |
Construct contrast cards for EACH candidate:
   - hypothesis it could corroborate
   - hypothesis it could challenge
   - expected observation IF H_i / IF H_j (uncertain, provenance-tagged)
   - preconditions, limits, missing telemetry
     |
COVER recommendation protocol (transparent RULE-BASED curation)
   1. put a feasible challenge to the current leading hunch in view
   2. ensure meaningful benign-vs-malicious rivalry is not ignored
   3. offer alternatives with different investigative purposes
   4. declare ambiguity / ask for review when claims are unsupported
     |
Top-k recommendations + rationale + analyst choice (or fixed simulator)
     |
Execute read-only query -> store OBSERVED result (never confused with prediction)
     |
Record whether the observation genuinely contradicted or differentiated rivals
     |
Update hypothesis record + analyst-facing reflection (or model-only simulation)
     |
Next recommendation or explicit unresolved / verdict / review
```

### 2.3 Replace optimization with a *transparent recommendation protocol*

**Do not derive a numerical utility, EIG-style score, or an optimal policy.** Use explicit rules that operationalize the design principles without tuning weights on outcomes:

1. **Safety first:** exclude unsafe / non-executable / inaccessible queries.
2. **Genuine challenge:** include a candidate with an intelligible, plausible outcome that would count *against* the current leading explanation, if such a candidate exists.
3. **Rival balance:** ensure at least one benign and one malicious interpretation is surfaced when feasible; never synthesize false parity if the evidence cannot support it.
4. **Nonredundancy:** prefer candidates that would test an as-yet-untested distinction, without treating mere query string differences as new evidence.
5. **Diversity of purpose:** when three are available, present a challenge query, an independent corroboration check, and an alternative explanation / missing-context check. If these categories are not feasible, return fewer suggestions and document why.
6. **Epistemic restraint:** if query outcomes are speculative or the necessary logs do not exist, indicate uncertainty and recommend review or data acquisition instead of pretending that a test is discriminative.
7. **Deterministic tie handling:** stable sort by immutable `query_id`; never silently prioritize the correct answer by consulting labels.

The recommender may return **no recommendation**. Count that as coverage loss and analyze it; do not drop from denominators.

### 2.4 Contrast card data contract

```json
{
  "case_id": "SC-XX",
  "turn": 2,
  "query_id": "Q-007",
  "query_language": "sql",
  "query_text": "SELECT ...",
  "feasible": true,
  "feasibility_reason": "available log and fields; read-only",
  "purpose": "challenge_leading_hunch",
  "leading_hypothesis_id": "H1",
  "rival_hypothesis_id": "H2",
  "if_leading_hypothesis": {"predicted_observation": "...", "source": "LLM_prediction", "uncertain": true},
  "if_rival_hypothesis": {"predicted_observation": "...", "source": "LLM_prediction", "uncertain": true},
  "what_would_count_against_leader": "...",
  "distinct_evidence_needed": "...",
  "previously_checked": false,
  "explanation": "Check whether ...; this could weaken H1 if ...",
  "limitations": ["..."],
  "human_choice": null
}
```

`human_choice` must be `null` in non-human runs; use a separate `simulated_choice` field for automated replay. Validate via Pydantic/JSON Schema; forbid undocumented keys in persisted outputs unless versioned.

### 2.5 Quality gates for counterfactual statements

- An outcome contrast is *hypothesis-conditional prediction*, not observation. Must state the associated assumption, source, and uncertainty.
- Validate referenced tables/fields/schema against actual data.
- Do not mark a query as falsifying solely because an LLM writes a fluent rationale. It must have an operationalized difference between outcomes under the two specified hypotheses.
- If predicted outcomes are identical or unknown for all important rivals, label `nondiscriminating` and do not disguise this as a meaningful challenge.
- Guard against non-exclusive hypotheses. Some benign and malicious explanations can co-occur. Mark `not_mutually_exclusive` and avoid claiming a single query decisively excludes a hypothesis.
- A negative result can be affected by visibility, time window and data quality; never treat `no_hit` as proof of innocence.
- Make outputs schema-validated and execution-safe; reject mutating SQL and uncontrolled arbitrary shell execution.

---

## 3. Repository changes

**Adapt to actual paths; do not overwrite historical results.** Suggested additions:

```text
cover/
  models.py                  # Pydantic hypothesis, query, card, recommendation, decision trace
  rivals.py                  # stable rival identity and preservation
  contrast.py                # create/verbalize if-H1 versus if-H2 contrast cards
  feasibility.py             # SQL/Sigma and dataset field validation
  recommender.py             # transparent protocol; no utility score
  explanation.py             # explanations and provenance/limitations
  hunch_shield.py            # masking boundary and tests
  trace.py                   # append-only event schemas
  protocol_ablation.py       # disable components independently
analysis/
  process_measures.py        # query/rival/trust-process proxy measures
  cluster_statistics.py      # scenario-level resampling and uncertainty
  failure_audit.py           # contradiction / leakage / ungrounded forecasts
  qualitative_coding.py     # analyst workbook, blinded coding scaffolds
scoring/
  cover_reference_judge.py   # can access frozen truth only AFTER runs
config/
  cover.yaml                 # versions, arms, seeds, budgets, prompts
prompts/
  cover_rivals.md
  cover_contrast.md
  cover_reflection.md
  cover_recommendations.md
schemas/
  contrast_card.schema.json
  investigation_trace.schema.json
tests/
  test_no_leakage.py
  test_feasibility.py
  test_rival_preservation.py
  test_hunch_shield.py
  test_contrast_grounding.py
  test_recommender_determinism.py
  test_arm_isolation.py
  test_result_provenance.py
  test_no_human_simulation_mislabel.py
docs/
  BASELINE_AUDIT.md
  DESIGN_TRACEABILITY.md
  NOVELTY_MATRIX.md
  EVALUATION_PROTOCOL.md
  RESEARCH_DECISIONS.md
  NEGATIVE_RESULTS.md
results/cover_v3/               # append only, no overwrite of original
```

Original `harness/eig.py`, `controller.py`, A2/A3 conditions, `scenarios/`, baseline outputs, original human workbook, and scored evidence maps remain intact. Export versions, git SHA, prompts hashes, model version, sampling settings and data fingerprints.

---

## 4. Experimental conditions and causal contrasts

Keep original published-style conditions: A1 generic LLM, A2 structured ACH with model query selection, A3 EIG controller. Preserve frozen **matched-state** A2/A3 results as distinct from *new sequential* tests. Do not compare their rates as if collected under the same new protocol.

### 4.1 Paired mechanistic ablations

| New arm | Structure | Rival shielding | Contrast cards | Transparent recommendation | Analyst choice | Main mechanism |
|---|---|---|---|---|---|---|
| S0 / A2-seq | Structured ACH | No | No | No, LLM chooses | Fixed autonomous replay | Structured baseline |
| S1 / A3-seq | Same as S0 | No | No | EIG selection | Fixed autonomous replay | Legacy controller comparator |
| C0 | Same candidate pool | No | No | Simple deterministic diverse top-k | Fixed simulator top-1 | Recommendation format alone |
| C1 | Same candidate pool | No | Yes | Challenge-oriented top-k | Fixed simulator top-1 | **Counterfactual contrast** mechanism vs C0 |
| C2 | Same as C1 | Yes for rival generation | Yes | Same as C1 | Fixed simulator top-1 | **Shielding** mechanism vs C1 with a wrong hunch |
| C3 | Same as C2 | Yes | Yes + uncertainty/provenance warnings | Same challenge protocol with abstention | Fixed simulator top-1 or unresolved | **Epistemic restraint** vs C2 |

**Important experimental isolation:** S0 vs S1 should differ only in selector; C0 vs C1 only in presence/use of contrast cards (same generated candidate pools); C1 vs C2 only in hunch visibility during rival generation (but changes in generated rivals are the intended mediator, so log them); C2 vs C3 only in provenance/uncertainty warnings and abstention rule. Do not simultaneously change prompt, model, dataset, query budget or initial state within a pairing.

If C1 is allowed to use contrast cards for candidate selection while C0 is not, distinguish this as the planned *recommendation mechanism*; additionally run a **presentation-only test** using the same preselected top-k lists to isolate effects of explanation visibility in human-facing evaluations.

### 4.2 Two distinct computational episodes

**Episode E1 — frozen matched states:** Reuse the original 60 A2/A3 decision states. For each state, give all selection policies identical rivals, evidence history, schema, candidates and predictions. New arms C0/C1/C3 can be tested *where existing candidate metadata permits valid contrast cards*. Do not fabricate unavailable predicted outcomes or secretly regenerate different candidates. Primary purpose: test whether challenge-oriented selection differs from model/EIG selection at the same state.

**Episode E2 — sequential investigations:** Execute each condition from the same trigger to a verdict, unresolved decision, or fixed budget limit. Each selected query changes the next state. This can assess evidence trajectories, not only isolated binary query diagnosticity. For a fair method comparison, freeze initial cases, model settings, candidate-generation policy and backend datasets; **after first divergence, the arms may naturally observe different evidence**, so do not pretend turns remain identical.

**Episode E3 — human analyst formative extension (optional, not simulated):** Run a balanced within-analyst crossover or randomized counterbalanced study, with comparable case difficulty, consent, time limits and blinded evaluation. Compare (a) same recommendations without challenge explanations and (b) with counterfactual cards/alternative controls, preferably separate from automated selection. Collect analyst accept/modify/reject, reason, confidence before/after and actual evidence traces. Do not reuse historical 12 cases as if they were randomized.

### 4.3 Hunch bias experiment

Use matched **correct and incorrect hunches** where scenario truth is known to the scorer, but hidden from all agents. In hunch-exposed arm, the rival generator sees the analyst's hunch. In shielded arm, it does not until after creating rivals. Both arms see the same hunch later for investigation prioritization. Report whether shielding changes rival diversity, benign rival representation, leading-hunch endorsement, first disconfirming test, and final verdict. No claim of sycophancy reduction unless directly supported.

### 4.4 Research designs that address the original null result

- **Candidate ceiling:** stratify by low/medium/high candidate diagnosticity and actual discriminative potential using pre-specified scenario criteria, not post-hoc cherry picking.
- **Forecast error:** contrast-card prediction fidelity is evaluated separately from recommendation quality. Test robust/not-robust-to-wrong predictions by perturbing or masking forecasts **as diagnostic stress tests**, not optimization or a new forecasting algorithm.
- **Missing telemetry:** systematically remove specified log sources before a run; label as simulated visibility constraints. Check for misleading certainty vs appropriate deferral.
- **Non-exclusive rivals:** include at least one scenario where benign activity and malicious activity can coexist, to challenge simplistic winner-take-all ACH.
- **Benign lookalikes:** ensure multiple authentic or clearly labeled constructed benign cases, and distinguish them in all outputs.

---

## 5. Measurement model: theoretical constructs vs operational proxies

**Do not interpret a machine-only proxy as a demonstrated analyst psychological effect.** Report both denominators and raw counts, with case-level trace evidence.

| Construct / observable outcome | Implemented measure | Interpretation / validity warning |
|---|---|---|
| **Disconfirming evidence seeking (primary process)** | `executed_queries_that_could_count_against_initial_lead / all_executed_queries`, adjudicated from a frozen, condition-blinded rubric | Potential to falsify, not proof the analyst engaged critically |
| **Rival coverage (co-primary process)** | fraction of credible registered rival distinctions addressed by >=1 executable, observed query | Requires operational reference rubric and inter-coder validity |
| Counterfactual contrast quality | % recommendations naming distinct, feasible predicted observations under ≥2 rivals; contradiction and unsupported-claim rate | Language fluency alone is not quality |
| Evidence redundancy | repeat attempts checking substantively equivalent evidence, from case-level canonical IDs | Avoid equating distinct SQL with distinct evidence |
| Query executable rate | executed valid read-only queries / all proposed executable-action recommendations | Missing telemetry and SQL errors are failures |
| Evidence traceability | proportion of recommendation→execution→observation→belief-update chains with complete provenance | Audit property, not accuracy |
| Belief revision | changes in confidence or ranking after *observed* counterevidence; report direction relative to reference truth | Algorithm belief change is not analyst belief change |
| Hunch endorsement | initial/final support for incorrect supplied hunch, with clear text adjudication rubric | Distinguish first response from terminal decision |
| Separation | earliest observed step where the evidence discriminates previously specified main rivals, or right-censored if never | May require validated hypothesis-specific mapping |
| Verdict quality | truth accuracy, balanced accuracy, false positive/negative, unresolved, calibration if confidences available | Secondary; all runs including unresolved in denominator or explicitly accounted for |
| Coverage / deferral | recommendations returned and episodes deferred, including errors | Abstention cannot boost accuracy by dropping hard cases |
| Human control (E3 only) | actual accepts/overrides, rationale, perceived contestability, justified disagreement | Cannot be measured from simulated interaction |
| Usability burden (E3 only) | reading time, review effort, comprehension/recall checks, cognitive workload instrument if approved | Theory predicts trade-offs, not automatic benefit |

**Primary claims must distinguish:** `recommendation proposed` vs `recommendation selected` vs `query executed` vs `observation received` vs `belief changed` vs `verdict`. These are different causal stages. An improved selection *process* does not establish improved verdicts.

### Adjudication and scoring rules

- Ground truth and frozen reference evidence maps are **scorer-only**, never seen by generation, controller, reflection or explanation code.
- Record `predicted`, `observed`, and `reference` as separate fields with source labels and timestamps.
- Develop a blinded rubric for *could this query genuinely challenge H1 versus H2?*, independence, and actually observed contradiction. Two qualified coders label a stratified sample; report agreement, disagreements and rubric revision. If coders unavailable, label all qualitative classifications provisional.
- Inspect possible false disconfirmation: `no_hit` caused by unavailable logs, wrong window, missing fields or detector insensitivity must not be scored as a justified refutation.
- Distinguish *rival count* from *credible rival diversity*, as trivial duplicates can inflate count.
- Use case/scenario as resampling cluster. Repeated model outputs within a scenario do not supply independent cases. Show scenario-level outcomes, uncertainty, and descriptive magnitudes before p-values.
- No inference from the original six-scenario dataset to broad cybersecurity or workplace behavior.

---

## 6. Data and reproducibility protections

Original short paper reports **six scenarios × two matched states × five repetitions = 60 paired decisions**, A2 53/60 diagnostic (88.3%), A3 51/60 (85.0%), identical chosen query 38/60, differences concentrated in SC-02. Keep these exact numbers as *historical targets to audit*, not hard-coded result outputs. If your program cannot regenerate them, identify missing inputs and report discrepancies; do not force them.

The paper also reports **12 real investigations by six analysts** (human only n=5, conventional AI n=3, Active ACH n=4). These are genuine investigations; do **not** call them synthetic or treat their unaudited descriptive correctness as comparative causal evidence. Only four detailed query traces are reported. Keep all annotations in their original condition and preserve provenance. Do not infer revealed analyst preferences or train recommendation rules from these records.

**Leakage security:** test that no `ground_truth`, `reference outcome`, `evidence_map`, scorer label, or future observed log result appears in runtime prompts, generation input, recommender objects, training fixtures or selection traces. Scorer-only file access should be enforced by separate loading paths and permissions. Fail closed on accidental inclusion.

**Security:** local/offline log replay, read-only SQL/Sigma, schema whitelist, query limits, no production writes, no sensitive-identifier leakage in public outputs; secrets only in environment. Freeze ATT&CK, Sigma, CTI lookup snapshots when used; CTI itself is an optional factor, not the conceptual contribution.

---

## 7. Concrete implementation algorithm (non-optimizing)

Implement `recommend(context, candidate_pool) -> RecommendationBundle`:

```python
# PSEUDOCODE: no score, utility weights or EIG inside COVER
safe = [q for q in candidate_pool if validate_read_only(q) and schema_available(q)]
unique = canonical_deduplicate(safe, executed_history=context.executed_queries)
cards = [build_hypothesis_contrast(q, context.rivals, context.lead) for q in unique]
cards = [verify_prediction_provenance_and_limits(c) for c in cards]
challenge = first_stable(cards, lambda c: c.feasible and c.has_genuine_rival_contrast
                         and c.could_undermine_leading_hypothesis)
corroboration = first_stable(cards, lambda c: c.is_independent_corroboration
                            and c.query_id != id_or_none(challenge))
alternative = first_stable(cards, lambda c: c.tests_unchecked_benign_or_malicious_rival
                          and c.query_id not in ids(challenge, corroboration))
selected = compact_unique([challenge, corroboration, alternative])
if not selected:
    return RecommendationBundle(items=[], review_required=True,
                                limitation="No defensible discriminating check")
return RecommendationBundle(items=selected[:3], review_required=False,
                            explanation=describe_rival_tradeoffs(selected))
```

Never let `first_stable` depend on answer labels or sorted ground-truth alignment. Log every rejected candidate and the rationale. Test that reordering otherwise equivalent candidates does not cause an unjustified truth-dependent change. If no plausible alternative or challenge exists, **explain that constraint rather than inventing one**.

Model updates after observations need not assume a Bayesian posterior; a transparent *reason record* is acceptable:

```text
Before evidence: H1 favored; H2 plausible; why
Recommendation: test Q4; if result A, H1 weaker; if B, H2 weaker; uncertainty caveat
Observed result: actual source + time + match count
After evidence: H1 supported / weakened / unchanged; H2 likewise; reason + analyst approval status
```

If confidence numbers are produced, never equate an LLM's self-reported confidence to calibrated probability. Keep original legacy belief updates only in the legacy baseline, not as a hidden mechanism in COVER.

---

## 8. Acceptance tests (must run)

1. **Baseline reproduction:** manifest original A2/A3 results (or honest `NOT REPRODUCIBLE` with root cause).
2. **Rival persistence:** rival IDs never vanish without recorded observation and explicit rationale; new rivals versioned.
3. **Falsification validity:** a card must specify at least one feasible outcome that weakens a stated hypothesis; otherwise label exploratory or nondiscriminating.
4. **No hindsight:** changing ground truth while keeping agent-visible data fixed must never alter recommendations; scorer changes only.
5. **Incorrect hunch:** exposed and shielded prompts differ in *only* planned visibility during rival generation.
6. **No evidence leakage:** scorer-only reference maps inaccessible to recommender runtime.
7. **No sham human data:** every human-choice event includes authenticated provenance; autonomous choices are `simulated_choice`.
8. **No hallucinated execution:** failure to execute is represented as an error, never `no_hit`.
9. **No false certainty:** unavailable telemetry and all-unknown forecasts trigger a warning/deferral.
10. **Deterministic rules:** same inputs, same model predictions, same frozen tie-break order → same recommendation bundle.
11. **Ablation integrity:** isolated feature toggle verified per comparison; ensure cache hits and random seeds are logged.
12. **End-to-end smoke:** at least one malicious and one benign test case; complete query→observation→belief-change audit chain.
13. **Negative-result audit:** same experiment writes all outcomes, including cases where the recommender is worse.
14. **Safety:** attempts to run `DELETE`, `UPDATE`, `DROP`, filesystem escapes, or unauthorized telemetry requests fail before execution.

Use `pytest`; log exact command, environment, pass/fail, and timestamp. Add a GitHub Actions workflow if repository permissions and dependencies permit, ensuring offline fixtures do not require secrets.

---

## 9. Analysis and reporting requirements

Generate machine-readable raw trajectories as JSONL, scored traces with separate access, individual scenario summaries and tables, plus a `results/cover_v3/report.md` clearly labeled **COMPLETE**, **PARTIAL**, or **NOT RUN**. Predefine primary outcomes and analysis in `docs/EVALUATION_PROTOCOL.md` before any new held-out evaluation.

Minimum report tables:

1. **Design traceability:** theory → problem mechanism → DP → software function → outcome proxy → result.
2. **Reproduction:** original A2/A3 results and discrepancies (if any).
3. **Matched-state comparator:** A2/A3/C0/C1/C3 by scenario, candidate ceiling and agreement.
4. **Sequential evidence-seeking:** disconfirmation share, rival coverage, evidence redundancy, invalid queries, first useful falsification, unresolved, verdict accuracy.
5. **Shielding:** wrong-hunch exposure vs masking; rival diversity and endorsement, per scenario.
6. **Failure taxonomy:** false contrast, hallucinated prediction, missing telemetry, inability to distinguish rivals, wrong-hunch anchoring, redundancy, and unwarranted conviction.
7. **Human descriptive evidence:** preserve original 12 investigations in descriptive table and clearly separate any newly collected randomized data.

Suggested figures: per-scenario paired slope plot for disconfirming evidence seeking; observed evidence trajectory diagrams for one beneficial and one adverse case; stage-level funnel (`candidate -> recommended -> chosen -> executed -> observed contradiction -> revised belief`); false contrast/error breakdown; missing-telemetry scenario comparison.

Quantitative method: small-number-of-scenarios caution; cluster scenario-level bootstrap or suitable randomization analysis where supported; uncertainty intervals; no naive treating five seeds × two states as 10 independent scenarios. Compare all cases including abstentions. No cherry-picking highlights; the adverse case figure is mandatory.

**Interpretation discipline:** if the recommender generates more disconfirming queries but does not improve verdicts, claim only *the former*; if showing explanations does not change automated decisions, do not assert improvements in human cognition; if shielding weakens rival generation or increases burden, report it.

---

## 10. Implementation order and concrete deliverables

### Phase A — audit and preserve (mandatory)

- Locate, run, and fingerprint existing experiments.
- Archive immutable inputs/configs and current A1/A2/A3/B arms.
- Write `docs/BASELINE_AUDIT.md` and commit.
- Inventory matched-state candidate fields and whether fully valid contrast cards can be built without rerunning generation.

### Phase B — build the theory mechanisms (mandatory)

- Implement rival registry, visibility shield, contrast card schema, evidence feasibility validation, deterministic non-optimizing recommender, explicit limitations and logging.
- Add tests 1–14 above.
- Run smoke tests on one benign and one malicious case using available genuine telemetry.

### Phase C — conduct reproducible computational evaluation (mandatory if dependencies available)

- Freeze a separate held-out scenario split before tuning prompts; keep earlier six scenarios as development/test history, not magically novel cases.
- Execute frozen-state ablation tests, then sequential matched-initial-condition tests.
- Generate missing telemetry / forecast perturbation stress tests and label their simulated nature.
- Create all primary/secondary tables without excluding poor outcomes.

### Phase D — human-facing recommendation evaluation (future/optional)

- Implement analyst UI or structured CLI with top-k cards and accept/modify/reject, without ever presenting simulated feedback as real.
- Prepare a counterbalanced human study protocol, case booklet, consent/ethics considerations, and instrument drafts. Do not claim results unless actual participants completed it.

### Required files to hand back

```text
docs/BASELINE_AUDIT.md
docs/DESIGN_TRACEABILITY.md
docs/NOVELTY_MATRIX.md
docs/EVALUATION_PROTOCOL.md
docs/RESEARCH_DECISIONS.md
docs/NEGATIVE_RESULTS.md
config/cover.yaml
cover/*.py
schemas/*.json
tests/test_cover_*.py
results/cover_v3/manifest.json
results/cover_v3/raw_runs.jsonl
results/cover_v3/scored_runs.jsonl
results/cover_v3/report.md
results/cover_v3/tables/*.csv
results/cover_v3/figures/*.png
README_COVER.md
```

Only claim output files that actually exist; mark blocked or non-run artifacts in `manifest.json`. Do not fabricate empty CSVs that look like real results. Include dependency installation commands, reproducible run commands, cache requirements and estimated external API usage when known.

## 11. Agent finish-line checklist

The work is complete only when the agent can truthfully answer:

- What original code and findings were preserved, and were published sample results reproduced?
- Precisely how does COVER differ from *structured ACH, EIG controller, generic LLM, and prior threat-hunting agents*?
- Which theory-derived mechanism is tested by each condition, with no bundled confounds?
- Where are all raw model predictions, feasible candidates, rejected cards, recommendations, executed observations, analyst/simulator choices and belief updates recorded?
- What evidence specifically supports or challenges P1–P4? Which remain untested?
- Under what conditions did COVER worsen performance, increase unresolved cases, or add workload?
- Which outcomes are *real analyst behavior*, which are *software simulation*, and which are *unverified prediction*?
- Is the claimed IS contribution transferable design knowledge rather than an algorithmic optimality claim?

**Research integrity:** A meaningful and reproducible null result with an explanation of sociotechnical boundary conditions is preferable to a numerically impressive but confounded experiment.
