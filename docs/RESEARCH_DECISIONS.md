# Research decisions log

| Date | Decision | Why | Alternative rejected |
|---|---|---|---|
| 2026-10-25 | Default model `claude-haiku-5-5` | Researcher request. Verified pricing $0.10/$0.50 per MTok (≤100k prompt) on platform.claude.com. | — |
| 2026-10-25 | Haiku: forced `tool_choice`, no thinking parameter, no temperature | Haiku 5.5 supports forced tool calls (no thinking block then); temperature cannot be set; `between_tools` is not documented for Haiku. | Copying the Sonnet profile (risk of 400 errors) |
| 2026-10-25 | Strict tools sent, with automatic logged fallback | Strict support is not documented on the Haiku migration page | Assuming support |
| 2026-10-25 | Tie-break by `sha256(case_id|query_id)`, not query id | Diagnostic queries are the low IDs (audit F3); ID order would leak the answer | Spec's literal "stable sort by query_id" |
| 2026-10-25 | Candidates shown in the same hashed order to every arm | Removes Q1-first position effects equally for all arms | Legacy Q1..Qn order |
| 2026-10-25 | Shielded generation reuses the no-hunch generation G0 | A shielded prompt contains no hunch, so it is textually identical to G0; reuse makes C2 exactly matched to C1/C3 and saves calls | A separate, independently sampled shielded call |
| 2026-10-25 | Contrast rule thresholds 0.35 / 0.50 / 0.60 / 0.30 | Fixed a priori as readable rules ("the rival's likely outcome would be unlikely under the leader") | Tuning on outcomes (forbidden) |
| 2026-10-25 | COVER treats missing predictions as unknown; the legacy baseline keeps uniform filling | Spec 2.5: unknown must not be disguised as a test | Uniform filling for all |
| 2026-10-25 | C0 = first k feasible in hashed order | Spec: "simple deterministic diverse top-k" without contrast. It is one fixed draw per state, so its rate is noisy around chance; read it alongside the chance column | Random C0 (non-deterministic) |
| 2026-10-25 | C3 = C2's bundle + warnings + abstain if top item is low-confidence/fallback | Isolates restraint from selection (C2 vs C3 differ only there) | C3 re-ranking toward confident items (would confound) |
| 2026-10-25 | E2 observations = simulated replay of reference outcomes | No telemetry supplied | Fabricating log data |
| 2026-10-25 | Rival coverage reduced to "≥ 1 nonredundant diagnostic check" | Evidence map has no per-hypothesis mapping | Inventing a mapping |
| 2026-10-25 | Mask stress uses the key to choose which telemetry is missing | It is a researcher-constructed stress condition; the agent only sees "unavailable" | — |
| 2026-10-25 | Config as JSON (`config/cover.json`), not YAML | Avoids a PyYAML dependency | `cover.yaml` |

## v3.1 — changes after the pilot (2026-10-25, pilot: Haiku 5.5, 1 rep, $0.28)

The pilot is development data. Every change below is motivated by a failure mechanism seen in the pilot, not by
fitting thresholds to its scores, and none uses the answer key. The pre-registered v3.0 rule is kept as arm C1v30
so readers can compare. Because the six scenarios were used both to diagnose and to evaluate, any C1 advantage on
them is optimistic; the held-out set (e.g. AIT alerts) is the real test.

| Pilot observation | Diagnosis | v3.1 change | Applies to |
|---|---|---|---|
| E2: almost every episode unresolved; SC-01 malicious mass 0.55 after three incriminating results | Prompt asked for "prior" probabilities, so the model kept its pre-evidence numbers (measurement bug) | Ask for probability "given the alert and all evidence observed so far" and to update after each result | All arms (shared generation) |
| E1: C1 50% vs A2 92%; 6 false contrasts | Generator assigns different outcome probabilities to generic checks; v3.0 took the FIRST qualifying challenge in fixed order, i.e. effectively random among them | (a) Generation prompt adds the ACH consistency principle: evidence consistent with all explanations is not diagnostic. (b) Challenges ordered by a qualitative ACH diagnosticity tier (decisive / strong / weak), thresholds set from the rubric wording (0.10 / 0.70 / 0.20) | (a) all arms; (b) COVER v3.1 arms |
| Same | A fluent prediction is not evidence of diagnosticity (spec 2.5) | Independent verifier: a separate-context call, blind to the generator's numbers, rates each claimed counter-result decisive / suggestive / not_diagnostic; not_diagnostic challenges become ineligible | C1, C1x, C2, C3 |
| C3 never abstained; under masked telemetry it still claimed challenges | Restraint keyed on the generator's own confidence, which is high even when wrong | C3 defers unless the top check is a challenge the independent verifier rated decisive or suggestive | C3 |
| Hunch shielding: exposed − shielded mass = 0.00 | Haiku did not anchor on the hunch at generation | No change. Reported as a finding (P3 not testable with this model) | — |

Call budget: the verifier adds one small call per (generation, leader) in E1 (usually 3–4 per state-rep) and one
per turn for COVER arms in E2. A2 also uses one extra call (its selection), so COVER's extra call is not an
unfair compute advantage over A2; it is over A3, which uses none.

## Held-out AIT test and fair baselines (2026-10-25)

| Decision | Why | Alternative rejected |
|---|---|---|
| Build 20 held-out cases from the AIT Alert Data Set's labelled CSV (GitHub `ait-aecid/alert-data-set`, `alerts_csv.zip`) | Real IDS alerts with per-event attack labels; many harmless alerts share alert types with attack alerts (realistic lookalikes); not used in any design decision | More constructed scenarios (no external validity) |
| Evidence map by a fixed LR ≥ 2 rule, leave-one-scenario-out | No researcher coding exists for AIT; the rule is label-based but scorer-only and was fixed before any run | Hand-coding by us (no second coder available now) |
| No `redundant_with` for AIT | No researcher mapping; inventing one would be arbitrary | — |
| Four harmless cases have no useful check under the 8-check catalog | Kept: real alerts are not always resolvable with standard checks; there, deferring is the right behaviour | Dropping hard cases (would inflate everyone's rate) |
| Fair baselines: S0_wrong / S1_wrong (baselines see the wrong hunch); A2 under masked telemetry with an explicit NONE option | Earlier design exposed only COVER arms to the hard conditions, which made H2/H3 untestable | Comparing COVER's hard-condition arms with baselines from easy conditions |
| Design frozen at v3.1 for the AIT run; v3.2 ideas (hunch release, redundancy check, two-sided verifier, strongest-rival filter) NOT included | Any change must be developed on the dev set before the held-out run; changing after seeing AIT results would void it | Adding untested changes right before the held-out run |
