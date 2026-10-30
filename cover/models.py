"""Pydantic data contracts. Every persisted model forbids undocumented keys (extra='forbid').

Spec 2.4 contrast card, plus recommendation bundle and investigation trace events.
"""
from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

SCHEMA_VERSION = "cover-v3.0"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ model (LLM) output

class Hypothesis(Strict):
    id: str
    label: Literal["malicious", "benign"]
    description: str
    prior: float


class OutcomeProb(Strict):
    outcome: str
    probability: float


class Prediction(Strict):
    query_id: str
    hypothesis_id: str
    outcome_probs: List[OutcomeProb]


class Retired(Strict):
    id: str
    rationale: str


class CompatiblePair(Strict):
    a: str
    b: str


class HypothesisReport(Strict):
    hypotheses: List[Hypothesis]
    predictions: List[Prediction]
    retired: List[Retired] = Field(default_factory=list)
    compatible_pairs: List[CompatiblePair] = Field(default_factory=list)


# ------------------------------------------------------------------ contrast card (spec 2.4)

class PredictedObservation(Strict):
    hypothesis_id: str
    predicted_observation: Optional[str]          # modal outcome, None if unknown/tied
    probability: Optional[float]
    source: Literal["LLM_prediction", "missing"] = "LLM_prediction"
    uncertain: bool


Purpose = Literal["challenge_leading_hunch", "independent_corroboration", "alternative_rival_check",
                  "exploratory", "nondiscriminating_fallback", "unranked_option", "candidate"]


class ContrastCard(Strict):
    schema_version: str = SCHEMA_VERSION
    case_id: str
    state_id: str
    turn: int
    arm: str
    query_id: str
    query_language: Literal["catalog_check"] = "catalog_check"
    query_text: str
    feasible: bool
    feasibility_reason: str
    purpose: Purpose = "candidate"
    leading_hypothesis_id: Optional[str]
    rival_hypothesis_id: Optional[str] = None
    if_leading_hypothesis: Optional[PredictedObservation] = None
    if_rival_hypothesis: Optional[PredictedObservation] = None
    what_would_count_against_leader: Optional[str] = None
    distinct_evidence_needed: Optional[str] = None
    previously_checked: bool = False
    discriminating: bool = False
    could_undermine_leader: bool = False
    corroborates_leader: bool = False
    rivals_challenging_leader: List[str] = Field(default_factory=list)
    rivals_challenged_by_leader: List[str] = Field(default_factory=list)
    cross_label_pairs_separated: List[List[str]] = Field(default_factory=list)
    not_mutually_exclusive: bool = False
    low_confidence: bool = False
    contrast_tier: Optional[Literal["decisive", "strong", "weak"]] = None          # ACH rubric on predictions
    corroboration_tier: Optional[Literal["decisive", "strong", "weak"]] = None
    verifier_rating: Optional[Literal["decisive", "suggestive", "not_diagnostic", "unverified"]] = None
    verifier_reason: Optional[str] = None
    missing_predictions: int = 0
    explanation: str = ""
    limitations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    human_choice: None = None                      # MUST stay None in every non-human run
    simulated_choice: Optional[Literal["selected_top1", "not_selected"]] = None


class Rejected(Strict):
    query_id: str
    reason: str


class RecommendationBundle(Strict):
    schema_version: str = SCHEMA_VERSION
    case_id: str
    state_id: str
    turn: int
    arm: str
    leading_hypothesis_id: Optional[str]
    items: List[ContrastCard]
    review_required: bool
    limitation: Optional[str] = None
    explanation: str = ""
    rejected: List[Rejected] = Field(default_factory=list)
    rule_trace: List[str] = Field(default_factory=list)
    tie_break_order: List[str] = Field(default_factory=list)
    _all_cards: list = PrivateAttr(default_factory=list)   # every card built, for the raw log only
    _withheld: list = PrivateAttr(default_factory=list)    # C3 items withheld by restraint, for the raw log

    @property
    def top1(self):
        return self.items[0].query_id if self.items else None


# ------------------------------------------------------------------ investigation trace

EventType = Literal["hypotheses_generated", "recommendation_proposed", "recommendation_selected",
                    "query_executed", "observation_received", "execution_error", "belief_updated",
                    "verdict", "deferred_to_analyst", "rival_persistence_violation"]


class HumanProvenance(Strict):
    participant_id: str
    session_id: str
    consent_record_id: str
    authenticated_by: str


class TraceEvent(Strict):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    case_id: str
    arm: str
    rep: int
    turn: int
    event_type: EventType
    timestamp_utc: str
    provenance: Literal["llm", "rule", "simulator", "simulated_replay", "human"]
    human_provenance: Optional[HumanProvenance] = None
    payload: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def human_needs_proof(self):
        if self.provenance == "human" and self.human_provenance is None:
            raise ValueError("A human-provenance event needs authenticated human_provenance")
        if self.provenance != "human" and self.human_provenance is not None:
            raise ValueError("Non-human events may not carry human_provenance")
        return self


class Observation(Strict):
    query_id: str
    outcome: str
    source: Literal["simulated_replay_of_reference_map"] = "simulated_replay_of_reference_map"
    timestamp_utc: str


class ExecutionError(Strict):
    query_id: str
    error: str
    kind: Literal["unknown_query", "unsafe_query", "telemetry_unavailable", "already_executed"]
    timestamp_utc: str
