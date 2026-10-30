"""Acceptance tests 2, 3, 5, 9, 10, 11 (spec section 8)."""
import copy, random
from cover.contrast import build_cards, challenges
from cover.hunch_shield import choose_leader, generation_prompt
from cover.recommender import recommend
from cover.rivals import RivalRegistry
from tests.conftest import make_model


# ---- 2. rival persistence ----------------------------------------------------------------------
def test_rival_vanishing_without_rationale_is_recorded():
    reg = RivalRegistry()
    reg.update(0, [{"id": "H1", "label": "malicious", "description": "a"},
                   {"id": "H2", "label": "benign", "description": "b"}], [])
    reg.update(1, [{"id": "H1", "label": "malicious", "description": "a"}], [])
    assert reg.violations and reg.violations[0]["rival_id"] == "H2"
    assert "H2" in reg.rivals and reg.rivals["H2"]["status"] == "vanished"   # never deleted


def test_rival_retired_with_rationale_is_not_a_violation_and_new_rival_versioned():
    reg = RivalRegistry()
    reg.update(0, [{"id": "H1", "label": "malicious", "description": "a"},
                   {"id": "H2", "label": "benign", "description": "b"}], [])
    reg.update(1, [{"id": "H1", "label": "malicious", "description": "a"},
                   {"id": "H3", "label": "benign", "description": "c"}],
               [{"id": "H2", "rationale": "Q2 showed a download, not an admin script"}])
    assert not reg.violations
    assert reg.rivals["H2"]["status"] == "retired" and reg.rivals["H3"]["first_turn"] == 1


# ---- 3. falsification validity -----------------------------------------------------------------
def test_challenge_requires_operational_outcome_difference(sc01_model):
    v, cand, m = sc01_model
    cards = {c.query_id: c for c in build_cards(v, "s0", 0, "C1", m, "H1", [])}
    assert cards["Q2"].could_undermine_leader and cards["Q2"].discriminating
    assert cards["Q2"].what_would_count_against_leader and "administrative_script" in cards["Q2"].what_would_count_against_leader
    # identical (uniform) predictions under both rivals -> nondiscriminating, never a challenge
    assert not cards["Q4"].discriminating and not cards["Q4"].could_undermine_leader
    assert "nondiscriminating" in cards["Q4"].explanation


def test_every_challenge_card_names_a_weakening_outcome(sc01_model):
    v, cand, m = sc01_model
    for c in build_cards(v, "s0", 0, "C1", m, "H1", []):
        if c.could_undermine_leader:
            o = c.if_rival_hypothesis.predicted_observation
            assert o and o != c.if_leading_hypothesis.predicted_observation
            assert challenges(m["lik"][c.query_id], c.rival_hypothesis_id, "H1")


def test_nonexclusive_pair_is_flagged(views):
    v = views["SC-01"]
    cand = list(v.queries)
    hyps = [{"id": "H1", "label": "malicious", "description": "x", "prior": 0.5},
            {"id": "H2", "label": "benign", "description": "y", "prior": 0.5}]
    preds = {("Q2", "H1"): {"download_and_execute": 0.9, "administrative_script": 0.05, "other": 0.05},
             ("Q2", "H2"): {"download_and_execute": 0.05, "administrative_script": 0.9, "other": 0.05}}
    m = make_model(v, cand, hyps, preds, compatible=[("H1", "H2")])
    c = next(c for c in build_cards(v, "s0", 0, "C1", m, "H1", []) if c.query_id == "Q2")
    assert c.not_mutually_exclusive and any("both true" in l for l in c.limitations)


# ---- 5. incorrect hunch: shield differs only by the hunch block --------------------------------
def test_shield_prompts_differ_only_in_hunch_block(views):
    v = views["SC-02"]
    exposed = generation_prompt(v, [], "malicious", shielded=False)
    shielded = generation_prompt(v, [], "malicious", shielded=True)
    none = generation_prompt(v, [], None, shielded=True)
    assert shielded == none                         # shielded generation never sees the hunch
    assert "ANALYST'S INITIAL HUNCH" in exposed and "ANALYST'S INITIAL HUNCH" not in shielded
    assert exposed.replace("\nANALYST'S INITIAL HUNCH: The analyst currently thinks this activity is malicious.\n", "") == shielded


def test_leader_follows_hunch_after_generation():
    hyps = [{"id": "H1", "label": "malicious", "prior": 0.7}, {"id": "H2", "label": "benign", "prior": 0.3}]
    assert choose_leader(hyps)[0] == "H1"
    assert choose_leader(hyps, "benign")[0] == "H2"
    lid, warn = choose_leader([{"id": "H1", "label": "malicious", "prior": 1.0},
                               {"id": "H9", "label": "malicious", "prior": 0.0}], "benign")
    assert lid == "H1" and warn


# ---- 9. no false certainty ---------------------------------------------------------------------
def test_all_unknown_forecasts_trigger_deferral(views):
    v = views["SC-03"]
    cand = list(v.queries)
    hyps = [{"id": "H1", "label": "malicious", "description": "x", "prior": 0.5},
            {"id": "H2", "label": "benign", "description": "y", "prior": 0.5}]
    m = make_model(v, cand, hyps, {})               # no predictions at all
    b3 = recommend(v, "s0", 0, "C3", m, "H1", [])
    assert b3.review_required and not b3.items and b3.limitation
    b1 = recommend(v, "s0", 0, "C1", m, "H1", [])
    assert b1.items[0].purpose == "nondiscriminating_fallback" and b1.items[0].warnings


def test_unavailable_telemetry_is_excluded_and_can_force_deferral(sc01_model):
    v, cand, m = sc01_model
    b = recommend(v, "s0", 0, "C3", m, "H1", [], unavailable=("Q1", "Q2"))
    assert all(c.query_id not in ("Q1", "Q2") for c in b.items)
    assert {"Q1", "Q2"} <= {r.query_id for r in b.rejected}
    assert b.review_required                         # nothing left that separates the rivals


# ---- 10. deterministic rules -------------------------------------------------------------------
def test_same_inputs_same_bundle(sc01_model):
    v, cand, m = sc01_model
    a = recommend(v, "s0", 0, "C1", m, "H1", []).model_dump()
    b = recommend(v, "s0", 0, "C1", copy.deepcopy(m), "H1", []).model_dump()
    assert a == b


def test_prediction_order_does_not_change_bundle(views, sc01_model):
    v, cand, m = sc01_model
    m2 = copy.deepcopy(m)
    items = list(m2["lik"].items())
    random.Random(3).shuffle(items)
    m2["lik"] = dict(items)
    assert recommend(v, "s0", 0, "C1", m, "H1", []).model_dump() == recommend(v, "s0", 0, "C1", m2, "H1", []).model_dump()


def test_tie_break_is_not_query_id_order(views):
    """Diagnostic queries are the low IDs in these scenarios, so tie-breaking by ID would leak (audit F3)."""
    from cover.prompts import stable_order
    flips = sum(stable_order(v.id, list(v.queries)) != sorted(v.queries) for v in views.values())
    assert flips == len(views)


# ---- 11. ablation integrity --------------------------------------------------------------------
def test_C1_and_C2_apply_identical_rules(sc01_model):
    v, cand, m = sc01_model
    a = recommend(v, "s0", 0, "C1", m, "H1", []).model_dump()
    b = recommend(v, "s0", 0, "C2", m, "H1", []).model_dump()
    strip = lambda d: {k: val for k, val in d.items() if k not in ("arm", "items")}
    assert strip(a) == strip(b)
    assert [c["query_id"] for c in a["items"]] == [c["query_id"] for c in b["items"]]


def test_C3_differs_from_C2_only_by_warnings_and_abstention(sc01_model):
    v, cand, m = sc01_model
    b2 = recommend(v, "s0", 0, "C2", m, "H1", [])
    b3 = recommend(v, "s0", 0, "C3", m, "H1", [])
    if not b3.review_required:
        assert [c.query_id for c in b2.items] == [c.query_id for c in b3.items]
        assert all(len(c3.warnings) >= len(c2.warnings) for c2, c3 in zip(b2.items, b3.items))


def test_C0_and_C1_share_the_candidate_pool(sc01_model):
    v, cand, m = sc01_model
    b0, b1 = recommend(v, "s0", 0, "C0", m, "H1", []), recommend(v, "s0", 0, "C1", m, "H1", [])
    assert {c.query_id for c in b0._all_cards} == {c.query_id for c in b1._all_cards}
    assert all(c.if_leading_hypothesis is None for c in b0.items)      # C0 never uses contrast
    assert b1.items[0].purpose == "challenge_leading_hunch"


# ---- v3.1 (post-pilot) rules -------------------------------------------------------------------
def _two_challenges(views):
    """SC-01: Q4 is a WEAK challenge (leader still often yields the rival's outcome),
    Q2 is DECISIVE. Q4 comes first in the fixed order, so v3.0 picks it and v3.1 must not."""
    from cover.prompts import stable_order
    v = views["SC-01"]
    cand = list(v.queries)
    hyps = [{"id": "H1", "label": "malicious", "description": "attack", "prior": 0.6},
            {"id": "H2", "label": "benign", "description": "admin", "prior": 0.4}]
    preds = {(q, h): {o: 1 / len(v.queries[q].outcomes) for o in v.queries[q].outcomes} for q in cand for h in ("H1", "H2")}
    preds[("Q2", "H1")] = {"download_and_execute": 0.92, "administrative_script": 0.04, "other": 0.04}
    preds[("Q2", "H2")] = {"download_and_execute": 0.03, "administrative_script": 0.90, "other": 0.07}
    order = stable_order(v.id, cand)
    weak = next(q for q in order if q not in ("Q2",) and len(v.queries[q].outcomes) == 2)
    o1, o2 = v.queries[weak].outcomes
    preds[(weak, "H1")] = {o1: 0.67, o2: 0.33}   # P(o2|H1)=0.33 <= 0.35 -> qualifies as a challenge, tier 'weak'
    preds[(weak, "H2")] = {o1: 0.35, o2: 0.65}
    return v, cand, make_model(v, cand, hyps, preds), weak, order


def test_v31_prefers_decisive_over_first_qualifying(views):
    v, cand, m, weak, order = _two_challenges(views)
    if order.index(weak) > order.index("Q2"):
        import pytest
        pytest.skip("fixed order already puts Q2 first in this scenario")
    assert recommend(v, "s0", 0, "C1v30", m, "H1", []).top1 == weak          # v3.0: first qualifying
    b = recommend(v, "s0", 0, "C1", m, "H1", [])
    assert b.top1 == "Q2" and b.items[0].contrast_tier == "decisive"


def test_verifier_not_diagnostic_makes_challenge_ineligible(sc01_model):
    v, cand, m = sc01_model
    b = recommend(v, "s0", 0, "C1", m, "H1", [], ratings={"Q2": ("not_diagnostic", "common in admin work")})
    assert b.top1 != "Q2"
    q2 = next(c for c in b._all_cards if c.query_id == "Q2")
    assert q2.verifier_rating == "not_diagnostic" and q2.warnings


def test_C3_defers_without_independent_support(sc01_model):
    v, cand, m = sc01_model
    assert recommend(v, "s0", 0, "C3", m, "H1", []).review_required                       # unverified
    assert recommend(v, "s0", 0, "C3", m, "H1", [], ratings={"Q1": ("not_diagnostic", ""), "Q2": ("not_diagnostic", "")}).review_required
    ok = recommend(v, "s0", 0, "C3", m, "H1", [], ratings={"Q2": ("decisive", "rare for admin scripts")})
    assert not ok.review_required and ok.top1 == "Q2"


def test_verifier_prompt_hides_generator_numbers_and_key(views, sc01_model):
    from cover.recommender import cards_for
    from cover.verify import verify_prompt
    v, cand, m = sc01_model
    cards, _ = cards_for(v, "s0", 0, "C1", m, "H1", [])
    claims = [c for c in cards if c.could_undermine_leader]
    hyps = {h["id"]: h for h in m["hypotheses"]}
    p = verify_prompt(v, [], hyps["H1"], claims, hyps)
    assert "0.85" not in p and "p=" not in p and "prior" not in p.lower()


def test_belief_prompt_asks_for_updated_probability(views):
    from cover.prompts import rivals_prompt
    p = rivals_prompt(views["SC-01"], [("Q2", "download_and_execute")])
    assert "GIVEN THE ALERT AND ALL EVIDENCE OBSERVED SO FAR" in p and "update these probabilities" in p
