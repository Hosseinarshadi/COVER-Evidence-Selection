"""COVER recommendation protocol (spec 2.3 / 7): transparent, rule-based, NO numeric utility or EIG.

Arms (spec 4.1):
  C0     'format only'   : first k feasible candidates in the fixed label-blind order, no contrast use.
  C1v30  pre-registered v3.0 rule: the FIRST qualifying challenge in fixed order (kept as a comparison arm;
         the pilot showed it often lands on checks a researcher coded as non-diagnostic).
  C1     v3.1 'contrast' : challenge-first, ordered lexicographically by
           1. independent verifier label  decisive > suggestive > unverified   (not_diagnostic is ineligible)
           2. ACH diagnosticity tier       decisive > strong > weak             (qualitative rubric)
           3. tests a not-yet-tested rival distinction
           4. fixed label-blind order sha256(case|query)
  C2/C1x identical rules to C1; the difference lies upstream (hunch hidden / exposed at generation).
  C3     v3.1 'restraint': C1's bundle + warnings; defers to the analyst unless the top check is a challenge
         that the independent verifier rated decisive or suggestive.
The simulated analyst always takes top-1 ('selected_top1'); there is no human choice in these runs.
"""
from .contrast import TIER_RANK, build_cards
from .prompts import stable_order
from .models import RecommendationBundle, Rejected

K = 3
RATING_RANK = {"decisive": 0, "suggestive": 1, "unverified": 2, None: 2, "not_diagnostic": 9}
V31_ARMS = {"C1", "C1x", "C2", "C3"}


def _first(cards, pred, exclude, prefer_untested=None, key=None):
    pool = [c for c in cards if c.query_id not in exclude and pred(c)]
    if key is not None:
        tested = prefer_untested or set()
        pool = sorted(pool, key=lambda c: key(c) + (0 if any(tuple(p) not in tested for p in c.cross_label_pairs_separated) else 1,))
        return pool[0] if pool else None      # sorted() is stable, so fixed order breaks remaining ties
    if prefer_untested is not None:
        fresh = [c for c in pool if any(tuple(p) not in prefer_untested for p in c.cross_label_pairs_separated)]
        if fresh:
            return fresh[0]
    return pool[0] if pool else None


def cards_for(view, state_id, turn, arm, model, leader, executed_ids, unavailable=()):
    """Cards in the fixed label-blind order (the verifier needs them before recommend() runs)."""
    order = stable_order(view.id, list(view.queries))
    cards = build_cards(view, state_id, turn, arm, model, leader, executed_ids, unavailable, with_contrast=arm != "C0")
    return sorted(cards, key=lambda c: order.index(c.query_id)), order


def recommend(view, state_id, turn, arm, model, leader, executed_ids, unavailable=(), tested_pairs=None, ratings=None):
    """Return a RecommendationBundle. model = rivals.clean_report output; leader = hypothesis id;
    ratings = {query_id: (label, reason)} from cover.verify (v3.1 arms only)."""
    cards, order = cards_for(view, state_id, turn, arm, model, leader, executed_ids, unavailable)
    v31 = arm in V31_ARMS
    if v31:
        for c in cards:
            if c.could_undermine_leader:
                lab, why = (ratings or {}).get(c.query_id, ("unverified", None))
                c.verifier_rating, c.verifier_reason = lab, why
                if lab == "not_diagnostic":
                    c.warnings.append("Independent review rated this claimed contrast not diagnostic.")
    rejected = [Rejected(query_id=c.query_id, reason=c.feasibility_reason) for c in cards if not c.feasible]
    feas = [c for c in cards if c.feasible]
    trace = [f"rule1 safety/feasibility: {len(feas)} feasible, {len(rejected)} rejected"]
    tested = {tuple(p) for p in (tested_pairs or [])}

    if not feas:
        return _finish(view, state_id, turn, arm, leader, [], True, "No feasible evidence check remains.",
                       rejected, trace, order, cards)

    if arm == "C0":
        items = feas[:K]
        for c in items:
            c.purpose = "unranked_option"
            c.explanation = f"Check {c.query_id} ({c.query_text})."
        trace.append("C0: first k feasible in fixed label-blind order; contrast cards not used")
        return _finish(view, state_id, turn, arm, leader, items, False, None, rejected, trace, order, cards)

    eligible = (lambda c: c.could_undermine_leader and c.verifier_rating != "not_diagnostic") if v31 \
        else (lambda c: c.could_undermine_leader)
    ch_key = (lambda c: (RATING_RANK[c.verifier_rating], TIER_RANK[c.contrast_tier])) if v31 else None
    co_key = (lambda c: (TIER_RANK[c.corroboration_tier],)) if v31 else None

    chosen = []
    ch = _first(feas, eligible, set(), tested, ch_key)
    trace.append(f"rule2 genuine challenge: {ch.query_id if ch else 'none available'}"
                 + (f" (verifier={ch.verifier_rating}, tier={ch.contrast_tier})" if ch and v31 else ""))
    if ch:
        ch.purpose = "challenge_leading_hunch"
        chosen.append(ch)
    co = _first(feas, lambda c: c.corroborates_leader, {c.query_id for c in chosen}, tested, co_key)
    trace.append(f"rule5 independent corroboration: {co.query_id if co else 'none available'}")
    if co:
        co.purpose = "independent_corroboration"
        chosen.append(co)
    covered = {tuple(p) for c in chosen for p in c.cross_label_pairs_separated}
    alt = _first(feas, lambda c: c.discriminating and c.verifier_rating != "not_diagnostic"
                 and any(tuple(p) not in covered for p in c.cross_label_pairs_separated), {c.query_id for c in chosen})
    trace.append(f"rule3/4 rival balance, untested distinction: {alt.query_id if alt else 'none available'}")
    if alt:
        alt.purpose = "alternative_rival_check"
        chosen.append(alt)
    if not chosen:
        disc = _first(feas, lambda c: c.discriminating and c.verifier_rating != "not_diagnostic", set())
        if disc:
            disc.purpose = "exploratory"
            chosen = [disc]
            trace.append("no challenge/corroboration; exploratory discriminating check offered")
        else:
            fb = feas[0]
            fb.purpose = "nondiscriminating_fallback"
            fb.warnings.append("No candidate is predicted (and independently supported) to separate a malicious "
                               "from a benign explanation.")
            chosen = [fb]
            trace.append("no discriminating candidate; first feasible offered as labelled fallback")

    if arm == "C3":
        for c in chosen:
            c.warnings.append("Prediction-based contrast; uncalibrated model output. Verify before relying on it.")
        top = chosen[0]
        supported = top.purpose == "challenge_leading_hunch" and top.verifier_rating in ("decisive", "suggestive")
        if not supported:
            trace.append("rule6 epistemic restraint: top check lacks an independently supported challenge -> defer")
            return _finish(view, state_id, turn, arm, leader, [], True,
                           "No defensible discriminating check: no available check has a challenge to the leading "
                           "explanation that independent review supports. Analyst review or new telemetry is needed.",
                           rejected, trace, order, cards, offered=chosen)
    return _finish(view, state_id, turn, arm, leader, chosen[:K], False, None, rejected, trace, order, cards)


def _finish(view, state_id, turn, arm, leader, items, review, limitation, rejected, trace, order, cards, offered=None):
    for i, c in enumerate(items):
        c.simulated_choice = "selected_top1" if i == 0 else "not_selected"
    expl = "; ".join(f"{c.query_id}: {c.purpose}" for c in items) or "no recommendation"
    b = RecommendationBundle(case_id=view.id, state_id=state_id, turn=turn, arm=arm, leading_hypothesis_id=leader,
                             items=items, review_required=review, limitation=limitation, explanation=expl,
                             rejected=rejected, rule_trace=trace, tie_break_order=order)
    b._all_cards = cards
    b._withheld = offered or []
    return b
