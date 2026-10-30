"""Contrast cards: explicit hypothesis-conditional predictions for each candidate (DP3).

"Counterfactual" here means contrasting PREDICTED outcomes under rival explanations. A card is marked
discriminating only by an operational rule on the model's predicted distributions, never by the fluency
of a rationale (spec 2.5). Thresholds come from config/cover.json and were fixed before any real run.

Rule "R challenges L on query q" (R's expected outcome would count against L):
  - both predictions exist;
  - R has a unique most-likely outcome o_R with P(o_R | R) >= rival_modal_min_prob;
  - L's most-likely outcome differs from o_R;
  - P(o_R | L) <= against_max_prob.
"""
from .config import RULES
from .feasibility import check
from .models import ContrastCard, PredictedObservation


def modal(dist):
    if not dist:
        return None, None
    best = max(dist.values())
    tops = [o for o, p in dist.items() if abs(p - best) < 1e-9]
    return (tops[0], best) if len(tops) == 1 else (None, best)


def challenges(lik_q, r, l):
    pr, pl = lik_q.get(r), lik_q.get(l)
    if pr is None or pl is None:
        return False
    o_r, p_r = modal(pr)
    o_l, _ = modal(pl)
    return (o_r is not None and p_r >= RULES["rival_modal_min_prob"] and o_r != o_l
            and pl.get(o_r, 0.0) <= RULES["against_max_prob"])


def gap(lik_q, r, l):
    """Size of the predicted difference behind 'r challenges l' (for restraint warnings only, not ranking)."""
    o_r, _ = modal(lik_q.get(r))
    if o_r is None or lik_q.get(l) is None:
        return 0.0
    return lik_q[r][o_r] - lik_q[l].get(o_r, 0.0)


TIER_RANK = {"decisive": 0, "strong": 1, "weak": 2, None: 3}


def tier(lik_q, r, l):
    """Qualitative ACH diagnosticity of 'r challenges l' (spec: 'transparent qualitative diagnosticity rubric').
    decisive: the rival's expected result is rare under the leader (<= 0.10) and likely under the rival (>= 0.70)
    strong  : the rival's expected result is uncommon under the leader (<= 0.20)
    weak    : it qualifies as a challenge but the leader would still often produce it."""
    if not challenges(lik_q, r, l):
        return None
    o_r, p_r = modal(lik_q[r])
    p_l = lik_q[l].get(o_r, 0.0)
    if p_l <= RULES["tier_decisive_leader_max"] and p_r >= RULES["tier_decisive_rival_min"]:
        return "decisive"
    return "strong" if p_l <= RULES["tier_strong_leader_max"] else "weak"


def _pred(h, dist):
    if dist is None:
        return PredictedObservation(hypothesis_id=h, predicted_observation=None, probability=None,
                                    source="missing", uncertain=True)
    o, p = modal(dist)
    return PredictedObservation(hypothesis_id=h, predicted_observation=o, probability=round(p, 3),
                                source="LLM_prediction", uncertain=(o is None or p < RULES["uncertain_below"]))


def build_cards(view, state_id, turn, arm, model, leader, executed_ids, unavailable=(), with_contrast=True):
    """One card per catalog query (feasible or not). model = rivals.clean_report output."""
    labels, prior, lik = model["labels"], model["prior"], model["lik"]
    by_prior = sorted(prior, key=lambda h: (-prior[h], h))
    cards = []
    for qid in view.queries:
        ok, reason, _ = check(view, qid, executed_ids, unavailable)
        q = view.queries[qid]
        base = dict(case_id=view.id, state_id=state_id, turn=turn, arm=arm, query_id=qid, query_text=q.description,
                    feasible=ok, feasibility_reason=reason, leading_hypothesis_id=leader,
                    previously_checked=qid in executed_ids)
        if not ok or qid not in lik or not with_contrast or leader is None:
            cards.append(ContrastCard(**base))
            continue
        lq = lik[qid]
        missing = sum(1 for h in prior if lq.get(h) is None)
        cross = [h for h in by_prior if h != leader and labels.get(h) != labels.get(leader)]
        against = [r for r in by_prior if r != leader and challenges(lq, r, leader)]
        by_leader = [r for r in by_prior if r != leader and challenges(lq, leader, r)]
        pairs = []
        hs = list(by_prior)
        for i, a in enumerate(hs):
            for b in hs[i + 1:]:
                if labels.get(a) != labels.get(b) and (challenges(lq, a, b) or challenges(lq, b, a)):
                    pairs.append(sorted([a, b]))
        undermine = [r for r in against if r in cross]
        corroborate = [r for r in by_leader if r in cross]
        # strongest challenger first (tier, then prior order); used for the card's rival and its tier
        undermine = sorted(undermine, key=lambda r: TIER_RANK[tier(lq, r, leader)])
        corroborate = sorted(corroborate, key=lambda r: TIER_RANK[tier(lq, leader, r)])
        rival = (undermine or corroborate or cross or [None])[0]
        c_tier = tier(lq, undermine[0], leader) if undermine else None
        k_tier = tier(lq, leader, corroborate[0]) if corroborate else None
        max_gap = max([gap(lq, r, leader) for r in undermine] + [gap(lq, leader, r) for r in corroborate] + [0.0])
        nme = rival is not None and frozenset((leader, rival)) in model["compatible"]
        card = ContrastCard(**base, rival_hypothesis_id=rival,
                            if_leading_hypothesis=_pred(leader, lq.get(leader)),
                            if_rival_hypothesis=_pred(rival, lq.get(rival)) if rival else None,
                            discriminating=bool(pairs), could_undermine_leader=bool(undermine),
                            corroborates_leader=bool(corroborate),
                            rivals_challenging_leader=against, rivals_challenged_by_leader=by_leader,
                            cross_label_pairs_separated=pairs, not_mutually_exclusive=nme,
                            low_confidence=(not pairs) or missing > 0 or max_gap < RULES["restraint_min_gap"],
                            contrast_tier=c_tier, corroboration_tier=k_tier,
                            missing_predictions=missing)
        cards.append(verbalize(card, labels))
    return cards


def verbalize(card, labels):
    """Fill explanation, counter-evidence statement and limitations (DP3, DP6)."""
    lim = ["Outcome contrasts are the model's predictions, not observations, and are not calibrated."]
    L, R = card.if_leading_hypothesis, card.if_rival_hypothesis
    if card.missing_predictions:
        lim.append(f"{card.missing_predictions} hypothesis prediction(s) missing for this query; treated as unknown.")
    if card.not_mutually_exclusive:
        lim.append("The model marked the leader and this rival as possibly both true; one result cannot exclude either.")
    lim.append("A null or negative result may reflect visibility, time window or data quality, not innocence.")
    exp = f"Check {card.query_id} ({card.query_text})."
    if L and R and L.predicted_observation and R.predicted_observation and card.could_undermine_leader:
        o = R.predicted_observation
        card.what_would_count_against_leader = (
            f"Observing '{o}' would count against {card.leading_hypothesis_id} "
            f"({labels.get(card.leading_hypothesis_id)}) and toward {card.rival_hypothesis_id} "
            f"({labels.get(card.rival_hypothesis_id)}).")
        card.distinct_evidence_needed = (f"'{L.predicted_observation}' if {card.leading_hypothesis_id} holds vs "
                                         f"'{o}' if {card.rival_hypothesis_id} holds.")
        exp += (f" If {card.leading_hypothesis_id} is true the model expects '{L.predicted_observation}' "
                f"(p={L.probability}); if {card.rival_hypothesis_id} is true it expects '{o}' (p={R.probability}). "
                + card.what_would_count_against_leader)
    elif card.corroborates_leader and L and L.predicted_observation:
        exp += (f" Observing '{L.predicted_observation}' would count against the {labels.get(card.rival_hypothesis_id)} "
                f"rival {card.rival_hypothesis_id}; the model predicts no plausible result here that counts against "
                f"the leader.")
    elif card.discriminating:
        exp += " The model predicts this separates rivals other than the leader."
    else:
        exp += " The model's predictions do not separate a malicious from a benign explanation (nondiscriminating)."
    card.explanation, card.limitations = exp, lim
    return card
