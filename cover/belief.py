"""Belief records (spec 7). Not a Bayesian posterior: a transparent reason record built from the model's
self-reported priors before and after an observation. Self-reported numbers are NOT calibrated
probabilities and are labelled as such everywhere they are stored.
"""
from .config import RULES


def label_mass(prior, labels, label):
    return sum(p for h, p in prior.items() if labels.get(h) == label)


def verdict(model):
    """Pre-registered verdict rule: a label needs >= verdict_mass of the model's reported prior mass."""
    m = label_mass(model["prior"], model["labels"], "malicious")
    t = RULES["verdict_mass"]
    if m >= t:
        return "malicious", round(m, 4)
    if 1 - m >= t:
        return "benign", round(1 - m, 4)
    return "unresolved", round(max(m, 1 - m), 4)


def reason_record(before, after, observation, card=None):
    """before/after: clean_report outputs from consecutive generation calls."""
    band = RULES["unchanged_belief_band"]
    rows = []
    for h in sorted(set(before["prior"]) | set(after["prior"])):
        b, a = before["prior"].get(h), after["prior"].get(h)
        if b is None or a is None:
            status = "new" if b is None else "dropped"
        else:
            status = "unchanged" if abs(a - b) < band else ("supported" if a > b else "weakened")
        rows.append({"hypothesis_id": h, "label": after["labels"].get(h) or before["labels"].get(h),
                     "before": None if b is None else round(b, 4), "after": None if a is None else round(a, 4),
                     "status": status})
    return {"recommendation": None if card is None else {"query_id": card.query_id, "purpose": card.purpose,
                                                          "what_would_count_against_leader": card.what_would_count_against_leader},
            "observed": observation, "hypotheses": rows,
            "note": "Self-reported model confidence; not a calibrated probability; no analyst approval (simulation)."}
