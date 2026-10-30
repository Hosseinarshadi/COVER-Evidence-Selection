"""Scorer-only judge. Reads the frozen key AFTER runs (or the replay during E2 execution only).

Every classification here is an AUTOMATED PROXY based on the researcher's evidence map. Until two coders
have applied the blinded rubric (analysis/coding_sheet.py), treat them as provisional.
"""
import json, math
from pathlib import Path
from cover.config import CONFIG
from cover.legacy_baseline import legacy_lik

EPS = 1e-6


def load_key(path):
    path = Path(path)
    if not path.name.endswith(".key.json"):
        raise ValueError("scorer expects a *.key.json file")
    return {k["id"]: k for k in json.loads(path.read_text(encoding="utf-8"))}


def nonredundant_diagnostic(key_sc, qid, executed_ids):
    q = key_sc["queries"].get(qid)
    if q is None:
        return False
    return bool(q["diagnostic"]) and not any(r in executed_ids for r in q.get("redundant_with", []))


def redundant(key_sc, qid, executed_ids):
    q = key_sc["queries"].get(qid) or {}
    return any(r in executed_ids for r in q.get("redundant_with", []))


def chance_rate(key_sc, cand_ids, executed_ids):
    if not cand_ids:
        return None
    return sum(nonredundant_diagnostic(key_sc, q, executed_ids) for q in cand_ids) / len(cand_ids)


def ceiling_bin(rate):
    b = CONFIG["ceiling_bins"]
    if rate is None:
        return "n/a"
    return "low" if rate < b["low_max"] else ("high" if rate > b["high_min"] else "medium")


def reference_outcome(key_sc, qid):
    return key_sc["queries"][qid]["reference_outcome"]


def predicted_contradiction_realized(key_sc, model, leader, qid):
    """Did the reference outcome of qid count against the leader under the model's OWN predictions,
    i.e. some opposite-label rival predicted it as more likely than the leader did? None if unknowable."""
    if qid is None or leader is None or qid not in model["lik"]:
        return None
    ref = reference_outcome(key_sc, qid)
    lq, labels = model["lik"][qid], model["labels"]
    if lq.get(leader) is None:
        return None
    pl = lq[leader].get(ref, 0.0)
    rivals = [r for r in lq if r != leader and labels.get(r) != labels.get(leader) and lq.get(r) is not None]
    if not rivals:
        return None
    return any(lq[r].get(ref, 0.0) > pl for r in rivals)


def delta_p_true(view, key_sc, model, qid):
    """Change in the model's probability mass on the true label after the reference outcome (legacy metric)."""
    if qid is None or qid not in model["lik"]:
        return 0.0
    lik = legacy_lik(view, model)[qid]
    prior, labels, truth = model["prior"], model["labels"], key_sc["truth"]
    ref = reference_outcome(key_sc, qid)
    post = {h: prior[h] * lik[h][ref] for h in prior}
    s = sum(post.values()) or 1.0
    before = sum(p for h, p in prior.items() if labels.get(h) == truth)
    after = sum(p / s for h, p in post.items() if labels.get(h) == truth)
    return after - before


def calibration_logloss(view, key_sc, model, cand_ids):
    truth_h = {h: p for h, p in model["prior"].items() if model["labels"].get(h) == key_sc["truth"]}
    if not truth_h:
        return None
    s = sum(truth_h.values())
    w = {h: p / s for h, p in truth_h.items()}
    lik = legacy_lik(view, model)
    losses = [-math.log2(max(sum(w[h] * lik[q][h][reference_outcome(key_sc, q)] for h in w), EPS))
              for q in cand_ids if q in lik]
    return sum(losses) / len(losses) if losses else None


from cover.belief import label_mass, verdict  # noqa: E402,F401  (re-exported for analysis)
