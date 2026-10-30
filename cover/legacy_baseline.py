"""Legacy A3/S1 comparator: the original cost-weighted EIG controller, copied from
legacy/active_ach_experiment.py. It is a BASELINE only and is not used by any COVER arm.
Missing predictions are filled with uniform values, exactly as the legacy build_model did.
"""
import math

EPS = 1e-6


def entropy(ps):
    return -sum(p * math.log2(p) for p in ps if p > 0)


def _norm(d):
    s = sum(d.values())
    return {k: v / s for k, v in d.items()} if s > 0 else {k: 1 / len(d) for k in d}


def legacy_lik(view, model):
    out = {}
    for qid, per_h in model["lik"].items():
        outs = view.queries[qid].outcomes
        out[qid] = {h: _norm({o: max((d or {}).get(o, 0.0), EPS) for o in outs}) if d is not None
                    else {o: 1 / len(outs) for o in outs} for h, d in per_h.items()}
    return out


def eig(prior, lik_q):
    outcomes = next(iter(lik_q.values())).keys()
    h0, post = entropy(prior.values()), 0.0
    for o in outcomes:
        po = sum(prior[h] * lik_q[h][o] for h in prior)
        if po > 0:
            post += po * entropy([prior[h] * lik_q[h][o] / po for h in prior])
    return h0 - post


def eig_select(view, model, feasible_ids, cost_weighted=True):
    """Return (query_id, eig dict). Ties break by EIG then by query id (as legacy max() did on dict order)."""
    lik = legacy_lik(view, model)
    eigs = {q: eig(model["prior"], lik[q]) for q in feasible_ids if q in lik}
    if not eigs:
        return None, {}
    cost = {q: (view.queries[q].cost if cost_weighted else 1.0) for q in eigs}
    return max(eigs, key=lambda q: (eigs[q] / cost[q], eigs[q])), eigs
