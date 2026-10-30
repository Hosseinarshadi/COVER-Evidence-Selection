"""Rival registry: clean the model's hypothesis report, keep stable rival identity across turns,
and record persistence violations (a rival that vanishes without a retirement rationale).

Likelihoods here are the model's *predictions*. Missing predictions stay None (unknown); they are NOT
silently filled with uniform values inside COVER (the legacy EIG baseline does its own filling).
"""
EPS = 1e-6


def normalize(d):
    s = sum(d.values())
    return {k: v / s for k, v in d.items()} if s > 0 else {k: 1 / len(d) for k in d}


def clean_report(raw, view, cand_ids):
    """Return dict(hypotheses, prior, lik, missing, unknown_outcomes, labels, compatible).
    lik[q][h] is a normalized outcome->prob dict, or None when the model gave no usable prediction."""
    hyps = []
    for h in raw.get("hypotheses", []):
        try:
            prior = float(h.get("prior", 0) or 0)
        except (TypeError, ValueError):
            prior = 0.0
        hyps.append({"id": str(h.get("id")).strip(), "label": str(h.get("label")).strip().lower(),
                     "description": str(h.get("description", "")), "prior": prior})
    prior = normalize({h["id"]: max(h["prior"], EPS) for h in hyps})
    given = {}
    for p in raw.get("predictions", []):
        if not isinstance(p, dict):
            continue
        probs = p.get("outcome_probs")
        if isinstance(probs, list):
            probs = {str(x.get("outcome")).strip().lower(): x.get("probability") for x in probs if isinstance(x, dict)}
        if isinstance(probs, dict):
            given[(str(p.get("query_id")).strip(), str(p.get("hypothesis_id")).strip())] = probs
    lik, missing, unknown_outcomes = {}, 0, 0
    for qid in cand_ids:
        outs = view.queries[qid].outcomes
        lik[qid] = {}
        for h in prior:
            probs = given.get((qid, h))
            if not probs:
                missing += 1
                lik[qid][h] = None
                continue
            unknown_outcomes += sum(1 for k in probs if k not in {o.lower() for o in outs})
            clean = {}
            for o in outs:
                try:
                    clean[o] = max(float(probs.get(o.lower(), 0) or 0), 0.0)
                except (TypeError, ValueError):
                    clean[o] = 0.0
            lik[qid][h] = normalize(clean) if sum(clean.values()) > 0 else None
            if lik[qid][h] is None:
                missing += 1
    compatible = {frozenset((str(c.get("a")), str(c.get("b")))) for c in raw.get("compatible_pairs", [])
                  if isinstance(c, dict)}
    return {"hypotheses": hyps, "prior": prior, "lik": lik, "missing": missing,
            "unknown_outcomes": unknown_outcomes, "labels": {h["id"]: h["label"] for h in hyps},
            "compatible": compatible}


class RivalRegistry:
    """Tracks rival ids across turns of one investigation. Never deletes; versions new rivals."""

    def __init__(self):
        self.rivals = {}       # id -> {"label","description","first_turn","status","retired_turn","rationale"}
        self.violations = []

    def update(self, turn, hypotheses, retired):
        retired = {str(r.get("id")): r.get("rationale", "") for r in (retired or []) if isinstance(r, dict)}
        current = {h["id"] for h in hypotheses}
        for h in hypotheses:
            if h["id"] not in self.rivals:
                self.rivals[h["id"]] = {"label": h["label"], "description": h["description"], "first_turn": turn,
                                        "status": "active", "retired_turn": None, "rationale": None}
            elif self.rivals[h["id"]]["status"] != "active":
                self.rivals[h["id"]]["status"] = "active"   # reinstated; keep history
        for rid, r in self.rivals.items():
            if r["status"] == "active" and rid not in current:
                if rid in retired and retired[rid].strip():
                    r.update(status="retired", retired_turn=turn, rationale=retired[rid])
                else:
                    r.update(status="vanished", retired_turn=turn, rationale=None)
                    self.violations.append({"turn": turn, "rival_id": rid,
                                            "problem": "rival vanished without a retirement rationale"})
        return self

    def snapshot(self):
        return {"rivals": {k: dict(v) for k, v in self.rivals.items()}, "violations": list(self.violations)}
