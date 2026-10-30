"""Independent contrast verifier (DP3 quality gate, spec 2.5: "do not mark a query as falsifying solely
because an LLM writes a fluent rationale").

Pilot diagnosis (2026-10-25): the generator assigned clearly different outcome probabilities to generic
checks that a researcher coded as non-diagnostic, and COVER v3.0 took the first such check. The verifier is a
SEPARATE call with a fresh context: it never sees the generator's probabilities, priors or other rivals,
only the alert, the evidence, the leading explanation and each claimed counter-result. It rates each claim
decisive / suggestive / not_diagnostic. Separate challenge and adjudication is used because same-context
self-review has been reported to undo correct decisions in LLM alert triage.

The verifier uses agent-visible information only. It is not a score: its labels are categorical and are
used as an eligibility gate and a lexicographic order, never summed or weighted.
"""
from .config import prompt_text
from .llm import VERIFY_TOOL, fake_verify
from .prompts import SYSTEM
from .view import assert_no_leak


def verify_prompt(view, observed, leader_h, cards, hyps_by_id):
    ev = [f"- {e}" for e in view.initial_evidence]
    ev += [f"- {q}: {view.queries[q].description} -> {o}" for q, o in observed]
    claims = []
    for c in cards:
        o = c.if_rival_hypothesis.predicted_observation
        rh = hyps_by_id.get(c.rival_hypothesis_id, {})
        claims.append(f"- {c.query_id}: {c.query_text}. Claimed result against the leading explanation: '{o}' "
                      f"(expected if instead: {rh.get('label', '?')}: {rh.get('description', '')})")
    text = (prompt_text("cover_verify.md")
            .replace("{TRIGGER}", view.trigger)
            .replace("{EVIDENCE}", "\n".join(ev))
            .replace("{LEADER_LABEL}", leader_h.get("label", "?"))
            .replace("{LEADER_DESC}", leader_h.get("description", ""))
            .replace("{CLAIMS}", "\n".join(claims)))
    return assert_no_leak(text, "verify prompt")


def verify(llm, view, observed, model, leader, cards, fake_key):
    """Rate every feasible card that claims to undermine the leader. Returns (ratings, record).
    ratings: {query_id: (rating, reason)}. Cards not returned by the model stay 'unverified'."""
    claim_cards = [c for c in cards if c.feasible and c.could_undermine_leader]
    if not claim_cards or leader is None:
        return {}, None
    hyps = {h["id"]: h for h in model["hypotheses"]}
    prompt = verify_prompt(view, observed, hyps.get(leader, {}), claim_cards, hyps)
    raw, meta = llm.call(prompt, SYSTEM, VERIFY_TOOL, fake_verify([c.query_id for c in claim_cards]), fake_key=fake_key)
    assert_no_leak(raw, "verifier output")
    valid = {c.query_id for c in claim_cards}
    ratings = {}
    for r in raw.get("ratings", []):
        q = str(r.get("query_id", "")).strip()
        if q in valid and r.get("rating") in ("decisive", "suggestive", "not_diagnostic"):
            ratings[q] = (r["rating"], str(r.get("reason", ""))[:500])
    return ratings, {"prompt": prompt, "raw": raw, "meta": meta, "leader": leader,
                     "claims": sorted(valid)}
