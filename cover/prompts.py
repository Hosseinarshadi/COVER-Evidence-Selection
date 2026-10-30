"""Prompt construction (agent-visible data only) and the hunch shield.

Candidate order: the legacy script listed queries Q1..Qn, and in these scenarios the diagnostic queries
are the low IDs (docs/BASELINE_AUDIT.md F3). All COVER-v3 prompts and the recommender's tie-break use a
fixed, label-blind order: sha256("<case_id>|<query_id>"). It is the same for every arm.
"""
import hashlib, json
from .config import prompt_text
from .view import assert_no_leak

SYSTEM = ("You assist a cybersecurity threat hunter. You do not know which explanation is correct. "
          "Reason only from the alert, the evidence observed so far, and the query catalog provided.")


def stable_order(case_id, query_ids):
    return sorted(query_ids, key=lambda q: hashlib.sha256(f"{case_id}|{q}".encode()).hexdigest())


def candidates(view, observed_ids, unavailable=()):
    """Catalog queries not yet run, in the fixed label-blind order. Unavailable ones are still listed in
    prompts only if the caller passes them; feasibility removes them before recommendation."""
    return stable_order(view.id, [q for q in view.queries if q not in observed_ids and q not in unavailable])


def state_text(view, observed, unavailable=()):
    """observed: list of (query_id, outcome)."""
    obs_ids = [q for q, _ in observed]
    lines = [f"ALERT: {view.trigger}", "", "INITIAL EVIDENCE:"]
    lines += [f"- {e}" for e in view.initial_evidence]
    if observed:
        lines += ["", "QUERIES ALREADY RUN AND THEIR RESULTS:"]
        for qid, outcome in observed:
            lines.append(f"- {qid}: {view.queries[qid].description} -> {outcome}")
    lines += ["", "CANDIDATE QUERIES (id: description [possible outcomes] (relative cost)):"]
    for qid in candidates(view, obs_ids, unavailable):
        q = view.queries[qid]
        cost = int(q.cost) if float(q.cost).is_integer() else q.cost
        lines.append(f"- {qid}: {q.description} [{', '.join(q.outcomes)}] (cost {cost})")
    if unavailable:
        lines += ["", "UNAVAILABLE (telemetry missing, cannot be run): " + ", ".join(sorted(unavailable))]
    return "\n".join(lines)


def hunch_block(hunch_label):
    return prompt_text("hunch_block.md").replace("{HUNCH_LABEL}", hunch_label) if hunch_label else ""


def prior_rivals_block(prev_hypotheses):
    if not prev_hypotheses:
        return ""
    rows = [{"id": h["id"], "label": h["label"], "description": h["description"]} for h in prev_hypotheses]
    return ("\nHYPOTHESES YOU REPORTED BEFORE THE LATEST EVIDENCE (keep the same id for the same explanation; "
            "retire one only with a reason):\n" + json.dumps(rows, indent=1) + "\n")


def rivals_prompt(view, observed, hunch_label=None, expose_hunch=False, prev_hypotheses=None, unavailable=()):
    """Rival-generation prompt. The hunch shield: when expose_hunch is False the hunch is NOT inserted,
    whatever hunch_label is. The two variants differ only in the hunch block (tested)."""
    text = (prompt_text("cover_rivals.md")
            .replace("{STATE}", state_text(view, observed, unavailable))
            .replace("{PRIOR_RIVALS_BLOCK}", prior_rivals_block(prev_hypotheses))
            .replace("{HUNCH_BLOCK}", hunch_block(hunch_label) if expose_hunch else ""))
    return assert_no_leak(text, "rivals prompt")


NONE_OPTION = ("\n\nIf none of the available candidate queries would help tell the explanations apart, return the id "
               "NONE instead of a query id.")


def select_prompt(view, observed, hypotheses, predictions, unavailable=(), hunch_label=None, allow_none=False):
    """Legacy A2/S0 selection prompt. Fair-baseline options (v3.1): hunch_label shows the analyst's hunch to the
    selector (S0_wrong); allow_none lets the selector decline when nothing helps (A2 under missing telemetry)."""
    text = (prompt_text("cover_select.md")
            .replace("{STATE}", state_text(view, observed, unavailable) + (hunch_block(hunch_label) if hunch_label else ""))
            .replace("{HYPOTHESES}", json.dumps(hypotheses, indent=1))
            .replace("{PREDICTIONS}", json.dumps(predictions, indent=1)))
    if allow_none:
        text = text.replace("\n\nRespond by calling the select_query tool.", NONE_OPTION + "\n\nRespond by calling the select_query tool.")
    return assert_no_leak(text, "select prompt")
