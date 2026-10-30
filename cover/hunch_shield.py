"""Hunch shield (DP1). The masking boundary sits at rival generation only.

exposed  : the rival generator sees the analyst's hunch.
shielded : the rival generator does not; the hunch is applied afterwards, when the recommender picks
           which hypothesis is 'leading' (both arms see it at that point).
"""
from .prompts import rivals_prompt


def generation_prompt(view, observed, hunch_label, shielded, prev_hypotheses=None, unavailable=()):
    return rivals_prompt(view, observed, hunch_label=hunch_label, expose_hunch=not shielded,
                         prev_hypotheses=prev_hypotheses, unavailable=unavailable)


def choose_leader(hypotheses, hunch_label=None):
    """Leading hypothesis: highest prior; with a hunch, the highest-prior hypothesis carrying the hunch label.
    Ties break on hypothesis id. Returns (leader_id, warning or None)."""
    hs = sorted(hypotheses, key=lambda h: (-float(h["prior"]), str(h["id"])))
    if not hs:
        return None, "no hypotheses"
    if hunch_label:
        match = [h for h in hs if h["label"] == hunch_label]
        if match:
            return match[0]["id"], None
        return hs[0]["id"], f"no hypothesis carries the hunch label '{hunch_label}'; leader = highest prior"
    return hs[0]["id"], None
