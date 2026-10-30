import json, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cover.view import load_views  # noqa: E402
from scoring.reference_judge import load_key  # noqa: E402

VISIBLE = ROOT / "scenarios" / "dev.visible.json"
KEY = ROOT / "scenarios" / "dev.key.json"


@pytest.fixture(scope="session")
def views():
    return {v.id: v for v in load_views(VISIBLE)}


@pytest.fixture(scope="session")
def key():
    return load_key(KEY)


def make_model(view, cand, hyps, preds, compatible=()):
    """Build a clean_report from compact specs. preds: {(q, h): {outcome: p}}."""
    from cover.rivals import clean_report
    raw = {"hypotheses": hyps,
           "predictions": [{"query_id": q, "hypothesis_id": h,
                            "outcome_probs": [{"outcome": o, "probability": p} for o, p in d.items()]}
                           for (q, h), d in preds.items()],
           "retired": [], "compatible_pairs": [{"a": a, "b": b} for a, b in compatible]}
    return clean_report(raw, view, cand)


@pytest.fixture
def sc01_model(views):
    """SC-01 s0 with hand-written predictions: Q2 strongly separates H1 (malicious) from H2 (benign);
    Q4 is identical under both; Q1 moderately separates."""
    v = views["SC-01"]
    cand = list(v.queries)
    hyps = [{"id": "H1", "label": "malicious", "description": "macro dropper", "prior": 0.6},
            {"id": "H2", "label": "benign", "description": "admin script", "prior": 0.4}]
    preds = {}
    for q in cand:
        outs = v.queries[q].outcomes
        for h in ("H1", "H2"):
            preds[(q, h)] = {o: 1 / len(outs) for o in outs}
    preds[("Q2", "H1")] = {"download_and_execute": 0.85, "administrative_script": 0.05, "other": 0.10}
    preds[("Q2", "H2")] = {"download_and_execute": 0.05, "administrative_script": 0.85, "other": 0.10}
    preds[("Q1", "H1")] = {"office_application": 0.7, "management_agent": 0.1, "user_shell": 0.2}
    preds[("Q1", "H2")] = {"office_application": 0.1, "management_agent": 0.7, "user_shell": 0.2}
    return v, cand, make_model(v, cand, hyps, preds)
