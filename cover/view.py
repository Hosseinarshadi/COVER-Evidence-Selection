"""Agent-visible scenario view and the fail-closed leakage guard.

The runtime loads ONLY *.visible.json files. Anything that looks like scorer data is refused.
"""
import json, re
from dataclasses import dataclass, field
from pathlib import Path

FORBIDDEN_KEYS = {"truth", "reference_outcome", "diagnostic", "redundant_with", "ground_truth",
                  "evidence_map", "validated", "nonexclusive_truth", "case_type"}
FORBIDDEN_TEXT = re.compile(r"reference_outcome|ground[_ ]truth|evidence_map|redundant_with|\"truth\"\s*:|"
                            r"\"diagnostic\"\s*:", re.I)


class LeakageError(RuntimeError):
    """Raised when scorer-only information reaches agent-visible code or text."""


def assert_no_leak(obj, where="runtime object"):
    """Fail closed if a forbidden key appears anywhere in obj, or forbidden text in a string."""
    if isinstance(obj, dict):
        bad = FORBIDDEN_KEYS & set(obj)
        if bad:
            raise LeakageError(f"{where}: scorer-only field(s) {sorted(bad)} present")
        for v in obj.values():
            assert_no_leak(v, where)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            assert_no_leak(v, where)
    elif isinstance(obj, str):
        if FORBIDDEN_TEXT.search(obj):
            raise LeakageError(f"{where}: scorer-only text found: {FORBIDDEN_TEXT.search(obj).group(0)!r}")
    return obj


@dataclass(frozen=True)
class Query:
    id: str
    description: str
    outcomes: tuple
    cost: float = 1.0


@dataclass(frozen=True)
class State:
    id: str
    observed: tuple = ()  # tuple of (query_id, outcome) the analyst already has

    @property
    def observed_ids(self):
        return [q for q, _ in self.observed]


@dataclass(frozen=True)
class ScenarioView:
    id: str
    trigger: str
    initial_evidence: tuple
    queries: dict = field(hash=False)
    states: tuple = ()

    def state(self, sid):
        return next(s for s in self.states if s.id == sid)


def view_from_dict(d):
    assert_no_leak(d, f"scenario {d.get('id')}")
    queries = {qid: Query(qid, q["description"], tuple(q["outcomes"]), float(q.get("cost", 1)))
               for qid, q in d["queries"].items()}
    states = tuple(State(s["id"], tuple((o["query_id"], o["outcome"]) for o in s.get("observed", [])))
                   for s in d["states"])
    return ScenarioView(d["id"], d["trigger"], tuple(d["initial_evidence"]), queries, states)


def load_views(path):
    path = Path(path)
    if path.name.endswith(".key.json") or "master" in path.name:
        raise LeakageError(f"Runtime may not load {path.name}; use a *.visible.json file")
    data = json.loads(path.read_text(encoding="utf-8"))
    return [view_from_dict(d) for d in data]
