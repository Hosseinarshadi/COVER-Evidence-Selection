#!/usr/bin/env python3
"""Split a researcher scenario master file into an agent-visible file and a scorer-only key.

The agent runtime (cover/*) may load ONLY the visible file. The scorer (scoring/*) loads the key.
Observed results of queries in a state's history are agent-visible by design (they are evidence the
analyst already has), so they are copied into the visible file.

Usage:
  python tools/split_scenarios.py scenarios/dev_master.json scenarios/dev
  -> scenarios/dev.visible.json and scenarios/dev.key.json
"""
import json, sys
from pathlib import Path

VISIBLE_QUERY_FIELDS = ("description", "outcomes", "cost")
HIDDEN_QUERY_FIELDS = ("reference_outcome", "diagnostic", "redundant_with", "lr_toward_truth")


def split(master):
    visible, key = [], []
    for sc in master:
        vq = {qid: {k: q[k] for k in VISIBLE_QUERY_FIELDS if k in q} for qid, q in sc["queries"].items()}
        for q in vq.values():
            q.setdefault("cost", 1)
        states = []
        for st in sc["states"]:
            states.append({"id": st["id"],
                           "observed": [{"query_id": o, "outcome": sc["queries"][o]["reference_outcome"]}
                                        for o in st.get("observed", [])]})
        visible.append({"id": sc["id"], "trigger": sc["trigger"], "initial_evidence": sc["initial_evidence"],
                        "queries": vq, "states": states})
        key.append({"id": sc["id"], "truth": sc["truth"], "validated": bool(sc.get("validated", False)),
                    "nonexclusive_truth": sc.get("nonexclusive_truth", False),
                    "case_type": sc.get("case_type", "constructed"),
                    "queries": {qid: {k: q[k] for k in HIDDEN_QUERY_FIELDS if k in q}
                                for qid, q in sc["queries"].items()},
                    "states": [{"id": st["id"], "observed": list(st.get("observed", []))} for st in sc["states"]]})
    return visible, key


def main():
    src, stem = Path(sys.argv[1]), sys.argv[2]
    master = json.loads(src.read_text(encoding="utf-8"))
    visible, key = split(master)
    Path(stem + ".visible.json").write_text(json.dumps(visible, indent=1), encoding="utf-8")
    Path(stem + ".key.json").write_text(json.dumps(key, indent=1), encoding="utf-8")
    print(f"Wrote {stem}.visible.json ({len(visible)} scenarios) and {stem}.key.json")


if __name__ == "__main__":
    main()
