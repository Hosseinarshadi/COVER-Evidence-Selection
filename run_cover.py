#!/usr/bin/env python3
"""COVER v3 command line. Default model: Claude Haiku 5.5 (claude-haiku-5-5).

  python run_cover.py validate
  python run_cover.py all --fake --out results/cover_v3/dryrun        # offline, free, meaningless numbers
  python run_cover.py all --pilot --out results/cover_v3/pilot        # 1 rep, $0.50 cap per episode
  python run_cover.py all --overwrite --out results/cover_v3/main     # rewrite results in the same folder
  python run_cover.py e1 --out results/cover_v3/main                  # 5 reps
  python run_cover.py e2 --out results/cover_v3/main                  # 3 reps x 6 arms
  python run_cover.py report --out results/cover_v3/main
  python run_cover.py coding-sheet --out results/cover_v3/main
  python run_cover.py kappa --sheet results/cover_v3/main/tables/coding_sheet.csv
"""
import argparse, datetime, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from cover.config import CONFIG                      # noqa: E402
from cover.llm import PRICES                         # noqa: E402
from cover.view import load_views                    # noqa: E402

DEV_VISIBLE = ROOT / "scenarios" / "dev.visible.json"
DEV_KEY = ROOT / "scenarios" / "dev.key.json"
DATASETS = {"dev": ("dev.visible.json", "dev.key.json"), "ait": ("ait.visible.json", "ait.key.json")}


def common(p):
    p.add_argument("--dataset", choices=list(DATASETS), default="dev",
                   help="dev = six constructed scenarios; ait = 20 held-out real AIT alerts")
    p.add_argument("--visible", default=None, help="agent-visible scenario file (*.visible.json); overrides --dataset")
    p.add_argument("--key", default=None, help="scorer-only key file (*.key.json); overrides --dataset")
    p.add_argument("--scenario", nargs="*", help="limit to these scenario ids")
    p.add_argument("--out", required=True)
    p.add_argument("--model", default=CONFIG["default_model"])
    p.add_argument("--reps", type=int, default=None)
    p.add_argument("--max-cost", type=float, default=None, help="hard USD cap per episode")
    p.add_argument("--pilot", action="store_true", help="1 rep, low cap, unvalidated scenarios allowed")
    p.add_argument("--fake", action="store_true", help="offline, no API calls; numbers meaningless")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--overwrite", action="store_true", help="delete this episode's previous results in --out first")
    p.add_argument("--allow-unvalidated", action="store_true")
    p.add_argument("--seed", type=int, default=0, help="seed for --fake only")
    p.add_argument("--query-budget", type=int, default=CONFIG["e2"]["query_budget"])
    p.add_argument("--arms", nargs="*", default=CONFIG["e2"]["arms"])
    p.add_argument("--hunches", nargs="*", default=CONFIG["e1"]["hunch_conditions"])


def load(args):
    from scoring.reference_judge import load_key
    vis, kf = DATASETS[args.dataset]
    args.visible = args.visible or str(ROOT / "scenarios" / vis)
    args.key = args.key or str(ROOT / "scenarios" / kf)
    views = load_views(args.visible)
    key = load_key(args.key)
    if args.scenario:
        views = [v for v in views if v.id in args.scenario]
    missing = [v.id for v in views if v.id not in key]
    if missing:
        sys.exit(f"Key file lacks scenarios {missing}")
    return views, key


def estimate(views, reps_e1, reps_e2, arms, budget_q):
    n_states = sum(len(v.states) for v in views)
    e1_calls = n_states * reps_e1 * 8          # 4 large calls + ~4 small verifier calls
    n_cover = sum(a not in ("S0", "S1", "C1v30") for a in arms)
    e2_calls = len(views) * reps_e2 * (len(arms) * (budget_q + 1) + (budget_q if "S0" in arms else 0) + n_cover * budget_q)
    return e1_calls, e2_calls


def main():
    ap = argparse.ArgumentParser(description="COVER v3 experiments")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--dataset", choices=list(DATASETS), default="dev")
    for name in ("e1", "e2", "all"):
        common(sub.add_parser(name))
    r = sub.add_parser("report")
    r.add_argument("--out", required=True)
    c = sub.add_parser("coding-sheet")
    c.add_argument("--out", required=True)
    k = sub.add_parser("kappa")
    k.add_argument("--sheet", required=True)
    args = ap.parse_args()

    if args.cmd == "validate":
        from scoring.reference_judge import load_key
        vis, kf = DATASETS[args.dataset]
        views, key = load_views(ROOT / "scenarios" / vis), load_key(ROOT / "scenarios" / kf)
        un = [i for i in key if not key[i].get("validated")]
        r1 = CONFIG["ait"]["e1_reps"] if args.dataset == "ait" else CONFIG["e1"]["reps"]
        r2 = CONFIG["ait"]["e2_reps"] if args.dataset == "ait" else CONFIG["e2"]["reps"]
        n_states = sum(len(v.states) for v in views)
        n_eps = len(views) * len(CONFIG["e2"]["arms"]) * r2
        # measured on the v3.1 pilot (Haiku 5.5, 2026-10-25): ~$0.0065 per E1 state-rep, ~$0.006 per E2 episode
        c1, c2 = n_states * r1 * 0.0070, n_eps * 0.0065
        print(f"OK: {len(views)} scenarios ({args.dataset}); unvalidated: {un or 'none'}")
        print(f"E1: {n_states} states x {r1} reps = {n_states * r1} state-reps, about ${c1:.2f}")
        print(f"E2: {len(views)} cases x {len(CONFIG['e2']['arms'])} arms x {r2} reps = {n_eps} episodes, about ${c2:.2f}")
        print(f"Total about ${c1 + c2:.2f} on claude-haiku-5-5 (estimate from the pilot; add ~30% margin).")
        return
    if args.cmd == "report":
        from analysis.report import build
        build(args.out)
        return
    if args.cmd == "coding-sheet":
        from analysis.coding_sheet import export
        export(args.out)
        return
    if args.cmd == "kappa":
        from analysis.coding_sheet import kappa
        kappa(args.sheet)
        return

    views, key = load(args)
    args.run_id = f"{args.cmd}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}"
    if args.pilot:
        args.reps = 1
    from analysis.report import build
    if args.cmd in ("e1", "all"):
        from experiments.e1_matched import run_e1
        a = argparse.Namespace(**vars(args))
        a.reps = args.reps or CONFIG["e1"]["reps"]
        run_e1(a, views, key)
    if args.cmd in ("e2", "all"):
        from experiments.e2_sequential import run_e2
        a = argparse.Namespace(**vars(args))
        a.reps = args.reps or CONFIG["e2"]["reps"]
        run_e2(a, views, key)
    build(args.out)


if __name__ == "__main__":
    main()
