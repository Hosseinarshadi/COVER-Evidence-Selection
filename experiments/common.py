"""Shared run infrastructure: output folders, run metadata (fingerprints), budget, resume, failures."""
import datetime, json, platform, subprocess, sys
from pathlib import Path
from cover.config import CONFIG, ROOT, prompt_hashes, sha256_file
from cover.llm import Budget, LLM
from cover.trace import read_jsonl


def git_sha():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              timeout=5).stdout.strip() or None
    except Exception:
        return None


def code_hashes():
    files = sorted(list((ROOT / "cover").glob("*.py")) + list((ROOT / "experiments").glob("*.py"))
                   + list((ROOT / "scoring").glob("*.py")))
    return {str(f.relative_to(ROOT)): sha256_file(f) for f in files}


class Run:
    def __init__(self, args, episode):
        self.args, self.episode = args, episode
        self.dir = Path(args.out) / episode
        self.dir.mkdir(parents=True, exist_ok=True)
        self.raw, self.scored = self.dir / "raw_runs.jsonl", self.dir / "scored_runs.jsonl"
        self.trace, self.fail, self.meta_path = self.dir / "trace.jsonl", self.dir / "failures.jsonl", self.dir / "run_meta.json"
        cap = args.max_cost if args.max_cost is not None else CONFIG["budgets_usd"]["pilot" if args.pilot else episode]
        spent, self.done = 0.0, set()
        if getattr(args, "overwrite", False):
            for f in (self.raw, self.scored, self.trace, self.fail, self.meta_path):
                if f.exists():
                    f.unlink()
            print(f"--overwrite: previous {episode} results in {self.dir} deleted.")
        if self.raw.exists() and self.raw.stat().st_size:
            if not args.resume:
                sys.exit(f"{self.raw} already has results. Use --overwrite to replace them, --resume to continue, or a new --out folder.")
            old = json.loads(self.meta_path.read_text(encoding="utf-8")) if self.meta_path.exists() else {}
            if old.get("visible_sha256") != sha256_file(args.visible) or old.get("model") != ("FAKE" if args.fake else args.model):
                sys.exit("Cannot resume: scenario file or model differs from the earlier run.")
            for r in read_jsonl(self.raw):
                self.done.add(r["job"])
                spent += r.get("cost_usd", 0.0)
            spent += sum(r.get("cost_usd", 0.0) for r in read_jsonl(self.fail))
            print(f"Resuming {episode}: {len(self.done)} jobs done, ${spent:.3f} spent.")
        self.budget = Budget(cap, spent)
        self.llm = LLM(args.model, fake=args.fake, budget=self.budget, seed=args.seed)
        self.meta = {
            "episode": episode, "status": "RUNNING",
            "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "model": "FAKE" if args.fake else args.model, "fake": args.fake, "pilot": args.pilot,
            "llm": self.llm.describe(), "reps": args.reps, "max_cost_usd": cap,
            "visible_file": str(args.visible), "visible_sha256": sha256_file(args.visible),
            "key_file": str(args.key), "key_sha256": sha256_file(args.key),
            "config_sha256": sha256_file(ROOT / "config" / "cover.json"), "config": CONFIG,
            "prompt_sha256": prompt_hashes(), "code_sha256": code_hashes(), "git_sha": git_sha(),
            "python": sys.version.split()[0], "platform": platform.platform(),
            "seed": args.seed, "cache": "none (every call is a fresh API request)",
            "unvalidated_scenarios": [],
        }
        self.write_meta()

    def write_meta(self, **upd):
        self.meta.update(upd)
        self.meta_path.write_text(json.dumps(self.meta, indent=2, default=str), encoding="utf-8")


def unvalidated(key, ids):
    return [i for i in ids if not key[i].get("validated", False)]


def gate_unvalidated(args, key, ids):
    bad = unvalidated(key, ids)
    if bad and not (args.fake or args.pilot or args.allow_unvalidated):
        sys.exit(f"Scenarios not validated: {', '.join(bad)}. Use --pilot/--fake to test, or --allow-unvalidated. "
                 "Results from unvalidated scenarios must not be reported.")
    return bad
