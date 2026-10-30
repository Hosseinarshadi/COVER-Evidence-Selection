"""Blinded coding scaffold (spec 5, adjudication rules).

export : writes tables/coding_sheet.csv — a stratified sample of top-1 recommendations with the arm, truth
         and every automated label REMOVED, in shuffled order, plus empty columns for two coders.
         A separate coding_sheet_key.csv (keep away from coders) maps item ids back to arms.
kappa  : after both coders fill the sheet, computes Cohen's kappa per question and lists disagreements.
"""
import csv, hashlib, json, random
from pathlib import Path
from cover.trace import read_jsonl

QUESTIONS = ["could_challenge_leader_y_n", "independent_of_prior_checks_y_n", "observed_result_contradicted_leader_y_n"]


def export(out, per_cell=3, seed=7):
    out = Path(out)
    raw = read_jsonl(out / "e1" / "raw_runs.jsonl")
    pool = {}
    for r in raw:
        for arm in ("A2", "A3", "C0", "C1", "C3"):
            q = r["picks"].get(arm)
            if not q:
                continue
            hyps = r["G0"]["raw"]["hypotheses"]
            lead = next((h for h in hyps if h["id"] == r["leader_G0"]), None)
            pool.setdefault((r["scenario"], arm), []).append({
                "scenario": r["scenario"], "state": r["state"], "arm": arm, "query_id": q,
                "leading_explanation": f"{lead['label']}: {lead['description']}" if lead else "",
                "rival_explanations": " | ".join(f"{h['label']}: {h['description']}" for h in hyps if h["id"] != r["leader_G0"]),
                "query_text": r["G0"]["prompt"].split(f"- {q}: ", 1)[-1].split("\n", 1)[0] if f"- {q}: " in r["G0"]["prompt"] else q})
    rng = random.Random(seed)
    items = []
    for cell in sorted(pool):
        rows = pool[cell]
        rng.shuffle(rows)
        items += rows[:per_cell]
    rng.shuffle(items)
    sheet, key = [], []
    for i, it in enumerate(items):
        iid = hashlib.sha256(f"{seed}|{i}|{it['scenario']}|{it['arm']}".encode()).hexdigest()[:10]
        sheet.append({"item_id": iid, "scenario": it["scenario"], "leading_explanation": it["leading_explanation"],
                      "rival_explanations": it["rival_explanations"], "query": it["query_text"],
                      **{f"coder1_{q}": "" for q in QUESTIONS}, **{f"coder2_{q}": "" for q in QUESTIONS}, "notes": ""})
        key.append({"item_id": iid, "arm": it["arm"], "state": it["state"], "query_id": it["query_id"]})
    t = out / "tables"
    t.mkdir(parents=True, exist_ok=True)
    for name, rows in (("coding_sheet.csv", sheet), ("coding_sheet_key.csv", key)):
        with (t / name).open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    print(f"Wrote {len(sheet)} blinded items to {t / 'coding_sheet.csv'} (key kept separately).")


def cohen_kappa(a, b):
    pairs = [(x.strip().lower(), y.strip().lower()) for x, y in zip(a, b) if x.strip() and y.strip()]
    if not pairs:
        return None, 0
    cats = sorted({c for p in pairs for c in p})
    n = len(pairs)
    po = sum(x == y for x, y in pairs) / n
    pe = sum((sum(x == c for x, _ in pairs) / n) * (sum(y == c for _, y in pairs) / n) for c in cats)
    return (1.0 if pe == 1 else (po - pe) / (1 - pe)), n


def kappa(sheet_path):
    rows = list(csv.DictReader(open(sheet_path, encoding="utf-8")))
    res = {}
    for q in QUESTIONS:
        k, n = cohen_kappa([r[f"coder1_{q}"] for r in rows], [r[f"coder2_{q}"] for r in rows])
        res[q] = {"kappa": k, "n_coded_by_both": n,
                  "disagreements": [r["item_id"] for r in rows if r[f"coder1_{q}"].strip() and r[f"coder2_{q}"].strip()
                                    and r[f"coder1_{q}"].strip().lower() != r[f"coder2_{q}"].strip().lower()]}
    print(json.dumps(res, indent=2))
    return res
