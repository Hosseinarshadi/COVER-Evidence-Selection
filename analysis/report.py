"""Build results tables, figures, report.md and manifest.json from a results folder.

Scenario is the unit of analysis. State-reps and episodes are averaged within scenario first;
uncertainty comes from a cluster bootstrap over scenarios. No p-values are reported.
"""
import csv, json, random, statistics
from pathlib import Path
from cover.config import CONFIG, sha256_file
from cover.trace import read_jsonl

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]   # dataviz reference palette, fixed order
INK, MUTED, GRID = "#1f1f1e", "#6b6a63", "#e4e3dc"
E1_ARMS = ["A2", "A3", "C0", "C1v30", "C1", "C3"]
LEGACY_TARGETS = {"A2_diagnostic": "53/60 (88.3%)", "A3_diagnostic": "51/60 (85.0%)", "same_pick": "38/60",
                  "note": "differences concentrated in SC-02"}


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def f(x, nd=2):
    return "n/a" if x is None else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))


def boot(per_scenario, draws=None, seed=None):
    """Cluster bootstrap of the mean over scenarios. per_scenario: list of scenario-level values."""
    vals = [v for v in per_scenario if v is not None]
    if len(vals) < 2:
        return mean(vals), None, None
    draws = draws or CONFIG["bootstrap"]["draws"]
    rng = random.Random(CONFIG["bootstrap"]["seed"] if seed is None else seed)
    ms = sorted(mean([rng.choice(vals) for _ in vals]) for _ in range(draws))
    return mean(vals), ms[int(0.025 * draws)], ms[int(0.975 * draws) - 1]


def ci(t, nd=2):
    m, lo, hi = t
    return f"{f(m, nd)} [{f(lo, nd)}, {f(hi, nd)}]" if lo is not None else f(m, nd)


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return False
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    return True


def md_table(rows, cols):
    out = ["| " + " | ".join(c for c, _ in cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(f(r.get(k)) for _, k in cols) + " |")
    return out


def by_scenario(rows):
    d = {}
    for r in rows:
        d.setdefault(r["scenario"], []).append(r)
    return d


# ----------------------------------------------------------------------------------- E1

def e1_tables(rows):
    sc_rows, mech, shield, stress, ceil = [], [], [], [], {}
    for sid, rs in by_scenario(rows).items():
        n = len(rs)
        row = {"scenario": sid, "truth": rs[0]["truth"], "validated": rs[0]["validated"], "state_reps": n,
               "chance": round(mean(r["chance_diagnostic_rate"] for r in rs), 3)}
        for a in E1_ARMS:
            row[f"{a}_diag"] = (round(sum(r["arms"][a]["nonredundant_diagnostic"] for r in rs) / n, 3)
                                if a in rs[0]["arms"] else None)
        row["C3_abstain"] = round(sum(r["arms"]["C3"]["abstained"] for r in rs) / n, 3)
        row["C1_eq_A2"] = round(sum(r["arms"]["C1"]["pick"] == r["arms"]["A2"]["pick"] for r in rs) / n, 3)
        row["C1_eq_A3"] = round(sum(r["arms"]["C1"]["pick"] == r["arms"]["A3"]["pick"] for r in rs) / n, 3)
        row["A2_eq_A3"] = round(sum(r["arms"]["A2"]["pick"] == r["arms"]["A3"]["pick"] for r in rs) / n, 3)
        row["A2_invalid"] = sum(not r["arms"]["A2"]["valid"] for r in rs)
        row["calibration_logloss"] = mean(r["calibration_logloss"] for r in rs)
        row["calibration_logloss"] = round(row["calibration_logloss"], 3) if row["calibration_logloss"] is not None else None
        sc_rows.append(row)
        m = {"scenario": sid}
        for a in ("C0", "C1v30", "C1", "C3"):
            if a not in rs[0]["arms"]:
                continue
            m[f"{a}_claimed_challenge"] = round(sum(r["arms"][a]["claimed_challenge"] for r in rs) / n, 3)
            m[f"{a}_false_contrast"] = sum(r["arms"][a]["false_contrast"] for r in rs)
            real = [r["arms"][a]["contradiction_of_leader_realized"] for r in rs if r["arms"][a]["contradiction_of_leader_realized"] is not None]
            m[f"{a}_contradiction_realized"] = round(sum(real) / len(real), 3) if real else None
        mech.append(m)
        for h in ("wrong", "correct"):
            hs = [r for r in rs if h in r.get("hunch", {})]
            if not hs:
                continue
            k = len(hs)
            shield.append({
                "scenario": sid, "hunch": h,
                "exposed_hunch_mass": round(mean(r["hunch"][h]["exposed_hunch_mass"] for r in hs), 3),
                "shielded_hunch_mass": round(mean(r["hunch"][h]["shielded_hunch_mass"] for r in hs), 3),
                "exposed_opposite_rivals": round(mean(r["hunch"][h]["exposed_n_opposite_rivals"] for r in hs), 2),
                "shielded_opposite_rivals": round(mean(r["hunch"][h]["shielded_n_opposite_rivals"] for r in hs), 2),
                "C1x_diag": round(sum(r["arms"][f"C1x_{h}"]["nonredundant_diagnostic"] for r in hs) / k, 3),
                "C2_diag": round(sum(r["arms"][f"C2_{h}"]["nonredundant_diagnostic"] for r in hs) / k, 3),
                "C3h_diag": round(sum(r["arms"][f"C3h_{h}"]["nonredundant_diagnostic"] for r in hs) / k, 3),
                "C1x_challenge": round(sum(r["arms"][f"C1x_{h}"]["claimed_challenge"] for r in hs) / k, 3),
                "C2_challenge": round(sum(r["arms"][f"C2_{h}"]["claimed_challenge"] for r in hs) / k, 3),
                "C3h_abstain": round(sum(r["arms"][f"C3h_{h}"]["abstained"] for r in hs) / k, 3)})
        def _rate(arm, field):
            vals = [r["arms"][arm][field] for r in rs if arm in r["arms"] and field in r["arms"][arm]]
            return round(sum(vals) / len(vals), 3) if vals else None
        stress.append({
            "scenario": sid,
            "mask_false_certainty_A2": _rate("stress_mask_A2", "presented_as_useful"),
            "mask_false_certainty_A3": _rate("stress_mask_A3", "presented_as_useful"),
            "mask_false_certainty_C1": _rate("stress_mask_C1", "presented_as_useful"),
            "mask_false_certainty_C3": _rate("stress_mask_C3", "presented_as_useful"),
            "flat_C1_fallback": round(sum(r["arms"]["stress_flat_C1"]["purpose"] == "nondiscriminating_fallback" for r in rs) / n, 3),
            "flat_C3_abstain": round(sum(r["arms"]["stress_flat_C3"]["abstained"] for r in rs) / n, 3),
            "mask_C1v30_claims_challenge": (round(sum(r["arms"]["stress_mask_C1v30"]["claimed_challenge"] for r in rs) / n, 3)
                                            if "stress_mask_C1v30" in rs[0]["arms"] else None),
            "mask_C1_claims_challenge": round(sum(r["arms"]["stress_mask_C1"]["claimed_challenge"] for r in rs) / n, 3),
            "mask_C3_abstain": round(sum(r["arms"]["stress_mask_C3"]["abstained"] for r in rs) / n, 3),
            "mask_C3_claims_challenge": round(sum(r["arms"]["stress_mask_C3"]["claimed_challenge"] for r in rs) / n, 3)})
        for r in rs:
            c = ceil.setdefault(r["candidate_ceiling"], {"state_reps": 0, "scenarios": set(), **{a: 0 for a in E1_ARMS}})
            c["state_reps"] += 1
            c["scenarios"].add(sid)
            for a in E1_ARMS:
                c[a] += r["arms"].get(a, {}).get("nonredundant_diagnostic", False)
    ver = []
    for sid, rs in by_scenario(rows).items():
        tot = {}
        for r in rs:
            for k2, v2 in r.get("verifier_vs_map", {}).items():
                tot[k2] = tot.get(k2, 0) + v2
        if tot:
            ver.append({"scenario": sid, **tot})
    e1_tables.verifier = ver
    ceil_rows = [{"ceiling": k, "state_reps": v["state_reps"], "scenarios": len(v["scenarios"]),
                  **{f"{a}_diag": round(v[a] / v["state_reps"], 3) for a in E1_ARMS}} for k, v in sorted(ceil.items())]
    return sc_rows, mech, shield, stress, ceil_rows


# ----------------------------------------------------------------------------------- E2

def e2_tables(rows):
    per = []
    for sid, rs in by_scenario(rows).items():
        arms = dict.fromkeys(r["arm"] for r in rs)
        for a in arms:
            ar = [r for r in rs if r["arm"] == a]
            n = len(ar)
            per.append({"scenario": sid, "arm": a, "truth": ar[0]["truth"], "episodes": n,
                        "disconfirming_share": round(mean(r["disconfirming_share_proxy"] for r in ar), 3) if mean(r["disconfirming_share_proxy"] for r in ar) is not None else None,
                        "rival_coverage": round(sum(r["rival_coverage_proxy"] for r in ar) / n, 3),
                        "redundant": sum(r["redundant_executions"] for r in ar),
                        "invalid": sum(r["n_invalid"] for r in ar),
                        "first_useful_step": mean(r["first_useful_step"] for r in ar),
                        "censored": sum(r["censored"] for r in ar),
                        "deferred": round(sum(r["deferred"] for r in ar) / n, 3),
                        "unresolved": round(sum(r["unresolved"] for r in ar) / n, 3),
                        "accuracy": round(sum(r["correct"] for r in ar) / n, 3),
                        "wrong_verdict": round(sum(r["wrong_verdict"] for r in ar) / n, 3),
                        "wrong_hunch_endorsed": (round(sum(bool(r["wrong_hunch_endorsed_final"]) for r in ar) / n, 3)
                                                 if ar[0]["wrong_hunch"] else None),
                        "rival_violations": sum(r["rival_persistence_violations"] for r in ar)})
    arms = list(dict.fromkeys(p["arm"] for p in per))
    agg = []
    for a in arms:
        ps = [p for p in per if p["arm"] == a]
        agg.append({"arm": a, "scenarios": len(ps),
                    **{k: ci(boot([p[k] for p in ps])) for k in ("disconfirming_share", "rival_coverage", "accuracy",
                                                                  "unresolved", "deferred", "wrong_verdict")},
                    "invalid_total": sum(p["invalid"] for p in ps), "redundant_total": sum(p["redundant"] for p in ps),
                    "censored_total": sum(p["censored"] for p in ps),
                    "wrong_hunch_endorsed": ci(boot([p["wrong_hunch_endorsed"] for p in ps]))
                    if ps[0]["wrong_hunch_endorsed"] is not None else "n/a"})
    return per, agg


# ----------------------------------------------------------------------------------- figures

def figures(out, e1_sc, e2_per, shield):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        return {"figures": f"NOT MADE: matplotlib unavailable ({e})"}
    made = {}
    fd = out / "figures"
    fd.mkdir(parents=True, exist_ok=True)

    def style(ax, title, ylabel):
        ax.set_title(title, loc="left", fontsize=11, color=INK)
        ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_color(GRID)
        ax.tick_params(colors=MUTED, labelsize=8)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)

    if e1_sc:
        fig, ax = plt.subplots(figsize=(8, 4), dpi=150)
        for i, r in enumerate(e1_sc):
            ys = [r[f"{a}_diag"] for a in E1_ARMS]
            ax.plot(E1_ARMS, ys, color=SERIES[i % len(SERIES)], linewidth=2, marker="o", markersize=5, label=r["scenario"])
        ax.set_ylim(-0.05, 1.05)
        style(ax, "E1: nonredundant diagnostic rate by arm, per scenario", "share of state-reps")
        ax.legend(frameon=False, fontsize=8, loc="upper left", bbox_to_anchor=(1.01, 1))
        fig.tight_layout()
        fig.savefig(fd / "e1_slope_by_scenario.png")
        plt.close(fig)
        made["e1_slope_by_scenario.png"] = "per-scenario paired slope plot"
    if e2_per:
        arms = list(dict.fromkeys(p["arm"] for p in e2_per))
        metrics = [("rival_coverage", "ran ≥1 useful check"), ("disconfirming_share", "useful share of checks"),
                   ("accuracy", "correct verdict")]
        fig, ax = plt.subplots(figsize=(8, 4), dpi=150)
        w = 0.8 / len(metrics)
        for j, (k, lab) in enumerate(metrics):
            vals = [mean(p[k] for p in e2_per if p["arm"] == a) or 0 for a in arms]
            ax.bar([i + j * w for i in range(len(arms))], vals, width=w * 0.9, color=SERIES[j], label=lab)
        ax.set_xticks([i + w for i in range(len(arms))], arms)
        ax.set_ylim(0, 1.05)
        style(ax, "E2: evidence-seeking stages by arm (scenario means)", "share")
        ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=3)
        fig.tight_layout()
        fig.savefig(fd / "e2_stage_funnel.png")
        plt.close(fig)
        made["e2_stage_funnel.png"] = "stage-level comparison"
    wr = [s for s in shield if s["hunch"] == "wrong"]
    if wr:
        fig, ax = plt.subplots(figsize=(7, 4), dpi=150)
        xs = [s["scenario"] for s in wr]
        ax.plot(xs, [s["exposed_hunch_mass"] for s in wr], color=SERIES[1], marker="o", linewidth=2, label="hunch exposed to generator")
        ax.plot(xs, [s["shielded_hunch_mass"] for s in wr], color=SERIES[0], marker="s", linewidth=2, label="hunch shielded")
        ax.set_ylim(-0.05, 1.05)
        style(ax, "Wrong-hunch endorsement: model prior mass on the (wrong) hunch label", "prior mass")
        ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=2)
        fig.tight_layout()
        fig.savefig(fd / "shielding_wrong_hunch.png")
        plt.close(fig)
        made["shielding_wrong_hunch.png"] = "shielding effect on wrong-hunch endorsement"
    return made


# ----------------------------------------------------------------------------------- trajectories

def trajectory_text(ep):
    lines = [f"**{ep['job']}** — verdict: {ep['verdict']}" + (" (deferred to analyst)" if ep["deferred"] else "")]
    for t in ep["turns"]:
        raw_h = t["raw"]["hypotheses"]
        tot = sum(max(float(h.get("prior") or 0), 0) for h in raw_h) or 1.0
        hs = ", ".join(f"{h['id']}({str(h['label'])[0]})={max(float(h.get('prior') or 0), 0) / tot:.2f}"
                       for h in sorted(raw_h, key=lambda h: str(h["id"])))
        step = f"- turn {t['turn']}: priors (normalized self-report) {hs}"
        if t.get("pick"):
            obs = t.get("observation", {}).get("outcome") or f"ERROR {t.get('execution_error', {}).get('kind')}"
            purpose = ""
            if t.get("bundle") and t["bundle"]["items"]:
                purpose = f" [{t['bundle']['items'][0]['purpose']}]"
            step += f" → ran {t['pick']}{purpose} → {obs}"
        elif t.get("bundle", {}).get("review_required"):
            step += " → deferred: " + (t["bundle"].get("limitation") or "")
        lines.append(step)
    return lines


# ----------------------------------------------------------------------------------- main

def build(out):
    out = Path(out)
    tables, manifest = out / "tables", {"generated_utc": None, "files": {}, "not_run": {}}
    m1 = json.loads((out / "e1" / "run_meta.json").read_text()) if (out / "e1" / "run_meta.json").exists() else None
    m2 = json.loads((out / "e2" / "run_meta.json").read_text()) if (out / "e2" / "run_meta.json").exists() else None
    e1 = read_jsonl(out / "e1" / "scored_runs.jsonl")
    e2 = read_jsonl(out / "e2" / "scored_runs.jsonl")
    e2raw = read_jsonl(out / "e2" / "raw_runs.jsonl")
    fake = any(m and m.get("fake") for m in (m1, m2))
    pilot = any(m and m.get("pilot") for m in (m1, m2))
    unval = sorted(set((m1 or {}).get("unvalidated_scenarios", []) + (m2 or {}).get("unvalidated_scenarios", [])))
    statuses = [m["status"] for m in (m1, m2) if m]
    status = "NOT RUN" if not statuses else ("COMPLETE" if all(s == "COMPLETE" for s in statuses) and m1 and m2 else "PARTIAL")

    L = [f"# COVER v3 results — {status}", ""]
    if fake:
        L += ["> **FAKE OFFLINE RUN. Every number below is meaningless; this only shows the harness works.**", ""]
    if pilot:
        L += ["> **Pilot run. Use it to check outputs, not as evidence.**", ""]
    if unval:
        L += [f"> **Unvalidated scenarios included: {', '.join(unval)}. Do not report these results.**", ""]
    for name, m in (("E1", m1), ("E2", m2)):
        if m:
            L.append(f"- {name}: model {m['model']}, status {m['status']}, reps {m['reps']}, spent ${m.get('spent_usd', 0):.3f} "
                     f"(cap ${m['max_cost_usd']:.2f}), stop reason {m.get('stop_reason')}, scenario file sha256 {m['visible_sha256'][:12]}…")
        else:
            L.append(f"- {name}: NOT RUN")
    L += ["- All 'diagnostic', 'disconfirming' and 'contradiction' figures are automated proxies from the researcher's "
          "evidence map. They are provisional until two coders apply the blinded rubric (tables/coding_sheet.csv).",
          "- Scenario is the unit. Brackets are 95% cluster-bootstrap intervals over scenarios; with ≤8 scenarios they are rough.",
          "- No human participated in any run. Every choice is `simulated_choice` (top-1).", ""]

    L += ["## 1. Design traceability", "",
          "| Theory | Problem mechanism | DP | Software function | Outcome proxy | Result section |", "|---|---|---|---|---|---|",
          "| OIPT (Galbraith; Daft & Lengel) | ambiguity needs interpretation, not more data | DP3, DP6 | contrast cards (cover/contrast.py) | contradiction realized, false contrast | §3, §6 |",
          "| Human–AI delegation (Baird & Maruping; Parasuraman et al.) | delegated evidence attention | DP4 | top-k bundle with alternatives, simulated_choice only | n/a without humans (E3 not run) | §7 |",
          "| Confirmation bias / ACH (Nickerson; Heuer) | hunch anchors search | DP1, DP2 | hunch shield (cover/hunch_shield.py), challenge rule | wrong-hunch mass, challenge rate | §5, §4 |",
          "| Appropriate reliance (Lee & See) | fluent output → false confidence | DP6 | C3 restraint, warnings, deferral | abstention, false certainty under stress | §3b, §4 |",
          "| DSR (Hevner; Gregor & Jones; Gregor & Hevner; Venable et al.) | design knowledge, not accuracy | DP5 | append-only trace (cover/trace.py) | complete audit chains | e2/trace.jsonl |", ""]

    L += ["## 2. Reproduction of the original A2/A3 result", "",
          "| Measure | Paper (historical target) | This package |", "|---|---|---|",
          f"| A2 diagnostic | {LEGACY_TARGETS['A2_diagnostic']} | NOT REPRODUCIBLE here |",
          f"| A3 diagnostic | {LEGACY_TARGETS['A3_diagnostic']} | NOT REPRODUCIBLE here |",
          f"| Same pick | {LEGACY_TARGETS['same_pick']} | NOT REPRODUCIBLE here |", "",
          "Root cause: the original raw runs (runs.jsonl), the model used and which scenario version produced the "
          "paper's numbers were not supplied (see docs/BASELINE_AUDIT.md). The A2/A3 arms in §3 are a NEW run with "
          f"{(m1 or {}).get('model', 'n/a')} on the extracted scenarios; do not compare them with the paper as if collected "
          "under one protocol.", ""]

    made = {}
    if e1:
        sc, mech, shield, stress, ceil = e1_tables(e1)
        for name, rows in (("e1_matched_state_by_scenario", sc), ("e1_mechanism_C0_C1_C3", mech),
                           ("e1_shielding", shield), ("e1_stress_tests", stress), ("e1_candidate_ceiling", ceil)):
            if write_csv(tables / f"{name}.csv", rows):
                manifest["files"][f"tables/{name}.csv"] = "written"
        L += ["## 3. E1 matched-state comparator (same rivals, predictions and candidates for every arm)", ""]
        L += md_table(sc, [("Scenario", "scenario"), ("Truth", "truth"), ("Val.", "validated"), ("n", "state_reps"),
                           ("Chance", "chance"), ("A2", "A2_diag"), ("A3", "A3_diag"), ("C0", "C0_diag"),
                           ("C1v30", "C1v30_diag"), ("C1", "C1_diag"), ("C3", "C3_diag"), ("C3 abstain", "C3_abstain"), ("C1=A2", "C1_eq_A2"),
                           ("C1=A3", "C1_eq_A3"), ("A2=A3", "A2_eq_A3"), ("A2 invalid", "A2_invalid"),
                           ("Log-loss", "calibration_logloss")])
        pairs_ = [("C1−A2", "C1_diag", "A2_diag"), ("C1−A3", "C1_diag", "A3_diag"), ("C1−C1v30", "C1_diag", "C1v30_diag"),
                  ("C1−C0", "C1_diag", "C0_diag"), ("C3−C1", "C3_diag", "C1_diag"), ("A3−A2", "A3_diag", "A2_diag")]
        pairs_ = [p_ for p_ in pairs_ if sc[0].get(p_[1]) is not None and sc[0].get(p_[2]) is not None]
        diffs = {k: boot([r[a] - r[b] for r in sc]) for k, a, b in pairs_}
        L += ["", "Scenario-level mean differences in nonredundant diagnostic rate (C3 abstentions count as non-diagnostic):", ""]
        L += [f"- {k}: {ci(v)}  (scenarios where first arm higher / equal / lower: "
              f"{sum((r[a]-r[b]) > 0 for r in sc)}/{sum((r[a]-r[b]) == 0 for r in sc)}/{sum((r[a]-r[b]) < 0 for r in sc)})"
              for (k, v), (_, a, b) in zip(diffs.items(), pairs_)]
        L += ["", "### 3a. By candidate ceiling (pre-specified bins on the chance rate)", ""]
        L += md_table(ceil, [("Ceiling", "ceiling"), ("State-reps", "state_reps"), ("Scenarios", "scenarios")]
                      + [(a, f"{a}_diag") for a in E1_ARMS])
        L += ["", "### 3b. Mechanism: does using contrast cards change what is put in front of the analyst?", ""]
        L += md_table(mech, [("Scenario", "scenario"), ("C0 challenge", "C0_claimed_challenge"),
                             ("C1v30 false contrast (n)", "C1v30_false_contrast"),
                             ("C1 challenge", "C1_claimed_challenge"), ("C3 challenge", "C3_claimed_challenge"),
                             ("C1 false contrast (n)", "C1_false_contrast"), ("C3 false contrast (n)", "C3_false_contrast"),
                             ("C1 contradiction realized", "C1_contradiction_realized")])
        L += ["", "'Challenge' = top-1 card predicted to count against the leader. 'False contrast' = the card claims a "
              "challenge but the evidence map says the query is not (nonredundantly) diagnostic.", ""]
        ver = getattr(e1_tables, "verifier", [])
        if ver:
            write_csv(tables / "e1_verifier_vs_map.csv", ver)
            manifest["files"]["tables/e1_verifier_vs_map.csv"] = "written"
            L += ["### 3c. Independent verifier vs the researcher's evidence map (claimed challenges only; C1 leader)", ""]
            L += md_table(ver, [("Scenario", "scenario"), ("Decoy rejected", "decoy_rejected"),
                                ("Decoy accepted", "decoy_accepted"), ("Diagnostic accepted", "diag_accepted"),
                                ("Diagnostic rejected", "diag_rejected"), ("Unverified", "unverified")])
            L += ["", "Good verifier behaviour = high 'decoy rejected' and 'diagnostic accepted'. 'Diagnostic rejected' is "
                  "the cost of restraint.", ""]
        L += ["## 4. Stress tests (simulated; labelled as such)", "",
              "- *flat*: every forecast replaced by a uniform distribution (no extra model calls).",
              "- *mask*: the researcher removes every diagnostic query's telemetry; the agent sees them only as unavailable. "
              "Any challenge claimed under *mask* is false certainty by construction.", ""]
        L += ["**Fair comparison under missing telemetry** — share of decisions where the method still put forward a "
              "check as useful although every useful check was unavailable (false certainty; lower is better). "
              "A2 was explicitly allowed to answer NONE.", ""]
        L += md_table(stress, [("Scenario", "scenario"), ("A2 (LLM)", "mask_false_certainty_A2"),
                               ("A3 (EIG)", "mask_false_certainty_A3"), ("C1", "mask_false_certainty_C1"),
                               ("C3", "mask_false_certainty_C3")])
        fc = {a: boot([r[f"mask_false_certainty_{a}"] for r in stress if r.get(f"mask_false_certainty_{a}") is not None])
              for a in ("A2", "A3", "C1", "C3")}
        L += [""] + [f"- {a}: {ci(v)}" for a, v in fc.items()] + ["", "Other stress details:", ""]
        L += md_table(stress, [("Scenario", "scenario"), ("flat: C1 fallback", "flat_C1_fallback"),
                               ("mask: C1v30 claims challenge", "mask_C1v30_claims_challenge"),
                               ("flat: C3 abstain", "flat_C3_abstain"), ("mask: C1 claims challenge", "mask_C1_claims_challenge"),
                               ("mask: C3 abstain", "mask_C3_abstain"), ("mask: C3 claims challenge", "mask_C3_claims_challenge")])
        L += ["", "## 5. Shielding (hunch exposed to vs hidden from the rival generator)", ""]
        L += md_table(shield, [("Scenario", "scenario"), ("Hunch", "hunch"), ("Exposed mass", "exposed_hunch_mass"),
                               ("Shielded mass", "shielded_hunch_mass"), ("Exposed opp. rivals", "exposed_opposite_rivals"),
                               ("Shielded opp. rivals", "shielded_opposite_rivals"), ("C1x diag", "C1x_diag"),
                               ("C2 diag", "C2_diag"), ("C3h diag", "C3h_diag"), ("C1x challenge", "C1x_challenge"),
                               ("C2 challenge", "C2_challenge"), ("C3h abstain", "C3h_abstain")])
        wr = [s for s in shield if s["hunch"] == "wrong"]
        if wr:
            L += ["", f"- Wrong hunch, exposed − shielded prior mass on the hunch label: "
                  f"{ci(boot([s['exposed_hunch_mass'] - s['shielded_hunch_mass'] for s in wr]))} (positive = anchoring under exposure)."]
        L.append("")
        made.update(figures(out, sc, None, shield))
    else:
        manifest["not_run"]["E1"] = "no scored E1 rows"
        L += ["## 3–5. E1: NOT RUN", ""]

    if e2:
        per, agg = e2_tables(e2)
        for name, rows in (("e2_sequential_by_scenario_arm", per), ("e2_sequential_by_arm", agg)):
            if write_csv(tables / f"{name}.csv", rows):
                manifest["files"][f"tables/{name}.csv"] = "written"
        L += ["## 6. E2 sequential evidence-seeking (arms diverge after the first pick)", ""]
        L += md_table(agg, [("Arm", "arm"), ("Scenarios", "scenarios"), ("Disconfirming share", "disconfirming_share"),
                            ("Rival coverage", "rival_coverage"), ("Accuracy", "accuracy"), ("Unresolved", "unresolved"),
                            ("Deferred", "deferred"), ("Wrong verdict", "wrong_verdict"), ("Invalid", "invalid_total"),
                            ("Redundant", "redundant_total"), ("Never useful", "censored_total"),
                            ("Wrong hunch endorsed", "wrong_hunch_endorsed")])
        L += ["", "Unresolved and deferred episodes stay in every denominator. Rival coverage reduces to 'ran at least one "
              "nonredundant diagnostic check', because the evidence map has no hypothesis-specific mapping.", ""]
        made.update(figures(out, None, per, []))
        # mandatory beneficial + adverse case, chosen by a fixed rule
        cmp = {}
        for p in per:
            cmp.setdefault(p["scenario"], {})[p["arm"]] = p["disconfirming_share"]
        deltas = {s: (d.get("C1") or 0) - (d.get("S0") or 0) for s, d in cmp.items() if "C1" in d and "S0" in d}
        if deltas:
            best, worst = max(deltas, key=deltas.get), min(deltas, key=deltas.get)
            L += ["### 6a. Trajectories (rule: scenario with the largest and smallest C1 − S0 disconfirming share; rep 0)", ""]
            for tag, s in (("Most favourable to COVER", best), ("Most adverse to COVER", worst)):
                L += [f"**{tag}: {s}** (C1 − S0 = {deltas[s]:+.2f})", ""]
                for arm in ("S0", "C1"):
                    ep = next((e for e in e2raw if e["scenario"] == s and e["arm"] == arm and e["rep"] == 0), None)
                    if ep:
                        L += trajectory_text(ep) + [""]
    else:
        manifest["not_run"]["E2"] = "no scored E2 rows"
        L += ["## 6. E2: NOT RUN", ""]

    ft = []
    if e1:
        for a in ("A2", "A3", "C0", "C1", "C3"):
            ft.append({"source": "E1", "arm": a, "false_contrast": sum(r["arms"][a]["false_contrast"] for r in e1),
                       "invalid_pick": sum(not r["arms"][a]["valid"] and not r["arms"][a]["abstained"] for r in e1),
                       "abstained": sum(r["arms"][a]["abstained"] for r in e1)})
        ft.append({"source": "E1", "arm": "generation", "missing_predictions": sum(r["missing_predictions"] for r in e1),
                   "unknown_outcome_names": sum(r["unknown_outcome_names"] for r in e1),
                   "no_true_label_hypothesis": sum(not r["has_true_label_hypothesis"] for r in e1)})
    if e2:
        for a in dict.fromkeys(r["arm"] for r in e2):
            rs = [r for r in e2 if r["arm"] == a]
            ft.append({"source": "E2", "arm": a, "invalid_pick": sum(r["n_invalid"] for r in rs),
                       "redundant": sum(r["redundant_executions"] for r in rs),
                       "unwarranted_conviction": sum(r["unwarranted_conviction"] for r in rs),
                       "wrong_hunch_anchoring": sum(bool(r["wrong_hunch_endorsed_final"]) for r in rs),
                       "rival_vanished": sum(r["rival_persistence_violations"] for r in rs),
                       "abstained": sum(r["deferred"] for r in rs)})
    if ft:
        write_csv(tables / "failure_taxonomy.csv", ft)
        manifest["files"]["tables/failure_taxonomy.csv"] = "written"
        L += ["## 7. Failure taxonomy (counts; see tables/failure_taxonomy.csv)", ""]
        cols = list(dict.fromkeys(k for r in ft for k in r))
        L += md_table(ft, [(c, c) for c in cols]) + [""]

    L += ["## 8. Human descriptive evidence", "",
          "The paper's 12 real investigations by six analysts (human only n=5, conventional AI n=3, Active ACH n=4) are "
          "NOT in this package: the workbook was not supplied. Nothing here is human data. E3 (human study): NOT RUN.", "",
          "## 9. How to read this", "",
          "- Report what each stage shows: proposed ≠ selected ≠ executed ≠ observed ≠ belief changed ≠ verdict.",
          "- More disconfirming checks without better verdicts supports only the former.",
          "- Simulated selection says nothing about analysts' cognition, trust or control.",
          "- Full prompts, raw model output, all contrast cards (incl. rejected and withheld) are in e1/raw_runs.jsonl "
          "and e2/raw_runs.jsonl; the E2 audit chain is in e2/trace.jsonl."]
    (out / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    for k, v in made.items():
        if k.endswith(".png"):
            manifest["files"][f"figures/{k}"] = v
        else:
            manifest["not_run"][k] = v
    for sub in ("e1", "e2"):
        for fn in ("raw_runs.jsonl", "scored_runs.jsonl", "trace.jsonl", "failures.jsonl", "run_meta.json"):
            p = out / sub / fn
            if p.exists():
                manifest["files"][f"{sub}/{fn}"] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    manifest.update(status=status, fake=fake, pilot=pilot, unvalidated_scenarios=unval,
                    generated_utc=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())
    manifest["not_run"].setdefault("E3_human_study", "not run; no participants")
    manifest["not_run"].setdefault("presentation_only_test", "human-facing only; requires E3")
    manifest["not_run"].setdefault("reproduction_of_paper_numbers", "inputs missing; see docs/BASELINE_AUDIT.md")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Report written: {out / 'report.md'} ({status})")
    return out / "report.md"
