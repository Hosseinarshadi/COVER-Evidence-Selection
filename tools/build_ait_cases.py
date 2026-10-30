#!/usr/bin/env python3
"""Build held-out COVER cases from the AIT Alert Data Set (AIT-ADS), real IDS alerts with per-event labels.

Source: alerts_csv.zip from https://github.com/ait-aecid/alert-data-set (columns: time, name, ip, host, short,
time_label, event_label). event_label '-' = not part of the attack; anything else = attack step.
Cite: Landauer, Skopik, Wurzenberger (2024), Introducing a New Alert Data Set for Multi-Step Attack Analysis,
CSET '24; data CC BY 4.0 (Zenodo 8263181).

All rules below were fixed on 2026-10-25 BEFORE any model saw these cases (held-out test):

Sampling (seed 20261025)
  - Attack cases: alerts whose event_label is an attack step, one per distinct attack step, spread across the
    eight AIT scenarios (round-robin), n_attack cases.
  - Harmless cases: "lookalikes" = alerts with event_label '-' whose alert type (short code) also occurs as a
    labelled attack alert in the same scenario; distinct alert types, spread across scenarios, n_benign cases.
    Half (rounded up) are drawn from inside attack time windows (time_label != false_positive) when available.
Checks (identical catalog for every case; outcomes computed from the real alert stream, trigger excluded)
  Q1 other alerts on the host within +-10 min      none / 1_to_20 / more_than_20
  Q2 same alert type on this host in previous 24 h  never / 1_to_10_times / more_than_10_times
  Q3 a different detector family on the host +-10 min  yes / no
  Q4 same alert type on other hosts +-30 min        only_this_host / other_hosts_too
  Q5 same IP address in alerts on other hosts +-30 min  yes / no
  Q6 host raised alert types not seen on it in the previous 24 h, within +-30 min  yes / no
  Q7 distinct alert types on the host +-10 min      one / two_to_four / five_or_more
  Q8 alert fired outside 08:00-18:00 UTC            business_hours / outside_business_hours
Evidence map (scorer-only)
  - reference_outcome = the real result for this case.
  - diagnostic = the real result is at least LR_MIN (=2) times as likely under the true label as under the other
    label, with likelihoods estimated by leave-one-scenario-out on labelled samples from the OTHER seven AIT
    scenarios (attack sample stratified by step; harmless sample = lookalikes, as above). Add-one smoothing.
  - redundant_with: none declared (no researcher mapping; reported as a limitation).
States: s0 (nothing run yet) and s1 (Q8, the time-of-day check, already run).

Usage:
  python tools/build_ait_cases.py --zip data/ait/alerts_csv.zip --out scenarios/ait_master.json
  python tools/split_scenarios.py scenarios/ait_master.json scenarios/ait
"""
import argparse, hashlib, io, json, random, zipfile
from pathlib import Path
import numpy as np
import pandas as pd

SEED = 20261025
LR_MIN = 2.0
MIN10, MIN30, H24 = 600, 1800, 86400
SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]
CHECKS = {
    "Q1": ("Count other alerts from the same host in the 10 minutes before and after this alert",
           ["none", "1_to_20", "more_than_20"], 1),
    "Q2": ("Check how often this alert type fired on this host in the previous 24 hours",
           ["never", "1_to_10_times", "more_than_10_times"], 2),
    "Q3": ("Check whether a different detector family (Wazuh, Suricata or AMiner) alerted on this host within 10 minutes",
           ["yes", "no"], 1),
    "Q4": ("Check whether the same alert type fired on other hosts within 30 minutes",
           ["only_this_host", "other_hosts_too"], 1),
    "Q5": ("Check whether the same IP address appears in alerts on other hosts within 30 minutes",
           ["yes", "no"], 1),
    "Q6": ("Check whether this host raised alert types it had not raised in the previous 24 hours, within 30 minutes of this alert",
           ["yes", "no"], 2),
    "Q7": ("Count distinct alert types on this host within 10 minutes of this alert",
           ["one", "two_to_four", "five_or_more"], 1),
    "Q8": ("Check whether the alert fired outside business hours (08:00-18:00 UTC)",
           ["business_hours", "outside_business_hours"], 1),
}


def family(name):
    return name.split(":", 1)[0].strip()


class Index:
    """Sorted per-key time arrays for fast window queries on one AIT scenario."""

    def __init__(self, df):
        self.df = df.sort_values("time", kind="stable").reset_index(drop=True)
        d = self.df
        d["fam"] = d["name"].map(family)
        self.by_host = {h: g.index.values for h, g in d.groupby("host", sort=False)}
        self.by_hc = {k: d.loc[g.index, "time"].values for k, g in d.groupby(["host", "short"], sort=False)}
        self.by_code = {k: g.index.values for k, g in d.groupby("short", sort=False)}
        self.by_ip = {k: g.index.values for k, g in d.groupby("ip", sort=False)}
        self.t = d["time"].values
        self.host = d["host"].values
        self.short = d["short"].values
        self.fam = d["fam"].values

    def _win(self, idx, t, lo, hi):
        ts = self.t[idx]
        return idx[np.searchsorted(ts, t - lo, "left"):np.searchsorted(ts, t + hi, "right")]

    def features(self, i):
        t, h, c, ip, fam = self.t[i], self.host[i], self.short[i], self.df.at[i, "ip"], self.fam[i]
        hw10 = self._win(self.by_host[h], t, MIN10, MIN10)
        hw10 = hw10[hw10 != i]
        n = len(hw10)
        out = {"Q1": "none" if n == 0 else ("1_to_20" if n <= 20 else "more_than_20")}
        prev = self.by_hc[(h, c)]
        k = np.searchsorted(prev, t, "left") - np.searchsorted(prev, t - H24, "left")
        out["Q2"] = "never" if k == 0 else ("1_to_10_times" if k <= 10 else "more_than_10_times")
        out["Q3"] = "yes" if np.any(self.fam[hw10] != fam) else "no"
        cw = self._win(self.by_code[c], t, MIN30, MIN30)
        out["Q4"] = "other_hosts_too" if np.any(self.host[cw] != h) else "only_this_host"
        iw = self._win(self.by_ip[ip], t, MIN30, MIN30) if ip in self.by_ip else np.array([], int)
        out["Q5"] = "yes" if np.any(self.host[iw] != h) else "no"
        hw30 = self._win(self.by_host[h], t, MIN30, MIN30)
        new = False
        for code in np.unique(self.short[hw30]):
            times = self.by_hc[(h, code)]
            start = t - MIN30
            if np.searchsorted(times, start, "left") - np.searchsorted(times, start - H24, "left") == 0:
                new = True
                break
        out["Q6"] = "yes" if new else "no"
        k7 = len(np.unique(self.short[np.append(hw10, i)]))
        out["Q7"] = "one" if k7 == 1 else ("two_to_four" if k7 <= 4 else "five_or_more")
        hour = (int(t) % 86400) // 3600
        out["Q8"] = "business_hours" if 8 <= hour < 18 else "outside_business_hours"
        return out


def load(zip_path):
    z = zipfile.ZipFile(zip_path)
    data = {}
    for sc in SCENARIOS:
        name = next(n for n in z.namelist() if n.endswith(f"{sc}_alerts.txt"))
        df = pd.read_csv(io.BytesIO(z.read(name)), dtype={"ip": str, "host": str, "short": str, "name": str,
                                                         "time_label": str, "event_label": str})
        df["ip"] = df["ip"].fillna("none")
        data[sc] = Index(df)
        print(f"loaded {sc}: {len(df):,} alerts")
    return data


def lookalike_mask(d):
    attack_codes = set(d["short"][d["event_label"] != "-"])
    return (d["event_label"] == "-") & d["short"].isin(attack_codes)


def calibration_sample(ix, rng, per_step=150, benign_n=1200):
    d = ix.df
    rows = []
    for step, g in d[d["event_label"] != "-"].groupby("event_label"):
        rows += [(i, "malicious") for i in rng.sample(list(g.index), min(per_step, len(g)))]
    b = list(d.index[lookalike_mask(d)])
    rows += [(i, "benign") for i in rng.sample(b, min(benign_n, len(b)))]
    return [(lab, ix.features(i)) for i, lab in rows]


def select_cases(data, rng, n_attack, n_benign):
    cases = []
    # attack: distinct steps, round-robin over scenarios
    steps_by_sc = {sc: sorted(set(data[sc].df["event_label"]) - {"-"}) for sc in SCENARIOS}
    used_steps, k = set(), 0
    while len([c for c in cases if c[2] == "malicious"]) < n_attack and k < 200:
        sc = SCENARIOS[k % len(SCENARIOS)]
        k += 1
        free = [s for s in steps_by_sc[sc] if s not in used_steps]
        if not free:
            continue
        step = rng.choice(free)
        used_steps.add(step)
        idx = list(data[sc].df.index[data[sc].df["event_label"] == step])
        cases.append((sc, rng.choice(idx), "malicious", step))
    # harmless lookalikes: distinct alert types, round-robin, half inside attack windows
    used_codes, k, n_in = set(), 0, 0
    while len([c for c in cases if c[2] == "benign"]) < n_benign and k < 400:
        sc = SCENARIOS[k % len(SCENARIOS)]
        k += 1
        d = data[sc].df
        m = lookalike_mask(d) & ~d["short"].isin(used_codes)
        want_inside = n_in < (n_benign + 1) // 2
        mm = m & ((d["time_label"] != "false_positive") if want_inside else (d["time_label"] == "false_positive"))
        pool = list(d.index[mm]) or list(d.index[m])
        if not pool:
            continue
        i = rng.choice(pool)
        used_codes.add(d.at[i, "short"])
        n_in += d.at[i, "time_label"] != "false_positive"
        cases.append((sc, i, "benign", "lookalike_inside_attack_window" if d.at[i, "time_label"] != "false_positive"
                      else "lookalike_routine"))
    return cases


def likelihoods(samples):
    tab = {}
    for q, (_, outs, _) in CHECKS.items():
        for lab in ("malicious", "benign"):
            cnt = {o: 1.0 for o in outs}           # add-one smoothing
            for l2, f in samples:
                if l2 == lab:
                    cnt[f[q]] += 1
            s = sum(cnt.values())
            tab[(q, lab)] = {o: v / s for o, v in cnt.items()}
    return tab


def build(zip_path, n_attack=10, n_benign=10):
    rng = random.Random(SEED)
    data = load(zip_path)
    calib = {sc: calibration_sample(data[sc], random.Random(f"{SEED}|{sc}")) for sc in SCENARIOS}
    cases = select_cases(data, rng, n_attack, n_benign)
    out = []
    for n, (sc, i, truth, kind) in enumerate(sorted(cases, key=lambda c: hashlib.sha256(f"{c[0]}|{c[1]}".encode()).hexdigest()), 1):
        ix = data[sc]
        r = ix.df.loc[i]
        feats = ix.features(i)
        lik = likelihoods([s for o in SCENARIOS if o != sc for s in calib[o]])   # leave-one-scenario-out
        other = "benign" if truth == "malicious" else "malicious"
        queries = {}
        for q, (desc, outs, cost) in CHECKS.items():
            lr = lik[(q, truth)][feats[q]] / lik[(q, other)][feats[q]]
            queries[q] = {"description": desc, "outcomes": outs, "reference_outcome": feats[q],
                          "diagnostic": bool(lr >= LR_MIN), "lr_toward_truth": round(float(lr), 3), "cost": cost}
        ip = r["ip"] if r["ip"] != "none" else "not recorded"
        out.append({
            "id": f"AIT-{n:02d}", "validated": True, "truth": truth, "case_type": f"ait_real_{kind}",
            "_provenance": {"ait_scenario": sc, "row": int(i), "time": int(r["time"]), "short": r["short"],
                            "time_label": r["time_label"], "event_label": r["event_label"],
                            "note": "Truth from AIT-ADS per-event labels; evidence map by the fixed LR rule above."},
            "trigger": f"{r['name']} on host {r['host']} (IP in alert: {ip}).",
            "initial_evidence": [f"Detector family: {family(r['name'])}",
                                 f"Host name: {r['host']}",
                                 "Environment: small enterprise network (web, mail, file share, VPN, DNS, firewall, monitoring)"],
            "queries": queries,
            "states": [{"id": "s0", "observed": []}, {"id": "s1", "observed": ["Q8"]}],
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", default="data/ait/alerts_csv.zip")
    ap.add_argument("--out", default="scenarios/ait_master.json")
    ap.add_argument("--attack", type=int, default=10)
    ap.add_argument("--benign", type=int, default=10)
    a = ap.parse_args()
    cases = build(a.zip, a.attack, a.benign)
    Path(a.out).write_text(json.dumps(cases, indent=1), encoding="utf-8")
    diag = [sum(q["diagnostic"] for q in c["queries"].values()) for c in cases]
    print(f"Wrote {len(cases)} cases to {a.out}; useful checks per case: min {min(diag)}, mean {sum(diag)/len(diag):.1f}, max {max(diag)}")


if __name__ == "__main__":
    main()
