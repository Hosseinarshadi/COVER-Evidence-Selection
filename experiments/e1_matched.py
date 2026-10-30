"""Episode E1: frozen matched states (spec 4.2) + hunch experiment (4.3) + stress tests (4.4).

Per (scenario, state, rep), model calls:
  1. G0  rival generation WITHOUT hunch  -> shared by A2, A3, C0, C1, C3 and (as the shielded generation) C2/C3h
  2. A2  LLM selects a query from G0's hypotheses/predictions (legacy structured ACH)
  3. Gx_correct  rival generation WITH the correct hunch exposed  -> C1x_correct
  4. Gx_wrong    rival generation WITH the wrong hunch exposed    -> C1x_wrong
  5. V   independent verifier (v3.1), one small call per distinct (generation, leader) pair, usually 3-4
Everything else is rule-based on the same outputs (no extra calls):
  A3 (legacy EIG), C0, C1v30 (pre-registered v3.0 rule), C1, C3, C2_<h>/C3h_<h> (G0 + hunch applied only when
  choosing the leader), stress_flat (forecasts replaced by uniform), stress_mask (researcher-masked telemetry).
Shielded generation == G0: the shielded prompt has no hunch block, so it is the same text as G0's.
"""
import copy, json, sys
from cover.belief import label_mass
from cover.hunch_shield import choose_leader, generation_prompt
from cover.legacy_baseline import eig_select
from cover.llm import HYP_TOOL, SELECT_TOOL, BudgetStop, CallFailed, FatalAPIError, fake_hyp, fake_sel
from cover.prompts import SYSTEM, candidates, select_prompt
from cover.recommender import cards_for, recommend
from cover.verify import verify
from cover.rivals import clean_report
from cover.trace import append_jsonl
from cover.view import assert_no_leak
from scoring import reference_judge as J
from experiments.common import Run, gate_unvalidated

OPP = {"malicious": "benign", "benign": "malicious"}


def bundle_dump(b):
    d = b.model_dump()
    d["all_cards"] = [c.model_dump() for c in b._all_cards]
    d["withheld_by_restraint"] = [c.model_dump() for c in b._withheld]
    return d


def flat(model):
    m = copy.deepcopy(model)
    for q in m["lik"]:
        for h in m["lik"][q]:
            if m["lik"][q][h] is not None:
                n = len(m["lik"][q][h])
                m["lik"][q][h] = {o: 1 / n for o in m["lik"][q][h]}
    return m


def gen(run, view, observed, cand, hunch, shielded, key):
    prompt = generation_prompt(view, observed, hunch, shielded)
    raw, meta = run.llm.call(prompt, SYSTEM, HYP_TOOL, fake_hyp(view, cand), fake_key=key)
    assert_no_leak(raw, "model output")
    return prompt, raw, meta, clean_report(raw, view, cand)


def run_e1(args, views, key):
    bad = gate_unvalidated(args, key, [v.id for v in views])   # refuse BEFORE asking for an API key
    run = Run(args, "e1")
    run.write_meta(unvalidated_scenarios=bad)
    jobs = [(v, st, rep) for v in views for st in v.states for rep in range(args.reps)]
    stop, fails = None, 0
    for i, (v, st, rep) in enumerate(jobs, 1):
        job = f"{v.id}|{st.id}|{rep}"
        if job in run.done:
            continue
        print(f"[E1 {i}/{len(jobs)}] {job}  spent ${run.budget.spent:.3f}")
        before = run.budget.spent
        observed = list(st.observed)
        executed = st.observed_ids
        cand = candidates(v, executed)
        truth = key[v.id]["truth"]          # orchestrator only: to set the hunch label, never shown as truth
        try:
            p0, raw0, m0, model0 = gen(run, v, observed, cand, None, True, f"e1|{job}|G0")
            sp = select_prompt(v, observed, raw0["hypotheses"], raw0["predictions"])
            sel, ms = run.llm.call(sp, SYSTEM, SELECT_TOOL, fake_sel(cand), fake_key=f"e1|{job}|A2")
            # fair baseline under missing telemetry: the LLM selector sees the same unavailable checks and may decline
            mask = tuple(q for q in cand if key[v.id]["queries"][q]["diagnostic"])
            spm = select_prompt(v, observed, raw0["hypotheses"], raw0["predictions"], unavailable=mask, allow_none=True)
            selm, msm = run.llm.call(spm, SYSTEM, SELECT_TOOL, fake_sel(list(cand) + ["NONE"]), fake_key=f"e1|{job}|A2mask")
            hunch_gens = {}
            for h in args.hunches:
                label = truth if h == "correct" else OPP[truth]
                hunch_gens[h] = (label,) + gen(run, v, observed, cand, label, False, f"e1|{job}|Gx_{h}")
            # v3.1 independent verifier: one call per (generation, leader); shared by every arm that uses them
            leader0, lw0 = choose_leader(model0["hypotheses"])
            needs = {("G0", leader0): model0}
            for h, (label, _, _, _, modelx) in hunch_gens.items():
                needs[(f"Gx_{h}", choose_leader(modelx["hypotheses"], label)[0])] = modelx
                needs[("G0", choose_leader(model0["hypotheses"], label)[0])] = model0
            ratings, verify_log = {}, {}
            for (g, ld), m in needs.items():
                cards, _ = cards_for(v, st.id, 0, "C1", m, ld, executed)
                ratings[(g, ld)], verify_log[f"{g}|{ld}"] = verify(run.llm, v, observed, m, ld, cards,
                                                                   f"e1|{job}|V|{g}|{ld}")
        except BudgetStop as e:
            print(f"Budget stop: {e}")
            stop = "budget"
            if run.budget.spent > before:
                append_jsonl(run.fail, {"job": job, "error": "budget stop mid job", "cost_usd": run.budget.spent - before})
            break
        except FatalAPIError as e:
            append_jsonl(run.fail, {"job": job, "error": str(e), "cost_usd": run.budget.spent - before})
            print(f"Stopping: {e}")
            stop = "fatal_api_error"
            break
        except CallFailed as e:
            fails += 1
            append_jsonl(run.fail, {"job": job, "error": str(e), "cost_usd": run.budget.spent - before})
            if fails >= 3:
                stop = "three_failures"
                break
            continue

        a2 = str(sel["query_id"]).strip()
        a3, eigs = eig_select(v, model0, cand)
        r0 = ratings[("G0", leader0)]
        bundles = {"C0": recommend(v, st.id, 0, "C0", model0, leader0, executed),
                   "C1v30": recommend(v, st.id, 0, "C1v30", model0, leader0, executed),
                   "C1": recommend(v, st.id, 0, "C1", model0, leader0, executed, ratings=r0),
                   "C3": recommend(v, st.id, 0, "C3", model0, leader0, executed, ratings=r0)}
        fm = flat(model0)
        bundles["stress_flat_C1"] = recommend(v, st.id, 0, "C1", fm, leader0, executed, ratings={})
        bundles["stress_flat_C3"] = recommend(v, st.id, 0, "C3", fm, leader0, executed, ratings={})
        # Researcher-constructed visibility stress (mask, set above): every diagnostic query's telemetry is "missing".
        bundles["stress_mask_C1v30"] = recommend(v, st.id, 0, "C1v30", model0, leader0, executed, unavailable=mask)
        bundles["stress_mask_C1"] = recommend(v, st.id, 0, "C1", model0, leader0, executed, unavailable=mask, ratings=r0)
        bundles["stress_mask_C3"] = recommend(v, st.id, 0, "C3", model0, leader0, executed, unavailable=mask, ratings=r0)
        a3_mask, _ = eig_select(v, model0, [q for q in cand if q not in mask])
        hunch_rows = {}
        for h, (label, px, rawx, mx, modelx) in hunch_gens.items():
            lx, lwx = choose_leader(modelx["hypotheses"], label)
            ls, lws = choose_leader(model0["hypotheses"], label)
            bundles[f"C1x_{h}"] = recommend(v, st.id, 0, "C1x", modelx, lx, executed, ratings=ratings[(f"Gx_{h}", lx)])
            bundles[f"C2_{h}"] = recommend(v, st.id, 0, "C2", model0, ls, executed, ratings=ratings[("G0", ls)])
            bundles[f"C3h_{h}"] = recommend(v, st.id, 0, "C3", model0, ls, executed, ratings=ratings[("G0", ls)])
            hunch_rows[h] = {"hunch_label": label, "prompt": px, "raw": rawx, "meta": mx,
                             "leader_exposed": lx, "leader_exposed_warning": lwx,
                             "leader_shielded": ls, "leader_shielded_warning": lws}

        a2m = str(selm["query_id"]).strip()
        picks = {"A2": a2, "A3": a3, "stress_mask_A3": a3_mask, "stress_mask_A2": None if a2m.upper() == "NONE" else a2m}
        picks.update({arm: b.top1 for arm, b in bundles.items()})
        raw_row = {"job": job, "scenario": v.id, "state": st.id, "rep": rep, "candidates": cand,
                   "leader_G0": leader0, "leader_G0_warning": lw0, "picks": picks,
                   "G0": {"prompt": p0, "raw": raw0, "meta": m0}, "A2": {"prompt": sp, "raw": sel, "meta": ms},
                   "A2_mask": {"prompt": spm, "raw": selm, "meta": msm},
                   "hunch_generations": hunch_rows, "verifier": verify_log, "eig": eigs, "stress_mask_unavailable": list(mask),
                   "bundles": {arm: bundle_dump(b) for arm, b in bundles.items()},
                   "cost_usd": round(run.budget.spent - before, 6)}
        append_jsonl(run.raw, raw_row)
        append_jsonl(run.scored, score_e1(v, st, key[v.id], cand, executed, model0, leader0, picks, bundles,
                                         {h: (r[0], r[4]) for h, r in hunch_gens.items()}, job, rep, mask))
    run.write_meta(status="COMPLETE" if stop is None else "PARTIAL", stop_reason=stop,
                   spent_usd=round(run.budget.spent, 4), jobs_planned=len(jobs), failed_jobs=fails,
                   strict_tools_final=run.llm.strict)
    print(f"E1 finished: ${run.budget.spent:.3f} spent; status {run.meta['status']}.")
    return run


def score_e1(v, st, ksc, cand, executed, model0, leader0, picks, bundles, hunch_models, job, rep, mask=()):
    chance = J.chance_rate(ksc, cand, executed)
    row = {"job": job, "scenario": v.id, "truth": ksc["truth"], "state": st.id, "rep": rep,
           "validated": ksc.get("validated", False), "case_type": ksc.get("case_type"),
           "chance_diagnostic_rate": round(chance, 4), "candidate_ceiling": J.ceiling_bin(chance),
           "n_hypotheses": len(model0["hypotheses"]),
           "n_malicious_rivals": sum(h["label"] == "malicious" for h in model0["hypotheses"]),
           "n_benign_rivals": sum(h["label"] == "benign" for h in model0["hypotheses"]),
           "has_true_label_hypothesis": ksc["truth"] in model0["labels"].values(),
           "missing_predictions": model0["missing"], "unknown_outcome_names": model0["unknown_outcomes"],
           "calibration_logloss": J.calibration_logloss(v, ksc, model0, cand), "arms": {}}
    for arm, q in picks.items():
        b = bundles.get(arm)
        top = b.items[0] if (b is not None and b.items) else None
        leader = b.leading_hypothesis_id if b is not None else leader0
        m = model0
        if arm.startswith("C1x_"):
            m = hunch_models[arm.split("_", 1)[1]][1]
        avail = [c for c in cand if not (arm.startswith("stress_mask") and c in mask)]
        valid = q is not None and q in avail
        diag = valid and J.nonredundant_diagnostic(ksc, q, executed)
        # "presented as useful": baselines always present their pick as the best check; COVER does unless the pick
        # is a labelled nondiscriminating fallback. Under mask, any check presented as useful is false certainty.
        if b is None:
            useful_claim = q is not None
        else:
            useful_claim = top is not None and top.purpose != "nondiscriminating_fallback"
        row["arms"][arm] = {
            "pick": q, "abstained": q is None, "valid": valid, "presented_as_useful": bool(useful_claim),
            "nonredundant_diagnostic": bool(diag),
            "purpose": top.purpose if top else None,
            "claimed_challenge": bool(top and top.could_undermine_leader),
            "false_contrast": bool(top and top.could_undermine_leader and not diag),
            "low_confidence": bool(top and top.low_confidence),
            "contradiction_of_leader_realized": J.predicted_contradiction_realized(ksc, m, leader, q),
            "delta_p_true": round(J.delta_p_true(v, ksc, m, q), 4) if q else 0.0,
            "n_items": len(b.items) if b is not None else 1,
            "review_required": bool(b.review_required) if b is not None else False,
        }
    row["mask_all_diagnostic_removed"] = True
    # Verifier vs evidence map (scorer-side): did the skeptic reject the claimed contrasts on decoy checks?
    b1 = bundles.get("C1")
    agree = {"decoy_rejected": 0, "decoy_accepted": 0, "diag_accepted": 0, "diag_rejected": 0, "unverified": 0}
    for c in (b1._all_cards if b1 is not None else []):
        if not c.could_undermine_leader or not c.feasible:
            continue
        d = J.nonredundant_diagnostic(ksc, c.query_id, executed)
        if c.verifier_rating in (None, "unverified"):
            agree["unverified"] += 1
        elif c.verifier_rating == "not_diagnostic":
            agree["diag_rejected" if d else "decoy_rejected"] += 1
        else:
            agree["diag_accepted" if d else "decoy_accepted"] += 1
    row["verifier_vs_map"] = agree
    row["hunch"] = {}
    for h, (label, mx) in hunch_models.items():
        row["hunch"][h] = {
            "hunch_label": label, "hunch_is_wrong": label != ksc["truth"],
            "exposed_hunch_mass": round(label_mass(mx["prior"], mx["labels"], label), 4),
            "shielded_hunch_mass": round(label_mass(model0["prior"], model0["labels"], label), 4),
            "exposed_n_rivals": len(mx["hypotheses"]), "shielded_n_rivals": len(model0["hypotheses"]),
            "exposed_n_opposite_rivals": sum(x["label"] != label for x in mx["hypotheses"]),
            "shielded_n_opposite_rivals": sum(x["label"] != label for x in model0["hypotheses"]),
            "exposed_has_true_label": ksc["truth"] in mx["labels"].values(),
        }
    return row
