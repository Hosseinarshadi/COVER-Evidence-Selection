"""Episode E2: sequential investigations from the alert (state s0) to a verdict, deferral or the query budget.

Arms (all start from the same alert, same model and settings; they diverge after the first pick):
  S0        structured ACH, LLM selects (A2-seq)
  S1        legacy EIG controller selects (A3-seq)
  C1v30     pre-registered v3.0 rule (first qualifying challenge), no hunch -- optional comparison arm
  C1        COVER v3.1 contrast protocol (verifier + ACH tiers), no hunch
  C3        COVER + epistemic restraint (may defer to the analyst)
  C1x_wrong COVER, WRONG analyst hunch exposed to the rival generator at every turn
  C2_wrong  COVER, same wrong hunch, shielded from generation (used only to choose the leader)
  S0_wrong  fair baseline: LLM selects; the wrong hunch is shown to generation and selection
  S1_wrong  fair baseline: EIG selects on the hunch-exposed generation
Observations come from the simulated replay of the reference map (never live telemetry).
The simulated analyst always runs the top-1 recommendation (simulated_choice), never a human choice.
"""
from cover.belief import reason_record, verdict
from cover.hunch_shield import choose_leader, generation_prompt
from cover.legacy_baseline import eig_select
from cover.llm import HYP_TOOL, SELECT_TOOL, BudgetStop, CallFailed, FatalAPIError, fake_hyp, fake_sel
from cover.models import ExecutionError
from cover.prompts import SYSTEM, candidates, select_prompt
from cover.recommender import V31_ARMS, cards_for, recommend
from cover.verify import verify
from cover.rivals import RivalRegistry, clean_report
from cover.trace import TraceWriter, append_jsonl
from cover.view import assert_no_leak
from scoring import reference_judge as J
from scoring.replay import Replay
from experiments.common import Run, gate_unvalidated
from experiments.e1_matched import OPP, bundle_dump

ARM_BASE = {"C1": "C1", "C3": "C3", "C1x_wrong": "C1x", "C2_wrong": "C2", "C1v30": "C1v30"}


class Stop(Exception):
    pass


def episode(run, tw, replay, v, arm, rep, truth, budget_q):
    job = f"{v.id}|{arm}|{rep}"
    hunch = OPP[truth] if arm.endswith("_wrong") else None     # orchestrator sets the manipulation
    shielded = arm not in ("C1x_wrong", "S0_wrong", "S1_wrong")   # baselines are told the hunch, as an analyst would
    observed, executed, turns, tested_pairs = [], [], [], []
    reg, prev_raw_h, prev_model, prev_card, last_obs = RivalRegistry(), None, None, None, None
    ev = dict(run_id=run.args.run_id, case_id=v.id, arm=arm, rep=rep)
    deferred, final_model = False, None
    for t in range(budget_q + 1):
        cand = candidates(v, executed)
        prompt = generation_prompt(v, observed, hunch, shielded, prev_hypotheses=prev_raw_h)
        raw, meta = run.llm.call(prompt, SYSTEM, HYP_TOOL, fake_hyp(v, cand, prev_raw_h), fake_key=f"e2|{job}|G{t}")
        assert_no_leak(raw, "model output")
        model = clean_report(raw, v, cand)
        reg.update(t, model["hypotheses"], raw.get("retired"))
        tw.emit(**ev, turn=t, event_type="hypotheses_generated", provenance="llm",
                payload={"hypotheses": model["hypotheses"], "retired": raw.get("retired", []),
                         "missing_predictions": model["missing"], "response": meta})
        for viol in [x for x in reg.violations if x["turn"] == t]:
            tw.emit(**ev, turn=t, event_type="rival_persistence_violation", provenance="rule", payload=viol)
        turn = {"turn": t, "prompt": prompt, "raw": raw, "meta": meta}
        if prev_model is not None:
            rec = reason_record(prev_model, model, last_obs, prev_card)
            turn["reason_record"] = rec
            tw.emit(**ev, turn=t, event_type="belief_updated", provenance="llm", payload=rec)
        final_model, prev_raw_h, prev_model = model, model["hypotheses"], model
        if t == budget_q or not cand:
            turns.append(turn)
            break
        leader, lw = choose_leader(model["hypotheses"], hunch)
        card, pick = None, None
        if arm in ("S0", "S0_wrong"):
            sp = select_prompt(v, observed, raw["hypotheses"], raw["predictions"], hunch_label=hunch)
            sel, ms = run.llm.call(sp, SYSTEM, SELECT_TOOL, fake_sel(cand), fake_key=f"e2|{job}|S{t}")
            pick, turn["select"] = str(sel["query_id"]).strip(), {"prompt": sp, "raw": sel, "meta": ms}
            tw.emit(**ev, turn=t, event_type="recommendation_selected", provenance="llm",
                    payload={"query_id": pick, "rationale": sel.get("rationale")})
        elif arm in ("S1", "S1_wrong"):
            pick, eigs = eig_select(v, model, cand)
            turn["eig"] = eigs
            tw.emit(**ev, turn=t, event_type="recommendation_selected", provenance="rule",
                    payload={"query_id": pick, "selector": "legacy cost-weighted EIG"})
        else:
            ratings = None
            if ARM_BASE[arm] in V31_ARMS:
                cards, _ = cards_for(v, "s0", t, "C1", model, leader, executed)
                ratings, turn["verifier"] = verify(run.llm, v, observed, model, leader, cards, f"e2|{job}|V{t}")
            b = recommend(v, "s0", t, ARM_BASE[arm], model, leader, executed, tested_pairs=tested_pairs, ratings=ratings)
            turn["bundle"] = bundle_dump(b)
            tw.emit(**ev, turn=t, event_type="recommendation_proposed", provenance="rule",
                    payload={"items": [c.query_id for c in b.items], "purposes": [c.purpose for c in b.items],
                             "review_required": b.review_required, "leader": leader, "leader_warning": lw})
            if b.review_required:
                deferred = True
                tw.emit(**ev, turn=t, event_type="deferred_to_analyst", provenance="rule",
                        payload={"limitation": b.limitation})
                turns.append(turn)
                break
            card, pick = b.items[0], b.items[0].query_id
            tested_pairs += [tuple(p) for p in card.cross_label_pairs_separated]
            tw.emit(**ev, turn=t, event_type="recommendation_selected", provenance="simulator",
                    payload={"query_id": pick, "simulated_choice": "selected_top1"})
        turn.update(leader=leader, leader_warning=lw, pick=pick)
        res = replay.execute(v, pick, executed)
        if isinstance(res, ExecutionError):
            turn["execution_error"] = res.model_dump()
            tw.emit(**ev, turn=t, event_type="execution_error", provenance="simulated_replay", payload=res.model_dump())
            last_obs = None
            executed.append(f"INVALID:{pick}")   # counts toward the budget; never a no_hit
        else:
            tw.emit(**ev, turn=t, event_type="query_executed", provenance="simulated_replay", payload={"query_id": pick})
            tw.emit(**ev, turn=t, event_type="observation_received", provenance="simulated_replay",
                    payload=res.model_dump())
            turn["observation"] = res.model_dump()
            observed.append((res.query_id, res.outcome))
            executed.append(res.query_id)
            last_obs = res.model_dump()
        prev_card = card
        turns.append(turn)
    v_label, v_mass = ("deferred", None) if deferred else verdict(final_model)
    tw.emit(**ev, turn=len(turns), event_type="verdict", provenance="rule",
            payload={"verdict": v_label, "mass": v_mass, "rule": "label mass >= verdict_mass; model self-report"})
    return {"job": job, "scenario": v.id, "arm": arm, "rep": rep, "hunch_label": hunch, "shielded": shielded,
            "turns": turns, "executed": executed, "observed": observed, "deferred": deferred,
            "verdict": v_label, "verdict_mass": v_mass, "final_hypotheses": final_model["hypotheses"],
            "rival_registry": reg.snapshot()}, final_model


def score_e2(ep, final_model, ksc):
    real = [q for q in ep["executed"] if not q.startswith("INVALID:")]
    useful, red, first_useful, seen = [], 0, None, []
    for i, q in enumerate(real):
        if J.redundant(ksc, q, seen):
            red += 1
        u = J.nonredundant_diagnostic(ksc, q, seen)
        useful.append(u)
        if u and first_useful is None:
            first_useful = i
        seen.append(q)
    labels = final_model["labels"]
    truth = ksc["truth"]
    wrong = ep["hunch_label"]
    return {"job": ep["job"], "scenario": ep["scenario"], "arm": ep["arm"], "rep": ep["rep"], "truth": truth,
            "validated": ksc.get("validated", False), "case_type": ksc.get("case_type"),
            "n_attempted": len(ep["executed"]), "n_executed": len(real),
            "n_invalid": len(ep["executed"]) - len(real),
            "disconfirming_share_proxy": round(sum(useful) / len(real), 4) if real else None,
            "rival_coverage_proxy": any(useful), "redundant_executions": red,
            "first_useful_step": first_useful, "censored": first_useful is None,
            "deferred": ep["deferred"], "verdict": ep["verdict"],
            "correct": ep["verdict"] == truth, "unresolved": ep["verdict"] in ("unresolved", "deferred"),
            "wrong_verdict": ep["verdict"] in ("malicious", "benign") and ep["verdict"] != truth,
            "unwarranted_conviction": ep["verdict"] in ("malicious", "benign") and ep["verdict"] != truth,
            "final_true_mass": round(J.label_mass(final_model["prior"], labels, truth), 4),
            "wrong_hunch": wrong, "final_wrong_hunch_mass": None if wrong is None
            else round(J.label_mass(final_model["prior"], labels, wrong), 4),
            "wrong_hunch_endorsed_final": None if wrong is None else ep["verdict"] == wrong,
            "rival_persistence_violations": len(ep["rival_registry"]["violations"])}


def run_e2(args, views, key):
    bad = gate_unvalidated(args, key, [v.id for v in views])   # refuse BEFORE asking for an API key
    run = Run(args, "e2")
    run.write_meta(unvalidated_scenarios=bad)
    replay, tw = Replay(key), TraceWriter(run.trace)
    arms = args.arms
    jobs = [(v, arm, rep) for v in views for arm in arms for rep in range(args.reps)]
    stop, fails = None, 0
    for i, (v, arm, rep) in enumerate(jobs, 1):
        job = f"{v.id}|{arm}|{rep}"
        if job in run.done:
            continue
        print(f"[E2 {i}/{len(jobs)}] {job}  spent ${run.budget.spent:.3f}")
        before = run.budget.spent
        try:
            ep, final_model = episode(run, tw, replay, v, arm, rep, key[v.id]["truth"], args.query_budget)
        except BudgetStop as e:
            print(f"Budget stop: {e}")
            stop = "budget"
            if run.budget.spent > before:
                append_jsonl(run.fail, {"job": job, "error": "budget stop mid episode", "cost_usd": run.budget.spent - before})
            break
        except FatalAPIError as e:
            append_jsonl(run.fail, {"job": job, "error": str(e), "cost_usd": run.budget.spent - before})
            stop = "fatal_api_error"
            print(f"Stopping: {e}")
            break
        except CallFailed as e:
            fails += 1
            append_jsonl(run.fail, {"job": job, "error": str(e), "cost_usd": run.budget.spent - before})
            if fails >= 3:
                stop = "three_failures"
                break
            continue
        ep["cost_usd"] = round(run.budget.spent - before, 6)
        append_jsonl(run.raw, ep)
        append_jsonl(run.scored, score_e2(ep, final_model, key[v.id]))
    tw.close()
    run.write_meta(status="COMPLETE" if stop is None else "PARTIAL", stop_reason=stop, arms=arms,
                   query_budget=args.query_budget, spent_usd=round(run.budget.spent, 4), jobs_planned=len(jobs),
                   failed_jobs=fails, strict_tools_final=run.llm.strict)
    print(f"E2 finished: ${run.budget.spent:.3f} spent; status {run.meta['status']}.")
    return run
