#!/usr/bin/env python3
"""
Active ACH matched-state experiment: A2 (LLM selects the next query) vs A3 (EIG controller selects).

For every scenario state and repetition:
  1. Generation call: the LLM proposes rival hypotheses (tagged malicious/benign) with priors and
     predicts the outcome distribution of every candidate query under every hypothesis.
  2. A2 call: the same LLM sees the same hypotheses, predictions and candidates and picks one query.
  3. A3: the controller picks the query with the highest expected information gain per unit cost,
     computed from the same predictions (no model call).
  4. Both picks are scored against the researcher's hidden evidence map, which the model never sees.

Commands (run them in order):
  python active_ach_experiment.py validate
  python active_ach_experiment.py run --fake --out dryrun      # offline, free
  python active_ach_experiment.py run --pilot --out pilot       # 1 rep, $1 cap
  python active_ach_experiment.py run --out results            # 5 reps, $5 cap
  python active_ach_experiment.py report --out results

The API key is read from the ANTHROPIC_API_KEY environment variable, or asked for with hidden input.
It is never written to disk or to any log.

API notes (Claude Sonnet 5.5 and Opus 5.5, verified against platform.claude.com docs, Oct 2026):
  - Forced tool_choice ("tool"/"any") is rejected, so tools are marked strict and tool_choice is "auto";
    the prompt asks the model to call the tool, and a reply without a tool call is retried.
  - Strict tools need additionalProperties: false on every object and no free-form maps, so outcome
    probabilities are returned as a list of {outcome, probability} pairs.
  - Non-default temperature is rejected, so it is never sent.
  - Thinking defaults to "between_tools" (no up-front thinking) to keep cost predictable; use
    --thinking adaptive to let the model think first (more output tokens, higher cost).
"""
import argparse, csv, datetime, getpass, hashlib, json, math, os, random, statistics, sys, time
from pathlib import Path

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 6000
RETRIES = 3
EPS = 1e-6


class BudgetStop(Exception):
    """Raised before an API call that could take total spend past the cap."""


class Budget:
    def __init__(self, cap, spent=0.0):
        self.cap, self.spent = cap, spent

    def check(self, worst_case):
        if self.spent + worst_case > self.cap:
            raise BudgetStop(f"${self.spent:.2f} spent; the next call could cost up to ${worst_case:.2f}, "
                             f"which might pass the ${self.cap:.2f} cap.")

    def add(self, cost):
        self.spent += cost

# USD per million tokens (input, output). Source: platform.claude.com/docs/en/about-claude/pricing (Oct 2026).
# Check the page before running; update here if prices change.
PRICES = {
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-opus-5-5": (4.0, 20.0),
}

SYSTEM = (
    "You assist a cybersecurity threat hunter. You do not know the ground truth. "
    "Reason only from the alert, the evidence observed so far, and the query catalog provided."
)

HYP_TOOL = {
    "name": "report_hypotheses",
    "description": "Report rival explanations and predicted outcomes for every candidate query.",
    "input_schema": {
        "type": "object",
        "properties": {
            "hypotheses": {
                "type": "array", "minItems": 1,
                "description": "2 to 6 rival explanations, at least one malicious and one benign.",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "label": {"type": "string", "enum": ["malicious", "benign"]},
                        "description": {"type": "string"},
                        "prior": {"type": "number", "description": "Prior probability; priors sum to 1."},
                    },
                    "required": ["id", "label", "description", "prior"],
                    "additionalProperties": False,
                },
            },
            "predictions": {
                "type": "array", "minItems": 1,
                "description": "One entry for every candidate query and every hypothesis.",
                "items": {
                    "type": "object",
                    "properties": {
                        "query_id": {"type": "string"},
                        "hypothesis_id": {"type": "string"},
                        "outcome_probs": {
                            "type": "array", "minItems": 1,
                            "description": "Probability of each listed outcome if the hypothesis were true; sums to 1.",
                            "items": {
                                "type": "object",
                                "properties": {"outcome": {"type": "string"}, "probability": {"type": "number"}},
                                "required": ["outcome", "probability"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    "required": ["query_id", "hypothesis_id", "outcome_probs"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["hypotheses", "predictions"],
        "additionalProperties": False,
    },
}

SELECT_TOOL = {
    "name": "select_query",
    "description": "Choose the single next query to run.",
    "input_schema": {
        "type": "object",
        "properties": {"query_id": {"type": "string"}, "rationale": {"type": "string"}},
        "required": ["query_id", "rationale"],
        "additionalProperties": False,
    },
}


# =============================================================== scenarios (embedded)
#
# The six scenarios are stored here, so this one file is all you need.
# HOW TO VALIDATE: check each scenario's hidden fields against your workbook (truth, reference_outcome,
# diagnostic, redundant_with), fix anything wrong directly in the text below, then change
#     "validated": true   to   "validated": true
# for that scenario and save the file. Keep the JSON format: double quotes, commas between items,
# and lowercase true/false. Run the "validate" command afterwards to catch typos.
# To use a separate scenario file instead, pass --scenarios yourfile.json.

SCENARIOS_JSON = r'''
[
  {
    "_draft_note": "DRAFT written from the paper's scenario table. Check every hidden field (truth, reference_outcome, diagnostic, redundant_with) against your workbook with a second coder, then set validated to true. Queries marked diagnostic=false and cost 1 are deliberate decoys: plausible checks that do not separate the malicious from the benign explanation.",
    "id": "SC-01",
    "validated": true,
    "truth": "malicious",
    "trigger": "powershell.exe started with an -EncodedCommand argument on workstation WS-114.",
    "initial_evidence": [
      "WS-114 is assigned to a user in the finance department",
      "No software deployment was scheduled for WS-114 today"
    ],
    "queries": {
      "Q1": {
        "description": "Identify the parent process of powershell.exe",
        "outcomes": [
          "office_application",
          "management_agent",
          "user_shell"
        ],
        "reference_outcome": "office_application",
        "diagnostic": true,
        "cost": 1
      },
      "Q2": {
        "description": "Decode the encoded command and classify its content",
        "outcomes": [
          "download_and_execute",
          "administrative_script",
          "other"
        ],
        "reference_outcome": "download_and_execute",
        "diagnostic": true,
        "cost": 1
      },
      "Q3": {
        "description": "Check outbound connections from WS-114 in the 5 minutes after execution",
        "outcomes": [
          "unknown_external_host",
          "internal_only",
          "none"
        ],
        "reference_outcome": "unknown_external_host",
        "diagnostic": true,
        "redundant_with": [
          "Q2"
        ],
        "cost": 2
      },
      "Q4": {
        "description": "Count PowerShell executions on WS-114 in the past 30 days",
        "outcomes": [
          "frequent",
          "rare"
        ],
        "reference_outcome": "rare",
        "diagnostic": false,
        "cost": 1
      },
      "Q5": {
        "description": "Check whether the logged-on user has local administrator rights",
        "outcomes": [
          "administrator",
          "standard_user"
        ],
        "reference_outcome": "standard_user",
        "diagnostic": false,
        "cost": 1
      },
      "Q6": {
        "description": "Check which account the PowerShell process ran under",
        "outcomes": [
          "logged_on_user",
          "system_account"
        ],
        "reference_outcome": "logged_on_user",
        "diagnostic": false,
        "cost": 1
      },
      "Q7": {
        "description": "Check whether endpoint antivirus raised an alert on WS-114 today",
        "outcomes": [
          "alert_raised",
          "no_alert"
        ],
        "reference_outcome": "no_alert",
        "diagnostic": false,
        "cost": 1
      }
    },
    "states": [
      {
        "id": "s0",
        "observed": []
      },
      {
        "id": "s1",
        "observed": [
          "Q2"
        ]
      }
    ]
  },
  {
    "id": "SC-02",
    "validated": true,
    "truth": "benign",
    "trigger": "347 failed Kerberos authentications for account svc_backup within 20 minutes.",
    "initial_evidence": [
      "svc_backup is a service account without interactive logon rights",
      "No successful logons for svc_backup occurred in the alert window"
    ],
    "queries": {
      "Q1": {
        "description": "Count distinct source hosts for the failed logons",
        "outcomes": [
          "single_source",
          "many_sources"
        ],
        "reference_outcome": "single_source",
        "diagnostic": true,
        "cost": 1
      },
      "Q2": {
        "description": "Search scheduled tasks on the source host that run as svc_backup",
        "outcomes": [
          "found",
          "not_found"
        ],
        "reference_outcome": "found",
        "diagnostic": true,
        "cost": 2
      },
      "Q3": {
        "description": "Compare failed-logon volume with the 30-day baseline for svc_backup",
        "outcomes": [
          "above_baseline",
          "within_baseline"
        ],
        "reference_outcome": "above_baseline",
        "diagnostic": false,
        "cost": 1
      },
      "Q4": {
        "description": "Check failed logons against other accounts from the same source hosts",
        "outcomes": [
          "many_accounts",
          "only_svc_backup"
        ],
        "reference_outcome": "only_svc_backup",
        "diagnostic": true,
        "redundant_with": [
          "Q1"
        ],
        "cost": 1
      },
      "Q5": {
        "description": "Check whether the svc_backup password was changed in the last 14 days",
        "outcomes": [
          "changed",
          "not_changed"
        ],
        "reference_outcome": "changed",
        "diagnostic": true,
        "cost": 2
      },
      "Q6": {
        "description": "Check the time of day of the failed logons",
        "outcomes": [
          "business_hours",
          "after_hours"
        ],
        "reference_outcome": "after_hours",
        "diagnostic": false,
        "cost": 1
      },
      "Q7": {
        "description": "Check whether svc_backup is a member of privileged groups",
        "outcomes": [
          "privileged",
          "not_privileged"
        ],
        "reference_outcome": "privileged",
        "diagnostic": false,
        "cost": 1
      }
    },
    "states": [
      {
        "id": "s0",
        "observed": []
      },
      {
        "id": "s1",
        "observed": [
          "Q1"
        ]
      }
    ]
  },
  {
    "id": "SC-03",
    "validated": true,
    "truth": "malicious",
    "trigger": "File server FS-07 has sent about 50 MB over HTTPS to one external IP address every 15 minutes for 6 hours.",
    "initial_evidence": [
      "FS-07 hosts the engineering department share",
      "The organization uses a commercial cloud backup service"
    ],
    "queries": {
      "Q1": {
        "description": "Check whether the destination is on the approved backup vendor list",
        "outcomes": [
          "approved_vendor",
          "not_listed"
        ],
        "reference_outcome": "not_listed",
        "diagnostic": true,
        "cost": 1
      },
      "Q2": {
        "description": "Search FS-07 for archive files created shortly before each transfer",
        "outcomes": [
          "archives_created",
          "none"
        ],
        "reference_outcome": "archives_created",
        "diagnostic": true,
        "cost": 2
      },
      "Q3": {
        "description": "Check the registration age of the destination domain from DNS logs",
        "outcomes": [
          "recently_registered",
          "established"
        ],
        "reference_outcome": "recently_registered",
        "diagnostic": true,
        "redundant_with": [
          "Q1"
        ],
        "cost": 1
      },
      "Q4": {
        "description": "Check DLP logs for sensitive-content matches in files read before the transfers",
        "outcomes": [
          "dlp_match",
          "no_match"
        ],
        "reference_outcome": "dlp_match",
        "diagnostic": true,
        "cost": 2
      },
      "Q5": {
        "description": "Compare FS-07 outbound volume today with its 30-day baseline",
        "outcomes": [
          "above_baseline",
          "within_baseline"
        ],
        "reference_outcome": "above_baseline",
        "diagnostic": false,
        "cost": 1
      },
      "Q6": {
        "description": "Check whether the transfers use TLS",
        "outcomes": [
          "encrypted",
          "unencrypted"
        ],
        "reference_outcome": "encrypted",
        "diagnostic": false,
        "cost": 1
      },
      "Q7": {
        "description": "Check whether the endpoint agent on FS-07 is installed and reporting",
        "outcomes": [
          "reporting",
          "not_reporting"
        ],
        "reference_outcome": "reporting",
        "diagnostic": false,
        "cost": 1
      }
    },
    "states": [
      {
        "id": "s0",
        "observed": []
      },
      {
        "id": "s1",
        "observed": [
          "Q1"
        ]
      }
    ]
  },
  {
    "id": "SC-04",
    "validated": true,
    "truth": "benign",
    "trigger": "New account adm_jlee was created and added to Domain Admins at 02:14 by IT operations user r.patel.",
    "initial_evidence": [
      "r.patel is a member of the IT operations team",
      "No new privileged accounts were created in the previous 30 days"
    ],
    "queries": {
      "Q1": {
        "description": "Search change management for a ticket covering the account creation",
        "outcomes": [
          "approved_emergency_change",
          "no_record"
        ],
        "reference_outcome": "approved_emergency_change",
        "diagnostic": true,
        "cost": 1
      },
      "Q2": {
        "description": "Check the source host of r.patel's session when the account was created",
        "outcomes": [
          "usual_workstation",
          "unusual_host"
        ],
        "reference_outcome": "usual_workstation",
        "diagnostic": true,
        "cost": 1
      },
      "Q3": {
        "description": "Review adm_jlee activity since creation for logons to many servers or bulk directory reads",
        "outcomes": [
          "no_unusual_activity",
          "lateral_movement_pattern"
        ],
        "reference_outcome": "no_unusual_activity",
        "diagnostic": true,
        "cost": 2
      },
      "Q4": {
        "description": "Check the incident system for an open major incident at 02:14",
        "outcomes": [
          "incident_open",
          "no_incident"
        ],
        "reference_outcome": "incident_open",
        "diagnostic": true,
        "redundant_with": [
          "Q1"
        ],
        "cost": 1
      },
      "Q5": {
        "description": "Check whether the creation happened outside business hours",
        "outcomes": [
          "after_hours",
          "business_hours"
        ],
        "reference_outcome": "after_hours",
        "diagnostic": false,
        "cost": 1
      },
      "Q6": {
        "description": "Check whether adm_jlee follows the naming convention for admin accounts",
        "outcomes": [
          "follows_convention",
          "does_not_follow"
        ],
        "reference_outcome": "follows_convention",
        "diagnostic": false,
        "cost": 1
      },
      "Q7": {
        "description": "Check whether adm_jlee has logged on since it was created",
        "outcomes": [
          "logged_on",
          "never_logged_on"
        ],
        "reference_outcome": "logged_on",
        "diagnostic": false,
        "cost": 1
      }
    },
    "states": [
      {
        "id": "s0",
        "observed": []
      },
      {
        "id": "s1",
        "observed": [
          "Q5"
        ]
      }
    ]
  },
  {
    "id": "SC-05",
    "validated": true,
    "truth": "malicious",
    "trigger": "About 12,000 files on share FS-02 were renamed within 9 minutes by account svc_sync, all with a new .lkd extension.",
    "initial_evidence": [
      "svc_sync is used by the file synchronization tool",
      "A storage migration project is planned for this quarter"
    ],
    "queries": {
      "Q1": {
        "description": "Measure the content entropy of a sample of renamed files",
        "outcomes": [
          "high_entropy",
          "unchanged_entropy"
        ],
        "reference_outcome": "high_entropy",
        "diagnostic": true,
        "cost": 2
      },
      "Q2": {
        "description": "Check whether canary files on the share were modified",
        "outcomes": [
          "canary_modified",
          "untouched"
        ],
        "reference_outcome": "canary_modified",
        "diagnostic": true,
        "cost": 1
      },
      "Q3": {
        "description": "Search change management for a migration scheduled at this time",
        "outcomes": [
          "migration_scheduled",
          "none_scheduled"
        ],
        "reference_outcome": "none_scheduled",
        "diagnostic": true,
        "cost": 1
      },
      "Q4": {
        "description": "Search the share for new text or HTML files created in each folder",
        "outcomes": [
          "new_note_files",
          "none"
        ],
        "reference_outcome": "new_note_files",
        "diagnostic": true,
        "redundant_with": [
          "Q2"
        ],
        "cost": 1
      },
      "Q5": {
        "description": "Compare the rename volume with svc_sync's nightly baseline",
        "outcomes": [
          "above_baseline",
          "within_baseline"
        ],
        "reference_outcome": "above_baseline",
        "diagnostic": false,
        "cost": 1
      },
      "Q6": {
        "description": "Check whether svc_sync's password was used from its usual host",
        "outcomes": [
          "usual_host",
          "other_host"
        ],
        "reference_outcome": "other_host",
        "diagnostic": true,
        "cost": 1
      },
      "Q7": {
        "description": "Check whether the renamed files are in user home folders, project folders or both",
        "outcomes": [
          "both",
          "project_only",
          "home_only"
        ],
        "reference_outcome": "both",
        "diagnostic": false,
        "cost": 1
      },
      "Q8": {
        "description": "Check whether last night's backup of FS-02 completed",
        "outcomes": [
          "completed",
          "failed"
        ],
        "reference_outcome": "completed",
        "diagnostic": false,
        "cost": 1
      }
    },
    "states": [
      {
        "id": "s0",
        "observed": []
      },
      {
        "id": "s1",
        "observed": [
          "Q3"
        ]
      }
    ]
  },
  {
    "id": "SC-06",
    "validated": true,
    "truth": "benign",
    "trigger": "A finance user granted a newly seen third-party app, InvoiceFlow, the Mail.ReadWrite and Files.ReadWrite.All permissions.",
    "initial_evidence": [
      "The app was first seen in the tenant today",
      "The user approved the consent prompt themselves"
    ],
    "queries": {
      "Q1": {
        "description": "Search procurement records for a purchase of InvoiceFlow",
        "outcomes": [
          "approved_purchase",
          "no_record"
        ],
        "reference_outcome": "approved_purchase",
        "diagnostic": true,
        "cost": 1
      },
      "Q2": {
        "description": "Check whether the app's publisher is verified",
        "outcomes": [
          "verified",
          "unverified"
        ],
        "reference_outcome": "verified",
        "diagnostic": true,
        "cost": 1
      },
      "Q3": {
        "description": "Check the location and network of the sign-in that granted consent",
        "outcomes": [
          "corporate_network",
          "anomalous_location"
        ],
        "reference_outcome": "corporate_network",
        "diagnostic": true,
        "cost": 1
      },
      "Q4": {
        "description": "Check the user's mailbox for new forwarding or deletion rules after consent",
        "outcomes": [
          "new_rules",
          "no_new_rules"
        ],
        "reference_outcome": "no_new_rules",
        "diagnostic": true,
        "cost": 2
      },
      "Q5": {
        "description": "Assess whether the granted permissions are high privilege",
        "outcomes": [
          "high_privilege",
          "low_privilege"
        ],
        "reference_outcome": "high_privilege",
        "diagnostic": false,
        "cost": 1
      },
      "Q6": {
        "description": "Count other users who consented to the same app",
        "outcomes": [
          "several_users",
          "only_this_user"
        ],
        "reference_outcome": "several_users",
        "diagnostic": false,
        "cost": 1
      },
      "Q7": {
        "description": "Check whether the app requested the offline_access permission",
        "outcomes": [
          "requested",
          "not_requested"
        ],
        "reference_outcome": "requested",
        "diagnostic": false,
        "cost": 1
      }
    },
    "states": [
      {
        "id": "s0",
        "observed": []
      },
      {
        "id": "s1",
        "observed": [
          "Q5"
        ]
      }
    ]
  }
]
'''


# =============================================================== scenario validation

def validate_scenarios(scenarios):
    """Return (errors, warnings). Errors block any run; warnings are printed."""
    errors, warnings = [], []
    if not isinstance(scenarios, list) or not scenarios:
        return ["Scenario file must be a non-empty JSON list."], warnings
    seen = set()
    for i, sc in enumerate(scenarios):
        where = f"scenario #{i + 1} ({sc.get('id', '?')})"
        for key in ("id", "truth", "trigger", "initial_evidence", "queries", "states"):
            if key not in sc:
                errors.append(f"{where}: missing '{key}'")
        if errors:
            continue
        if sc["id"] in seen:
            errors.append(f"{where}: duplicate id")
        seen.add(sc["id"])
        if sc["truth"] not in ("malicious", "benign"):
            errors.append(f"{where}: truth must be 'malicious' or 'benign'")
        if not isinstance(sc["initial_evidence"], list):
            errors.append(f"{where}: initial_evidence must be a list of strings")
        qs = sc["queries"]
        if not isinstance(qs, dict) or len(qs) < 2:
            errors.append(f"{where}: needs at least 2 queries")
            continue
        n_diag = 0
        for qid, q in qs.items():
            qw = f"{where} query {qid}"
            for key in ("description", "outcomes", "reference_outcome", "diagnostic"):
                if key not in q:
                    errors.append(f"{qw}: missing '{key}'")
            if any(k not in q for k in ("outcomes", "reference_outcome", "diagnostic")):
                continue
            if len(q["outcomes"]) < 2 or len(set(q["outcomes"])) != len(q["outcomes"]):
                errors.append(f"{qw}: needs 2+ distinct outcomes")
            if q["reference_outcome"] not in q["outcomes"]:
                errors.append(f"{qw}: reference_outcome '{q['reference_outcome']}' not in outcomes")
            if not isinstance(q["diagnostic"], bool):
                errors.append(f"{qw}: diagnostic must be true or false")
            n_diag += bool(q["diagnostic"])
            if float(q.get("cost", 1)) <= 0:
                errors.append(f"{qw}: cost must be positive")
            for r in q.get("redundant_with", []):
                if r not in qs:
                    errors.append(f"{qw}: redundant_with refers to unknown query '{r}'")
            visible = (q["description"] + " " + " ".join(q["outcomes"])).lower()
            if "malicious" in visible or "benign" in visible:
                warnings.append(f"{qw}: visible text contains 'malicious'/'benign' and may leak the answer")
        if n_diag == 0:
            warnings.append(f"{where}: no diagnostic query, so both selectors will score 0")
        if n_diag == len(qs):
            warnings.append(f"{where}: every query is diagnostic, so the test cannot separate selectors")
        visible = (sc["trigger"] + " " + " ".join(sc["initial_evidence"])).lower()
        if "malicious" in visible or "benign" in visible:
            warnings.append(f"{where}: alert or initial evidence mentions 'malicious'/'benign'")
        if not sc["states"]:
            errors.append(f"{where}: needs at least one state")
        for st in sc["states"]:
            for o in st.get("observed", []):
                if o not in qs:
                    errors.append(f"{where} state {st.get('id')}: observed query '{o}' unknown")
            if len(qs) - len(st.get("observed", [])) < 2:
                errors.append(f"{where} state {st.get('id')}: fewer than 2 candidate queries remain")
        if not sc.get("validated", False):
            warnings.append(f"{where}: not marked validated (set \"validated\": true after coding review)")
    return errors, warnings


def scenarios_text(path):
    """The scenario JSON text: from --scenarios if given, otherwise the copy embedded in this script."""
    return Path(path).read_text(encoding="utf-8") if path else SCENARIOS_JSON


def scenarios_sha256(path):
    return hashlib.sha256(scenarios_text(path).encode("utf-8")).hexdigest()


def load_scenarios(path):
    try:
        scenarios = json.loads(scenarios_text(path))
    except json.JSONDecodeError as e:
        line = e.lineno
        if not path:  # convert to a line number in this script, as VS Code shows it
            src = Path(__file__).read_text(encoding="utf-8").splitlines()
            start = next(i for i, l in enumerate(src, 1) if l.startswith("SCENARIOS_JSON = r'''"))
            line = start + e.lineno - 1
        where = path or "this script"
        sys.exit(f"Scenario JSON formatting error in {where}, around line {line}: {e.msg}. "
                 "Look for a missing comma or quote on that line or the line just above it.")
    errors, warnings = validate_scenarios(scenarios)
    return scenarios, errors, warnings


# =============================================================== prompts (no ground truth inside)

def candidates(sc, state):
    return [q for q in sc["queries"] if q not in state.get("observed", [])]


def state_text(sc, state):
    lines = [f"ALERT: {sc['trigger']}", "", "INITIAL EVIDENCE:"]
    lines += [f"- {e}" for e in sc["initial_evidence"]]
    observed = state.get("observed", [])
    if observed:
        lines += ["", "QUERIES ALREADY RUN AND THEIR RESULTS:"]
        for qid in observed:
            q = sc["queries"][qid]
            lines.append(f"- {qid}: {q['description']} -> {q['reference_outcome']}")
    lines += ["", "CANDIDATE QUERIES (id: description [possible outcomes] (relative cost)):"]
    for qid in candidates(sc, state):
        q = sc["queries"][qid]
        cost = q.get("cost", 1)
        cost = int(cost) if float(cost).is_integer() else cost
        lines.append(f"- {qid}: {q['description']} [{', '.join(q['outcomes'])}] (cost {cost})")
    return "\n".join(lines)


def hyp_prompt(sc, state):
    return (
        state_text(sc, state)
        + "\n\nTASK: Generate 2-6 rival explanations, including at least one malicious and one benign "
        "explanation. Give each a prior probability (priors sum to 1). Then, for EVERY candidate query "
        "and EVERY hypothesis, give the probability of each listed outcome if that hypothesis were true "
        "(probabilities per query-hypothesis pair sum to 1). Use only the listed outcome names.\n\n"
        "Respond by calling the report_hypotheses tool."
    )


def select_prompt(sc, state, hyps, preds):
    return (
        state_text(sc, state)
        + "\n\nRIVAL HYPOTHESES:\n" + json.dumps(hyps, indent=1)
        + "\n\nPREDICTED OUTCOMES:\n" + json.dumps(preds, indent=1)
        + "\n\nTASK: Choose the single candidate query that gives the most help in determining which explanation "
        "is correct, taking its relative cost into account. Return its id exactly as listed.\n\n"
        "Respond by calling the select_query tool."
    )


# =============================================================== cost

def call_cost(model, input_tokens, output_tokens):
    p_in, p_out = PRICES[model]
    return (input_tokens * p_in + output_tokens * p_out) / 1e6


def worst_case_call_cost(model, prompt_chars):
    """Upper bound for one API call: ~3 chars per token plus system and tool schema, full max_tokens output."""
    return call_cost(model, prompt_chars / 3 + 2000, MAX_TOKENS)


# =============================================================== LLM calls

def make_client():
    try:
        import anthropic
    except ImportError:
        sys.exit("The 'anthropic' package is missing. Install it with: pip install -r requirements.txt")
    key = os.environ.get("ANTHROPIC_API_KEY") or getpass.getpass("Anthropic API key (input hidden): ").strip()
    if not key:
        sys.exit("No API key provided.")
    return anthropic.Anthropic(api_key=key, max_retries=2)


def check_hyp_output(out):
    hyps = out.get("hypotheses")
    if not isinstance(hyps, list) or len(hyps) < 2:
        raise ValueError("fewer than 2 hypotheses")
    ids = [h.get("id") for h in hyps]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate hypothesis ids")
    if not isinstance(out.get("predictions"), list):
        raise ValueError("predictions missing")


def check_sel_output(out):
    if not isinstance(out.get("query_id"), str):
        raise ValueError("query_id missing")


def call_model(client, model, prompt, tool, thinking, check, budget):
    """Call the model with one strict tool. Returns (tool_input, meta). Every attempt is charged to the budget."""
    kwargs = dict(model=model, max_tokens=MAX_TOKENS, system=SYSTEM,
                  tools=[{**tool, "strict": True}], tool_choice={"type": "auto"},
                  thinking={"type": thinking},
                  messages=[{"role": "user", "content": prompt}])
    usage_in = usage_out = 0
    last_err = None
    for attempt in range(1, RETRIES + 1):
        budget.check(worst_case_call_cost(model, len(prompt)))
        try:
            resp = client.messages.create(**kwargs)
        except Exception as e:  # network error, rate limit after SDK retries, server error
            last_err = e
            print(f"    API error (attempt {attempt}/{RETRIES}): {e}", file=sys.stderr)
            if getattr(e, "status_code", None) in (400, 401, 403, 404):
                # request or key problem: retrying will not help, so stop the whole run with the message
                raise RuntimeError(f"API rejected the request: {e}",
                                   {"input_tokens": usage_in, "output_tokens": usage_out}, True)
            time.sleep(2 ** attempt)
            continue
        usage_in += resp.usage.input_tokens
        usage_out += resp.usage.output_tokens
        budget.add(call_cost(model, resp.usage.input_tokens, resp.usage.output_tokens))
        try:
            if resp.stop_reason == "max_tokens":
                raise ValueError("output truncated at max_tokens")
            block = next((b for b in resp.content if b.type == "tool_use"), None)
            if block is None:
                raise ValueError("no tool_use block in response")
            check(block.input)
            meta = {"response_id": resp.id, "model_returned": resp.model, "stop_reason": resp.stop_reason,
                    "attempts": attempt, "input_tokens": usage_in, "output_tokens": usage_out}
            return block.input, meta
        except ValueError as e:
            last_err = e
            print(f"    Malformed output (attempt {attempt}/{RETRIES}): {e}", file=sys.stderr)
    raise RuntimeError(f"Model call failed after {RETRIES} attempts: {last_err}",
                       {"input_tokens": usage_in, "output_tokens": usage_out}, False)


def fake_call(kind, sc, state, rng):
    """Offline stand-in with valid structure, for testing the harness only. Results are meaningless."""
    cands = candidates(sc, state)
    if kind == "hyp":
        hyps = [{"id": "H1", "label": "malicious", "description": "fake", "prior": 0.5},
                {"id": "H2", "label": "benign", "description": "fake", "prior": 0.5}]
        preds = []
        for qid in cands:
            for h in hyps:
                preds.append({"query_id": qid, "hypothesis_id": h["id"],
                              "outcome_probs": [{"outcome": o, "probability": rng.random() + 0.05}
                                                for o in sc["queries"][qid]["outcomes"]]})
        return {"hypotheses": hyps, "predictions": preds}, {"fake": True, "input_tokens": 0, "output_tokens": 0}
    return ({"query_id": rng.choice(cands), "rationale": "fake"},
            {"fake": True, "input_tokens": 0, "output_tokens": 0})


# =============================================================== information-gain math

def entropy(ps):
    return -sum(p * math.log2(p) for p in ps if p > 0)


def normalize(d):
    s = sum(d.values())
    return {k: v / s for k, v in d.items()} if s > 0 else {k: 1 / len(d) for k in d}


def build_model(sc, state, raw):
    """Clean priors and likelihoods; fill missing predictions with uniform and count them."""
    hyps = raw["hypotheses"]
    for h in hyps:
        h["id"] = str(h.get("id")).strip()
        try:
            h["prior"] = float(h.get("prior", 0) or 0)
        except (TypeError, ValueError):
            h["prior"] = 0.0
    prior = normalize({h["id"]: max(h["prior"], EPS) for h in hyps})
    given = {}
    for p in raw["predictions"]:
        if not isinstance(p, dict):
            continue
        probs = p.get("outcome_probs")
        if isinstance(probs, list):  # strict-tool format: [{"outcome": ..., "probability": ...}, ...]
            probs = {str(x.get("outcome")).strip().lower(): x.get("probability")
                     for x in probs if isinstance(x, dict)}
        if isinstance(probs, dict):
            given[(str(p.get("query_id")).strip(), str(p.get("hypothesis_id")).strip())] = probs
    lik, missing = {}, 0
    for qid in candidates(sc, state):
        outs = sc["queries"][qid]["outcomes"]
        lik[qid] = {}
        for h in prior:
            probs = given.get((qid, h))
            if probs is None:
                missing += 1
                probs = {}
            clean = {}
            for o in outs:
                try:
                    clean[o] = max(float(probs.get(o.lower(), probs.get(o, 0)) or 0), EPS)
                except (TypeError, ValueError):
                    clean[o] = EPS
            lik[qid][h] = normalize(clean)
    return hyps, prior, lik, missing


def eig(prior, lik_q):
    outcomes = next(iter(lik_q.values())).keys()
    h0, expected_post = entropy(prior.values()), 0.0
    for o in outcomes:
        po = sum(prior[h] * lik_q[h][o] for h in prior)
        if po > 0:
            expected_post += po * entropy([prior[h] * lik_q[h][o] / po for h in prior])
    return h0 - expected_post


def posterior(prior, lik_q, outcome):
    return normalize({h: prior[h] * lik_q[h][outcome] for h in prior})


def p_label(dist, labels, truth):
    return sum(p for h, p in dist.items() if labels.get(h) == truth)


# =============================================================== scoring against the hidden evidence map

def score_pick(sc, state, qid, prior, lik, labels):
    if qid not in sc["queries"] or qid in state.get("observed", []):
        return {"valid": False, "diagnostic": False, "delta_p_true": 0.0}
    q = sc["queries"][qid]
    redundant = any(r in state.get("observed", []) for r in q.get("redundant_with", []))
    post = posterior(prior, lik[qid], q["reference_outcome"])
    return {"valid": True, "diagnostic": bool(q["diagnostic"]) and not redundant,
            "delta_p_true": p_label(post, labels, sc["truth"]) - p_label(prior, labels, sc["truth"])}


def calibration(sc, state, prior, lik, labels):
    """Mean log-loss (bits) of the reference outcomes under true-label hypotheses. Lower is better."""
    true_h = {h: p for h, p in prior.items() if labels.get(h) == sc["truth"]}
    if not true_h:
        return None
    w = normalize(true_h)
    losses = [-math.log2(max(sum(w[h] * lik[q][h][sc["queries"][q]["reference_outcome"]] for h in w), EPS))
              for q in candidates(sc, state)]
    return sum(losses) / len(losses)


def chance_diagnostic_rate(sc, state):
    """Share of candidate queries that are nonredundant-diagnostic: the rate a random selector would get."""
    c = candidates(sc, state)
    good = [q for q in c if sc["queries"][q]["diagnostic"]
            and not any(r in state.get("observed", []) for r in sc["queries"][q].get("redundant_with", []))]
    return len(good) / len(c)


# =============================================================== run

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cmd_run(args):
    scenarios, errors, warnings = load_scenarios(args.scenarios)
    for w in warnings:
        print("WARNING:", w)
    if errors:
        for e in errors:
            print("ERROR:", e)
        sys.exit("Fix the scenario file before running.")
    unvalidated = [sc["id"] for sc in scenarios if not sc.get("validated", False)]
    if args.pilot:
        args.reps = 1
        if args.max_cost is None:
            args.max_cost = 1.00
    if args.max_cost is None:
        args.max_cost = 5.0
    if unvalidated and not (args.fake or args.pilot or args.allow_unvalidated):
        sys.exit(f"Scenarios not validated: {', '.join(unvalidated)}. Review and set \"validated\": true, "
                 "or use --pilot / --fake to test. Results from unvalidated scenarios should not be reported.")
    if not args.fake and args.model not in PRICES:
        sys.exit(f"No price on file for {args.model}; add it to PRICES so the budget cap works.")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    runs_path, fail_path, meta_path = out / "runs.jsonl", out / "failures.jsonl", out / "run_meta.json"

    done, spent = set(), 0.0
    if args.resume and runs_path.exists():
        old_meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        if old_meta.get("scenarios_sha256") != scenarios_sha256(args.scenarios) or old_meta.get("model") != (
                "FAKE" if args.fake else args.model):
            sys.exit("Cannot resume: the scenario file or model differs from the earlier run.")
        for line in runs_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["scenario"], r["state"], r["rep"]))
                spent += r.get("cost_usd", 0.0)
        if fail_path.exists():
            spent += sum(json.loads(l).get("cost_usd", 0.0) for l in fail_path.read_text(encoding="utf-8").splitlines() if l.strip())
        print(f"Resuming: {len(done)} state-reps already done, ${spent:.2f} already spent.")
    elif runs_path.exists() and runs_path.stat().st_size and not args.resume:
        sys.exit(f"{runs_path} already has results. Use --resume to continue it, or a new --out folder.")

    client = None if args.fake else make_client()
    budget = Budget(args.max_cost, spent)
    rng = random.Random(args.seed)
    jobs = [(sc, st, rep) for sc in scenarios for st in sc["states"] for rep in range(args.reps)]
    run_meta = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "model": "FAKE" if args.fake else args.model, "fake": args.fake, "pilot": args.pilot,
        "thinking": args.thinking, "temperature": "model default (not sent)", "tool_choice": "auto, strict tools",
        "reps": args.reps, "cost_weighted": not args.no_cost,
        "max_tokens": MAX_TOKENS, "max_cost_usd": args.max_cost,
        "prices_per_mtok": None if args.fake else PRICES[args.model],
        "unvalidated_scenarios": unvalidated,
        "script_sha256": sha256(__file__), "scenarios_sha256": scenarios_sha256(args.scenarios),
        "scenarios_source": args.scenarios or "embedded in script",
        "python": sys.version.split()[0],
    }
    meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")

    stopped_early, fatal_error, failures, n_new = False, None, 0, 0
    with runs_path.open("a", encoding="utf-8") as log:
        for i, (sc, state, rep) in enumerate(jobs, 1):
            if (sc["id"], state["id"], rep) in done:
                continue
            print(f"[{i}/{len(jobs)}] {sc['id']} {state['id']} rep {rep + 1}   spent ${budget.spent:.2f}")
            hp = hyp_prompt(sc, state)
            before = budget.spent
            sp = sel = meta_h = meta_s = None
            try:
                if args.fake:
                    raw, meta_h = fake_call("hyp", sc, state, rng)
                else:
                    raw, meta_h = call_model(client, args.model, hp, HYP_TOOL, args.thinking, check_hyp_output, budget)
                hyps, prior, lik, missing = build_model(sc, state, raw)
                labels = {h["id"]: str(h.get("label")).strip().lower() for h in hyps}

                eigs = {q: eig(prior, lik[q]) for q in lik}
                cost = {q: 1.0 if args.no_cost else float(sc["queries"][q].get("cost", 1.0)) for q in lik}
                a3 = max(lik, key=lambda q: (eigs[q] / cost[q], eigs[q]))

                sp = select_prompt(sc, state, raw["hypotheses"], raw["predictions"])
                if args.fake:
                    sel, meta_s = fake_call("sel", sc, state, rng)
                else:
                    sel, meta_s = call_model(client, args.model, sp, SELECT_TOOL, args.thinking, check_sel_output, budget)
            except BudgetStop as e:
                print(f"\nBudget stop: {e}")
                stopped_early = True
                if budget.spent > before:
                    with fail_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps({"scenario": sc["id"], "state": state["id"], "rep": rep,
                                            "error": "budget stop mid state-rep",
                                            "cost_usd": round(budget.spent - before, 6)}) + "\n")
                break
            except RuntimeError as e:
                failures += 1
                fatal = len(e.args) > 2 and e.args[2]
                with fail_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"scenario": sc["id"], "state": state["id"], "rep": rep,
                                        "error": str(e.args[0]), "cost_usd": round(budget.spent - before, 6)}) + "\n")
                print(f"    Skipped after failure: {e.args[0]}", file=sys.stderr)
                if fatal:
                    fatal_error = str(e.args[0])
                    print("\nStopping: the API rejected the request, so later calls would fail the same way. "
                          "Send this error message (not your key) to get it fixed.")
                    break
                if failures >= 3:
                    print("Three state-reps failed; stopping. Check your network and the error messages above.")
                    break
                continue
            step_cost = budget.spent - before
            a2 = str(sel["query_id"]).strip()

            s2 = score_pick(sc, state, a2, prior, lik, labels)
            s3 = score_pick(sc, state, a3, prior, lik, labels)
            row = {
                "scenario": sc["id"], "truth": sc["truth"], "state": state["id"], "rep": rep,
                "n_hypotheses": len(hyps), "missing_predictions": missing,
                "has_true_label_hypothesis": sc["truth"] in labels.values(),
                "chance_diagnostic_rate": round(chance_diagnostic_rate(sc, state), 4),
                "a2_query": a2, "a2_valid": s2["valid"], "a2_diagnostic": s2["diagnostic"],
                "a2_delta_p_true": round(s2["delta_p_true"], 4),
                "a3_query": a3, "a3_diagnostic": s3["diagnostic"], "a3_delta_p_true": round(s3["delta_p_true"], 4),
                "same_pick": a2 == a3,
                "calibration_logloss": calibration(sc, state, prior, lik, labels),
                "cost_usd": round(step_cost, 6),
            }
            log.write(json.dumps({**row, "hyp_prompt": hp, "hyp_raw": raw, "hyp_meta": meta_h,
                                  "select_prompt": sp, "select_raw": sel, "select_meta": meta_s,
                                  "eig": eigs}) + "\n")
            log.flush()
            n_new += 1

    spent = budget.spent
    run_meta.update({"finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "spent_usd": round(spent, 4), "state_reps_planned": len(jobs),
                     "failed_state_reps": failures, "stopped_early_for_budget": stopped_early,
                     "fatal_api_error": fatal_error})
    meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
    print(f"\nRun finished: {n_new} new state-reps, ${spent:.2f} spent in total.")
    if runs_path.exists() and runs_path.stat().st_size:
        write_report(out)


# =============================================================== report

def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def fmt(x, nd=2):
    return "n/a" if x is None else f"{x:.{nd}f}"


def write_report(out):
    out = Path(out)
    meta = json.loads((out / "run_meta.json").read_text(encoding="utf-8"))
    rows = [json.loads(l) for l in (out / "runs.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    keep = [k for k in rows[0] if k not in ("hyp_prompt", "hyp_raw", "hyp_meta", "select_prompt",
                                             "select_raw", "select_meta", "eig")]
    with (out / "rows.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keep, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    summary = []
    for sid in dict.fromkeys(r["scenario"] for r in rows):
        rs = [r for r in rows if r["scenario"] == sid]
        n = len(rs)
        summary.append({
            "scenario": sid, "truth": rs[0]["truth"], "n_state_reps": n,
            "chance_diagnostic_rate": round(mean(r["chance_diagnostic_rate"] for r in rs), 3),
            "a2_diagnostic_rate": round(sum(r["a2_diagnostic"] for r in rs) / n, 3),
            "a3_diagnostic_rate": round(sum(r["a3_diagnostic"] for r in rs) / n, 3),
            "a3_minus_a2": round((sum(r["a3_diagnostic"] for r in rs) - sum(r["a2_diagnostic"] for r in rs)) / n, 3),
            "same_pick_rate": round(sum(r["same_pick"] for r in rs) / n, 3),
            "a2_invalid_picks": sum(not r["a2_valid"] for r in rs),
            "a2_mean_delta_p_true": round(mean(r["a2_delta_p_true"] for r in rs), 4),
            "a3_mean_delta_p_true": round(mean(r["a3_delta_p_true"] for r in rs), 4),
            "true_label_hypothesis_rate": round(sum(r["has_true_label_hypothesis"] for r in rs) / n, 3),
            "mean_missing_predictions": round(mean(r["missing_predictions"] for r in rs), 2),
            "mean_calibration_logloss": (round(mean(r["calibration_logloss"] for r in rs), 3)
                                         if mean(r["calibration_logloss"] for r in rs) is not None else None),
        })
    with (out / "summary_by_scenario.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=summary[0].keys())
        w.writeheader()
        w.writerows(summary)

    wins = sum(s["a3_minus_a2"] > 0 for s in summary)
    ties = sum(s["a3_minus_a2"] == 0 for s in summary)
    losses = sum(s["a3_minus_a2"] < 0 for s in summary)
    cal = [s for s in summary if s["mean_calibration_logloss"] is not None]
    split = ""
    if len(cal) >= 2:
        med = statistics.median(s["mean_calibration_logloss"] for s in cal)
        good = [s["a3_minus_a2"] for s in cal if s["mean_calibration_logloss"] <= med]
        poor = [s["a3_minus_a2"] for s in cal if s["mean_calibration_logloss"] > med]
        split = (f"- Mean A3 minus A2 in better-calibrated scenarios (log-loss at or below median {med:.2f}): "
                 f"{fmt(mean(good))} (n = {len(good)})\n"
                 f"- Mean A3 minus A2 in worse-calibrated scenarios: {fmt(mean(poor))} (n = {len(poor)})\n")

    lines = [
        "# Active ACH matched-state test: results", "",
        f"- Model: {meta['model']}" + ("  **(FAKE offline run: numbers are meaningless)**" if meta.get("fake") else ""),
        f"- Run started (UTC): {meta['started_utc']}",
        f"- Repetitions per state: {meta['reps']}; thinking: {meta.get('thinking', 'n/a')}; temperature: model default; "
        f"cost-weighted EIG: {meta['cost_weighted']}",
        f"- State-reps completed: {len(rows)} of {meta.get('state_reps_planned', '?')}; "
        f"failed: {meta.get('failed_state_reps', 0)}; stopped for budget: {meta.get('stopped_early_for_budget')}",
        f"- Spent: ${meta.get('spent_usd', 0):.2f} (cap ${meta['max_cost_usd']:.2f})",
        f"- Scenario file SHA-256: {meta['scenarios_sha256']}",
    ]
    if meta.get("unvalidated_scenarios"):
        lines.append(f"- **Unvalidated scenarios: {', '.join(meta['unvalidated_scenarios'])}. "
                     "Do not report these results.**")
    if meta.get("pilot"):
        lines.append("- **Pilot run (1 repetition). Use it to check outputs, not as evidence.**")
    lines += ["", "## Nonredundant diagnostic rate by scenario", "",
              "| Scenario | Truth | State-reps | Chance | A2 (LLM selects) | A3 (controller) | A3 âˆ’ A2 | Same pick | "
              "A2 invalid | Calibration log-loss |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for s in summary:
        lines.append(f"| {s['scenario']} | {s['truth']} | {s['n_state_reps']} | {s['chance_diagnostic_rate']:.2f} | "
                     f"{s['a2_diagnostic_rate']:.2f} | {s['a3_diagnostic_rate']:.2f} | {s['a3_minus_a2']:+.2f} | "
                     f"{s['same_pick_rate']:.2f} | {s['a2_invalid_picks']} | {fmt(s['mean_calibration_logloss'])} |")
    lines += ["", "## Across scenarios (scenario is the unit)", "",
              f"- Scenarios where A3 > A2: {wins}; equal: {ties}; A3 < A2: {losses}",
              f"- Mean scenario-level diagnostic rate: A2 {fmt(mean(s['a2_diagnostic_rate'] for s in summary))}, "
              f"A3 {fmt(mean(s['a3_diagnostic_rate'] for s in summary))}, "
              f"chance {fmt(mean(s['chance_diagnostic_rate'] for s in summary))}",
              f"- Mean change in probability of the true label after the selected query: "
              f"A2 {fmt(mean(s['a2_mean_delta_p_true'] for s in summary), 3)}, "
              f"A3 {fmt(mean(s['a3_mean_delta_p_true'] for s in summary), 3)}",
              f"- Share of state-reps where the model generated a hypothesis with the true label: "
              f"{fmt(mean(s['true_label_hypothesis_rate'] for s in summary))}",
              split.rstrip("\n"),
              "", "## How to read this", "",
              "- Results are descriptive. With few scenarios, no significance tests are reported.",
              "- 'Chance' is the share of candidate queries that are nonredundant-diagnostic, i.e. what random "
              "selection would score.",
              "- Calibration is the mean log-loss (bits) of the reference outcomes under the model's true-label "
              "hypotheses; lower means the model predicted the evidence better. DP1 expects the controller to help "
              "most when calibration is good.",
              "- Full prompts and raw model outputs for every call are in runs.jsonl."]
    (out / "report.md").write_text("\n".join(l for l in lines if l is not None) + "\n", encoding="utf-8")
    print(f"Report written: {out / 'report.md'}")


# =============================================================== CLI

def main():
    ap = argparse.ArgumentParser(description="Active ACH matched-state experiment (A2 vs A3).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="check the scenario file and estimate cost")
    v.add_argument("--scenarios", default=None, help="optional JSON file; default: scenarios embedded in this script")
    v.add_argument("--reps", type=int, default=5)
    v.add_argument("--model", default=DEFAULT_MODEL)

    r = sub.add_parser("run", help="run the experiment")
    r.add_argument("--scenarios", default=None, help="optional JSON file; default: scenarios embedded in this script")
    r.add_argument("--out", required=True, help="output folder")
    r.add_argument("--model", default=DEFAULT_MODEL)
    r.add_argument("--reps", type=int, default=5)
    r.add_argument("--max-cost", type=float, default=None, help="hard budget in USD (default 5; pilot 1.00)")
    r.add_argument("--thinking", choices=["between_tools", "adaptive"], default="between_tools",
                   help="between_tools (default): no up-front thinking, predictable cost; adaptive: model thinks first")
    r.add_argument("--no-cost", action="store_true", help="rank by EIG alone, ignoring query cost")
    r.add_argument("--pilot", action="store_true", help="1 repetition, $1 cap, unvalidated scenarios allowed")
    r.add_argument("--fake", action="store_true", help="offline dry run with no API calls")
    r.add_argument("--resume", action="store_true", help="continue an interrupted run in the same folder")
    r.add_argument("--allow-unvalidated", action="store_true", help="run full reps on unvalidated scenarios")
    r.add_argument("--seed", type=int, default=0, help="seed for --fake mode only")

    p = sub.add_parser("report", help="rebuild report.md and CSVs from a results folder")
    p.add_argument("--out", required=True)

    args = ap.parse_args()
    if args.cmd == "validate":
        scenarios, errors, warnings = load_scenarios(args.scenarios)
        for w in warnings:
            print("WARNING:", w)
        for e in errors:
            print("ERROR:", e)
        if errors:
            sys.exit(f"{len(errors)} error(s). Fix them before running.")
        n = sum(len(sc["states"]) for sc in scenarios) * args.reps
        typical = n * 0.04 * PRICES[args.model][1] / 10 if args.model in PRICES else None
        print(f"OK: {len(scenarios)} scenarios, {n} state-reps at {args.reps} reps "
              f"({2 * n} model calls). Rough typical cost on {args.model}: "
              f"{'$%.2f' % typical if typical is not None else 'unknown'}.")
    elif args.cmd == "run":
        cmd_run(args)
    else:
        write_report(args.out)


if __name__ == "__main__":
    main()

