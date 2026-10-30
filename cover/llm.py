"""Model adapter, pricing and budget. Default model: Claude Haiku 5.5 (claude-haiku-5-5).

API notes (verified 2026-10-25 against platform.claude.com):
  Haiku 5.5   - forced tool_choice ({"type":"tool","name":...}) is SUPPORTED; the response then starts
                with the tool call and has no thinking block, which keeps cost predictable. Adaptive
                thinking is on by default otherwise. temperature/top_p/top_k must be omitted.
                Pricing: $0.10 in / $0.50 out per MTok for prompts up to 100k tokens; $0.50 / $2.50 above.
                New tokenizer: ~30% more tokens for the same text (used in the worst-case estimate).
                stop_reason "refusal" must be handled (treated as a malformed reply and retried).
  Sonnet/Opus 5.5 - forced tool_choice rejected, so tool_choice "auto" + thinking "between_tools"
                (kept from the legacy script).
  Strict tools - not documented on the Haiku 5.5 migration page; the adapter sends strict=True and, if
                the API answers 400 mentioning 'strict', drops strict for the session and records it.
                Outputs are validated locally either way.
The API key is read from ANTHROPIC_API_KEY or asked for with hidden input; never written anywhere.
"""
import getpass, hashlib, json, os, random, sys, time
from .config import CONFIG

PRICES = {  # USD per MTok: (input, output, input_over_100k, output_over_100k)
    "claude-haiku-5-5": (0.10, 0.50, 0.50, 2.50),
    "claude-sonnet-5-5": (2.0, 10.0, 2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0, 4.0, 20.0),
}
PROFILES = {
    "claude-haiku-5-5": {"tool_choice": "forced", "thinking": None},
    "claude-sonnet-5-5": {"tool_choice": "auto", "thinking": "between_tools"},
    "claude-opus-5-5": {"tool_choice": "auto", "thinking": "between_tools"},
}
MAX_TOKENS = CONFIG["max_tokens"]
RETRIES = CONFIG["retries"]

HYP_TOOL = {
    "name": "report_hypotheses",
    "description": "Report rival explanations and predicted outcomes for every candidate query.",
    "input_schema": {
        "type": "object",
        "properties": {
            "hypotheses": {"type": "array", "minItems": 1,
                           "description": "2 to 6 rival explanations, at least one malicious and one benign.",
                           "items": {"type": "object", "properties": {
                               "id": {"type": "string"},
                               "label": {"type": "string", "enum": ["malicious", "benign"]},
                               "description": {"type": "string"},
                               "prior": {"type": "number", "description": "Probability this explanation is correct given the alert and all evidence observed so far; sums to 1 across hypotheses."}},
                               "required": ["id", "label", "description", "prior"], "additionalProperties": False}},
            "predictions": {"type": "array", "minItems": 1,
                            "description": "One entry for every candidate query and every hypothesis.",
                            "items": {"type": "object", "properties": {
                                "query_id": {"type": "string"}, "hypothesis_id": {"type": "string"},
                                "outcome_probs": {"type": "array", "minItems": 1,
                                                  "description": "Probability of each listed outcome if the hypothesis were true; sums to 1.",
                                                  "items": {"type": "object", "properties": {
                                                      "outcome": {"type": "string"}, "probability": {"type": "number"}},
                                                      "required": ["outcome", "probability"], "additionalProperties": False}}},
                                "required": ["query_id", "hypothesis_id", "outcome_probs"], "additionalProperties": False}},
            "retired": {"type": "array", "description": "Previously reported hypothesis ids no longer included, with reasons.",
                        "items": {"type": "object", "properties": {"id": {"type": "string"}, "rationale": {"type": "string"}},
                                  "required": ["id", "rationale"], "additionalProperties": False}},
            "compatible_pairs": {"type": "array", "description": "Pairs of hypothesis ids that could both be true.",
                                 "items": {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                                           "required": ["a", "b"], "additionalProperties": False}},
        },
        "required": ["hypotheses", "predictions", "retired", "compatible_pairs"],
        "additionalProperties": False,
    },
}
SELECT_TOOL = {
    "name": "select_query",
    "description": "Choose the single next query to run.",
    "input_schema": {"type": "object", "properties": {"query_id": {"type": "string"}, "rationale": {"type": "string"}},
                     "required": ["query_id", "rationale"], "additionalProperties": False},
}


VERIFY_TOOL = {
    "name": "rate_checks",
    "description": "Rate how strongly each claimed result would count against the leading explanation.",
    "input_schema": {"type": "object", "properties": {
        "ratings": {"type": "array", "items": {"type": "object", "properties": {
            "query_id": {"type": "string"},
            "rating": {"type": "string", "enum": ["decisive", "suggestive", "not_diagnostic"]},
            "reason": {"type": "string"}},
            "required": ["query_id", "rating", "reason"], "additionalProperties": False}}},
        "required": ["ratings"], "additionalProperties": False},
}


class BudgetStop(Exception):
    pass


class FatalAPIError(RuntimeError):
    pass


class CallFailed(RuntimeError):
    pass


class Budget:
    def __init__(self, cap, spent=0.0):
        self.cap, self.spent = cap, spent

    def check(self, worst):
        if self.spent + worst > self.cap:
            raise BudgetStop(f"${self.spent:.3f} spent; next call could cost up to ${worst:.3f}; cap ${self.cap:.2f}")

    def add(self, c):
        self.spent += c


def call_cost(model, tin, tout):
    p = PRICES[model]
    over = tin > 100_000
    return (tin * (p[2] if over else p[0]) + tout * (p[3] if over else p[1])) / 1e6


def worst_case_cost(model, prompt_chars):
    return call_cost(model, int(prompt_chars / 3 * 1.3) + 2500, MAX_TOKENS)


def check_hyp(out):
    hyps = out.get("hypotheses")
    if not isinstance(hyps, list) or len(hyps) < 2:
        raise ValueError("fewer than 2 hypotheses")
    ids = [h.get("id") for h in hyps]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate hypothesis ids")
    if not isinstance(out.get("predictions"), list):
        raise ValueError("predictions missing")


def check_verify(out):
    if not isinstance(out.get("ratings"), list):
        raise ValueError("ratings missing")


def check_sel(out):
    if not isinstance(out.get("query_id"), str):
        raise ValueError("query_id missing")


class LLM:
    def __init__(self, model, fake=False, budget=None, seed=0):
        if not fake and model not in PRICES:
            sys.exit(f"No price on file for {model}; add it to PRICES so the budget cap works.")
        self.model, self.fake, self.budget = model, fake, budget or Budget(1e9)
        self.seed, self.strict = seed, True
        self.profile = PROFILES.get(model, {"tool_choice": "auto", "thinking": None})
        self.client = None if fake else self._client()

    def _client(self):
        try:
            import anthropic
        except ImportError:
            sys.exit("The 'anthropic' package is missing. Install it with: pip install -r requirements.txt")
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            try:
                key = getpass.getpass("Anthropic API key (input hidden): ").strip()
            except (EOFError, KeyboardInterrupt):
                sys.exit("No API key: set ANTHROPIC_API_KEY or run in an interactive terminal.")
        if not key:
            sys.exit("No API key provided.")
        return anthropic.Anthropic(api_key=key, max_retries=2)

    def describe(self):
        return {"model": "FAKE" if self.fake else self.model, "tool_choice": self.profile["tool_choice"],
                "thinking": self.profile["thinking"] or "not sent (forced tool call => no thinking block)",
                "temperature": "not sent (model default)", "max_tokens": MAX_TOKENS, "strict_tools": self.strict}

    def call(self, prompt, system, tool, fake_fn=None, fake_key=""):
        """Returns (tool_input, meta). Every attempt is charged to the budget."""
        if self.fake:
            rng = random.Random(int(hashlib.sha256(f"{self.seed}|{fake_key}".encode()).hexdigest()[:12], 16))
            return fake_fn(rng), {"fake": True, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        check = {"report_hypotheses": check_hyp, "rate_checks": check_verify}.get(tool["name"], check_sel)
        uin = uout = 0
        cost = 0.0
        last = None
        for attempt in range(1, RETRIES + 1):
            kwargs = dict(model=self.model, max_tokens=MAX_TOKENS, system=system,
                          tools=[{**tool, "strict": True} if self.strict else tool],
                          messages=[{"role": "user", "content": prompt}])
            if self.profile["tool_choice"] == "forced":
                kwargs["tool_choice"] = {"type": "tool", "name": tool["name"]}
            else:
                kwargs["tool_choice"] = {"type": "auto"}
            if self.profile["thinking"]:
                kwargs["thinking"] = {"type": self.profile["thinking"]}
            self.budget.check(worst_case_cost(self.model, len(prompt) + len(json.dumps(tool))))
            try:
                resp = self.client.messages.create(**kwargs)
            except Exception as e:
                last = e
                code = getattr(e, "status_code", None)
                if code == 400 and self.strict and "strict" in str(e).lower():
                    print("    API rejected strict tools; continuing without strict (recorded).", file=sys.stderr)
                    self.strict = False
                    continue
                if code in (400, 401, 403, 404):
                    raise FatalAPIError(f"API rejected the request: {e}")
                print(f"    API error (attempt {attempt}/{RETRIES}): {e}", file=sys.stderr)
                time.sleep(2 ** attempt)
                continue
            uin += resp.usage.input_tokens
            uout += resp.usage.output_tokens
            c = call_cost(self.model, resp.usage.input_tokens, resp.usage.output_tokens)
            cost += c
            self.budget.add(c)
            try:
                if resp.stop_reason in ("max_tokens", "refusal"):
                    raise ValueError(f"stop_reason={resp.stop_reason}")
                block = next((b for b in resp.content if b.type == "tool_use"), None)
                if block is None:
                    raise ValueError("no tool_use block")
                check(block.input)
                return block.input, {"response_id": resp.id, "model_returned": resp.model,
                                     "stop_reason": resp.stop_reason, "attempts": attempt, "strict_tools": self.strict,
                                     "input_tokens": uin, "output_tokens": uout, "cost_usd": round(cost, 6)}
            except ValueError as e:
                last = e
                print(f"    Malformed output (attempt {attempt}/{RETRIES}): {e}", file=sys.stderr)
        err = CallFailed(f"Model call failed after {RETRIES} attempts: {last}")
        err.cost = cost
        raise err


# ------------------------------------------------------------------ offline fakes (harness tests only)

def fake_hyp(view, cand_ids, prev=None):
    """Valid-structured random output. Uses only agent-visible data. Results are meaningless."""
    def fn(rng):
        hyps = prev or [{"id": "H1", "label": "malicious", "description": "fake malicious", "prior": 0.5},
                        {"id": "H2", "label": "benign", "description": "fake benign", "prior": 0.3},
                        {"id": "H3", "label": "benign", "description": "fake benign 2", "prior": 0.2}]
        hyps = [dict(h, prior=rng.random() + 0.1) for h in hyps]
        preds = []
        for q in cand_ids:
            for h in hyps:
                w = [rng.random() ** 3 + 0.02 for _ in view.queries[q].outcomes]
                preds.append({"query_id": q, "hypothesis_id": h["id"],
                              "outcome_probs": [{"outcome": o, "probability": x / sum(w)}
                                                for o, x in zip(view.queries[q].outcomes, w)]})
        return {"hypotheses": hyps, "predictions": preds, "retired": [], "compatible_pairs": []}
    return fn


def fake_sel(cand_ids):
    return lambda rng: {"query_id": rng.choice(sorted(cand_ids)), "rationale": "fake"}


def fake_verify(query_ids):
    return lambda rng: {"ratings": [{"query_id": q, "rating": rng.choice(["decisive", "suggestive", "not_diagnostic"]),
                                     "reason": "fake"} for q in query_ids]}
