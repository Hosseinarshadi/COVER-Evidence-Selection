"""Feasibility and safety gate (protocol rule 1). Runs before any recommendation or execution.

In this harness an evidence check is a catalog item (description + outcome set), not live SQL/Sigma.
The safety gate still rejects mutating or escaping text so the same contract holds when a real
SQL/Sigma backend is plugged in.
"""
import re

UNSAFE = re.compile(r"\b(DELETE|UPDATE|DROP|INSERT|ALTER|TRUNCATE|GRANT|REVOKE|EXEC|MERGE|CREATE)\b"
                    r"|;|\.\./|~/|\brm\s+-|`|\$\(|\|\s*sh\b|>\s*/", re.I)


def check(view, query_id, executed_ids=(), unavailable=(), query_text=None):
    """Return (feasible: bool, reason: str, kind: str|None)."""
    if query_id not in view.queries:
        return False, f"{query_id} is not in the case's query catalog", "unknown_query"
    text = query_text if query_text is not None else view.queries[query_id].description
    if UNSAFE.search(text or ""):
        return False, "query text contains a mutating or escaping construct; refused before execution", "unsafe_query"
    if query_id in unavailable:
        return False, "required telemetry is unavailable (simulated visibility constraint)", "telemetry_unavailable"
    if query_id in executed_ids:
        return False, "already executed in this investigation", "already_executed"
    return True, "catalog check; read-only; telemetry available in the replay", None
