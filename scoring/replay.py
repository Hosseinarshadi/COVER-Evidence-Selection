"""Simulated telemetry replay. Executing a catalog check returns the researcher's reference outcome.

This is the only path by which the runtime can learn a result, and only for a query it has chosen to run.
It is SIMULATED evidence (source='simulated_replay_of_reference_map'), not live log data.
Failures are ExecutionError objects, never a 'no_hit' observation (acceptance test 8).
"""
from cover.feasibility import check
from cover.models import ExecutionError, Observation
from cover.trace import now


class Replay:
    def __init__(self, key_by_id):
        self._key = key_by_id

    def execute(self, view, query_id, executed_ids=(), unavailable=(), query_text=None):
        ok, reason, kind = check(view, query_id, executed_ids, unavailable, query_text)
        if not ok:
            return ExecutionError(query_id=str(query_id), error=reason, kind=kind, timestamp_utc=now())
        outcome = self._key[view.id]["queries"][query_id]["reference_outcome"]
        return Observation(query_id=query_id, outcome=outcome, timestamp_utc=now())
