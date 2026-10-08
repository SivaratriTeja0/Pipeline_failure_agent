"""Outcome verification (spec L9). Read-only polling after a confirmed LIVE dispatch.

VERIFIED          every enumerated instance reached success and the run reached success.
RECOVERY_FAILED   an enumerated instance failed again (new try, or failed after being reset),
                  or the run failed again.
INCONCLUSIVE      still running or unreadable at the timeout. The window is extended once, then
                  the incident is escalated. INCONCLUSIVE never closes an incident.

Depth is STATE_ONLY unless the platform exposes data-quality / row-count reads and they were
checked. A task reaching success does not prove the data is correct (documented V1 limitation).
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from adapters.base.interfaces import AdapterError, PipelineAdapter
from core.config import Settings
from core.evidence.conventions import DQ_RESULT
from core.models.base import utcnow
from core.models.enums import ReadCapability, VerificationDepth, VerificationStatus
from core.models.reads import ReadRequest, ReadStatus
from core.models.remediation import RemediationPlan
from core.remediation.selector import CLEARABLE_STATES, FAILED

STATE_ONLY_CAVEAT = ("State-only verification: the task instances and run reached success, which does not "
                     "prove the data they produced is correct.")


class VerificationResult(BaseModel):
    status: VerificationStatus
    depth: VerificationDepth = VerificationDepth.STATE_ONLY
    polls: int = 0
    extended: bool = False
    detail: str = ""
    observed: list[dict[str, Any]] = Field(default_factory=list)
    data_checks: list[str] = Field(default_factory=list)

    def as_record(self) -> dict[str, Any]:
        record = self.model_dump(mode="json")
        if self.depth is VerificationDepth.STATE_ONLY:
            record["caveat"] = STATE_ONLY_CAVEAT
        return record


class Verifier:
    def __init__(self, adapter: PipelineAdapter, settings: Settings, *,
                 clock: Callable[[], datetime] = utcnow, sleep: Callable[[float], None]) -> None:
        self._adapter = adapter
        self._settings = settings
        self._clock = clock
        self._sleep = sleep

    def verify(self, plan: RemediationPlan, on_extend: Callable[[str], None] | None = None) -> VerificationResult:
        if plan.target is None:
            return VerificationResult(status=VerificationStatus.INCONCLUSIVE, detail="plan has no target")
        refs = {t.key: t for t in plan.task_instances_to_clear}
        seen_reset: set[tuple[str, int]] = set()
        polls = 0
        extended = False
        deadline = self._clock() + timedelta(seconds=self._settings.verify_timeout_seconds)
        last_detail = "no successful read yet"
        observed: list[dict[str, Any]] = []

        while True:
            polls += 1
            try:
                snapshot = self._adapter.get_run_snapshot(plan.target.dag_id, plan.target.dag_run_id)
            except AdapterError as exc:
                snapshot, last_detail = None, f"state unreadable: {exc}"
            if snapshot is not None and snapshot.run_state is not None:
                live = {ti.key: ti for ti in snapshot.task_instances}
                observed = [{"task_id": k[0], "map_index": k[1], "state": ti.state, "try_number": ti.try_number}
                            for k, ti in live.items() if k in refs]
                failed_again = []
                for key, ref in refs.items():
                    ti = live.get(key)
                    if ti is None:
                        continue
                    if ti.state not in CLEARABLE_STATES:
                        seen_reset.add(key)
                    elif (ti.state == FAILED and (ti.try_number or 0) > ref.try_number) or key in seen_reset:
                        failed_again.append(f"{ref.task_id}[{ref.map_index}] {ti.state} (try {ti.try_number})")
                if failed_again:
                    return VerificationResult(status=VerificationStatus.RECOVERY_FAILED, polls=polls,
                                              extended=extended, observed=observed,
                                              detail="failed again: " + ", ".join(failed_again))
                all_success = all(live.get(k) is not None and live[k].state == "success" for k in refs)
                if snapshot.run_state == "failed" and seen_reset:
                    return VerificationResult(status=VerificationStatus.RECOVERY_FAILED, polls=polls,
                                              extended=extended, observed=observed,
                                              detail="the run failed again after the clear")
                if all_success and snapshot.run_state == "success":
                    return self._data_checks(plan, polls, extended, observed)
                last_detail = f"run {snapshot.run_state}; enumerated instances not all success yet"

            if self._clock() >= deadline:
                if extended:
                    return VerificationResult(status=VerificationStatus.INCONCLUSIVE, polls=polls, extended=True,
                                              observed=observed, detail=f"timeout after one extension: {last_detail}")
                extended = True
                deadline = self._clock() + timedelta(seconds=self._settings.verify_timeout_seconds)
                if on_extend:
                    on_extend(last_detail)
            self._sleep(self._settings.verify_poll_seconds)

    def _data_checks(self, plan: RemediationPlan, polls: int, extended: bool,
                     observed: list[dict[str, Any]]) -> VerificationResult:
        capabilities = self._adapter.read_capabilities()
        checks: list[str] = []
        target = plan.target
        if target is not None and capabilities & {ReadCapability.DATA_QUALITY, ReadCapability.ROW_COUNTS}:
            req = ReadRequest(pipeline_id=target.dag_id, execution_id=target.dag_run_id,
                              task_id=target.task_id, investigation_cycle=plan.investigation_cycle)
            for read in (self._adapter.get_data_quality_results(req), self._adapter.get_row_counts(req)):
                if read.status is not ReadStatus.AVAILABLE:
                    continue
                checks.append(read.tool)
                for item in read.evidence:
                    dq = item.metadata.get(DQ_RESULT)
                    if isinstance(dq, dict) and dq.get("gate_failed") is True:
                        return VerificationResult(status=VerificationStatus.RECOVERY_FAILED,
                                                  depth=VerificationDepth.STATE_AND_DATA_CHECKS, polls=polls,
                                                  extended=extended, observed=observed, data_checks=checks,
                                                  detail="state reached success but a data-quality gate failed")
        depth = VerificationDepth.STATE_AND_DATA_CHECKS if checks else VerificationDepth.STATE_ONLY
        return VerificationResult(status=VerificationStatus.VERIFIED, depth=depth, polls=polls, extended=extended,
                                  observed=observed, data_checks=checks,
                                  detail="enumerated task instances and the run reached success")
