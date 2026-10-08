"""Deterministic remediation-plan construction.

Everything executable (action, scope, target, task list, parameters, preconditions, risk) comes
from deterministic inputs. The only free text accepted is the rationale, expected effect and
condition wording, which the LLM planner may supply and which cannot alter the plan's structure.
"""

from datetime import datetime, timedelta

from core.models.enums import ConfidenceLevel, ExecutionMode, RemediationClass, RerunSafety
from core.models.reasoning import BasisCondition, Claim, RuleEvaluation
from core.models.remediation import PlanCondition, PlanParameters, Precondition, RemediationPlan
from core.remediation.risk import ROLLBACK_DESCRIPTION, compute_risk_level
from core.remediation.selector import SelectionResult

_MAX_TEXT = 2000


def _clip(text: str) -> str:
    return text.strip()[:_MAX_TEXT]


def default_expected_effect(selection: SelectionResult) -> str:
    tasks = ", ".join(f"{t.task_id}" + (f"[{t.map_index}]" if t.map_index is not None else "")
                      for t in selection.task_instances_to_clear)
    return (f"Clear {len(selection.task_instances_to_clear)} failed task instance(s) ({tasks}) in the existing "
            f"run {selection.target.dag_run_id if selection.target else '?'}; the scheduler re-runs them. "
            "No new run is created.")


# Machine-checkable preconditions the live-state re-validation knows how to check. A plan carrying
# any other precondition cannot be re-validated and is therefore blocked (fail closed).
PRECONDITION_CHECKS = frozenset({
    "run_state_failed", "task_instances_unchanged", "live_set_equals_plan", "no_forbidden_concurrent_run",
    "rerun_safety_still_permits",
})


def build_preconditions(selection: SelectionResult) -> list[Precondition]:
    pre = [
        Precondition(check="run_state_failed", description="The run is still in the failed state"),
        Precondition(check="task_instances_unchanged",
                     description="Every enumerated task instance is still in its observed state and try number"),
        Precondition(check="live_set_equals_plan",
                     description="The live set of failed/upstream_failed instances equals the enumerated list"),
        Precondition(check="no_forbidden_concurrent_run",
                     description="No newer or overlapping active run that the task's concurrency policy forbids"),
        Precondition(check="rerun_safety_still_permits",
                     description="Rerun safety recomputed from fresh state still permits the action"),
    ]
    return pre


def build_plan(
    *,
    remediation_id: str,
    incident_id: str,
    investigation_cycle: int,
    selection: SelectionResult,
    reason: Claim,
    supporting_evidence_ids: list[str],
    cause_cleared_evidence_ids: list[str],
    remediation_confidence: ConfidenceLevel,
    remediation_confidence_basis: list[BasisCondition],
    rerun_safety: RerunSafety,
    rerun_safety_rule_trace: list[RuleEvaluation],
    conditions: list[PlanCondition],
    environment: str | None,
    execution_mode: ExecutionMode,
    now: datetime,
    approval_ttl_minutes: int,
    expected_effect: str | None = None,
    condition_text: dict[str, str] | None = None,
) -> RemediationPlan:
    if not selection.selected or selection.action_type is None or selection.recovery_scope is None:
        raise ValueError("cannot build an executable plan without a deterministic selection")
    texts = condition_text or {}
    worded = [c.model_copy(update={"text": _clip(texts[c.condition_id])}) if texts.get(c.condition_id, "").strip()
              else c for c in conditions]
    return RemediationPlan(
        remediation_id=remediation_id,
        incident_id=incident_id,
        investigation_cycle=investigation_cycle,
        remediation_class=RemediationClass.AUTOMATABLE,
        action_type=selection.action_type,
        recovery_scope=selection.recovery_scope,
        target=selection.target,
        task_instances_to_clear=selection.task_instances_to_clear,
        parameters=PlanParameters(dry_run=execution_mode is ExecutionMode.DRY_RUN),
        reason=reason,
        supporting_evidence_ids=sorted(set(supporting_evidence_ids)),
        cause_cleared_evidence_ids=sorted(set(cause_cleared_evidence_ids)),
        remediation_confidence=remediation_confidence,
        remediation_confidence_basis=remediation_confidence_basis,
        rerun_safety=rerun_safety,
        rerun_safety_rule_trace=rerun_safety_rule_trace,
        preconditions=build_preconditions(selection),
        conditions=worded,
        risk_level=compute_risk_level(environment, selection.recovery_scope),
        expected_effect=_clip(expected_effect) if expected_effect else default_expected_effect(selection),
        rollback_description=ROLLBACK_DESCRIPTION,
        expires_at=now + timedelta(minutes=approval_ttl_minutes),
        execution_mode=execution_mode,
    )
