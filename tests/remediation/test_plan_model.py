"""RemediationPlan (C9): approval always required, server-side hashing, invariants."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from core.models import (
    HASHED_FIELDS,
    ActionType,
    ApprovalStatus,
    ConfidenceLevel,
    ExecutionMode,
    ExecutionStatus,
    PlanParameters,
    PlanTarget,
    Precondition,
    RecoveryScope,
    RemediationClass,
    RemediationPlan,
    RerunSafety,
    RiskLevel,
    TaskInstanceRef,
    compute_plan_hash,
)
from core.remediation.hashing import PlanRevisionError, revise_plan, verify_plan_hash
from tests.factories import automatable_plan, condition


# ---------------------------------------------------------------- approval always required


def test_requires_approval_false_is_rejected():
    with pytest.raises(ValidationError, match="requires_approval"):
        automatable_plan(requires_approval=False)


def test_requires_approval_false_rejected_via_model_validate_too():
    data = automatable_plan().model_dump()
    data["requires_approval"] = False
    with pytest.raises(ValidationError):
        RemediationPlan.model_validate(data)


# ---------------------------------------------------------------- hashing


def test_hash_is_computed_server_side_and_client_value_discarded():
    plan = automatable_plan(plan_hash="f" * 64)
    assert plan.plan_hash != "f" * 64
    assert plan.plan_hash == compute_plan_hash(plan)
    assert len(plan.plan_hash) == 64


def test_derived_executed_flag_cannot_be_injected():
    plan = automatable_plan(executed=True)
    assert plan.executed is False
    live_confirmed = automatable_plan(execution_mode=ExecutionMode.LIVE, dispatch_confirmed=True)
    assert live_confirmed.executed is True
    dry = automatable_plan(execution_mode=ExecutionMode.DRY_RUN, dispatch_confirmed=True)
    assert dry.executed is False


def test_hashed_fields_match_spec():
    assert set(HASHED_FIELDS) == {
        "incident_id", "investigation_cycle", "action_type", "recovery_scope", "target",
        "task_instances_to_clear", "parameters", "preconditions", "conditions", "risk_level",
        "supporting_evidence_ids", "cause_cleared_evidence_ids", "rerun_safety",
        "remediation_confidence", "execution_mode",
    }


_DAG_RUN_TASKS = [TaskInstanceRef(task_id="a", try_number=1, observed_state="failed"),
                  TaskInstanceRef(task_id="b", try_number=1, observed_state="failed")]

# One modification per hashed field; each must produce a valid plan with a different hash.
HASH_MUTATIONS = {
    "incident_id": {"incident_id": "inc-2"},
    "investigation_cycle": {"investigation_cycle": 2},
    "action_type": {"action_type": ActionType.RETRY_FAILED_DAG_RUN,
                    "recovery_scope": RecoveryScope.FAILED_DAG_RUN,
                    "target": PlanTarget(dag_id="sales_etl", dag_run_id="scheduled__2026-10-08T00:00:00+00:00"),
                    "task_instances_to_clear": _DAG_RUN_TASKS},
    "recovery_scope": {"action_type": ActionType.RETRY_FAILED_DAG_RUN,
                       "recovery_scope": RecoveryScope.FAILED_DAG_RUN,
                       "target": PlanTarget(dag_id="sales_etl", dag_run_id="scheduled__2026-10-08T00:00:00+00:00")},
    "target": {"target": PlanTarget(dag_id="sales_etl", dag_run_id="manual__2", task_id="load")},
    "task_instances_to_clear": {"task_instances_to_clear": [
        TaskInstanceRef(task_id="load", try_number=1, observed_state="failed")]},
    "parameters": {"parameters": PlanParameters(include_downstream=True)},
    "preconditions": {"preconditions": [Precondition(check="other", description="d")]},
    "conditions": {"conditions": [condition()]},
    "risk_level": {"risk_level": RiskLevel.HIGH},
    "supporting_evidence_ids": {"supporting_evidence_ids": ["ev-1", "ev-9"]},
    "cause_cleared_evidence_ids": {"cause_cleared_evidence_ids": ["ev-4"]},
    "rerun_safety": {"rerun_safety": RerunSafety.SAFE_WITH_CONDITIONS},
    "remediation_confidence": {"remediation_confidence": ConfidenceLevel.MEDIUM},
    "execution_mode": {"execution_mode": ExecutionMode.LIVE},
}


def test_every_hashed_field_has_a_mutation_case():
    assert set(HASH_MUTATIONS) == set(HASHED_FIELDS)


@pytest.mark.parametrize("field", sorted(HASH_MUTATIONS))
def test_plan_hash_changes_with_every_hashed_field(field):
    base = automatable_plan()
    changed = automatable_plan(**HASH_MUTATIONS[field])
    assert changed.plan_hash != base.plan_hash, field


@pytest.mark.parametrize(
    "change",
    [{"expected_effect": "different text"}, {"rollback_description": "x"},
     {"approval_status": ApprovalStatus.APPROVED}, {"plan_version": 7}],
)
def test_non_hashed_fields_do_not_change_hash(change):
    assert automatable_plan(**change).plan_hash == automatable_plan().plan_hash


def test_hash_is_order_independent_for_id_lists_and_task_lists():
    a = automatable_plan(supporting_evidence_ids=["ev-1", "ev-2"])
    b = automatable_plan(supporting_evidence_ids=["ev-2", "ev-1"],
                         task_instances_to_clear=list(reversed(automatable_plan().task_instances_to_clear)))
    assert a.plan_hash == b.plan_hash


def test_in_place_mutation_is_detected_by_recompute():
    plan = automatable_plan()
    recorded = plan.plan_hash
    plan.task_instances_to_clear = [TaskInstanceRef(task_id="other", try_number=1, observed_state="failed")]
    assert not plan.hash_is_current()
    assert not verify_plan_hash(plan, recorded)


def test_verify_plan_hash_ignores_stored_hash_on_the_object():
    plan = automatable_plan()
    object.__setattr__(plan, "plan_hash", "0" * 64)
    assert verify_plan_hash(plan, compute_plan_hash(plan))
    assert not verify_plan_hash(plan, "0" * 64)


# ---------------------------------------------------------------- revision voids approvals (I5)


def test_revision_bumps_version_changes_hash_and_voids_approval():
    approved = automatable_plan(approval_status=ApprovalStatus.APPROVED, approved_by=["alice"])
    revised = revise_plan(approved, risk_level=RiskLevel.HIGH)
    assert revised.plan_version == approved.plan_version + 1
    assert revised.plan_hash != approved.plan_hash
    assert revised.approval_status is ApprovalStatus.PENDING
    assert revised.approved_by == []


def test_revision_cannot_set_hash_or_identity():
    with pytest.raises(PlanRevisionError):
        revise_plan(automatable_plan(), plan_hash="a" * 64)
    with pytest.raises(PlanRevisionError):
        revise_plan(automatable_plan(), incident_id="other")


# ---------------------------------------------------------------- invariants


def test_automatable_requires_cause_cleared_evidence():
    with pytest.raises(ValidationError, match="cause_cleared"):
        automatable_plan(cause_cleared_evidence_ids=[])


def test_low_remediation_confidence_cannot_be_automatable():
    with pytest.raises(ValidationError, match="LOW"):
        automatable_plan(remediation_confidence=ConfidenceLevel.LOW)


@pytest.mark.parametrize("safety", [RerunSafety.UNSAFE, RerunSafety.UNKNOWN])
def test_unsafe_or_unknown_rerun_safety_cannot_be_automatable(safety):
    with pytest.raises(ValidationError):
        automatable_plan(rerun_safety=safety)


def test_scope_must_match_action():
    with pytest.raises(ValidationError, match="does not match"):
        automatable_plan(recovery_scope=RecoveryScope.FAILED_DAG_RUN)


def test_failed_dag_run_scope_has_no_task_target():
    with pytest.raises(ValidationError):
        automatable_plan(action_type=ActionType.RETRY_FAILED_DAG_RUN, recovery_scope=RecoveryScope.FAILED_DAG_RUN)


def test_only_two_action_types_and_two_scopes_exist():
    assert {a.value for a in ActionType} == {"RETRY_FAILED_TASK", "RETRY_FAILED_DAG_RUN"}
    assert {s.value for s in RecoveryScope} == {"FAILED_TASK", "FAILED_DAG_RUN"}


def test_success_task_instances_cannot_be_enumerated():
    with pytest.raises(ValidationError):
        TaskInstanceRef(task_id="t", try_number=1, observed_state="success")


def test_only_failed_parameter_is_fixed_true():
    with pytest.raises(ValidationError):
        PlanParameters(only_failed=False)


def test_unsafe_ids_rejected_in_target():
    with pytest.raises(ValidationError):
        PlanTarget(dag_id="../../admin", dag_run_id="r1")
    with pytest.raises(ValidationError):
        PlanTarget(dag_id="ok", dag_run_id="r1?x=1")


def test_duplicate_task_instances_rejected():
    ti = TaskInstanceRef(task_id="load", try_number=1, observed_state="failed")
    with pytest.raises(ValidationError, match="duplicates"):
        automatable_plan(task_instances_to_clear=[ti, ti])


@pytest.mark.parametrize(
    "cls", [RemediationClass.MANUAL_FIX_REQUIRED, RemediationClass.NO_ACTION_REQUIRED, RemediationClass.BLOCKED]
)
def test_non_automatable_plans_carry_no_action(cls):
    with pytest.raises(ValidationError, match="no action_type"):
        automatable_plan(remediation_class=cls)
    manual = automatable_plan(remediation_class=cls, action_type=None, recovery_scope=None, target=None,
                              task_instances_to_clear=[], cause_cleared_evidence_ids=[],
                              remediation_confidence=ConfidenceLevel.LOW, rerun_safety=RerunSafety.UNKNOWN)
    assert manual.action_type is None and not manual.executed


def test_non_automatable_plan_can_never_be_in_an_execution_status():
    with pytest.raises(ValidationError, match="never be executed"):
        automatable_plan(remediation_class=RemediationClass.MANUAL_FIX_REQUIRED, action_type=None,
                         recovery_scope=None, target=None, task_instances_to_clear=[],
                         execution_status=ExecutionStatus.QUEUED)


def test_expiry_must_be_timezone_aware():
    from datetime import datetime

    with pytest.raises(ValidationError):
        automatable_plan(expires_at=datetime(2026, 1, 1))
    automatable_plan(expires_at=automatable_plan().expires_at + timedelta(minutes=1))
