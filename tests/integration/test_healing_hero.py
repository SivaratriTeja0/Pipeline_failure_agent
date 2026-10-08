"""Phase 4a: the hero path end to end against FAKE AIRFLOW (DEMO) - LIVE (against the fake) and DRY_RUN."""

from core.models import (
    ActionType,
    ApprovalStatus,
    AuditEventType,
    ExecutionMode,
    ExecutionStatus,
    IncidentState,
    RecoveryScope,
    VerificationDepth,
    VerificationStatus,
)
from core.remediation.audit import verify_audit_chain
from tests.healing_helpers import HERO_HEALING_AUDIT, build, is_subsequence


def test_hero_live_end_to_end_resolves_with_required_audit_sequence():
    h = build()
    assert h.triage.report.remediation_class.value == "AUTOMATABLE"
    assert h.state_of() == "AWAITING_APPROVAL"
    plan = h.plan
    assert plan.action_type is ActionType.RETRY_FAILED_TASK and plan.recovery_scope is RecoveryScope.FAILED_TASK

    out = h.approve("alice")
    assert out.incident_state is IncidentState.RESOLVED
    final = h.plan
    assert final.approval_status is ApprovalStatus.APPROVED and final.approved_by == ["alice"]
    assert final.execution_status is ExecutionStatus.SUCCESS and final.executed is True
    assert final.verification_status is VerificationStatus.VERIFIED
    assert final.verification_depth is VerificationDepth.STATE_ONLY
    assert "State-only verification" in final.verification_result["caveat"]
    assert is_subsequence(HERO_HEALING_AUDIT, h.audit_types())
    assert h.audit.verify().valid


def test_hero_request_log_executed_set_equals_approved_set_equals_live_set():
    h = build()
    approved = sorted(t.task_id for t in h.plan.task_instances_to_clear)
    h.approve("alice")
    posts = h.state.mutating_requests()
    assert [r.body["dry_run"] for r in posts] == [True, False]   # Airflow's own listing first, then one clear
    clear = h.clears()
    assert len(clear) == 1 and clear[0].path == "/api/v1/dags/sales_etl/clearTaskInstances"
    assert sorted(clear[0].body["task_ids"]) == approved == ["load", "publish"]
    assert clear[0].body["only_failed"] is True and clear[0].body["include_downstream"] is False
    assert "extract" not in clear[0].body["task_ids"]             # tasks in success are never cleared
    assert all(r.path.endswith("/clearTaskInstances") for r in posts)  # no trigger / pause / mark / delete


def test_every_state_transition_is_audited_in_the_chain():
    h = build()
    h.approve("alice")
    events = h.audit.events(h.incident_id)
    transitions = [(e.payload["from"], e.payload["to"]) for e in events
                   if e.event_type is AuditEventType.INCIDENT_STATE_CHANGED]
    assert transitions == [
        ("DETECTED", "INVESTIGATING"), ("INVESTIGATING", "DIAGNOSED"), ("DIAGNOSED", "PLAN_PROPOSED"),
        ("PLAN_PROPOSED", "AWAITING_APPROVAL"), ("AWAITING_APPROVAL", "APPROVED"), ("APPROVED", "POLICY_VALIDATING"),
        ("POLICY_VALIDATING", "REVALIDATING"), ("REVALIDATING", "EXECUTING"), ("EXECUTING", "VERIFYING"),
        ("VERIFYING", "RESOLVED")]
    assert verify_audit_chain(h.audit.events()).valid


def test_hero_dry_run_makes_zero_mutating_calls():
    h = build(mode=ExecutionMode.DRY_RUN, demo_auth=True)
    out = h.approve("demo-engineer")
    assert out.execution.outcome == "DRY_RUN"
    assert h.state.mutating_requests() == []                       # not even the dry-run listing POST
    plan = h.plan
    assert plan.execution_status is ExecutionStatus.NOT_EXECUTED and plan.executed is False
    assert plan.execution_result["dispatched"] is False
    assert plan.execution_result["dry_run_listing"] == ["load (try 1, failed)", "publish (try 0, upstream_failed)"]
    types = h.audit_types()
    assert is_subsequence(HERO_HEALING_AUDIT[:14] + ["EXECUTION_DRY_RUN"], types)
    assert "EXECUTION_DISPATCHED" not in types
    assert h.state_of() == "ESCALATED"                              # a human decides what happens next


def test_default_configuration_never_heals():
    # Rule 6 defaults: HEALING_ENABLED=false, pipeline healing_enabled=false, DRY_RUN.
    h = build(mode=ExecutionMode.DRY_RUN, demo_auth=True, healing_enabled=False, pipeline_healing=False)
    assert h.settings.healing_execution_mode is ExecutionMode.DRY_RUN
    out = h.approve("demo-engineer")
    assert out.execution.outcome == "BLOCKED"
    assert "HEALING_ENABLED=false" in out.execution.detail and "healing_enabled=false" in out.execution.detail
    assert h.state.mutating_requests() == [] and h.state_of() == "BLOCKED"
    assert "POLICY_BLOCKED" in h.audit_types()


def test_dag_run_retry_with_two_independent_failures_needs_two_approvers():
    h = build("multi_failure")
    plan = h.plan
    assert plan.action_type is ActionType.RETRY_FAILED_DAG_RUN and plan.recovery_scope is RecoveryScope.FAILED_DAG_RUN
    assert plan.risk_level.value == "HIGH" and plan.target.task_id is None
    assert sorted(t.task_id for t in plan.task_instances_to_clear) == [
        "extract_customers", "extract_orders", "merge", "publish"]

    first = h.approve("alice")
    assert not first.approval.complete and first.approval.required == 2
    assert h.state_of() == "AWAITING_APPROVAL" and h.clears() == []
    assert "APPROVAL_RECORDED" in h.audit_types() and "APPROVAL_GRANTED" not in h.audit_types()

    second = h.approve("bob")
    assert second.incident_state is IncidentState.RESOLVED
    assert sorted(h.plan.approved_by) == ["alice", "bob"]
    assert sorted(h.clears()[0].body["task_ids"]) == ["extract_customers", "extract_orders", "merge", "publish"]
