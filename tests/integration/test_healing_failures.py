"""Phase 4c: failure handling - recovery failure and re-investigation, uncertain dispatch and
reconciliation, startup reconciliation, verification outcomes, the manual-fix attestation loop,
and the remaining Part R scenarios (partial write, concurrency)."""

import json

import pytest

from actions.approval.service import ForbiddenError, PlanStateError
from agent.mock_llm import scripted_triage
from core.models import (
    ExecutionStatus,
    IncidentState,
    Reliability,
    RemediationClass,
    RerunSafety,
    TaskExecutionPolicy,
    TaskType,
    TemporalLabel,
    VerificationStatus,
    WriteMode,
)
from core.models.enums import StateMechanism
from core.taxonomy import FailureCategory
from demo.scenarios.registrations import SALES_ETL
from tests.healing_helpers import HERO_RUN, build
from tests.triage_helpers import default_conclusion_turn


# ---------------------------------------------------------------- RECOVERY_FAILED -> re-investigate -> ESCALATED


def test_recovery_failure_reinvestigates_then_escalates_at_max_cycles():
    h = build(clear_behavior="fail_again", mutate=lambda s: setattr(s, "post_failure_pool_success", True))
    first = h.approve("alice")
    assert first.execution.verification.status is VerificationStatus.RECOVERY_FAILED
    cycle2 = first.reinvestigation
    assert cycle2 is not None and h.state_of() == "AWAITING_APPROVAL"
    report = cycle2.report
    assert report.investigation_cycles[-1].cycle == 2 and report.attempt_number == 2
    assert cycle2.investigation.calls_used <= 5                                   # its own 5-call budget
    assert any(e.temporal_label is TemporalLabel.HISTORICAL and e.provenance.investigation_cycle == 1
               for e in report.evidence)                                          # earlier cycle kept as HISTORICAL
    plan2 = cycle2.plan
    assert plan2 is not None and plan2.remediation_id != first.execution.plan.remediation_id
    assert plan2.investigation_cycle == 2 and plan2.task_instances_to_clear[0].try_number == 2

    second = h.approve("alice", plan=h.store.get_plan(plan2.remediation_id))
    assert second.execution.verification.status is VerificationStatus.RECOVERY_FAILED
    assert second.incident_state is IncidentState.ESCALATED and h.state_of() == "ESCALATED"
    assert len(h.clears()) == 2                                                   # never retry, retry, retry
    assert "INCIDENT_ESCALATED" in h.audit_types() and h.audit_types().count("VERIFICATION_FAILED") == 2
    assert h.audit.verify().valid


def test_identical_failed_action_is_not_reproposed_without_new_evidence():
    h = build(clear_behavior="fail_again")      # no later success on the shared pool after the new failure
    out = h.approve("alice")
    cycle2 = out.reinvestigation
    assert cycle2 is not None and cycle2.plan is None
    assert "identical action already failed" in cycle2.selection.block_reason
    assert cycle2.report.remediation_class is RemediationClass.MANUAL_FIX_REQUIRED   # cause not shown cleared
    assert h.state_of() == "MANUAL_FIX_REQUIRED" and len(h.clears()) == 1


def test_max_healing_cycles_one_escalates_after_the_first_failure():
    h = build(clear_behavior="fail_again", env={"MAX_HEALING_CYCLES": "1"},
              mutate=lambda s: setattr(s, "post_failure_pool_success", True))
    out = h.approve("alice")
    assert out.incident_state is IncidentState.ESCALATED and out.reinvestigation is None
    assert len(h.clears()) == 1


# ---------------------------------------------------------------- UNCERTAIN dispatch


def test_uncertain_dispatch_is_reconciled_from_state_and_never_resent():
    h = build(fault="timeout")
    out = h.approve("alice")
    assert len(h.clears()) == 1                                                   # no resend after UNCERTAIN
    types = h.audit_types()
    assert {"EXECUTION_UNCERTAIN", "RECONCILIATION_STARTED", "RECONCILIATION_COMPLETED"} <= set(types)
    assert "EXECUTION_DISPATCHED" not in types
    assert out.incident_state is IncidentState.RESOLVED
    assert h.plan.dispatch_confirmed and h.plan.verification_status is VerificationStatus.VERIFIED


def test_uncertain_dispatch_with_unreadable_state_escalates_without_resend():
    h = build(fault="timeout_then_down")
    out = h.approve("alice")
    assert out.execution.outcome == "UNCERTAIN_ESCALATED" and h.state_of() == "ESCALATED"
    assert h.plan.execution_status is ExecutionStatus.UNCERTAIN and not h.plan.executed
    assert len(h.clears()) == 1
    reads = [r for r in h.state.request_log if r.method == "GET"]
    assert reads  # it tried to reconcile by reading, and only by reading


def test_connection_refused_at_dispatch_is_blocked_nothing_sent():
    h = build(fault="connect_refused")
    out = h.approve("alice")
    assert out.execution.outcome == "BLOCKED" and h.plan.execution_status is ExecutionStatus.BLOCKED
    assert h.clears() == []


# ---------------------------------------------------------------- startup reconciliation


class Crash(BaseException):
    """Simulates the process dying mid-execution (not an Exception: nothing catches it)."""


def _crash_during_dispatch(h, *, after_airflow_applied: bool):
    backend = h.orch._executor._backend
    real = backend.dispatch

    def dying(plan):
        if after_airflow_applied:
            real(plan)
        raise Crash()

    backend.dispatch = dying
    with pytest.raises(Crash):
        h.approve("alice")
    backend.dispatch = real
    assert h.plan.execution_status is ExecutionStatus.RUNNING


def test_startup_reconciles_a_crash_after_dispatch_without_resending():
    h = build()
    _crash_during_dispatch(h, after_airflow_applied=True)
    reports = h.orch.startup()
    assert len(reports) == 1 and h.state_of() == "RESOLVED"
    assert len(h.clears()) == 1


def test_startup_reconciles_a_crash_before_dispatch_and_escalates():
    h = build()
    _crash_during_dispatch(h, after_airflow_applied=False)
    h.orch.startup()
    assert h.state_of() == "ESCALATED" and h.plan.execution_status is ExecutionStatus.UNCERTAIN
    assert h.clears() == []                       # never re-dispatched; a human decides
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "REFUSED"


# ---------------------------------------------------------------- verification outcomes


@pytest.mark.parametrize("behavior", ["running", "stuck"])
def test_inconclusive_verification_extends_once_then_escalates(behavior):
    h = build(clear_behavior=behavior)
    out = h.approve("alice")
    v = out.execution.verification
    assert v.status is VerificationStatus.INCONCLUSIVE and v.extended
    assert out.incident_state is IncidentState.ESCALATED
    assert h.audit_types().count("VERIFICATION_INCONCLUSIVE") == 2   # extension notice + final result
    assert len(h.clears()) == 1


# ---------------------------------------------------------------- double submit / write-ahead


def test_double_submit_dispatches_once():
    h = build()
    h.approve("alice")
    again = h.orch.execute(h.plan.remediation_id)
    assert again.execution.outcome == "REFUSED"
    assert len(h.clears()) == 1


def test_dry_run_cannot_be_replayed_and_consumes_the_approval():
    from core.models import ExecutionMode

    h = build(mode=ExecutionMode.DRY_RUN, demo_auth=True)
    h.approve("demo-engineer")
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "REFUSED"
    assert all(r.consumed for r in h.store.approvals_for(h.plan.remediation_id))
    assert h.state.mutating_requests() == []


# ---------------------------------------------------------------- limits (I11)


def test_tasks_cleared_limit_blocks():
    h = build(env={"MAX_TASKS_CLEARED": "1"})
    out = h.approve("alice")
    assert out.execution.outcome == "BLOCKED" and "tasks_cleared_limit" in out.execution.detail
    assert h.clears() == []


def test_dag_action_rate_limit_blocks():
    h = build(clear_behavior="fail_again", env={"MAX_ACTIONS_PER_DAG_PER_HOUR": "1", "MAX_HEALING_CYCLES": "3"},
              mutate=lambda s: setattr(s, "post_failure_pool_success", True))
    first = h.approve("alice")
    plan2 = first.reinvestigation.plan
    out = h.approve("alice", plan=h.store.get_plan(plan2.remediation_id))
    assert out.execution.outcome == "BLOCKED" and "dag_action_rate" in out.execution.detail
    assert len(h.clears()) == 1


# ---------------------------------------------------------------- manual-fix attestation loop (scenario 9)


def test_schema_drift_manual_fix_attested_then_rerun_after_approval():
    h = build("schema_drift")
    assert h.triage.report.failure_category is FailureCategory.SOURCE_SCHEMA_DRIFT
    assert h.triage.report.remediation_class is RemediationClass.MANUAL_FIX_REQUIRED and h.triage.plan is None
    assert h.state_of() == "MANUAL_FIX_REQUIRED"

    with pytest.raises(ForbiddenError):
        h.orch.fix_applied(h.incident_id, h.who("victor"), "viewer cannot attest")
    with pytest.raises(ForbiddenError):
        h.orch.fix_applied(h.incident_id, h.who("triage-bot"), "service cannot attest")
    h.clock.advance(600)
    result = h.orch.fix_applied(h.incident_id, h.who("erin"), "Added amount_usd back to crm.orders view")
    attestation = next(e for e in result.report.evidence if e.provenance.tool == "fix_applied")
    assert attestation.reliability is Reliability.MEDIUM and attestation.temporal_label is TemporalLabel.CURRENT
    assert result.plan is not None and result.plan.cause_cleared_evidence_ids == [attestation.evidence_id]
    assert result.report.remediation_confidence.value == "MEDIUM"      # an attestation is not proof
    assert h.state_of() == "AWAITING_APPROVAL" and h.clears() == []    # still needs explicit approval
    assert "FIX_APPLIED" in h.audit_types()

    out = h.approve("alice", plan=h.store.get_plan(result.plan.remediation_id))
    assert out.incident_state is IncidentState.RESOLVED and len(h.clears()) == 1


def test_fix_can_only_be_attested_for_manual_fix_incidents():
    h = build()
    with pytest.raises(PlanStateError):
        h.orch.fix_applied(h.incident_id, h.who("erin"), "nothing to fix")


def test_manual_close_requires_engineer_and_note():
    h = build("schema_drift")
    with pytest.raises(ForbiddenError):
        h.orch.manual_close(h.incident_id, h.who("victor"), "done")
    with pytest.raises(PlanStateError):
        h.orch.manual_close(h.incident_id, h.who("erin"), "")
    assert h.orch.manual_close(h.incident_id, h.who("erin"), "fixed and re-run by hand") is IncidentState.RESOLVED
    assert "MANUAL_CLOSE" in h.audit_types()


# ---------------------------------------------------------------- scenario 11: partial write, non-idempotent


def test_partial_write_on_non_idempotent_task_is_blocked_unsafe():
    def partial(state):
        state.logs[0]["content"] = state.logs[0]["content"].replace(
            "target_write=none_confirmed failure_stage=pre_write", "target_write=partial_confirmed failure_stage=mid_write")

    append_only = SALES_ETL.model_copy(update={"task_policies": {**SALES_ETL.task_policies, "load": TaskExecutionPolicy(
        task_type=TaskType.APPEND, write_mode=WriteMode.APPEND, idempotent=False, state_mechanism=StateMechanism.NONE)}})
    h = build(mutate=partial, registration=append_only)
    report = h.triage.report
    assert report.rerun_safety is RerunSafety.UNSAFE and report.remediation_class is RemediationClass.BLOCKED
    assert any(t.rule == "R3" and t.matched for t in report.rerun_safety_rule_trace)
    assert h.triage.plan is None and h.state_of() == "BLOCKED" and h.state.mutating_requests() == []


# ---------------------------------------------------------------- scenario 12: concurrency


def concurrency_diagnosis(request):
    if request.role == "planner":
        return scripted_triage(request)
    turn = default_conclusion_turn(request)
    turn["conclusion"].update(category="CONCURRENCY", subcategory="overlapping_run")
    return json.dumps(turn)


def overlapping_run(finished: bool):
    def mutate(state):
        state.dag_runs.append({
            "dag_id": "sales_etl", "dag_run_id": "manual__2026-10-09T00:01:00+00:00", "run_type": "manual",
            "logical_date": "2026-10-09T00:01:00+00:00", "start_date": "2026-10-09T00:01:00+00:00",
            "state": "success" if finished else "running",
            "end_date": "2026-10-09T00:20:00+00:00" if finished else None, "external_trigger": True})
    return mutate


def test_concurrent_run_still_active_is_blocked():
    h = build(mutate=overlapping_run(finished=False), script=concurrency_diagnosis)
    report = h.triage.report
    assert report.failure_category is FailureCategory.CONCURRENCY
    assert report.remediation_class is RemediationClass.BLOCKED and h.triage.plan is None
    assert h.state.mutating_requests() == []


def test_concurrent_run_finished_is_automatable_and_heals():
    h = build(mutate=overlapping_run(finished=True), script=concurrency_diagnosis)
    report = h.triage.report
    assert report.failure_category is FailureCategory.CONCURRENCY
    assert report.remediation_class is RemediationClass.AUTOMATABLE
    cleared = [e for e in report.evidence if e.evidence_id in h.plan.cause_cleared_evidence_ids]
    assert cleared and all("overlapped" in e.description for e in cleared)   # the pool signal does not count here
    assert h.approve("alice").incident_state is IncidentState.RESOLVED


def test_hero_run_is_untouched_by_other_dags():
    h = build()
    h.approve("alice")
    assert all("/dags/sales_etl/" in r.path for r in h.state.mutating_requests())
    assert h.state.ti("inventory_sync", "scheduled__2026-10-09T00:15:00+00:00", "sync")["state"] == "success"
    assert h.state.ti("sales_etl", HERO_RUN, "extract")["try_number"] == 1   # success task never cleared
