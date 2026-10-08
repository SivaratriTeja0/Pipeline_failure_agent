"""Phase 4b: everything that must refuse. Each scenario asserts, from the fake Airflow request log,
that no mutating clear was ever sent."""

import pytest

from actions.approval.service import (
    ApprovalError,
    ForbiddenError,
    PlanExpiredError,
    PlanStateError,
    StaleViewError,
    UnauthenticatedError,
)
from core.models import ApprovalStatus, ExecutionStatus, IncidentState, PlanCondition
from core.models.remediation import compute_plan_hash
from security.auth import AuthProviderUnavailableError
from tests.healing_helpers import build

HERO_RUN = "scheduled__2026-10-08T00:00:00+00:00"
MANUAL_CONDITION = PlanCondition(condition_id="cond-manual-1", text="Confirm the warehouse maintenance window ended.",
                                 source_rule="engineer")


def never_cleared(h) -> None:
    assert h.clears() == [], [r.body for r in h.clears()]


# ---------------------------------------------------------------- reject / cancel


def test_rejected_plan_is_never_executed():
    h = build()
    with pytest.raises(ApprovalError):
        h.orch.reject(h.plan.remediation_id, h.who("alice"), reason="  ")       # a reason is required
    assert h.orch.reject(h.plan.remediation_id, h.who("alice"), reason="maintenance in progress") is IncidentState.REJECTED
    assert h.plan.approval_status is ApprovalStatus.REJECTED and h.plan.rejected_by == "alice"
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED"
    with pytest.raises(PlanStateError):
        h.approve("bob")
    never_cleared(h)
    assert "APPROVAL_REJECTED" in h.audit_types()


def test_reject_is_still_available_after_approval_and_before_dispatch():
    h = build()
    h.approve("alice", execute=False)
    assert h.orch.reject(h.plan.remediation_id, h.who("bob"), reason="changed my mind") is IncidentState.REJECTED
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "BLOCKED"
    never_cleared(h)


def test_cancelled_plan_is_never_executed():
    h = build()
    h.approve("alice", execute=False)
    assert h.orch.cancel(h.plan.remediation_id, h.who("erin"), reason="fixing upstream instead") is IncidentState.CANCELLED
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "BLOCKED"
    with pytest.raises(ForbiddenError):
        h.orch.cancel(h.plan.remediation_id, h.who("victor"), reason="viewer")
    never_cleared(h)


# ---------------------------------------------------------------- expiry


def test_approval_expired_at_execution_time_never_executes():
    h = build()
    h.approve("alice", execute=False)
    h.clock.advance(61 * 60)  # APPROVAL_TTL_MINUTES=60; checked at execution time, no sweeper involved
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "EXPIRED"
    assert h.plan.approval_status is ApprovalStatus.EXPIRED and h.plan.execution_status is ExecutionStatus.BLOCKED
    assert h.state_of() == "EXPIRED" and "APPROVAL_EXPIRED" in h.audit_types()
    never_cleared(h)


def test_expiry_boundary_is_inclusive():
    h = build()
    h.approve("alice", execute=False)
    h.clock.now = h.plan.expires_at  # now >= expires_at -> EXPIRED
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "EXPIRED"
    never_cleared(h)


def test_approving_an_expired_plan_is_refused_and_sweeper_expires_pending_plans():
    h = build()
    h.clock.advance(3601)
    with pytest.raises(PlanExpiredError):
        h.approve("alice")
    assert h.plan.approval_status is ApprovalStatus.EXPIRED

    h2 = build()
    h2.clock.advance(3601)
    assert h2.orch.approvals.expire_due() == [h2.plan.remediation_id]
    assert h2.state_of() == "EXPIRED"
    never_cleared(h2)


# ---------------------------------------------------------------- plan edit / stale view / hash


def test_plan_edit_after_approval_voids_the_approval():
    h = build()
    h.approve("alice", execute=False)
    old = h.plan
    revised = h.orch.revise(old.remediation_id, h.who("alice"), {"conditions": [MANUAL_CONDITION]})
    assert revised.plan_version == 2 and compute_plan_hash(revised) != compute_plan_hash(old)
    assert revised.approval_status is ApprovalStatus.PENDING and revised.approved_by == []
    assert h.state_of() == "AWAITING_APPROVAL"
    assert {"PLAN_REVISED", "APPROVAL_VOIDED"} <= set(h.audit_types())

    # The old approval (bound to version 1 / old hash) cannot carry the edited plan.
    assert h.orch.approvals.valid_approvals(revised) == []
    with pytest.raises(StaleViewError):
        h.orch.approve(old.remediation_id, h.who("bob"), h.body(old))
    with pytest.raises(ApprovalError):  # the new condition must be acknowledged
        h.approve("bob", conditions_acknowledged=[])
    never_cleared(h)

    out = h.approve("bob")  # fresh approval of the exact new version
    assert out.incident_state is IncidentState.RESOLVED
    assert h.plan.plan_version == 2 and len(h.clears()) == 1


def test_executing_right_after_an_edit_is_blocked():
    h = build()
    h.approve("alice", execute=False)
    h.orch.revise(h.plan.remediation_id, h.who("alice"), {"expected_effect": "re-run load and publish"})
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "BLOCKED"
    never_cleared(h)


def test_executable_fields_cannot_be_edited():
    h = build()
    for field in ("task_instances_to_clear", "action_type", "recovery_scope", "target", "risk_level",
                  "rerun_safety", "remediation_confidence", "approved_by", "plan_hash"):
        with pytest.raises(ApprovalError):
            h.orch.revise(h.plan.remediation_id, h.who("alice"), {field: None})
    with pytest.raises(ForbiddenError):
        h.orch.revise(h.plan.remediation_id, h.who("triage-bot"), {"expected_effect": "x"})


def test_stale_displayed_hash_or_version_is_409():
    h = build()
    with pytest.raises(StaleViewError) as err:
        h.approve("alice", displayed_plan_hash="0" * 64)
    assert err.value.status == 409
    with pytest.raises(StaleViewError):
        h.approve("alice", plan_version=7)
    assert h.store.approvals_for(h.plan.remediation_id) == []


def test_tampered_persisted_plan_is_blocked_by_hash_recomputation():
    h = build()
    h.approve("alice", execute=False)
    plan = h.plan
    # Someone edits the persisted plan behind the approval service's back (no validation, stale hash).
    h.store._plans[plan.remediation_id] = plan.model_copy(update={"task_instances_to_clear": plan.task_instances_to_clear[:1]})
    out = h.orch.execute(plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and "hash mismatch" in out.execution.detail
    never_cleared(h)


# ---------------------------------------------------------------- who may approve


def test_service_principal_cannot_approve_even_with_the_role():
    h = build()
    with pytest.raises(ForbiddenError):
        h.approve("triage-bot")
    assert h.store.approvals_for(h.plan.remediation_id) == []
    assert "AUTH_FAILURE" in h.audit_types()
    never_cleared(h)


@pytest.mark.parametrize("who", ["erin", "victor", "carol"])
def test_missing_role_or_pipeline_membership_cannot_approve(who):
    h = build()
    with pytest.raises(ForbiddenError):
        h.approve(who)
    never_cleared(h)


def test_unauthenticated_cannot_approve():
    h = build()
    with pytest.raises(UnauthenticatedError) as err:
        h.orch.approve(h.plan.remediation_id, None, h.body())
    assert err.value.status == 401
    never_cleared(h)


def test_admin_may_approve_without_listing():
    h = build()
    assert h.approve("root").incident_state is IncidentState.RESOLVED


def test_identity_in_request_body_is_ignored_and_logged():
    h = build()
    body = h.body(approved_by="root", decided_by="root", principal_id="root", role="ADMIN")
    with pytest.raises(ForbiddenError):  # the body cannot make a viewer an approver
        h.orch.approve(h.plan.remediation_id, h.who("victor"), body, execute=False)
    out = h.orch.approve(h.plan.remediation_id, h.who("alice"), body, execute=False)
    assert out.approval.record.decided_by == "alice" and out.approval.plan.approved_by == ["alice"]
    suspicious = [e for e in h.audit.events(h.incident_id) if e.event_type.value == "SUSPICIOUS_REQUEST"]
    assert suspicious and suspicious[-1].payload["fields"] == ["approved_by", "decided_by", "principal_id", "role"]


def test_unacknowledged_condition_blocks_approval():
    h = build()
    h.orch.revise(h.plan.remediation_id, h.who("alice"), {"conditions": [MANUAL_CONDITION]})
    with pytest.raises(ApprovalError):
        h.approve("alice", conditions_acknowledged=[])
    with pytest.raises(ApprovalError):
        h.approve("alice", conditions_acknowledged=["cond-manual-1", "cond-invented"])
    never_cleared(h)


def test_high_risk_needs_two_distinct_approvers():
    h = build("multi_failure")
    h.approve("alice", execute=False)
    with pytest.raises(PlanStateError):
        h.approve("alice")                     # the same person twice does not count
    assert h.plan.approval_status is ApprovalStatus.PENDING
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "BLOCKED"
    never_cleared(h)


def test_approver_losing_the_role_before_execution_blocks():
    h = build()
    h.approve("alice", execute=False)
    h.auth._store.update("alice", roles=frozenset())
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and "approver_still_authorized" in out.execution.detail
    never_cleared(h)


# ---------------------------------------------------------------- kill switches


def test_global_kill_switch_blocks():
    h = build(healing_enabled=False)
    assert h.approve("alice").execution.outcome == "BLOCKED"
    never_cleared(h)


def test_pipeline_kill_switch_blocks():
    h = build(pipeline_healing=False)
    out = h.approve("alice")
    assert out.execution.outcome == "BLOCKED" and "healing_enabled=false" in out.execution.detail
    never_cleared(h)


def test_admin_halt_blocks_every_pending_plan_immediately():
    h = build()
    h.approve("alice", execute=False)
    with pytest.raises(ForbiddenError):
        h.orch.halt(h.who("alice"), "not an admin")
    assert h.orch.halt(h.who("root"), "incident review") == [h.plan.remediation_id]
    assert h.plan.execution_status is ExecutionStatus.BLOCKED and h.state_of() == "BLOCKED"
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "REFUSED"
    never_cleared(h)


# ---------------------------------------------------------------- the world changed between approval and execution


def _run(state):
    return next(r for r in state.dag_runs if r["dag_run_id"] == HERO_RUN)


def new_run_started(state):
    state.dag_runs.append({**_run(state), "dag_run_id": "manual__2026-10-09T00:31:00+00:00", "state": "running",
                           "run_type": "manual", "start_date": "2026-10-09T00:31:00+00:00", "end_date": None})


def task_already_cleared(state):
    state.ti("sales_etl", HERO_RUN, "load").update(state="queued", try_number=1)
    _run(state)["state"] = "queued"


def log_now_unreadable(state):  # SAFE -> UNKNOWN: the target-write marker can no longer be read
    state.logs.clear()


@pytest.mark.parametrize("change,expected", [
    (new_run_started, "no_forbidden_concurrent_run"),
    (task_already_cleared, "task_instances_unchanged"),
    (log_now_unreadable, "rerun_safety_still_permits"),
])
def test_changed_live_state_blocks_at_revalidation(change, expected):
    h = build()
    h.approve("alice", execute=False)
    change(h.state)
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and expected in out.execution.detail
    assert "REVALIDATION_BLOCKED" in h.audit_types() and h.state_of() == "BLOCKED"
    never_cleared(h)


def test_live_set_differing_from_approved_list_blocks_and_is_never_adjusted():
    h = build()
    h.approve("alice", execute=False)
    h.state.ti("sales_etl", HERO_RUN, "extract").update(state="failed")  # a second primary failure appeared
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and "live_set_equals_plan" in out.execution.detail
    assert [t.task_id for t in h.plan.task_instances_to_clear] == ["load", "publish"]
    never_cleared(h)


# ---------------------------------------------------------------- Rule 7 / I18: fail closed


def _down(h):
    h.state.down = True


def _approval_lookup_fails(h):
    def broken(remediation_id):
        raise RuntimeError("approvals table unavailable")
    h.store.approvals_for = broken


def _hash_mismatch(h):
    plan = h.plan
    h.store._plans[plan.remediation_id] = plan.model_copy(update={"risk_level": plan.risk_level.LOW})


def _state_unreadable(h):
    h.state.fail_paths.append("/taskInstances")


def _concurrency_unknown(h):
    h.state.fail_paths.append("/sales_etl/dagRuns")


def _auth_provider_down(h):
    def broken(principal_id):
        raise AuthProviderUnavailableError("principal store unavailable")
    h.auth.lookup = broken


@pytest.mark.parametrize("failure,reason", [
    (_down, "unreadable"),
    (_approval_lookup_fails, "approval lookup failed"),
    (_hash_mismatch, "hash mismatch"),
    (_state_unreadable, "unreadable"),
    (_concurrency_unknown, "concurrency"),
    (_auth_provider_down, "auth provider unavailable"),
], ids=["airflow_unavailable", "approval_lookup_failure", "plan_hash_mismatch", "unreadable_state",
        "unknown_concurrency", "auth_provider_failure"])
def test_I18_fail_closed(failure, reason):
    h = build()
    h.approve("alice", execute=False)
    failure(h)
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED", out.execution.detail
    assert reason in out.execution.detail
    assert h.store.get_plan(h.plan.remediation_id).execution_status is ExecutionStatus.BLOCKED
    never_cleared(h)
