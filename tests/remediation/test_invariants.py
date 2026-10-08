"""Healing invariants I1-I18 (spec L12): one explicitly named test per invariant.

Each test drives the real boundary (approval -> policy -> re-validation -> executor) against
FAKE AIRFLOW (DEMO) and asserts on the fake's request log where execution is concerned. Broader
coverage of each invariant lives in tests/integration/test_healing_*.py (see the Phase 4 report).
"""

import pytest

from actions.approval.service import ForbiddenError
from core.config import Settings
from core.models import (
    ApprovalStatus,
    AuditEventType,
    ConfidenceLevel,
    ExecutionMode,
    ExecutionStatus,
    IncidentState,
    PlanTarget,
    RemediationClass,
    RerunSafety,
)
from core.models.remediation import compute_plan_hash
from core.remediation.audit import verify_audit_chain
from security.auth import DemoAuthNotAllowedError, DemoAuthProvider
from tests.architecture import scanner as sc
from tests.factories import automatable_plan
from tests.healing_helpers import HERO_RUN, build
from tests.triage_helpers import DEFAULT, investigator
from tools.catalog import READ_ONLY_TOOLS
from tools.registry import MUTATION_VERBS


def test_I1_executor_requires_an_approved_unexpired_hash_matching_approval():
    pending = build()
    assert pending.orch.execute(pending.plan.remediation_id).execution.outcome == "BLOCKED"  # never approved
    expired = build()
    expired.approve("alice", execute=False)
    expired.clock.advance(3600)
    assert expired.orch.execute(expired.plan.remediation_id).execution.outcome == "EXPIRED"
    for h in (pending, expired):
        assert h.clears() == []
    ok = build()
    ok.approve("alice", execute=False)
    record = ok.store.approvals_for(ok.plan.remediation_id)[0]
    assert record.plan_hash == compute_plan_hash(ok.plan)
    assert ok.orch.execute(ok.plan.remediation_id).incident_state is IncidentState.RESOLVED


def test_I2_only_authenticated_human_approvers_and_body_identity_is_ignored():
    h = build()
    for who in ("triage-bot", "victor", "erin", "carol"):
        with pytest.raises(ForbiddenError):
            h.approve(who)
    out = h.orch.approve(h.plan.remediation_id, h.who("bob"), h.body(approved_by="root", decided_by="root"),
                         execute=False)
    assert out.approval.record.decided_by == "bob"
    assert AuditEventType.SUSPICIOUS_REQUEST.value in h.audit_types()


def test_I3_llm_registry_has_no_mutating_tools_and_investigation_cannot_import_actions():
    names = READ_ONLY_TOOLS.names()
    assert not [n for n in names if n.split("_")[0] in MUTATION_VERBS]
    assert not [n for n in names if "clear" in n or "retry" in n or "trigger" in n]
    for path in sc.python_files("agent", "tools", "core"):
        assert not sc.forbidden_import_violations(sc.imports_of(path), ("actions",)), path


@pytest.mark.parametrize("terminal", ["reject", "cancel", "expire", "block"])
def test_I4_rejected_cancelled_expired_blocked_plans_never_execute(terminal):
    h = build()
    h.approve("alice", execute=False)
    rid = h.plan.remediation_id
    if terminal == "reject":
        h.orch.reject(rid, h.who("bob"), "no")
    elif terminal == "cancel":
        h.orch.cancel(rid, h.who("alice"), "no")
    elif terminal == "expire":
        h.clock.advance(3600)
        h.orch.approvals.expire_due()
    else:
        h.orch.halt(h.who("root"), "freeze")
    assert h.orch.execute(rid).execution.outcome in ("BLOCKED", "REFUSED", "EXPIRED")
    assert h.clears() == []


def test_I5_plan_edits_void_approvals():
    h = build()
    h.approve("alice", execute=False)
    revised = h.orch.revise(h.plan.remediation_id, h.who("alice"), {"expected_effect": "edited"})
    assert revised.plan_version == 2 and revised.approval_status is ApprovalStatus.PENDING
    assert h.orch.approvals.valid_approvals(revised) == []
    assert h.orch.execute(revised.remediation_id).execution.outcome == "BLOCKED"
    assert h.clears() == []


def test_I6_a_plan_executes_at_most_once():
    h = build()
    h.approve("alice")
    for _ in range(3):
        assert h.orch.execute(h.plan.remediation_id).execution.outcome == "REFUSED"
    assert len(h.clears()) == 1
    assert len(h.store.executions()) == 1 and h.plan.idempotency_key is not None


def test_I7_unsafe_or_unknown_rerun_safety_blocks():
    h = build(mutate=lambda s: s.logs.clear())  # no target-write evidence -> UNKNOWN
    assert h.triage.report.rerun_safety is RerunSafety.UNKNOWN
    assert h.triage.report.remediation_class is RemediationClass.BLOCKED and h.triage.plan is None
    for unsafe in (RerunSafety.UNKNOWN, RerunSafety.UNSAFE):
        with pytest.raises(ValueError):
            automatable_plan(rerun_safety=unsafe)  # an executable plan cannot even be constructed
    assert h.state.mutating_requests() == []


def test_I8_live_state_revalidation_runs_before_every_execution_and_blocks_changes():
    h = build()
    h.approve("alice", execute=False)
    h.state.logs.clear()  # SAFE -> UNKNOWN on fresh state
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and "SAFE -> UNKNOWN" in out.execution.detail
    ok = build()
    ok.approve("alice")
    types = ok.audit_types()
    assert types.index("LIVE_STATE_REVALIDATED") < types.index("EXECUTION_QUEUED") < types.index("EXECUTION_DISPATCHED")


def test_I9_kill_switches_and_dry_run_default_are_honored():
    assert Settings.from_env({}).healing_execution_mode is ExecutionMode.DRY_RUN
    assert Settings.from_env({}).healing_enabled is False
    dry = build(mode=ExecutionMode.DRY_RUN, demo_auth=True)
    dry.approve("demo-engineer")
    assert dry.state.mutating_requests() == []
    off = build(healing_enabled=False)
    assert off.approve("alice").execution.outcome == "BLOCKED" and off.clears() == []


def test_I10_every_transition_is_audited_and_tampering_is_detected():
    h = build()
    h.approve("alice")
    events = list(h.audit.events())
    assert sum(e.event_type is AuditEventType.INCIDENT_STATE_CHANGED for e in events) == 10
    assert verify_audit_chain(events).valid
    tampered = events[:]
    tampered[20] = tampered[20].model_copy(update={"payload": {"reason": "nothing to see"}})
    assert not verify_audit_chain(tampered).valid
    assert not verify_audit_chain(events[:5] + events[6:]).valid


def test_I11_healing_cycles_and_action_rates_are_bounded():
    h = build(clear_behavior="fail_again", env={"MAX_HEALING_CYCLES": "1"},
              mutate=lambda s: setattr(s, "post_failure_pool_success", True))
    assert h.approve("alice").incident_state is IncidentState.ESCALATED
    assert len(h.clears()) == 1
    rate = build(env={"MAX_ACTIONS_PER_DAG_PER_HOUR": "1"})
    rate.store.executions_for_incident = lambda _: 0
    rate.store.actions_for_dag_last_hour = lambda dag, now: 1
    assert "dag_action_rate" in rate.approve("alice").execution.detail and rate.clears() == []


def test_I12_only_two_actions_no_cross_dag_target_no_dag_scope():
    from actions.registry import ACTION_REGISTRY
    from core.models import RecoveryScope

    assert ACTION_REGISTRY.names() == ["RETRY_FAILED_DAG_RUN", "RETRY_FAILED_TASK"]
    assert {s.value for s in RecoveryScope} == {"FAILED_TASK", "FAILED_DAG_RUN"}
    h = build()
    h.approve("alice", execute=False)
    plan = h.plan
    h.store._plans[plan.remediation_id] = plan.model_copy(
        update={"target": PlanTarget(dag_id="inventory_sync", dag_run_id=HERO_RUN, task_id="load")})
    assert h.orch.execute(plan.remediation_id).execution.outcome == "BLOCKED"
    assert h.clears() == []


def test_I13_executor_recomputes_the_plan_hash_and_rejects_a_mismatch():
    h = build()
    h.approve("alice", execute=False)
    plan = h.plan
    forged = plan.model_copy(update={"task_instances_to_clear": plan.task_instances_to_clear[:1]})
    assert forged.plan_hash == plan.plan_hash  # the stored hash field is stale and must not be trusted
    h.store._plans[plan.remediation_id] = forged
    out = h.orch.execute(plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and "hash mismatch" in out.execution.detail
    assert h.clears() == []


def test_I14_demo_auth_cannot_start_under_live_mode():
    with pytest.raises(DemoAuthNotAllowedError):
        DemoAuthProvider(Settings.from_env({"HEALING_EXECUTION_MODE": "LIVE"}))
    with pytest.raises(DemoAuthNotAllowedError):
        DemoAuthProvider(Settings.from_env({"DEMO_MODE": "false"}))


def test_I15_an_ambiguous_dispatch_is_never_resent():
    h = build(fault="timeout_then_down")
    h.approve("alice")
    assert len(h.clears()) == 1 and h.plan.execution_status is ExecutionStatus.UNCERTAIN
    h.state.down = False
    assert h.orch.execute(h.plan.remediation_id).execution.outcome == "REFUSED"
    h.orch.startup()  # startup reconciliation reads, never re-dispatches
    assert len(h.clears()) == 1


def test_I16_executed_set_equals_approved_set_equals_live_set():
    h = build()
    approved = sorted((t.task_id, t.observed_state) for t in h.plan.task_instances_to_clear)
    live = sorted((ti["task_id"], ti["state"]) for ti in h.state.task_instances_for("sales_etl", HERO_RUN)
                  if ti["state"] in ("failed", "upstream_failed"))
    h.approve("alice")
    executed = sorted(h.clears()[0].body["task_ids"])
    assert approved == live and executed == [t for t, _ in approved]
    assert "extract" not in executed  # success tasks are never cleared
    changed = build()
    changed.approve("alice", execute=False)
    changed.state.ti("sales_etl", HERO_RUN, "extract").update(state="failed")
    assert changed.orch.execute(changed.plan.remediation_id).execution.outcome == "BLOCKED"
    assert changed.clears() == []


def test_I17_low_remediation_confidence_never_executable_and_llm_cannot_broaden():
    with pytest.raises(ValueError):
        automatable_plan(remediation_confidence=ConfidenceLevel.LOW)
    # The planner tries to switch to the DAG-run action and add a success task: the strict schema rejects it.
    rogue = {"rationale": "x", "action_type": "RETRY_FAILED_DAG_RUN", "task_instances_to_clear": [{"task_id": "extract"}]}
    h = build(script=investigator([DEFAULT], planner=rogue))
    plan = h.plan
    assert plan.action_type.value == "RETRY_FAILED_TASK"
    assert [t.task_id for t in plan.task_instances_to_clear] == ["load", "publish"]
    assert any(l.startswith("planner output rejected") for l in h.triage.report.limitations)
    # The planner may only lower to manual.
    manual = build(script=investigator([DEFAULT], planner={"rationale": "x", "recommend_manual": True,
                                                           "manual_reason": "unsure"}))
    assert manual.triage.plan is None and manual.triage.report.remediation_class is RemediationClass.MANUAL_FIX_REQUIRED


@pytest.mark.parametrize("failure", ["airflow_unavailable", "approval_lookup", "hash_mismatch", "unreadable_state",
                                     "unknown_concurrency", "auth_provider"])
def test_I18_fail_closed(failure):
    from security.auth import AuthProviderUnavailableError

    h = build()
    h.approve("alice", execute=False)
    if failure == "airflow_unavailable":
        h.state.down = True
    elif failure == "approval_lookup":
        h.store.approvals_for = lambda _: (_ for _ in ()).throw(RuntimeError("db down"))
    elif failure == "hash_mismatch":
        h.store._plans[h.plan.remediation_id] = h.plan.model_copy(update={"risk_level": h.plan.risk_level.HIGH})
    elif failure == "unreadable_state":
        h.state.fail_paths.append("/taskInstances")
    elif failure == "unknown_concurrency":
        h.state.fail_paths.append("/sales_etl/dagRuns")
    else:
        def broken(_):
            raise AuthProviderUnavailableError("down")
        h.auth.lookup = broken
    out = h.orch.execute(h.plan.remediation_id)
    assert out.execution.outcome == "BLOCKED" and h.clears() == []
    assert h.store.get_plan(h.plan.remediation_id).execution_status is ExecutionStatus.BLOCKED
