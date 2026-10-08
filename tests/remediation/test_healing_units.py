"""Unit tests for the healing boundary building blocks: registry, store CAS, policy engine."""

import ast
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from actions.policy.engine import PolicyContext, PolicyEngine
from actions.registry import ACTION_REGISTRY, ActionRegistrationError, ActionRegistry, ActionSpec
from actions.store import InMemoryHealingStore, revalidated
from core.config import Settings
from core.models import (
    ActionCapability,
    ActionType,
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStatus,
    ExecutionMode,
    ExecutionStatus,
    PlanTarget,
    RecoveryScope,
    RiskLevel,
    Role,
)
from core.models.remediation import compute_plan_hash
from core.remediation.risk import compute_risk_level
from demo.scenarios.registrations import SALES_ETL
from tests.factories import T0, automatable_plan

ALL = frozenset(ActionCapability)
REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------- registry (L2, I12)


def test_registry_has_exactly_the_two_v1_actions_and_is_frozen():
    assert ACTION_REGISTRY.names() == ["RETRY_FAILED_DAG_RUN", "RETRY_FAILED_TASK"]
    assert set(ActionType) == {ActionType.RETRY_FAILED_TASK, ActionType.RETRY_FAILED_DAG_RUN}
    assert set(RecoveryScope) == {RecoveryScope.FAILED_TASK, RecoveryScope.FAILED_DAG_RUN}
    spec = ACTION_REGISTRY.get(ActionType.RETRY_FAILED_TASK)
    with pytest.raises(ActionRegistrationError):
        ACTION_REGISTRY.register(spec)
    for spec in ACTION_REGISTRY.specs.values():
        assert spec.mutating is True and spec.requires_approval is True
        assert "cannot be undone" in spec.rollback_description


def _spec(**kw):
    base = ACTION_REGISTRY.get(ActionType.RETRY_FAILED_TASK).model_dump()
    base.update(kw)
    return ActionSpec(**base)


def test_registering_without_approval_or_with_wrong_scope_raises():
    with pytest.raises(ActionRegistrationError):
        _spec(requires_approval=False)
    spec = ACTION_REGISTRY.get(ActionType.RETRY_FAILED_TASK)
    with pytest.raises(Exception):
        spec.requires_approval = False  # frozen: immutable after construction
    registry = ActionRegistry()
    with pytest.raises(ActionRegistrationError):
        registry.register(_spec(recovery_scope=RecoveryScope.FAILED_DAG_RUN))
    with pytest.raises(ActionRegistrationError):
        registry.register(_spec(precondition_checks=frozenset({"looks_fine_to_me"})))
    with pytest.raises(ValueError):
        _spec(name="TRIGGER_DAG_RUN")


# ---------------------------------------------------------------- store write-ahead (I6)


def approved_store(plan=None):
    store = InMemoryHealingStore()
    plan = plan or automatable_plan(approval_status=ApprovalStatus.APPROVED)
    store.save_plan(plan)
    record = ApprovalRecord(approval_id="apr-1", remediation_id=plan.remediation_id, plan_version=1,
                            plan_hash=compute_plan_hash(plan), decision=ApprovalDecision.APPROVED, decided_by="alice",
                            role=Role.APPROVER, decided_at=T0, expires_at=T0 + timedelta(hours=1))
    store.add_approval(record)
    return store, plan


def test_write_ahead_is_compare_and_set_and_consumes_the_approval():
    store, plan = approved_store()
    h = compute_plan_hash(plan)
    first = store.write_ahead("rem-1", expected_hash=h, approval_ids=["apr-1"], action_execution_id="aex-1",
                              idempotency_key="k1", now=T0)
    assert first is not None and first.execution_status is ExecutionStatus.QUEUED and first.idempotency_key == "k1"
    assert store.approvals_for("rem-1")[0].consumed
    assert store.write_ahead("rem-1", expected_hash=h, approval_ids=["apr-1"], action_execution_id="aex-2",
                             idempotency_key="k2", now=T0) is None
    assert len(store.executions()) == 1


def test_write_ahead_refuses_changed_hash_or_unknown_approval():
    store, plan = approved_store()
    assert store.write_ahead("rem-1", expected_hash="0" * 64, approval_ids=["apr-1"], action_execution_id="a",
                             idempotency_key="k", now=T0) is None
    assert store.write_ahead("rem-1", expected_hash=compute_plan_hash(plan), approval_ids=["apr-404"],
                             action_execution_id="a", idempotency_key="k", now=T0) is None
    assert store.get_plan("rem-1").execution_status is ExecutionStatus.NOT_EXECUTED


def test_concurrent_write_ahead_has_exactly_one_winner():
    store, plan = approved_store()
    h = compute_plan_hash(plan)
    results = []
    barrier = threading.Barrier(16)

    def worker(i):
        barrier.wait()
        results.append(store.write_ahead("rem-1", expected_hash=h, approval_ids=["apr-1"],
                                         action_execution_id=f"aex-{i}", idempotency_key=f"k{i}", now=T0))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r is not None for r in results) == 1 and len(store.executions()) == 1


def test_revalidated_recomputes_derived_fields():
    plan = automatable_plan(execution_mode=ExecutionMode.LIVE)
    done = revalidated(plan, dispatch_confirmed=True, execution_status=ExecutionStatus.SUCCESS)
    assert done.executed is True
    assert revalidated(automatable_plan(), dispatch_confirmed=True).executed is False  # DRY_RUN never 'executed'


# ---------------------------------------------------------------- policy engine (L6)


LIVE = Settings.from_env({"HEALING_ENABLED": "true", "HEALING_EXECUTION_MODE": "LIVE", "DEMO_MODE": "false",
                          "AUTH_PROVIDER": "token", "AIRFLOW_WRITE_TOKEN": "x"})
REG = SALES_ETL.model_copy(update={"healing_enabled": True, "approver_ids": ["alice", "bob"]})
CTX = PolicyContext(incident_id="inc-1", pipeline_id="sales_etl", execution_id="scheduled__2026-10-08T00:00:00+00:00")


def policy_check(plan, *, settings=LIVE, reg=REG, ctx=CTX, approvals=None, caps=ALL):
    if approvals is None:
        approvals = [ApprovalRecord(approval_id="apr-1", remediation_id=plan.remediation_id,
                                    plan_version=plan.plan_version, plan_hash=compute_plan_hash(plan),
                                    decision=ApprovalDecision.APPROVED, decided_by="alice", role=Role.APPROVER,
                                    decided_at=T0, expires_at=T0 + timedelta(hours=1))]
    return PolicyEngine(settings, ACTION_REGISTRY, caps).validate(plan, approvals, reg, ctx, T0)


def live_plan(**kw):
    return automatable_plan(execution_mode=ExecutionMode.LIVE, approval_status=ApprovalStatus.APPROVED,
                            risk_level=compute_risk_level("production", RecoveryScope.FAILED_TASK), **kw)


def failed(decision):
    return {c.name for c in decision.checks if not c.passed}


def test_policy_allows_a_fully_valid_plan():
    decision = policy_check(live_plan())
    assert decision.allowed, decision.block_reason


@pytest.mark.parametrize("kw,check", [
    ({"settings": Settings.from_env({"HEALING_EXECUTION_MODE": "LIVE"})}, "healing_enabled_global"),
    ({"reg": REG.model_copy(update={"healing_enabled": False})}, "healing_enabled_pipeline"),
    ({"reg": REG.model_copy(update={"allowed_actions": [ActionType.RETRY_FAILED_DAG_RUN]})},
     "action_allowed_for_pipeline"),
    ({"caps": frozenset()}, "executor_capability"),
    ({"ctx": CTX.model_copy(update={"halted": True})}, "not_halted"),
    ({"ctx": CTX.model_copy(update={"executions_for_incident": 2})}, "healing_cycles"),
    ({"ctx": CTX.model_copy(update={"actions_for_dag_last_hour": 2})}, "dag_action_rate"),
    ({"ctx": CTX.model_copy(update={"incident_id": "inc-other"})}, "bound_to_incident"),
    ({"approvals": []}, "approvals_sufficient"),
])
def test_policy_refusals(kw, check):
    assert check in failed(policy_check(live_plan(), **kw))


def test_policy_refuses_mode_mismatch_and_cross_dag_targets():
    dry = automatable_plan(approval_status=ApprovalStatus.APPROVED)  # made for DRY_RUN
    assert "execution_mode_matches" in failed(policy_check(dry))
    other = live_plan(target=PlanTarget(dag_id="payroll", dag_run_id="scheduled__2026-10-08T00:00:00+00:00",
                                        task_id="load"))
    assert {"target_pipeline"} <= failed(policy_check(other))
    other_run = live_plan(target=PlanTarget(dag_id="sales_etl", dag_run_id="manual__x", task_id="load"))
    assert "target_execution" in failed(policy_check(other_run))


def test_policy_uses_the_stricter_risk_so_a_lowered_risk_cannot_reduce_approvals():
    dag_run = live_plan(action_type=ActionType.RETRY_FAILED_DAG_RUN, recovery_scope=RecoveryScope.FAILED_DAG_RUN,
                        target=PlanTarget(dag_id="sales_etl", dag_run_id="scheduled__2026-10-08T00:00:00+00:00"))
    tampered = revalidated(dag_run, risk_level=RiskLevel.LOW)
    decision = policy_check(tampered)
    assert "approvals_sufficient" in failed(decision) and "risk LOW/HIGH" in decision.block_reason


def test_policy_ignores_approvals_for_other_versions_hashes_or_consumed():
    plan = live_plan()
    good = policy_check(plan).approval_ids
    assert good == ["apr-1"]
    base = dict(approval_id="apr-x", remediation_id=plan.remediation_id, decision=ApprovalDecision.APPROVED,
                decided_by="alice", role=Role.APPROVER, decided_at=T0, expires_at=T0 + timedelta(hours=1))
    stale = [ApprovalRecord(plan_version=1, plan_hash="a" * 64, **base),
             ApprovalRecord(plan_version=2, plan_hash=compute_plan_hash(plan), **base),
             ApprovalRecord(plan_version=1, plan_hash=compute_plan_hash(plan), consumed=True, **base),
             ApprovalRecord(plan_version=1, plan_hash=compute_plan_hash(plan), expires_at=T0,
                            **{k: v for k, v in base.items() if k != "expires_at"}),
             ApprovalRecord(plan_version=1, plan_hash=compute_plan_hash(plan), decided_by="mallory",
                            **{k: v for k, v in base.items() if k != "decided_by"})]
    for record in stale:
        assert "approvals_sufficient" in failed(policy_check(plan, approvals=[record]))


# ---------------------------------------------------------------- the action client module has one HTTP verb


def test_action_client_module_issues_only_post_to_the_clear_endpoint():
    tree = ast.parse((REPO / "actions" / "airflow_actions.py").read_text(encoding="utf-8"))
    verbs = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and node.func.attr in {"get", "post", "put", "patch", "delete", "request", "send", "stream"}}
    verbs.discard("get")  # dict.get / headers.get only; no HTTP GET goes through this client
    assert verbs == {"post"}
    source = (REPO / "actions" / "airflow_actions.py").read_text(encoding="utf-8")
    assert source.count("_http.post(") == 1 and "clearTaskInstances" in source
