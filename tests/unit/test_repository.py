"""SQL repository: healing-store contract (incl. conditional-UPDATE write-ahead), append-only audit,
token principals, and persistence across a restart."""

import threading
from datetime import timedelta

import pytest

from actions.store import IncidentRecord, StoreError
from core.models import ApprovalDecision, ApprovalRecord, ApprovalStatus, ExecutionStatus, PrincipalType, Role
from core.models.enums import AuditEventType, IncidentState
from core.models.remediation import compute_plan_hash
from core.remediation.audit import AuditLog, AuditStore
from database.repository import Database, SqlAuditStore, SqlHealingStore, SqlPrincipalStore
from security.auth import TokenAuthProvider, create_principal, hash_token
from tests.factories import T0, automatable_plan
from tests.healing_helpers import Req


def approved(store):
    plan = automatable_plan(approval_status=ApprovalStatus.APPROVED)
    store.save_plan(plan)
    store.add_approval(ApprovalRecord(approval_id="apr-1", remediation_id="rem-1", plan_version=1,
                                      plan_hash=compute_plan_hash(plan), decision=ApprovalDecision.APPROVED,
                                      decided_by="alice", role=Role.APPROVER, decided_at=T0,
                                      expires_at=T0 + timedelta(hours=1)))
    return plan


def test_write_ahead_conditional_update_has_exactly_one_winner(tmp_path):
    # A file database: each thread gets its own connection and SQLite serializes the writers.
    db = Database(f"sqlite:///{(tmp_path / 'race.db').as_posix()}")
    store = SqlHealingStore(db)
    plan = approved(store)
    h = compute_plan_hash(plan)
    results = []
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        try:
            results.append(store.write_ahead("rem-1", expected_hash=h, approval_ids=["apr-1"],
                                             action_execution_id=f"aex-{i}", idempotency_key=f"key-{i}", now=T0))
        except StoreError:  # e.g. 'database is locked': a loser, fails closed
            results.append(None)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r is not None for r in results) == 1
    assert store.get_plan("rem-1").execution_status is ExecutionStatus.QUEUED
    assert store.approvals_for("rem-1")[0].consumed is True and len(store.executions()) == 1


def test_write_ahead_rolls_back_entirely_when_any_part_fails():
    db = Database("sqlite://")
    store = SqlHealingStore(db)
    plan = approved(store)
    h = compute_plan_hash(plan)
    assert store.write_ahead("rem-1", expected_hash="0" * 64, approval_ids=["apr-1"], action_execution_id="a",
                             idempotency_key="k", now=T0) is None
    assert store.write_ahead("rem-1", expected_hash=h, approval_ids=["apr-1", "apr-missing"], action_execution_id="a",
                             idempotency_key="k", now=T0) is None
    assert store.get_plan("rem-1").execution_status is ExecutionStatus.NOT_EXECUTED
    assert store.approvals_for("rem-1")[0].consumed is False and store.executions() == []


def test_idempotency_key_is_unique_across_plans():
    db = Database("sqlite://")
    store = SqlHealingStore(db)
    plan = approved(store)
    assert store.write_ahead("rem-1", expected_hash=compute_plan_hash(plan), approval_ids=["apr-1"],
                             action_execution_id="aex-1", idempotency_key="same", now=T0) is not None
    other = automatable_plan(remediation_id="rem-2", approval_status=ApprovalStatus.APPROVED)
    store.save_plan(other)
    store.add_approval(ApprovalRecord(approval_id="apr-2", remediation_id="rem-2", plan_version=1,
                                      plan_hash=compute_plan_hash(other), decision=ApprovalDecision.APPROVED,
                                      decided_by="alice", role=Role.APPROVER, decided_at=T0,
                                      expires_at=T0 + timedelta(hours=1)))
    assert store.write_ahead("rem-2", expected_hash=compute_plan_hash(other), approval_ids=["apr-2"],
                             action_execution_id="aex-2", idempotency_key="same", now=T0) is None
    assert store.get_plan("rem-2").execution_status is ExecutionStatus.NOT_EXECUTED


def test_audit_store_is_append_only_and_chain_survives_restart(tmp_path):
    url = f"sqlite:///{(tmp_path / 'audit.db').as_posix()}"
    log = AuditLog(SqlAuditStore(Database(url)), clock=lambda: T0)
    for i in range(3):
        log.record(incident_id="inc-1", actor="SYSTEM", event_type=AuditEventType.FAILURE_RECEIVED, payload={"i": i})
    reopened = AuditLog(SqlAuditStore(Database(url)), clock=lambda: T0)
    assert reopened.verify().valid and reopened.verify().checked == 3
    assert {m for m in dir(SqlAuditStore) if not m.startswith("_")} - set(dir(AuditStore)) == {"for_incident"}
    assert not any(hasattr(SqlAuditStore, m) for m in ("update", "delete", "remove", "clear"))


def test_principal_store_keeps_only_token_hashes():
    db = Database("sqlite://")
    store = SqlPrincipalStore(db)
    principal, token = create_principal(store, "alice", PrincipalType.HUMAN, frozenset({Role.APPROVER}))
    from database.models import PrincipalRow

    with db.session() as s:
        row = s.get(PrincipalRow, "alice")
        assert row.token_hash == hash_token(token) and token not in str(row.__dict__)
    auth = TokenAuthProvider(store)
    assert auth.authenticate(Req({"Authorization": f"Bearer {token}"})) == principal
    store.update("alice", roles=frozenset({Role.VIEWER}))
    assert auth.lookup("alice").roles == frozenset({Role.VIEWER})
    store.update("alice", disabled=True)
    assert auth.authenticate(Req({"Authorization": f"Bearer {token}"})) is None and auth.lookup("alice") is None
    with pytest.raises(ValueError):
        create_principal(store, "alice", PrincipalType.HUMAN, frozenset({Role.APPROVER}))


def test_incident_state_and_halt_flag_persist_across_restart(tmp_path):
    from tests.healing_helpers import build

    url = f"sqlite:///{(tmp_path / 'triage.db').as_posix()}"
    h = build(run_triage=True)
    record = h.store.get_incident(h.incident_id)
    store = SqlHealingStore(Database(url))
    store.save_incident(record)
    store.save_plan(h.plan)
    store.set_halted(True)
    store.set_incident_state(h.incident_id, IncidentState.APPROVED)

    again = SqlHealingStore(Database(url))
    loaded = again.get_incident(h.incident_id)
    assert isinstance(loaded, IncidentRecord) and loaded.state is IncidentState.APPROVED
    assert [e.evidence_id for e in loaded.evidence] == [e.evidence_id for e in record.evidence]
    assert again.get_plan(h.plan.remediation_id) == h.plan and again.is_halted()
