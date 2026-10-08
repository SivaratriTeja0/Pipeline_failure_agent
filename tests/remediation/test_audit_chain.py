"""Hash-chained audit log (C11, I10)."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from core.models import AuditEvent, AuditEventType
from core.remediation.audit import AuditLog, InMemoryAuditStore, verify_audit_chain
from tests.factories import T0


def build_log(n: int = 4) -> tuple[AuditLog, InMemoryAuditStore]:
    store = InMemoryAuditStore()
    ticks = iter(T0 + timedelta(seconds=i) for i in range(1000))
    log = AuditLog(store, clock=lambda: next(ticks))
    types = [AuditEventType.FAILURE_RECEIVED, AuditEventType.INCIDENT_CREATED,
             AuditEventType.EVIDENCE_COLLECTED, AuditEventType.ROOT_CAUSE_DETERMINED]
    for i in range(n):
        log.record(incident_id="inc-1", actor="SYSTEM", event_type=types[i % len(types)], payload={"i": i})
    return log, store


def test_intact_chain_verifies():
    log, _ = build_log()
    result = log.verify()
    assert result.valid and result.checked == 4


def test_chain_links_and_genesis():
    log, _ = build_log()
    events = log.events()
    assert events[0].prev_hash == "0" * 64
    for prev, cur in zip(events, events[1:]):
        assert cur.prev_hash == prev.hash


def test_payload_tampering_detected():
    _, store = build_log()
    events = list(store.all())
    events[1] = events[1].model_copy(update={"payload": {"i": 999}})
    result = verify_audit_chain(events)
    assert not result.valid and result.broken_at_seq == 2 and "payload" in result.reason


def test_rehashed_payload_tampering_still_detected():
    from core.canonical import canonical_hash

    _, store = build_log()
    events = list(store.all())
    forged = {"i": 999}
    events[1] = events[1].model_copy(update={"payload": forged, "payload_hash": canonical_hash(forged)})
    assert not verify_audit_chain(events).valid


def test_actor_tampering_detected():
    _, store = build_log()
    events = list(store.all())
    events[2] = events[2].model_copy(update={"actor": "HUMAN:mallory"})
    assert not verify_audit_chain(events).valid


def test_deletion_detected():
    _, store = build_log()
    events = list(store.all())
    del events[1]
    assert not verify_audit_chain(events).valid


def test_reorder_detected():
    _, store = build_log()
    events = list(store.all())
    events[1], events[2] = events[2], events[1]
    assert not verify_audit_chain(events).valid


def test_events_are_immutable():
    log, _ = build_log()
    with pytest.raises(ValidationError):
        log.events()[0].payload = {"x": 1}  # type: ignore[misc]


def test_no_update_or_delete_api():
    public = {n for n in dir(AuditLog) if not n.startswith("_")}
    assert public == {"record", "events", "verify"}
    store_public = {n for n in dir(InMemoryAuditStore) if not n.startswith("_")}
    assert store_public == {"append", "all", "last"}


def test_actor_format_enforced():
    with pytest.raises(ValidationError):
        AuditLog().record(incident_id="i", actor="root", event_type=AuditEventType.MANUAL_CLOSE)
    AuditLog().record(incident_id="i", actor="HUMAN:alice", event_type=AuditEventType.MANUAL_CLOSE)
    AuditLog().record(incident_id="i", actor="LLM", event_type=AuditEventType.INVESTIGATION_COMPLETED)


def test_audit_event_type_is_audit_event():
    log, _ = build_log(1)
    assert isinstance(log.events()[0], AuditEvent)


def test_events_filtered_per_incident_but_one_global_chain():
    log = AuditLog()
    log.record(incident_id="a", actor="SYSTEM", event_type=AuditEventType.INCIDENT_CREATED)
    log.record(incident_id="b", actor="SYSTEM", event_type=AuditEventType.INCIDENT_CREATED)
    assert len(log.events("a")) == 1 and len(log.events()) == 2 and log.verify().valid
