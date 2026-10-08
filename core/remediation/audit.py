"""Hash-chained, append-only audit log (spec C11, invariant I10).

Each event's ``hash`` covers its own fields (including ``payload_hash``) and ``prev_hash``,
so altering, deleting, inserting or reordering any event breaks verification.

The store interface exposes only ``append`` and read operations: there is no update or
delete path. Phase 5 provides a database-backed store with the same interface.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from datetime import datetime
from threading import Lock
from typing import Any

from pydantic import BaseModel

from core.canonical import canonical_hash
from core.logging_setup import get_logger
from core.models.audit import GENESIS_HASH, AuditEvent
from core.models.base import utcnow
from core.models.enums import AuditEventType

_log = get_logger(__name__)


def compute_event_hash(
    *,
    seq: int,
    timestamp: datetime,
    incident_id: str,
    remediation_id: str | None,
    actor: str,
    event_type: AuditEventType,
    payload_hash: str,
    prev_hash: str,
) -> str:
    return canonical_hash(
        {
            "seq": seq,
            "timestamp": timestamp.isoformat(),
            "incident_id": incident_id,
            "remediation_id": remediation_id,
            "actor": actor,
            "event_type": event_type.value,
            "payload_hash": payload_hash,
            "prev_hash": prev_hash,
        }
    )


class ChainVerification(BaseModel):
    valid: bool
    checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


def verify_audit_chain(events: Sequence[AuditEvent]) -> ChainVerification:
    """Verify sequence numbering, payload hashes, event hashes and chain links."""
    prev = GENESIS_HASH
    for index, event in enumerate(events, start=1):
        if event.seq != index:
            return ChainVerification(
                valid=False, checked=index - 1, broken_at_seq=event.seq, reason="sequence gap or reorder"
            )
        if event.prev_hash != prev:
            return ChainVerification(
                valid=False, checked=index - 1, broken_at_seq=event.seq, reason="prev_hash mismatch"
            )
        if canonical_hash(event.payload) != event.payload_hash:
            return ChainVerification(
                valid=False, checked=index - 1, broken_at_seq=event.seq, reason="payload_hash mismatch"
            )
        expected = compute_event_hash(
            seq=event.seq,
            timestamp=event.timestamp,
            incident_id=event.incident_id,
            remediation_id=event.remediation_id,
            actor=event.actor,
            event_type=event.event_type,
            payload_hash=event.payload_hash,
            prev_hash=event.prev_hash,
        )
        if expected != event.hash:
            return ChainVerification(
                valid=False, checked=index - 1, broken_at_seq=event.seq, reason="event hash mismatch"
            )
        prev = event.hash
    return ChainVerification(valid=True, checked=len(events))


class AuditStore(ABC):
    """Append-only storage. Implementations must not offer update or delete."""

    @abstractmethod
    def append(self, event: AuditEvent) -> None: ...

    @abstractmethod
    def all(self) -> tuple[AuditEvent, ...]: ...

    @abstractmethod
    def last(self) -> AuditEvent | None: ...


class InMemoryAuditStore(AuditStore):
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def all(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def last(self) -> AuditEvent | None:
        return self._events[-1] if self._events else None


class AuditLog:
    """A single global hash chain. Events are filtered per incident on read."""

    def __init__(self, store: AuditStore | None = None, clock: Callable[[], datetime] = utcnow) -> None:
        self._store = store or InMemoryAuditStore()
        self._clock = clock
        self._lock = Lock()

    def record(
        self,
        *,
        incident_id: str,
        actor: str,
        event_type: AuditEventType,
        payload: dict[str, Any] | None = None,
        remediation_id: str | None = None,
    ) -> AuditEvent:
        body = dict(payload or {})
        with self._lock:
            last = self._store.last()
            seq = 1 if last is None else last.seq + 1
            prev_hash = GENESIS_HASH if last is None else last.hash
            timestamp = self._clock()
            payload_hash = canonical_hash(body)
            event = AuditEvent(
                seq=seq,
                timestamp=timestamp,
                incident_id=incident_id,
                remediation_id=remediation_id,
                actor=actor,
                event_type=event_type,
                payload=body,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
                hash=compute_event_hash(
                    seq=seq,
                    timestamp=timestamp,
                    incident_id=incident_id,
                    remediation_id=remediation_id,
                    actor=actor,
                    event_type=event_type,
                    payload_hash=payload_hash,
                    prev_hash=prev_hash,
                ),
            )
            self._store.append(event)
        _log.info(
            "audit_event",
            extra={"seq": seq, "incident_id": incident_id, "event_type": event_type.value, "actor": actor},
        )
        return event

    def events(self, incident_id: str | None = None) -> tuple[AuditEvent, ...]:
        events = self._store.all()
        if incident_id is None:
            return events
        return tuple(e for e in events if e.incident_id == incident_id)

    def verify(self) -> ChainVerification:
        return verify_audit_chain(self._store.all())
