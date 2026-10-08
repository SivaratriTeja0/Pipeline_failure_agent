"""Incident lifecycle helper for the healing boundary.

Every incident state change goes through ``IncidentStateMachine`` (the transition table in
core/remediation is the single authority; illegal transitions raise) and writes an audit event.
"""

from actions.store import HealingStore
from core.models.enums import AuditEventType, IncidentState
from core.remediation.audit import AuditLog
from core.remediation.state_machine import IncidentStateMachine, is_legal


class Lifecycle:
    def __init__(self, store: HealingStore, audit: AuditLog) -> None:
        self._store = store
        self._audit = audit

    def state(self, incident_id: str) -> IncidentState:
        return self._store.get_incident(incident_id).state

    def move(self, incident_id: str, target: IncidentState, *, actor: str = "SYSTEM", reason: str = "",
             remediation_id: str | None = None) -> IncidentState:
        """Transition (raises IllegalTransitionError) and persist."""
        sm = IncidentStateMachine(incident_id, self._audit, state=self.state(incident_id))
        sm.transition(target, actor=actor, reason=reason, remediation_id=remediation_id)
        self._store.set_incident_state(incident_id, sm.state)
        return sm.state

    def move_if_legal(self, incident_id: str, target: IncidentState, *, actor: str = "SYSTEM", reason: str = "",
                      remediation_id: str | None = None) -> bool:
        if not is_legal(self.state(incident_id), target):
            return False
        self.move(incident_id, target, actor=actor, reason=reason, remediation_id=remediation_id)
        return True

    def record(self, incident_id: str, event_type: AuditEventType, payload: dict, *, actor: str = "SYSTEM",
               remediation_id: str | None = None) -> None:
        self._audit.record(incident_id=incident_id, actor=actor, event_type=event_type, payload=payload,
                           remediation_id=remediation_id)

    def escalate(self, incident_id: str, reason: str, *, remediation_id: str | None = None) -> None:
        self.move(incident_id, IncidentState.ESCALATED, reason=reason, remediation_id=remediation_id)
        self.record(incident_id, AuditEventType.INCIDENT_ESCALATED, {"reason": reason}, remediation_id=remediation_id)
