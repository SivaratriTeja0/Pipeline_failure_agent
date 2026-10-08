"""Incident lifecycle state machine (spec C12).

The transition table is the single authority. Illegal transitions raise. Every legal
transition writes an AuditEvent. REJECTED, EXPIRED, CANCELLED and BLOCKED are terminal for
the plan: none of them can reach any approval/execution state.
"""

from types import MappingProxyType

from core.models.enums import AuditEventType, IncidentState
from core.remediation.audit import AuditLog

S = IncidentState


class IllegalTransitionError(RuntimeError):
    def __init__(self, current: IncidentState, target: IncidentState) -> None:
        super().__init__(f"illegal incident transition {current.value} -> {target.value}")
        self.current = current
        self.target = target


# Where a plan-terminal state may lead: never back into approval or execution.
_PLAN_TERMINAL_EXITS = frozenset({S.MANUAL_FIX_REQUIRED, S.RE_INVESTIGATING, S.ESCALATED, S.RESOLVED})

TRANSITIONS: MappingProxyType[IncidentState, frozenset[IncidentState]] = MappingProxyType(
    {
        S.DETECTED: frozenset({S.INVESTIGATING}),
        S.INVESTIGATING: frozenset({S.DIAGNOSED, S.ESCALATED}),
        S.DIAGNOSED: frozenset(
            {S.PLAN_PROPOSED, S.NO_ACTION_REQUIRED, S.MANUAL_FIX_REQUIRED, S.BLOCKED, S.ESCALATED}
        ),
        S.PLAN_PROPOSED: frozenset({S.AWAITING_APPROVAL, S.BLOCKED, S.CANCELLED}),
        # Back to PLAN_PROPOSED = the plan was edited; prior approvals are void.
        S.AWAITING_APPROVAL: frozenset(
            {S.APPROVED, S.REJECTED, S.EXPIRED, S.CANCELLED, S.PLAN_PROPOSED, S.BLOCKED}
        ),
        S.APPROVED: frozenset({S.POLICY_VALIDATING, S.EXPIRED, S.CANCELLED, S.PLAN_PROPOSED, S.BLOCKED}),
        S.REJECTED: _PLAN_TERMINAL_EXITS,
        S.EXPIRED: _PLAN_TERMINAL_EXITS,
        S.CANCELLED: _PLAN_TERMINAL_EXITS,
        S.BLOCKED: _PLAN_TERMINAL_EXITS,
        S.POLICY_VALIDATING: frozenset({S.REVALIDATING, S.BLOCKED}),
        S.REVALIDATING: frozenset({S.EXECUTING, S.BLOCKED}),
        # EXECUTING -> ESCALATED covers a completed DRY_RUN (nothing dispatched, human decides)
        # and failed dispatch; exceptions otherwise go to BLOCKED.
        S.EXECUTING: frozenset({S.VERIFYING, S.EXECUTION_UNCERTAIN, S.BLOCKED, S.ESCALATED}),
        S.EXECUTION_UNCERTAIN: frozenset({S.RECONCILING}),
        S.RECONCILING: frozenset({S.VERIFYING, S.ESCALATED}),
        S.VERIFYING: frozenset({S.RESOLVED, S.RE_INVESTIGATING, S.ESCALATED}),
        S.RE_INVESTIGATING: frozenset({S.DIAGNOSED, S.ESCALATED}),
        S.NO_ACTION_REQUIRED: frozenset({S.RESOLVED}),
        S.MANUAL_FIX_REQUIRED: frozenset({S.AWAITING_FIX_CONFIRMATION, S.RESOLVED, S.ESCALATED}),
        S.AWAITING_FIX_CONFIRMATION: frozenset(
            {S.RE_INVESTIGATING, S.MANUAL_FIX_REQUIRED, S.RESOLVED, S.ESCALATED}
        ),
        S.RESOLVED: frozenset(),
        S.ESCALATED: frozenset({S.RESOLVED}),
    }
)

PLAN_TERMINAL_STATES = frozenset({S.REJECTED, S.EXPIRED, S.CANCELLED, S.BLOCKED})
EXECUTION_PATH_STATES = frozenset(
    {S.APPROVED, S.POLICY_VALIDATING, S.REVALIDATING, S.EXECUTING, S.VERIFYING,
     S.EXECUTION_UNCERTAIN, S.RECONCILING}
)


def is_legal(current: IncidentState, target: IncidentState) -> bool:
    return target in TRANSITIONS[current]


class IncidentStateMachine:
    def __init__(
        self,
        incident_id: str,
        audit_log: AuditLog,
        state: IncidentState = IncidentState.DETECTED,
    ) -> None:
        self.incident_id = incident_id
        self._audit = audit_log
        self._state = state

    @property
    def state(self) -> IncidentState:
        return self._state

    def transition(
        self,
        target: IncidentState,
        *,
        actor: str = "SYSTEM",
        reason: str = "",
        remediation_id: str | None = None,
    ) -> IncidentState:
        if not is_legal(self._state, target):
            raise IllegalTransitionError(self._state, target)
        previous = self._state
        self._audit.record(
            incident_id=self.incident_id,
            remediation_id=remediation_id,
            actor=actor,
            event_type=AuditEventType.INCIDENT_STATE_CHANGED,
            payload={"from": previous.value, "to": target.value, "reason": reason},
        )
        self._state = target
        return target
