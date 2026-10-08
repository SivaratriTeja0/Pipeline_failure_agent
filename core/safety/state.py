"""State abstraction (Rule 5, spec C4).

A watermark is one mechanism among many and is never assumed. The five statuses stay
distinct: UNAVAILABLE and UNKNOWN are never converted into 'unchanged', and evidence about
one mechanism is never used to infer the state of another.
"""

from enum import Enum

from core.models.enums import StateMechanism, StateStatus
from core.models.evidence import StateEvidence


class ResolvedState(str, Enum):
    """The state status as it applies to a task's declared mechanism."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"


_STATUS_TO_RESOLVED = {
    StateStatus.NOT_APPLICABLE: ResolvedState.NOT_APPLICABLE,
    StateStatus.UNAVAILABLE: ResolvedState.UNAVAILABLE,
    StateStatus.UNKNOWN: ResolvedState.UNKNOWN,
    StateStatus.AVAILABLE_BUT_UNCHANGED: ResolvedState.UNCHANGED,
    StateStatus.AVAILABLE_AND_CHANGED: ResolvedState.CHANGED,
}


def resolve_state(declared: StateMechanism, evidence: StateEvidence | None) -> ResolvedState:
    """Resolve state for the task's declared mechanism.

    - declared ``none``: NOT_APPLICABLE (no state to corrupt), unless contradictory evidence
      shows a concrete mechanism, in which case the declaration is in doubt -> UNKNOWN.
    - declared ``unknown``: UNKNOWN; nothing can be proven about an unknown mechanism.
    - declared concrete mechanism: evidence must be about that exact mechanism; missing
      evidence is UNAVAILABLE and evidence about another mechanism is UNKNOWN.
    """
    if declared is StateMechanism.NONE:
        if evidence is None or evidence.mechanism is StateMechanism.NONE:
            return ResolvedState.NOT_APPLICABLE
        return ResolvedState.UNKNOWN
    if declared is StateMechanism.UNKNOWN:
        if evidence is not None and evidence.status is StateStatus.UNAVAILABLE:
            return ResolvedState.UNAVAILABLE
        return ResolvedState.UNKNOWN
    if evidence is None:
        return ResolvedState.UNAVAILABLE
    if evidence.mechanism is not declared:
        return ResolvedState.UNKNOWN
    return _STATUS_TO_RESOLVED[evidence.status]


def is_proven_unchanged(resolved: ResolvedState) -> bool:
    """Only an actual read showing no change counts as unchanged."""
    return resolved is ResolvedState.UNCHANGED
