"""Incident state machine (C12)."""

import pytest

from core.models import AuditEventType, IncidentState
from core.remediation.audit import AuditLog
from core.remediation.state_machine import (
    EXECUTION_PATH_STATES,
    PLAN_TERMINAL_STATES,
    TRANSITIONS,
    IllegalTransitionError,
    IncidentStateMachine,
)

S = IncidentState

HERO_PATH = [S.INVESTIGATING, S.DIAGNOSED, S.PLAN_PROPOSED, S.AWAITING_APPROVAL, S.APPROVED,
             S.POLICY_VALIDATING, S.REVALIDATING, S.EXECUTING, S.VERIFYING, S.RESOLVED]


def test_every_state_has_a_transition_entry():
    assert set(TRANSITIONS) == set(IncidentState)


def test_hero_path_is_legal_and_audited():
    log = AuditLog()
    sm = IncidentStateMachine("inc-1", log)
    for target in HERO_PATH:
        sm.transition(target)
    assert sm.state is S.RESOLVED
    events = log.events("inc-1")
    assert len(events) == len(HERO_PATH)
    assert all(e.event_type is AuditEventType.INCIDENT_STATE_CHANGED for e in events)
    assert log.verify().valid


@pytest.mark.parametrize(
    "start,target",
    [
        (S.DETECTED, S.EXECUTING),
        (S.DETECTED, S.APPROVED),
        (S.AWAITING_APPROVAL, S.EXECUTING),
        (S.AWAITING_APPROVAL, S.POLICY_VALIDATING),
        (S.PLAN_PROPOSED, S.APPROVED),
        (S.APPROVED, S.EXECUTING),
        (S.POLICY_VALIDATING, S.EXECUTING),
        (S.RESOLVED, S.INVESTIGATING),
        (S.MANUAL_FIX_REQUIRED, S.PLAN_PROPOSED),
        (S.EXECUTION_UNCERTAIN, S.EXECUTING),
    ],
)
def test_illegal_transitions_raise_and_do_not_audit(start, target):
    log = AuditLog()
    sm = IncidentStateMachine("inc-1", log, state=start)
    with pytest.raises(IllegalTransitionError):
        sm.transition(target)
    assert sm.state is start
    assert log.events() == ()


@pytest.mark.parametrize("terminal", sorted(PLAN_TERMINAL_STATES, key=lambda s: s.value))
def test_plan_terminal_states_never_lead_to_execution(terminal):
    # Breadth-first: no path from the terminal state reaches the execution path without
    # first going back through a fresh diagnosis / proposal (RE_INVESTIGATING -> DIAGNOSED ...).
    assert not (TRANSITIONS[terminal] & EXECUTION_PATH_STATES)
    assert S.AWAITING_APPROVAL not in TRANSITIONS[terminal]
    assert S.PLAN_PROPOSED not in TRANSITIONS[terminal]


def test_uncertain_execution_must_reconcile_never_redispatch():
    assert TRANSITIONS[S.EXECUTION_UNCERTAIN] == frozenset({S.RECONCILING})
    assert S.EXECUTING not in TRANSITIONS[S.RECONCILING]


def test_plan_edit_returns_to_proposed():
    sm = IncidentStateMachine("inc", AuditLog(), state=S.APPROVED)
    sm.transition(S.PLAN_PROPOSED, reason="plan edited; approvals void")
    assert sm.state is S.PLAN_PROPOSED
