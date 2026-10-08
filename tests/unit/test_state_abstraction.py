"""State abstraction (Rule 5, C4): five statuses stay distinct; never 'unchanged' by default."""

import pytest
from pydantic import ValidationError

from core.models import Reliability, StateEvidence, StateMechanism, StateStatus
from core.safety.state import ResolvedState, is_proven_unchanged, resolve_state


def se(mechanism: StateMechanism, status: StateStatus) -> StateEvidence:
    return StateEvidence(mechanism=mechanism, status=status, source="t", execution_id="r",
                         reliability=Reliability.HIGH)


def test_five_statuses_are_distinct_values():
    values = {s.value for s in StateStatus}
    assert values == {"NOT_APPLICABLE", "UNAVAILABLE", "UNKNOWN", "AVAILABLE_BUT_UNCHANGED",
                      "AVAILABLE_AND_CHANGED"}
    assert len(values) == 5


@pytest.mark.parametrize(
    "evidence,expected",
    [
        (se(StateMechanism.NONE, StateStatus.NOT_APPLICABLE), ResolvedState.NOT_APPLICABLE),
        (se(StateMechanism.WATERMARK, StateStatus.UNAVAILABLE), ResolvedState.UNAVAILABLE),
        (se(StateMechanism.WATERMARK, StateStatus.UNKNOWN), ResolvedState.UNKNOWN),
        (se(StateMechanism.WATERMARK, StateStatus.AVAILABLE_BUT_UNCHANGED), ResolvedState.UNCHANGED),
        (se(StateMechanism.WATERMARK, StateStatus.AVAILABLE_AND_CHANGED), ResolvedState.CHANGED),
    ],
)
def test_each_status_resolves_to_its_own_distinct_value(evidence, expected):
    declared = evidence.mechanism
    assert resolve_state(declared, evidence) is expected


@pytest.mark.parametrize("status", [StateStatus.UNAVAILABLE, StateStatus.UNKNOWN])
def test_unavailable_and_unknown_are_never_unchanged(status):
    resolved = resolve_state(StateMechanism.CHECKPOINT, se(StateMechanism.CHECKPOINT, status))
    assert resolved is not ResolvedState.UNCHANGED
    assert not is_proven_unchanged(resolved)


def test_missing_evidence_for_concrete_mechanism_is_unavailable():
    assert resolve_state(StateMechanism.KAFKA_OFFSET, None) is ResolvedState.UNAVAILABLE


def test_watermark_is_not_assumed_for_unknown_mechanism():
    assert resolve_state(StateMechanism.UNKNOWN, None) is ResolvedState.UNKNOWN


def test_unrelated_mechanism_evidence_is_unknown():
    ev = se(StateMechanism.WATERMARK, StateStatus.AVAILABLE_BUT_UNCHANGED)
    assert resolve_state(StateMechanism.DELTA_VERSION, ev) is ResolvedState.UNKNOWN


def test_declared_none_contradicted_by_concrete_evidence_is_unknown():
    ev = se(StateMechanism.CHECKPOINT, StateStatus.AVAILABLE_AND_CHANGED)
    assert resolve_state(StateMechanism.NONE, ev) is ResolvedState.UNKNOWN


@pytest.mark.parametrize(
    "mechanism,status",
    [
        (StateMechanism.NONE, StateStatus.AVAILABLE_BUT_UNCHANGED),
        (StateMechanism.WATERMARK, StateStatus.NOT_APPLICABLE),
        (StateMechanism.UNKNOWN, StateStatus.AVAILABLE_BUT_UNCHANGED),
        (StateMechanism.UNKNOWN, StateStatus.AVAILABLE_AND_CHANGED),
    ],
)
def test_inconsistent_mechanism_status_rejected(mechanism, status):
    with pytest.raises(ValidationError):
        se(mechanism, status)


def test_all_mechanisms_supported_and_watermark_is_one_of_many():
    names = {m.value for m in StateMechanism}
    assert {"watermark", "checkpoint", "batch_id", "kafka_offset", "delta_version", "cursor",
            "transaction_id", "control_table", "partition_state", "job_state", "none", "unknown"} == names
