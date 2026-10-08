"""Rerun safety (Part F): one test per rule R1-R13, plus conflict resolution."""

import pytest

from core.models import (
    ConcurrencyStatus,
    DQGateFinding,
    FailureStage,
    Reliability,
    RerunSafety,
    StateEvidence,
    StateMechanism,
    StateStatus,
    TargetWrite,
    TaskExecutionPolicy,
    TaskType,
)
from core.safety.rerun_safety import RerunSafetyInput, evaluate_rerun_safety, most_conservative

S = RerunSafety


def policy(idempotent: bool | None, mechanism: StateMechanism = StateMechanism.NONE) -> TaskExecutionPolicy:
    return TaskExecutionPolicy(task_type=TaskType.UPSERT, idempotent=idempotent, state_mechanism=mechanism)


def state(mechanism: StateMechanism, status: StateStatus) -> StateEvidence:
    return StateEvidence(mechanism=mechanism, status=status, source="t", execution_id="run-1",
                         reliability=Reliability.HIGH)


def run(**kw) -> tuple[RerunSafety, dict]:
    kw.setdefault("concurrency", ConcurrencyStatus.NONE_CONFIRMED)
    result = evaluate_rerun_safety(RerunSafetyInput(**kw))
    matched = {t.rule: t for t in result.rule_trace if t.matched}
    return result.outcome, matched


def test_trace_records_every_rule():
    result = evaluate_rerun_safety(RerunSafetyInput(policy=policy(True)))
    assert [t.rule for t in result.rule_trace] == [f"R{i}" for i in range(1, 14)]


@pytest.mark.parametrize("idem", [False, None])
def test_r1_committed_non_idempotent_or_unknown_is_unsafe(idem):
    outcome, matched = run(policy=policy(idem), target_write=TargetWrite.COMMITTED)
    assert "R1" in matched and matched["R1"].outcome is S.UNSAFE
    assert outcome is S.UNSAFE


def test_r2_committed_idempotent_is_safe_with_conditions():
    outcome, matched = run(policy=policy(True), target_write=TargetWrite.COMMITTED)
    assert "R2" in matched and outcome is S.SAFE_WITH_CONDITIONS


def test_r3_partial_confirmed_non_idempotent_is_unsafe():
    outcome, matched = run(policy=policy(False), target_write=TargetWrite.PARTIAL_CONFIRMED)
    assert matched["R3"].outcome is S.UNSAFE and outcome is S.UNSAFE


def test_r3_partial_confirmed_idempotency_unknown_is_unknown():
    outcome, matched = run(policy=policy(None), target_write=TargetWrite.PARTIAL_CONFIRMED)
    assert matched["R3"].outcome is S.UNKNOWN and outcome is S.UNKNOWN


def test_r4_partial_confirmed_idempotent_is_safe_with_conditions():
    outcome, matched = run(policy=policy(True), target_write=TargetWrite.PARTIAL_CONFIRMED)
    assert "R4" in matched and outcome is S.SAFE_WITH_CONDITIONS


def test_r5_partial_possible_non_idempotent_is_unsafe():
    outcome, matched = run(policy=policy(False), target_write=TargetWrite.PARTIAL_POSSIBLE)
    assert matched["R5"].outcome is S.UNSAFE and outcome is S.UNSAFE


def test_r5_partial_possible_idempotency_unknown_is_unknown():
    outcome, matched = run(policy=policy(None), target_write=TargetWrite.PARTIAL_POSSIBLE)
    assert matched["R5"].outcome is S.UNKNOWN and outcome is S.UNKNOWN


def test_r6_overlap_confirmed_non_idempotent_is_unsafe():
    outcome, matched = run(policy=policy(False), target_write=TargetWrite.NONE_CONFIRMED,
                           concurrency=ConcurrencyStatus.OVERLAP_CONFIRMED)
    assert matched["R6"].outcome is S.UNSAFE and outcome is S.UNSAFE


def test_r6_overlap_confirmed_otherwise_is_unknown():
    outcome, matched = run(policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
                           concurrency=ConcurrencyStatus.OVERLAP_CONFIRMED)
    assert matched["R6"].outcome is S.UNKNOWN and outcome is S.UNKNOWN


def test_r7_unknown_concurrency_caps_at_safe_with_conditions_at_planning():
    result = evaluate_rerun_safety(RerunSafetyInput(
        policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
        concurrency=ConcurrencyStatus.UNKNOWN))
    assert result.outcome is S.SAFE_WITH_CONDITIONS  # R12 would be SAFE; R7 caps it
    assert any(c.source_rule == "R7" and c.machine_check == "no_concurrent_run" for c in result.conditions)


def test_r7_unknown_concurrency_at_execution_time_is_not_permitted():
    result = evaluate_rerun_safety(RerunSafetyInput(
        policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
        concurrency=ConcurrencyStatus.UNKNOWN, at_execution_time=True))
    assert result.outcome is S.UNKNOWN


def test_r7_alone_does_not_count_as_a_match_for_r13():
    result = evaluate_rerun_safety(RerunSafetyInput(
        policy=policy(None), target_write=TargetWrite.NONE_CONFIRMED,
        concurrency=ConcurrencyStatus.UNKNOWN))
    r13 = next(t for t in result.rule_trace if t.rule == "R13")
    assert r13.matched and result.outcome is S.UNKNOWN


def test_r8_target_write_unknown_is_unknown():
    outcome, matched = run(policy=policy(True), target_write=TargetWrite.UNKNOWN)
    assert "R8" in matched and outcome is S.UNKNOWN


@pytest.mark.parametrize("status", [StateStatus.UNAVAILABLE, StateStatus.UNKNOWN])
def test_r9_applicable_state_unavailable_or_unknown_is_unknown(status):
    outcome, matched = run(policy=policy(True, StateMechanism.WATERMARK),
                           state=state(StateMechanism.WATERMARK, status),
                           target_write=TargetWrite.NONE_CONFIRMED)
    assert "R9" in matched and outcome is S.UNKNOWN


def test_r9_missing_state_evidence_is_unavailable_not_unchanged():
    outcome, matched = run(policy=policy(True, StateMechanism.CHECKPOINT), state=None,
                           target_write=TargetWrite.NONE_CONFIRMED)
    assert "R9" in matched and "R12" not in matched and outcome is S.UNKNOWN


def test_r9_state_from_unrelated_mechanism_is_not_used():
    outcome, matched = run(policy=policy(True, StateMechanism.KAFKA_OFFSET),
                           state=state(StateMechanism.WATERMARK, StateStatus.AVAILABLE_BUT_UNCHANGED),
                           target_write=TargetWrite.NONE_CONFIRMED)
    assert "R9" in matched and "R12" not in matched and outcome is S.UNKNOWN


def test_r10_unknown_mechanism_without_proven_write_safety_is_unknown():
    outcome, matched = run(policy=policy(None, StateMechanism.UNKNOWN),
                           target_write=TargetWrite.NONE_CONFIRMED, failure_stage=FailureStage.MID_WRITE)
    assert "R10" in matched and outcome is S.UNKNOWN


def test_r10_does_not_fire_when_write_safety_is_proven():
    _, matched = run(policy=policy(True, StateMechanism.UNKNOWN), target_write=TargetWrite.NONE_CONFIRMED)
    assert "R10" not in matched


def test_r11_dq_gate_failed_pre_write_with_retry_is_safe_with_conditions():
    outcome, matched = run(policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
                           failure_stage=FailureStage.PRE_WRITE, dq_gate=DQGateFinding.FAILED,
                           retry_supported=True)
    assert "R11" in matched and outcome is S.SAFE_WITH_CONDITIONS


def test_r11_requires_retry_support():
    _, matched = run(policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
                     failure_stage=FailureStage.PRE_WRITE, dq_gate=DQGateFinding.FAILED,
                     retry_supported=False)
    assert "R11" not in matched


def test_r12_no_write_idempotent_state_unchanged_is_safe():
    outcome, matched = run(policy=policy(True, StateMechanism.WATERMARK),
                           state=state(StateMechanism.WATERMARK, StateStatus.AVAILABLE_BUT_UNCHANGED),
                           target_write=TargetWrite.NONE_CONFIRMED)
    assert "R12" in matched and outcome is S.SAFE


def test_r12_mechanism_none_not_applicable_is_safe():
    outcome, matched = run(policy=policy(True, StateMechanism.NONE),
                           target_write=TargetWrite.NONE_CONFIRMED)
    assert "R12" in matched and outcome is S.SAFE


def test_r12_state_changed_is_not_safe():
    outcome, matched = run(policy=policy(True, StateMechanism.WATERMARK),
                           state=state(StateMechanism.WATERMARK, StateStatus.AVAILABLE_AND_CHANGED),
                           target_write=TargetWrite.NONE_CONFIRMED)
    assert "R12" not in matched and outcome is S.UNKNOWN  # R13


def test_r13_no_rule_matched_is_unknown():
    outcome, matched = run(policy=policy(False), target_write=TargetWrite.NONE_CONFIRMED)
    assert set(matched) == {"R13"} and outcome is S.UNKNOWN


# ---------------------------------------------------------------- conflicts


def test_conflict_unsafe_beats_safe_with_conditions():
    # R1 (UNSAFE, committed+unknown idempotency) and R11 (SWC) both match.
    outcome, matched = run(policy=policy(None), target_write=TargetWrite.COMMITTED,
                           failure_stage=FailureStage.PRE_WRITE, dq_gate=DQGateFinding.FAILED,
                           retry_supported=True)
    assert {"R1", "R11"} <= set(matched) and outcome is S.UNSAFE


def test_conflict_unknown_beats_safe():
    # R12 would say SAFE, but R7 at execution time says UNKNOWN.
    result = evaluate_rerun_safety(RerunSafetyInput(
        policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
        concurrency=ConcurrencyStatus.UNKNOWN, at_execution_time=True))
    matched = {t.rule for t in result.rule_trace if t.matched}
    assert {"R7", "R12"} <= matched and result.outcome is S.UNKNOWN


def test_conflict_unsafe_beats_unknown():
    outcome, matched = run(policy=policy(False, StateMechanism.WATERMARK), state=None,
                           target_write=TargetWrite.PARTIAL_CONFIRMED)
    assert {"R3", "R9"} <= set(matched) and outcome is S.UNSAFE


def test_conflict_safe_with_conditions_beats_safe():
    outcome, matched = run(policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
                           failure_stage=FailureStage.PRE_WRITE, dq_gate=DQGateFinding.FAILED,
                           retry_supported=True)
    assert {"R11", "R12"} <= set(matched) and outcome is S.SAFE_WITH_CONDITIONS


def test_ordering():
    assert most_conservative([S.SAFE, S.UNSAFE, S.UNKNOWN, S.SAFE_WITH_CONDITIONS]) is S.UNSAFE
    assert most_conservative([S.SAFE, S.UNKNOWN, S.SAFE_WITH_CONDITIONS]) is S.UNKNOWN
    assert most_conservative([S.SAFE, S.SAFE_WITH_CONDITIONS]) is S.SAFE_WITH_CONDITIONS


def test_safe_has_no_conditions_and_reason_names_deciding_rules():
    result = evaluate_rerun_safety(RerunSafetyInput(
        policy=policy(True), target_write=TargetWrite.NONE_CONFIRMED,
        concurrency=ConcurrencyStatus.NONE_CONFIRMED))
    assert result.outcome is S.SAFE and result.conditions == [] and "R12" in result.reason
