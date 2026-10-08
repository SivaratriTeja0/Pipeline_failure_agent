"""Deterministic rerun-safety engine (spec Part F). The LLM never determines rerun safety.

Every rule R1-R13 is evaluated and recorded in the rule trace. The result is the most
conservative outcome among matched rules: UNSAFE > UNKNOWN > SAFE_WITH_CONDITIONS > SAFE.

Interpretations (documented, conservative):
- R3 with idempotency unknown yields UNKNOWN (mirrors R5); the table is silent on it.
- R7 is a *cap*: it limits the result to SAFE_WITH_CONDITIONS but does not by itself count
  as a matching rule for R13. At execution time an unresolved concurrency yields UNKNOWN,
  which the healing path treats as BLOCKED.
- R9 applies to a declared concrete mechanism whose state is UNAVAILABLE/UNKNOWN (including
  evidence about a different mechanism). R10 applies when the mechanism itself is unknown.
- 'Write safety otherwise proven' (R10) = target write NONE_CONFIRMED and either the task is
  idempotent or the failure stage is PRE_WRITE.
"""

from collections.abc import Callable

from pydantic import BaseModel, Field

from core.models.enums import (
    ConcurrencyStatus,
    DQGateFinding,
    FailureStage,
    RerunSafety,
    StateMechanism,
    TargetWrite,
)
from core.models.evidence import StateEvidence
from core.models.policy import TaskExecutionPolicy
from core.models.reasoning import RuleEvaluation
from core.models.remediation import PlanCondition
from core.safety.state import ResolvedState, resolve_state

SEVERITY: dict[RerunSafety, int] = {
    RerunSafety.SAFE: 0,
    RerunSafety.SAFE_WITH_CONDITIONS: 1,
    RerunSafety.UNKNOWN: 2,
    RerunSafety.UNSAFE: 3,
}


def most_conservative(outcomes: list[RerunSafety]) -> RerunSafety:
    return max(outcomes, key=SEVERITY.__getitem__)


class RerunSafetyInput(BaseModel):
    policy: TaskExecutionPolicy
    state: StateEvidence | None = None
    target_write: TargetWrite = TargetWrite.UNKNOWN
    concurrency: ConcurrencyStatus = ConcurrencyStatus.UNKNOWN
    failure_stage: FailureStage = FailureStage.UNKNOWN
    dq_gate: DQGateFinding = DQGateFinding.NOT_APPLICABLE
    retry_supported: bool = False
    at_execution_time: bool = False


class RerunSafetyResult(BaseModel):
    outcome: RerunSafety
    reason: str
    rule_trace: list[RuleEvaluation]
    conditions: list[PlanCondition] = Field(default_factory=list)
    resolved_state: ResolvedState


class _Ctx:
    def __init__(self, inp: RerunSafetyInput) -> None:
        self.inp = inp
        self.idem = inp.policy.idempotent
        self.tw = inp.target_write
        self.mechanism = inp.policy.state_mechanism
        self.state = resolve_state(self.mechanism, inp.state)


_Rule = Callable[[_Ctx], RuleEvaluation]


def _r1(c: _Ctx) -> RuleEvaluation:
    hit = c.tw is TargetWrite.COMMITTED and c.idem is not True
    return RuleEvaluation(
        rule="R1",
        matched=hit,
        outcome=RerunSafety.UNSAFE if hit else None,
        detail="committed write; task non-idempotent or idempotency unknown" if hit else "",
    )


def _r2(c: _Ctx) -> RuleEvaluation:
    hit = c.tw is TargetWrite.COMMITTED and c.idem is True
    return RuleEvaluation(
        rule="R2",
        matched=hit,
        outcome=RerunSafety.SAFE_WITH_CONDITIONS if hit else None,
        detail="committed write; task idempotent" if hit else "",
    )


def _r3(c: _Ctx) -> RuleEvaluation:
    if c.tw is TargetWrite.PARTIAL_CONFIRMED and c.idem is False:
        return RuleEvaluation(rule="R3", matched=True, outcome=RerunSafety.UNSAFE,
                              detail="confirmed partial write; task non-idempotent")
    if c.tw is TargetWrite.PARTIAL_CONFIRMED and c.idem is None:
        return RuleEvaluation(rule="R3", matched=True, outcome=RerunSafety.UNKNOWN,
                              detail="confirmed partial write; idempotency unknown (conservative extension)")
    return RuleEvaluation(rule="R3", matched=False)


def _r4(c: _Ctx) -> RuleEvaluation:
    hit = c.tw is TargetWrite.PARTIAL_CONFIRMED and c.idem is True
    return RuleEvaluation(
        rule="R4",
        matched=hit,
        outcome=RerunSafety.SAFE_WITH_CONDITIONS if hit else None,
        detail="confirmed partial write; task idempotent" if hit else "",
    )


def _r5(c: _Ctx) -> RuleEvaluation:
    if c.tw is TargetWrite.PARTIAL_POSSIBLE and c.idem is False:
        return RuleEvaluation(rule="R5", matched=True, outcome=RerunSafety.UNSAFE,
                              detail="possible partial write; task non-idempotent")
    if c.tw is TargetWrite.PARTIAL_POSSIBLE and c.idem is None:
        return RuleEvaluation(rule="R5", matched=True, outcome=RerunSafety.UNKNOWN,
                              detail="possible partial write; idempotency unknown")
    return RuleEvaluation(rule="R5", matched=False)


def _r6(c: _Ctx) -> RuleEvaluation:
    if c.inp.concurrency is not ConcurrencyStatus.OVERLAP_CONFIRMED:
        return RuleEvaluation(rule="R6", matched=False)
    if c.idem is False:
        return RuleEvaluation(rule="R6", matched=True, outcome=RerunSafety.UNSAFE,
                              detail="overlapping run confirmed; task non-idempotent")
    return RuleEvaluation(rule="R6", matched=True, outcome=RerunSafety.UNKNOWN,
                          detail="overlapping run confirmed")


def _r7(c: _Ctx) -> RuleEvaluation:
    if c.inp.concurrency is not ConcurrencyStatus.UNKNOWN:
        return RuleEvaluation(rule="R7", matched=False, is_cap=True)
    if c.inp.at_execution_time:
        return RuleEvaluation(rule="R7", matched=True, is_cap=True, outcome=RerunSafety.UNKNOWN,
                              detail="concurrency unresolved at execution time -> BLOCKED")
    return RuleEvaluation(rule="R7", matched=True, is_cap=True,
                          outcome=RerunSafety.SAFE_WITH_CONDITIONS,
                          detail="concurrency unknown at planning time; capped, must confirm no concurrent run")


def _r8(c: _Ctx) -> RuleEvaluation:
    hit = c.tw is TargetWrite.UNKNOWN
    return RuleEvaluation(rule="R8", matched=hit, outcome=RerunSafety.UNKNOWN if hit else None,
                          detail="target write unknown" if hit else "")


def _r9(c: _Ctx) -> RuleEvaluation:
    concrete = c.mechanism not in (StateMechanism.NONE, StateMechanism.UNKNOWN)
    hit = concrete and c.state in (ResolvedState.UNAVAILABLE, ResolvedState.UNKNOWN)
    return RuleEvaluation(
        rule="R9",
        matched=hit,
        outcome=RerunSafety.UNKNOWN if hit else None,
        detail=f"state for mechanism '{c.mechanism.value}' is {c.state.value}" if hit else "",
    )


def _write_safety_proven(c: _Ctx) -> bool:
    return c.tw is TargetWrite.NONE_CONFIRMED and (
        c.idem is True or c.inp.failure_stage is FailureStage.PRE_WRITE
    )


def _r10(c: _Ctx) -> RuleEvaluation:
    hit = c.mechanism is StateMechanism.UNKNOWN and not _write_safety_proven(c)
    return RuleEvaluation(rule="R10", matched=hit, outcome=RerunSafety.UNKNOWN if hit else None,
                          detail="state mechanism unknown and write safety not proven" if hit else "")


def _r11(c: _Ctx) -> RuleEvaluation:
    hit = (
        c.inp.dq_gate is DQGateFinding.FAILED
        and c.inp.failure_stage is FailureStage.PRE_WRITE
        and c.inp.retry_supported
    )
    return RuleEvaluation(
        rule="R11",
        matched=hit,
        outcome=RerunSafety.SAFE_WITH_CONDITIONS if hit else None,
        detail="DQ gate failed before any write; retry supported" if hit else "",
    )


def _r12(c: _Ctx) -> RuleEvaluation:
    state_ok = c.state is ResolvedState.UNCHANGED or (
        c.mechanism is StateMechanism.NONE and c.state is ResolvedState.NOT_APPLICABLE
    )
    hit = c.tw is TargetWrite.NONE_CONFIRMED and c.idem is True and state_ok
    return RuleEvaluation(rule="R12", matched=hit, outcome=RerunSafety.SAFE if hit else None,
                          detail="no write, idempotent, state unchanged or not applicable" if hit else "")


_RULES: tuple[_Rule, ...] = (_r1, _r2, _r3, _r4, _r5, _r6, _r7, _r8, _r9, _r10, _r11, _r12)

_CONDITION_TEXT: dict[str, tuple[str, str | None]] = {
    "R2": ("Committed data will be rewritten; confirm the idempotent re-write is acceptable.", None),
    "R4": ("A partial write exists; confirm the idempotent re-write will reconcile it.", None),
    "R7": ("Confirm no concurrent run of this pipeline is active.", "no_concurrent_run"),
    "R11": ("DQ gate failed before writing; confirm the source data has been corrected.", None),
}


def evaluate_rerun_safety(inp: RerunSafetyInput) -> RerunSafetyResult:
    ctx = _Ctx(inp)
    trace = [rule(ctx) for rule in _RULES]
    outcome_rules_matched = [t for t in trace if t.matched and not t.is_cap]
    if outcome_rules_matched:
        trace.append(RuleEvaluation(rule="R13", matched=False))
    else:
        trace.append(RuleEvaluation(rule="R13", matched=True, outcome=RerunSafety.UNKNOWN,
                                    detail="no rule established safety"))

    matched = [t for t in trace if t.matched and t.outcome is not None]
    outcome = most_conservative([t.outcome for t in matched if t.outcome is not None])
    deciding = [t.rule for t in matched if t.outcome is outcome]

    conditions: list[PlanCondition] = []
    if outcome is RerunSafety.SAFE_WITH_CONDITIONS:
        for t in matched:
            if t.outcome is RerunSafety.SAFE_WITH_CONDITIONS and t.rule in _CONDITION_TEXT:
                text, machine_check = _CONDITION_TEXT[t.rule]
                conditions.append(
                    PlanCondition(condition_id=f"cond-{t.rule}", text=text, source_rule=t.rule,
                                  machine_check=machine_check)
                )

    return RerunSafetyResult(
        outcome=outcome,
        reason=f"{outcome.value} (deciding rules: {', '.join(deciding)})",
        rule_trace=trace,
        conditions=conditions,
        resolved_state=ctx.state,
    )
