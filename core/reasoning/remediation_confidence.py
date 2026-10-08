"""Deterministic remediation confidence (spec L4), separate from diagnostic confidence.

HIGH:   diagnostic HIGH; rerun_safety SAFE; a HIGH-reliability CURRENT cause-cleared item;
        same action not previously failed; no unavailable capability that would have tested
        whether the cause cleared.
MEDIUM: diagnostic >= MEDIUM; rerun_safety in {SAFE, SAFE_WITH_CONDITIONS}; cause-cleared
        evidence present with reliability >= MEDIUM; same action not previously failed.
LOW:    everything else. Only MEDIUM or HIGH may yield an AUTOMATABLE plan.
"""

from pydantic import BaseModel

from core.models.enums import ConfidenceLevel, Reliability, RerunSafety, TemporalLabel
from core.models.evidence import EvidenceItem
from core.models.reasoning import BasisCondition
from core.reasoning.levels import apply_llm_ceiling, at_least, reliability_at_least_medium


class RemediationConfidenceResult(BaseModel):
    level: ConfidenceLevel
    deterministic_level: ConfidenceLevel
    basis: list[BasisCondition]

    @property
    def permits_automation(self) -> bool:
        return self.level is not ConfidenceLevel.LOW


def compute_remediation_confidence(
    *,
    diagnostic_confidence: ConfidenceLevel,
    rerun_safety: RerunSafety,
    cause_cleared_items: list[EvidenceItem],
    same_action_previously_failed: bool,
    cause_cleared_test_capability_unavailable: bool,
    llm_suggested: ConfidenceLevel | None = None,
) -> RemediationConfidenceResult:
    usable = [e for e in cause_cleared_items if e.temporal_label is not TemporalLabel.MISMATCHED]
    high_current = [
        e for e in usable if e.reliability is Reliability.HIGH and e.temporal_label is TemporalLabel.CURRENT
    ]
    medium_plus = [e for e in usable if reliability_at_least_medium(e.reliability)]

    basis = [
        BasisCondition(name="diagnostic_high", passed=diagnostic_confidence is ConfidenceLevel.HIGH),
        BasisCondition(
            name="diagnostic_at_least_medium",
            passed=at_least(diagnostic_confidence, ConfidenceLevel.MEDIUM),
            detail=diagnostic_confidence.value,
        ),
        BasisCondition(name="rerun_safety_safe", passed=rerun_safety is RerunSafety.SAFE),
        BasisCondition(
            name="rerun_safety_permits",
            passed=rerun_safety in (RerunSafety.SAFE, RerunSafety.SAFE_WITH_CONDITIONS),
            detail=rerun_safety.value,
        ),
        BasisCondition(name="cause_cleared_high_current", passed=bool(high_current)),
        BasisCondition(name="cause_cleared_medium_or_better", passed=bool(medium_plus)),
        BasisCondition(name="action_not_previously_failed", passed=not same_action_previously_failed),
        BasisCondition(
            name="cause_clear_testable", passed=not cause_cleared_test_capability_unavailable
        ),
    ]
    p = {b.name: b.passed for b in basis}

    if all(
        p[n]
        for n in (
            "diagnostic_high",
            "rerun_safety_safe",
            "cause_cleared_high_current",
            "action_not_previously_failed",
            "cause_clear_testable",
        )
    ):
        level = ConfidenceLevel.HIGH
    elif all(
        p[n]
        for n in (
            "diagnostic_at_least_medium",
            "rerun_safety_permits",
            "cause_cleared_medium_or_better",
            "action_not_previously_failed",
        )
    ):
        level = ConfidenceLevel.MEDIUM
    else:
        level = ConfidenceLevel.LOW

    final = apply_llm_ceiling(level, llm_suggested)
    if final is not level:
        basis.append(BasisCondition(name="llm_lowered", passed=True, detail=f"{level.value}->{final.value}"))
    return RemediationConfidenceResult(level=final, deterministic_level=level, basis=basis)
