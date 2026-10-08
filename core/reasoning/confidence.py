"""Deterministic diagnostic confidence (spec Part G).

HIGH:   >=2 supporting items from >=2 categories; >=1 HIGH-reliability item; no unresolved
        MEDIUM/HIGH contradiction; all supporting evidence CURRENT; no unavailable capability
        that would have tested the top rival hypothesis.
MEDIUM: one HIGH or two (>=)MEDIUM supporting items; contradictions only LOW reliability.
LOW:    everything else, including any UNKNOWN root cause.

MISMATCHED evidence never influences confidence. STALE evidence does not count as support.
Contradictions with UNKNOWN reliability are treated as non-LOW (conservative).
"""

from pydantic import BaseModel

from core.models.enums import ConfidenceLevel, Reliability, TemporalLabel
from core.models.evidence import EvidenceItem
from core.models.reasoning import BasisCondition
from core.reasoning.levels import apply_llm_ceiling, reliability_at_least_medium

_USABLE_SUPPORT = (TemporalLabel.CURRENT, TemporalLabel.HISTORICAL)


class ConfidenceResult(BaseModel):
    level: ConfidenceLevel
    deterministic_level: ConfidenceLevel
    basis: list[BasisCondition]


def compute_diagnostic_confidence(
    *,
    root_cause_known: bool,
    supporting: list[EvidenceItem],
    contradicting: list[EvidenceItem],
    rival_test_capability_unavailable: bool,
    llm_suggested: ConfidenceLevel | None = None,
) -> ConfidenceResult:
    support = [e for e in supporting if e.temporal_label in _USABLE_SUPPORT]
    contra = [e for e in contradicting if e.temporal_label is not TemporalLabel.MISMATCHED]
    excluded = [e.evidence_id for e in supporting if e.temporal_label not in _USABLE_SUPPORT]

    high_items = [e for e in support if e.reliability is Reliability.HIGH]
    medium_plus = [e for e in support if reliability_at_least_medium(e.reliability)]
    categories = {e.category for e in support}
    strong_contra = [e for e in contra if e.reliability is not Reliability.LOW]

    basis = [
        BasisCondition(name="root_cause_known", passed=root_cause_known),
        BasisCondition(
            name="excluded_stale_or_mismatched_support",
            passed=not excluded,
            detail=", ".join(excluded),
        ),
        BasisCondition(name="support_count>=2", passed=len(support) >= 2, detail=str(len(support))),
        BasisCondition(name="support_categories>=2", passed=len(categories) >= 2, detail=str(len(categories))),
        BasisCondition(name="has_high_reliability_support", passed=bool(high_items)),
        BasisCondition(name="two_medium_or_better_support", passed=len(medium_plus) >= 2),
        BasisCondition(
            name="no_medium_or_high_contradiction",
            passed=not strong_contra,
            detail=", ".join(e.evidence_id for e in strong_contra),
        ),
        BasisCondition(
            name="all_support_current",
            passed=bool(support) and not excluded
            and all(e.temporal_label is TemporalLabel.CURRENT for e in support),
        ),
        BasisCondition(
            name="rival_hypothesis_testable",
            passed=not rival_test_capability_unavailable,
        ),
    ]
    passed = {b.name: b.passed for b in basis}

    if not root_cause_known:
        level = ConfidenceLevel.LOW
    elif all(
        passed[n]
        for n in (
            "support_count>=2",
            "support_categories>=2",
            "has_high_reliability_support",
            "no_medium_or_high_contradiction",
            "all_support_current",
            "rival_hypothesis_testable",
        )
    ):
        level = ConfidenceLevel.HIGH
    elif (passed["has_high_reliability_support"] or passed["two_medium_or_better_support"]) and passed[
        "no_medium_or_high_contradiction"
    ]:
        level = ConfidenceLevel.MEDIUM
    else:
        level = ConfidenceLevel.LOW

    final = apply_llm_ceiling(level, llm_suggested)
    if final is not level:
        basis.append(BasisCondition(name="llm_lowered", passed=True, detail=f"{level.value}->{final.value}"))
    return ConfidenceResult(level=final, deterministic_level=level, basis=basis)
