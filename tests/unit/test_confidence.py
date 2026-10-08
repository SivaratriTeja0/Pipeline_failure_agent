"""Diagnostic confidence (Part G) and remediation confidence (L4)."""

import pytest

from core.models import ConfidenceLevel, EvidenceCategory, Reliability, RerunSafety, TemporalLabel
from core.reasoning.confidence import compute_diagnostic_confidence
from core.reasoning.remediation_confidence import compute_remediation_confidence
from tests.factories import evidence

H, M, L = ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW


def strong_support():
    return [
        evidence("e1", category=EvidenceCategory.LOG, reliability=Reliability.HIGH),
        evidence("e2", category=EvidenceCategory.RUN_HISTORY, reliability=Reliability.MEDIUM),
    ]


def diag(**kw):
    kw.setdefault("root_cause_known", True)
    kw.setdefault("supporting", strong_support())
    kw.setdefault("contradicting", [])
    kw.setdefault("rival_test_capability_unavailable", False)
    return compute_diagnostic_confidence(**kw)


# ---------------------------------------------------------------- diagnostic


def test_high_when_all_conditions_met():
    r = diag()
    assert r.level is H
    assert all(b.passed for b in r.basis)


def test_unknown_root_cause_is_low():
    assert diag(root_cause_known=False).level is L


def test_single_category_is_medium_not_high():
    support = [evidence("e1", reliability=Reliability.HIGH), evidence("e2", reliability=Reliability.HIGH)]
    assert diag(supporting=support).level is M


def test_non_current_support_prevents_high():
    support = strong_support()
    support[1] = evidence("e2", category=EvidenceCategory.RUN_HISTORY, temporal_label=TemporalLabel.HISTORICAL)
    assert diag(supporting=support).level is M


def test_unavailable_rival_test_capability_prevents_high():
    assert diag(rival_test_capability_unavailable=True).level is M


def test_medium_contradiction_prevents_high_and_medium():
    contra = [evidence("x", reliability=Reliability.MEDIUM)]
    assert diag(contradicting=contra).level is L


def test_low_reliability_contradiction_does_not_block_high():
    contra = [evidence("x", reliability=Reliability.LOW)]
    assert diag(contradicting=contra).level is H


def test_unknown_reliability_contradiction_is_treated_conservatively():
    contra = [evidence("x", reliability=Reliability.UNKNOWN)]
    assert diag(contradicting=contra).level is L


def test_one_high_item_is_medium():
    assert diag(supporting=[evidence("e1", reliability=Reliability.HIGH)]).level is M


def test_two_medium_items_is_medium():
    s = [evidence("e1", reliability=Reliability.MEDIUM), evidence("e2", reliability=Reliability.MEDIUM)]
    assert diag(supporting=s).level is M


def test_one_medium_item_is_low():
    assert diag(supporting=[evidence("e1", reliability=Reliability.MEDIUM)]).level is L


def test_mismatched_evidence_never_influences_confidence():
    s = [evidence("e1", reliability=Reliability.HIGH, temporal_label=TemporalLabel.MISMATCHED),
         evidence("e2", category=EvidenceCategory.RUN_HISTORY, reliability=Reliability.HIGH,
                  temporal_label=TemporalLabel.MISMATCHED)]
    assert diag(supporting=s).level is L
    contra = [evidence("x", reliability=Reliability.HIGH, temporal_label=TemporalLabel.MISMATCHED)]
    assert diag(contradicting=contra).level is H


def test_llm_may_lower_but_never_raise():
    assert diag(llm_suggested=L).level is L
    r = diag(supporting=[evidence("e1", reliability=Reliability.HIGH)], llm_suggested=H)
    assert r.level is M and r.deterministic_level is M


def test_basis_lists_every_condition():
    names = {b.name for b in diag().basis}
    assert {"support_count>=2", "support_categories>=2", "has_high_reliability_support",
            "no_medium_or_high_contradiction", "all_support_current", "rival_hypothesis_testable"} <= names


# ---------------------------------------------------------------- remediation (L4)


def rem(**kw):
    kw.setdefault("diagnostic_confidence", H)
    kw.setdefault("rerun_safety", RerunSafety.SAFE)
    kw.setdefault("cause_cleared_items", [evidence("cc", category=EvidenceCategory.RUN_HISTORY)])
    kw.setdefault("same_action_previously_failed", False)
    kw.setdefault("cause_cleared_test_capability_unavailable", False)
    return compute_remediation_confidence(**kw)


def test_remediation_high():
    r = rem()
    assert r.level is H and r.permits_automation


@pytest.mark.parametrize(
    "override",
    [
        {"diagnostic_confidence": M},
        {"rerun_safety": RerunSafety.SAFE_WITH_CONDITIONS},
        {"cause_cleared_items": [evidence("cc", reliability=Reliability.MEDIUM)]},
        {"cause_cleared_test_capability_unavailable": True},
    ],
)
def test_remediation_medium_cases(override):
    assert rem(**override).level is M


@pytest.mark.parametrize(
    "override",
    [
        {"diagnostic_confidence": L},
        {"rerun_safety": RerunSafety.UNKNOWN},
        {"rerun_safety": RerunSafety.UNSAFE},
        {"cause_cleared_items": []},
        {"cause_cleared_items": [evidence("cc", reliability=Reliability.LOW)]},
        {"cause_cleared_items": [evidence("cc", temporal_label=TemporalLabel.MISMATCHED)]},
        {"same_action_previously_failed": True},
    ],
)
def test_remediation_low_cases(override):
    r = rem(**override)
    assert r.level is L and not r.permits_automation


def test_remediation_high_requires_current_high_item():
    r = rem(cause_cleared_items=[evidence("cc", temporal_label=TemporalLabel.HISTORICAL)])
    assert r.level is M


def test_remediation_llm_cannot_raise():
    r = rem(diagnostic_confidence=M, llm_suggested=H)
    assert r.level is M
    assert rem(llm_suggested=L).level is L
