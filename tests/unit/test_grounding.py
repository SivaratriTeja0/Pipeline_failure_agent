"""Grounding validator."""

from core.models import Claim, ClaimKind, EvidenceCategory, ReportStatus, TemporalLabel
from core.reasoning.grounding import validate_grounding
from tests.factories import evidence


def test_grounded_claims_pass():
    ev = [evidence("e1", category=EvidenceCategory.LOG)]
    claims = [Claim(claim_id="c", text="t", kind=ClaimKind.FACT, evidence_ids=["e1"],
                    evidence_categories=[EvidenceCategory.LOG]),
              Claim(claim_id="r", text="rec", kind=ClaimKind.RECOMMENDATION)]
    result = validate_grounding(claims, ev)
    assert result.grounded and result.report_status() is ReportStatus.COMPLETE


def test_unknown_or_hypothesis_id_is_ungrounded():
    claims = [Claim(claim_id="c", text="t", kind=ClaimKind.INFERENCE, evidence_ids=["hyp-1"])]
    result = validate_grounding(claims, [evidence("e1")])
    assert not result.grounded
    assert result.report_status() is ReportStatus.INCOMPLETE_UNGROUNDED


def test_mismatched_evidence_cannot_ground():
    claims = [Claim(claim_id="c", text="t", kind=ClaimKind.FACT, evidence_ids=["e1"])]
    result = validate_grounding(claims, [evidence("e1", temporal_label=TemporalLabel.MISMATCHED)])
    assert not result.grounded


def test_declared_category_must_be_backed():
    claims = [Claim(claim_id="c", text="t", kind=ClaimKind.FACT, evidence_ids=["e1"],
                    evidence_categories=[EvidenceCategory.SCHEMA])]
    assert not validate_grounding(claims, [evidence("e1", category=EvidenceCategory.LOG)]).grounded
