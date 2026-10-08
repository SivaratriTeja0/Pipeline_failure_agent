"""Grounding validator: FACT/INFERENCE claims may cite only collected EvidenceItems.

A report may be COMPLETE only if every claim is grounded. Citations of unknown ids (e.g.
hypothesis ids or invented ids), MISMATCHED evidence, or wrong evidence categories fail.
"""

from collections.abc import Iterable

from pydantic import BaseModel, Field

from core.models.enums import ClaimKind, ReportStatus, TemporalLabel
from core.models.evidence import EvidenceItem
from core.models.reasoning import Claim


class GroundingIssue(BaseModel):
    claim_id: str
    problem: str


class GroundingResult(BaseModel):
    grounded: bool
    issues: list[GroundingIssue] = Field(default_factory=list)

    def report_status(self) -> ReportStatus:
        return ReportStatus.COMPLETE if self.grounded else ReportStatus.INCOMPLETE_UNGROUNDED


def validate_grounding(claims: Iterable[Claim], evidence: Iterable[EvidenceItem]) -> GroundingResult:
    by_id = {e.evidence_id: e for e in evidence}
    issues: list[GroundingIssue] = []
    for claim in claims:
        if claim.kind is ClaimKind.RECOMMENDATION and not claim.evidence_ids:
            continue
        if claim.kind in (ClaimKind.FACT, ClaimKind.INFERENCE) and not claim.evidence_ids:
            issues.append(GroundingIssue(claim_id=claim.claim_id, problem="no evidence cited"))
            continue
        cited_categories = set()
        for eid in claim.evidence_ids:
            item = by_id.get(eid)
            if item is None:
                issues.append(GroundingIssue(claim_id=claim.claim_id, problem=f"unknown evidence id {eid!r}"))
                continue
            if item.temporal_label is TemporalLabel.MISMATCHED:
                issues.append(
                    GroundingIssue(claim_id=claim.claim_id, problem=f"evidence {eid!r} is MISMATCHED")
                )
            cited_categories.add(item.category)
        for category in claim.evidence_categories:
            if category not in cited_categories:
                issues.append(
                    GroundingIssue(
                        claim_id=claim.claim_id,
                        problem=f"declared category {category.value} not backed by cited evidence",
                    )
                )
    return GroundingResult(grounded=not issues, issues=issues)
