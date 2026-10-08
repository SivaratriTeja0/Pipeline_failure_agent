"""Evidence freshness (spec Part H).

Detects STALE, MISMATCHED_EXECUTION, MISMATCHED_ATTEMPT and UNRELATED_RUN. Useful old
evidence (an earlier attempt of this execution, or an earlier investigation cycle) is
HISTORICAL. Mismatched evidence is labeled MISMATCHED and never influences confidence.
Precedence: MISMATCHED > STALE > HISTORICAL > CURRENT.
"""

from datetime import datetime, timedelta
from enum import Enum

from pydantic import BaseModel, Field

from core.models.enums import TemporalLabel
from core.models.evidence import EvidenceItem


class FreshnessIssue(str, Enum):
    STALE = "STALE"
    MISMATCHED_EXECUTION = "MISMATCHED_EXECUTION"
    MISMATCHED_ATTEMPT = "MISMATCHED_ATTEMPT"
    UNRELATED_RUN = "UNRELATED_RUN"
    EARLIER_ATTEMPT = "EARLIER_ATTEMPT"
    EARLIER_CYCLE = "EARLIER_CYCLE"


class FreshnessContext(BaseModel):
    pipeline_id: str
    execution_id: str
    attempt_number: int | None = None
    investigation_cycle: int = Field(default=1, ge=1)
    now: datetime
    max_age: timedelta = timedelta(hours=24)


class FreshnessAssessment(BaseModel):
    evidence_id: str
    label: TemporalLabel
    issues: list[FreshnessIssue] = Field(default_factory=list)


def assess_freshness(item: EvidenceItem, ctx: FreshnessContext) -> FreshnessAssessment:
    issues: list[FreshnessIssue] = []
    mismatched = False
    historical = False

    item_pipeline = item.metadata.get("pipeline_id")
    if item_pipeline is not None and item_pipeline != ctx.pipeline_id:
        issues.append(FreshnessIssue.UNRELATED_RUN)
        mismatched = True
    if item.execution_id != ctx.execution_id:
        issues.append(FreshnessIssue.MISMATCHED_EXECUTION)
        mismatched = True
    if item.attempt_number is not None and ctx.attempt_number is not None:
        if item.attempt_number > ctx.attempt_number:
            issues.append(FreshnessIssue.MISMATCHED_ATTEMPT)
            mismatched = True
        elif item.attempt_number < ctx.attempt_number:
            issues.append(FreshnessIssue.EARLIER_ATTEMPT)
            historical = True
    if item.provenance.investigation_cycle < ctx.investigation_cycle:
        issues.append(FreshnessIssue.EARLIER_CYCLE)
        historical = True
    elif item.provenance.investigation_cycle > ctx.investigation_cycle:
        issues.append(FreshnessIssue.MISMATCHED_EXECUTION)
        mismatched = True

    observed = item.timestamp or item.provenance.collected_at
    stale = ctx.now - observed > ctx.max_age
    if stale:
        issues.append(FreshnessIssue.STALE)

    if mismatched:
        label = TemporalLabel.MISMATCHED
    elif stale:
        label = TemporalLabel.STALE
    elif historical:
        label = TemporalLabel.HISTORICAL
    else:
        label = TemporalLabel.CURRENT
    return FreshnessAssessment(evidence_id=item.evidence_id, label=label, issues=issues)


def apply_freshness(items: list[EvidenceItem], ctx: FreshnessContext) -> list[EvidenceItem]:
    """Return copies of ``items`` with ``temporal_label`` set; issues recorded in metadata."""
    out: list[EvidenceItem] = []
    for item in items:
        assessment = assess_freshness(item, ctx)
        metadata = dict(item.metadata)
        metadata["freshness_issues"] = [i.value for i in assessment.issues]
        out.append(item.model_copy(update={"temporal_label": assessment.label, "metadata": metadata}))
    return out


def confidence_eligible(item: EvidenceItem) -> bool:
    return item.temporal_label is not TemporalLabel.MISMATCHED
