"""Deterministic remediation classification and cause-cleared check (spec L1)."""

from datetime import datetime

from pydantic import BaseModel, Field

from core.evidence.conventions import CAUSE_CLEARED_FOR, FIX_ATTESTATION
from core.models.enums import (
    ConfidenceLevel,
    EvidenceCategory,
    RemediationClass,
    RerunSafety,
    TemporalLabel,
)
from core.models.evidence import EvidenceItem
from core.taxonomy.categories import FailureCategory

FC = FailureCategory

# --------------------------------------------------------------------------- cause cleared

# Evidence categories that can show the cause has changed, per failure category.
CAUSE_CLEARED_CATEGORIES: dict[FailureCategory, frozenset[EvidenceCategory]] = {
    FC.NETWORK_CONNECTIVITY: frozenset(
        {EvidenceCategory.RUN_HISTORY, EvidenceCategory.NETWORK, EvidenceCategory.INFRASTRUCTURE}
    ),
    FC.INFRASTRUCTURE: frozenset({EvidenceCategory.RUN_HISTORY, EvidenceCategory.INFRASTRUCTURE}),
    FC.RESOURCE_QUOTA: frozenset({EvidenceCategory.RUN_HISTORY, EvidenceCategory.RESOURCE}),
    FC.UPSTREAM_DEPENDENCY: frozenset({EvidenceCategory.UPSTREAM, EvidenceCategory.RUN_HISTORY}),
    FC.CONCURRENCY: frozenset({EvidenceCategory.RUN_HISTORY, EvidenceCategory.STATE}),
    FC.ORCHESTRATION_STATE: frozenset({EvidenceCategory.RUN_HISTORY, EvidenceCategory.STATE}),
}


class CauseClearedResult(BaseModel):
    accepted_ids: list[str] = Field(default_factory=list)
    rejected: dict[str, str] = Field(default_factory=dict)

    @property
    def cleared(self) -> bool:
        return bool(self.accepted_ids)


def check_cause_cleared(
    category: FailureCategory,
    candidates: list[EvidenceItem],
    failure_time: datetime | None,
) -> CauseClearedResult:
    """Accept only CURRENT items collected (and, if timestamped, observed) after the failure,
    whose evidence category can demonstrate the cause changed for this failure category.

    Without a known failure time nothing can be proven to be 'after', so nothing is accepted.
    A candidate that declares ``cause_cleared_for`` speaks only to those failure categories.
    A human fix attestation (L10) is accepted only for manual-fix categories, where the fix
    happens outside the system; it never stands in for evidence of a transient cause clearing.
    """
    result = CauseClearedResult()
    allowed = CAUSE_CLEARED_CATEGORIES.get(category, frozenset())
    for item in candidates:
        eid = item.evidence_id
        scoped = item.metadata.get(CAUSE_CLEARED_FOR)
        attested = item.metadata.get(FIX_ATTESTATION) is True
        if isinstance(scoped, list) and category.value not in scoped:
            result.rejected[eid] = f"candidate speaks only to {scoped}, not {category.value}"
            continue
        if attested:
            if category not in MANUAL_CATEGORIES:
                result.rejected[eid] = f"a fix attestation cannot show a {category.value} cause cleared"
            elif failure_time is None or item.temporal_label is not TemporalLabel.CURRENT:
                result.rejected[eid] = "attestation is not CURRENT or the failure time is unknown"
            elif item.provenance.collected_at <= failure_time:
                result.rejected[eid] = "attestation recorded before the failure"
            else:
                result.accepted_ids.append(eid)
            continue
        if failure_time is None:
            result.rejected[eid] = "failure time unknown; cannot prove evidence is after the failure"
        elif item.temporal_label is not TemporalLabel.CURRENT:
            result.rejected[eid] = f"temporal label {item.temporal_label.value} is not CURRENT"
        elif item.provenance.collected_at <= failure_time:
            result.rejected[eid] = "collected before or at the failure time"
        elif item.timestamp is not None and item.timestamp <= failure_time:
            result.rejected[eid] = "observed signal predates the failure"
        elif item.category not in allowed:
            result.rejected[eid] = (
                f"category {item.category.value} cannot show the cause cleared for {category.value}"
            )
        else:
            result.accepted_ids.append(eid)
    return result


# --------------------------------------------------------------------------- classification

MANUAL_CATEGORIES = frozenset(
    {
        FC.SOURCE_SCHEMA_DRIFT,
        FC.CODE_LOGIC_BUG,
        FC.CONFIGURATION,
        FC.SECURITY_AUTHORIZATION,
        FC.VOLUME_ANOMALY,
    }
)

# (category -> subcategories that are automatable; None = every subcategory, including unset)
AUTOMATABLE_SUBCATEGORIES: dict[FailureCategory, frozenset[str] | None] = {
    FC.NETWORK_CONNECTIVITY: None,
    FC.INFRASTRUCTURE: frozenset({"node_loss", "cluster_terminated"}),  # transient infra only
    FC.RESOURCE_QUOTA: frozenset({"throttling"}),
    FC.ORCHESTRATION_STATE: frozenset({"stuck_state", "scheduler_issue"}),
    FC.UPSTREAM_DEPENDENCY: None,
    FC.CONCURRENCY: None,
}


class ClassificationInput(BaseModel):
    category: FailureCategory
    subcategory: str | None = None
    root_cause_known: bool
    diagnostic_confidence: ConfidenceLevel
    rerun_safety: RerunSafety
    remediation_confidence: ConfidenceLevel
    cause_cleared_evidence_ids: list[str] = Field(default_factory=list)
    transient_recovered: bool = False
    dq_gate_worked_as_designed: bool = False
    dq_target_corrupted: bool | None = None
    dq_bad_records_quarantined: bool | None = None
    overlapping_run_active: bool | None = None
    fix_attested: bool = False


class ClassificationResult(BaseModel):
    remediation_class: RemediationClass
    rule: str
    reason: str


def _is_automatable_category(category: FailureCategory, subcategory: str | None) -> bool:
    if category not in AUTOMATABLE_SUBCATEGORIES:
        return False
    allowed = AUTOMATABLE_SUBCATEGORIES[category]
    if allowed is None:
        return True
    return subcategory in allowed


def classify_remediation(inp: ClassificationInput) -> ClassificationResult:
    """Apply the L1 eligibility table. Returns the first matching row, in this priority order."""
    R = RemediationClass
    if inp.transient_recovered or inp.category is FC.TRANSIENT_RECOVERED:
        return ClassificationResult(
            remediation_class=R.NO_ACTION_REQUIRED,
            rule="L1.transient_recovered",
            reason="a later attempt succeeded; nothing is broken, never retry again",
        )

    if inp.category is FC.DATA_QUALITY:
        if (
            inp.dq_gate_worked_as_designed
            and inp.dq_target_corrupted is False
            and inp.dq_bad_records_quarantined is True
        ):
            return ClassificationResult(
                remediation_class=R.NO_ACTION_REQUIRED,
                rule="L1.dq_gate_worked",
                reason="the DQ gate appears to have worked as designed; no target corruption, bad records quarantined",
            )
        return ClassificationResult(
            remediation_class=R.MANUAL_FIX_REQUIRED,
            rule="L1.dq_violation",
            reason="data quality violation with possible target corruption or unquarantined bad data",
        )

    if not inp.root_cause_known or inp.category is FC.OTHER_UNKNOWN:
        return ClassificationResult(
            remediation_class=R.MANUAL_FIX_REQUIRED,
            rule="L1.unknown_failure",
            reason="root cause unknown; no plan",
        )

    # L10 manual-fix loop: once an engineer attests the fix, a manual-category failure may be
    # re-run, but only through every remaining gate below (safety, cause cleared, confidence).
    attested_manual = inp.fix_attested and inp.category in MANUAL_CATEGORIES
    if not attested_manual and (
        inp.category in MANUAL_CATEGORIES or not _is_automatable_category(inp.category, inp.subcategory)
    ):
        return ClassificationResult(
            remediation_class=R.MANUAL_FIX_REQUIRED,
            rule="L1.manual_category",
            reason=f"{inp.category.value}/{inp.subcategory or '-'} requires a human to fix the cause",
        )

    if inp.category is FC.CONCURRENCY and inp.overlapping_run_active is True:
        return ClassificationResult(
            remediation_class=R.BLOCKED,
            rule="L1.concurrency_active",
            reason="the overlapping run is still active",
        )

    if inp.rerun_safety in (RerunSafety.UNSAFE, RerunSafety.UNKNOWN):
        return ClassificationResult(
            remediation_class=R.BLOCKED,
            rule="L1.rerun_unsafe",
            reason=f"rerun safety is {inp.rerun_safety.value}; rerun-type actions are blocked (no override)",
        )

    if not inp.cause_cleared_evidence_ids:
        return ClassificationResult(
            remediation_class=R.MANUAL_FIX_REQUIRED,
            rule="L1.cause_not_cleared",
            reason="no CURRENT evidence shows the cause has cleared",
        )

    if inp.remediation_confidence is ConfidenceLevel.LOW:
        return ClassificationResult(
            remediation_class=R.MANUAL_FIX_REQUIRED,
            rule="L1.low_remediation_confidence",
            reason="remediation confidence LOW",
        )

    return ClassificationResult(
        remediation_class=R.AUTOMATABLE,
        rule="L1.automatable",
        reason=("engineer attested the fix; " if attested_manual else "automatable category, ")
        + "cause cleared, rerun safety and remediation confidence permit a plan",
    )
