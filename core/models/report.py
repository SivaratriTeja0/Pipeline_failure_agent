"""UniversalTriageReport (C13)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from core.models.base import StrictModel, utcnow
from core.models.enums import (
    ActionCapability,
    ApprovalStatus,
    ConfidenceLevel,
    ExecutionStatus,
    IncidentState,
    LLMMode,
    ReadCapability,
    RemediationClass,
    ReportStatus,
    RerunSafety,
    StateMechanism,
    VerificationDepth,
    VerificationStatus,
)
from core.models.evidence import EvidenceItem
from core.models.reasoning import BasisCondition, Claim, Hypothesis, RuleEvaluation
from core.models.remediation import RemediationPlan
from core.taxonomy.categories import FailureCategory


class SuggestedFix(StrictModel):
    """Human-readable guidance. Never executable; the literal flag executed is always False."""

    claim: Claim
    executed: Literal[False] = False


class ToolCallRecord(StrictModel):
    """Hypothesis -> Tool -> Evidence -> Decision."""

    hypothesis_id: str | None = None
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    decision: str = ""
    investigation_cycle: int = Field(ge=1)


class InvestigationCycleRecord(StrictModel):
    cycle: int = Field(ge=1)
    started_at: datetime
    tool_calls: int = Field(ge=0, le=5)
    outcome: str = ""


class UniversalTriageReport(StrictModel):
    incident_id: str
    pipeline_id: str
    pipeline_name: str | None = None
    platform: str
    orchestrator: str | None = None
    compute_engine: str | None = None
    task_id: str | None = None
    execution_id: str
    platform_run_id: str | None = None
    attempt_number: int | None = None
    failure_category: FailureCategory
    failure_subcategory: str | None = None
    confidence: ConfidenceLevel
    confidence_basis: list[BasisCondition] = Field(default_factory=list)
    root_cause: Claim
    primary_failure: Claim
    contributing_causes: list[Claim] = Field(default_factory=list)
    downstream_symptoms: list[Claim] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    rejected_hypotheses: list[Hypothesis] = Field(default_factory=list)
    suggested_fix: SuggestedFix
    remediation_class: RemediationClass
    remediation_confidence: ConfidenceLevel
    remediation_confidence_basis: list[BasisCondition] = Field(default_factory=list)
    rerun_safety: RerunSafety
    rerun_safety_reason: str = ""
    rerun_safety_rule_trace: list[RuleEvaluation] = Field(default_factory=list)
    impact: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    state_mechanism: StateMechanism = StateMechanism.UNKNOWN
    available_capabilities: list[ReadCapability] = Field(default_factory=list)
    action_capabilities: list[ActionCapability] = Field(default_factory=list)
    capability_status: dict[str, str] = Field(default_factory=dict)
    missing_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    llm_mode: LLMMode
    status: ReportStatus
    incident_state: IncidentState
    created_at: datetime = Field(default_factory=utcnow)
    feedback_status: str | None = None
    actual_root_cause: str | None = None
    human_note: str | None = None
    remediation_plan: RemediationPlan | None = None
    approval_status: ApprovalStatus | None = None
    healing_status: ExecutionStatus | None = None
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    verification_depth: VerificationDepth = VerificationDepth.STATE_ONLY
    investigation_cycles: list[InvestigationCycleRecord] = Field(default_factory=list)
