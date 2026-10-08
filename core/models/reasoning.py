"""Hypothesis (C7), Claim (C8) and deterministic basis records."""

from pydantic import Field, model_validator

from core.models.base import StrictModel
from core.models.enums import ClaimKind, EvidenceCategory, HypothesisStatus, RerunSafety
from core.taxonomy.categories import FailureCategory, is_valid_subcategory


class Hypothesis(StrictModel):
    hypothesis_id: str = Field(min_length=1)
    category: FailureCategory
    subcategory: str | None = None
    statement: str = Field(min_length=1)
    status: HypothesisStatus = HypothesisStatus.OPEN
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    rank: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _subcategory_valid(self) -> "Hypothesis":
        if not is_valid_subcategory(self.category, self.subcategory):
            raise ValueError(f"subcategory {self.subcategory!r} is not valid for {self.category.value}")
        return self


class Claim(StrictModel):
    """FACT and INFERENCE claims must cite at least one EvidenceItem id."""

    claim_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    kind: ClaimKind
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_categories: list[EvidenceCategory] = Field(default_factory=list)

    @model_validator(mode="after")
    def _grounded_kinds_cite_evidence(self) -> "Claim":
        if self.kind in (ClaimKind.FACT, ClaimKind.INFERENCE) and not self.evidence_ids:
            raise ValueError(f"{self.kind.value} claims require at least one evidence id")
        return self


class BasisCondition(StrictModel):
    """One condition evaluated by a deterministic engine, recorded for auditability."""

    name: str
    passed: bool
    detail: str = ""


class RuleEvaluation(StrictModel):
    """One rerun-safety rule (R1-R13) as evaluated; every rule is recorded, matched or not."""

    rule: str
    matched: bool
    outcome: RerunSafety | None = None
    is_cap: bool = False
    detail: str = ""
