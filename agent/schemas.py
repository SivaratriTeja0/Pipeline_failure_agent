"""Strict schemas for everything the LLM may return. Unknown fields are rejected, so an LLM
output that tries to set an action, scope, target, task list or approval fails validation."""

import json
import re
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.models.enums import ConfidenceLevel, RerunSafety
from core.taxonomy.categories import FailureCategory


class _LLMModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LLMToolCall(_LLMModel):
    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, str | int] = Field(default_factory=dict)


class LLMHypothesis(_LLMModel):
    hypothesis_id: str = Field(min_length=1, max_length=64)
    category: FailureCategory
    subcategory: str | None = None
    statement: str = Field(min_length=1, max_length=1000)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    status: Literal["OPEN", "CONFIRMED", "REJECTED", "INCONCLUSIVE"] = "OPEN"


class LLMClaim(_LLMModel):
    text: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list)


class LLMConclusion(_LLMModel):
    root_cause_known: bool
    category: FailureCategory
    subcategory: str | None = None
    root_cause: LLMClaim
    primary_failure: LLMClaim
    contributing_causes: list[LLMClaim] = Field(default_factory=list)
    suggested_fix: str = Field(min_length=1, max_length=2000)
    impact: str = Field(default="", max_length=2000)
    confidence: ConfidenceLevel
    # Recorded for transparency only; deterministic code decides rerun safety.
    rerun_safety_opinion: RerunSafety | None = None
    limitations: list[str] = Field(default_factory=list)


class InvestigatorTurn(_LLMModel):
    action: Literal["call_tool", "conclude"]
    reasoning: str = Field(default="", max_length=4000)
    hypotheses: list[LLMHypothesis] = Field(default_factory=list)
    tool_call: LLMToolCall | None = None
    conclusion: LLMConclusion | None = None


class PlannerOutput(_LLMModel):
    """The planner writes text only. It may recommend manual handling; nothing else."""

    rationale: str = Field(min_length=1, max_length=2000)
    rationale_evidence_ids: list[str] = Field(default_factory=list)
    expected_effect: str = Field(default="", max_length=2000)
    conditions_text: dict[str, str] = Field(default_factory=dict)
    recommend_manual: bool = False
    manual_reason: str | None = Field(default=None, max_length=2000)


class LLMOutputError(ValueError):
    """The LLM output was not valid JSON for the expected schema. It is rejected."""


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


M = TypeVar("M", bound=_LLMModel)


def parse_llm_json(text: str, model: type[M]) -> M:
    stripped = _FENCE.sub("", text.strip()).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise LLMOutputError(f"not valid JSON: {exc.msg}") from exc
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise LLMOutputError(f"does not match {model.__name__}: {exc.error_count()} error(s)") from exc
