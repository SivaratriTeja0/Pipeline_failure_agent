"""LLM planner: writes rationale-only text for a deterministically selected plan.

The planner receives the selection as data. It may supply the rationale, expected effect and
plain-language condition wording, and may recommend manual handling (lowering only). Output
that tries to set anything else (action, scope, target, parameters, task list) fails strict
schema validation and is rejected; a deterministic rationale is used instead.
"""

from pydantic import BaseModel

from agent.evidence_pipeline import EvidencePipeline
from agent.llm_provider import LLMProvider, LLMRequest, LLMUnavailableError
from agent.prompts import PLANNER_SYSTEM, render_context
from agent.schemas import LLMOutputError, PlannerOutput, parse_llm_json
from core.models.evidence import EvidenceItem
from core.models.remediation import PlanCondition
from core.remediation.selector import SelectionResult


class PlannerResult(BaseModel):
    output: PlannerOutput | None
    rejected_reason: str | None = None


def write_rationale(
    provider: LLMProvider,
    *,
    selection: SelectionResult,
    evidence: list[EvidenceItem],
    supporting_evidence_ids: list[str],
    cause_cleared_evidence_ids: list[str],
    conditions: list[PlanCondition],
) -> PlannerResult:
    context = {
        "action_type": selection.action_type.value if selection.action_type else None,
        "recovery_scope": selection.recovery_scope.value if selection.recovery_scope else None,
        "target": selection.target.model_dump() if selection.target else None,
        "task_instances_to_clear": [t.model_dump() for t in selection.task_instances_to_clear],
        "supporting_evidence_ids": supporting_evidence_ids,
        "cause_cleared_evidence_ids": cause_cleared_evidence_ids,
        "conditions": [c.model_dump() for c in conditions],
    }
    request = LLMRequest(role="planner", system=PLANNER_SYSTEM,
                         messages=[{"role": "user", "content": render_context(context, EvidencePipeline.wrap(evidence))}],
                         context=context)
    try:
        response = provider.generate(request)
        parsed = parse_llm_json(response.text, PlannerOutput)
    except (LLMUnavailableError, LLMOutputError) as exc:
        return PlannerResult(output=None, rejected_reason=f"planner output rejected: {exc}")
    known = {e.evidence_id for e in evidence}
    unknown = [eid for eid in parsed.rationale_evidence_ids if eid not in known]
    if unknown:
        return PlannerResult(output=None, rejected_reason=f"planner cited unknown evidence {unknown}")
    condition_ids = {c.condition_id for c in conditions}
    stray = sorted(set(parsed.conditions_text) - condition_ids)
    if stray:
        return PlannerResult(output=None, rejected_reason=f"planner introduced conditions {stray}")
    return PlannerResult(output=parsed)
