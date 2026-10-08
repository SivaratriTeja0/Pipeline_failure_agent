"""Bounded LLM investigation loop (spec Part I).

- At most ``max_calls`` (default 5) investigative tool calls per cycle; initial collection is
  not counted. Repeated requests are deduplicated and never re-executed.
- Tools must be on the capability-filtered allowlist; anything else is rejected, not run.
- Every LLM output is parsed into a strict schema; invalid output is rejected and counted.
- Stops early when the LLM concludes; if it never does, the root cause is UNKNOWN.
- Every step is recorded as Hypothesis -> Tool -> Evidence -> Decision.
"""

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from agent.evidence_pipeline import EvidencePipeline
from security.prompt_injection import wrap_evidence
from agent.llm_provider import LLMProvider, LLMRequest, LLMUnavailableError
from agent.prompts import INVESTIGATOR_SYSTEM, render_context
from agent.schemas import InvestigatorTurn, LLMConclusion, LLMHypothesis, LLMOutputError, parse_llm_json
from core.evidence.conventions import CAUSE_CLEARED_CANDIDATE
from core.evidence.freshness import FreshnessContext
from core.logging_setup import get_logger
from core.models.evidence import EvidenceItem
from core.models.reads import ReadRequest
from core.models.report import ToolCallRecord
from core.taxonomy.preclassifier import PreClassifiedSignal
from tools.invoker import ToolInputError, ToolInvoker

_log = get_logger(__name__)

MAX_CALLS_PER_CYCLE = 5


class InvestigationStep(BaseModel):
    turn: int
    action: str
    tool: str | None = None
    decision: str


class InvestigationOutcome(BaseModel):
    conclusion: LLMConclusion | None = None
    hypotheses: list[LLMHypothesis] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    steps: list[InvestigationStep] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    calls_used: int = 0
    rejected_requests: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def _evidence_view(item: EvidenceItem) -> dict[str, Any]:
    return {"id": item.evidence_id, "category": item.category.value, "normalized_signal": item.normalized_signal,
            "reliability": item.reliability.value, "temporal_label": item.temporal_label.value,
            "attempt": item.attempt_number, CAUSE_CLEARED_CANDIDATE: bool(item.metadata.get(CAUSE_CLEARED_CANDIDATE))}


class InvestigationLoop:
    def __init__(
        self,
        provider: LLMProvider,
        invoker: ToolInvoker,
        pipeline: EvidencePipeline,
        *,
        max_calls: int = MAX_CALLS_PER_CYCLE,
        max_invalid_outputs: int = 2,
    ) -> None:
        self._provider = provider
        self._invoker = invoker
        self._pipeline = pipeline
        self._max_calls = max_calls
        self._max_invalid = max_invalid_outputs
        self._max_turns = max_calls + 4

    def run(
        self,
        *,
        incident: ReadRequest,
        evidence: list[EvidenceItem],
        signals: list[PreClassifiedSignal],
        freshness: FreshnessContext,
        context_extra: dict[str, Any] | None = None,
        untrusted_text: dict[str, str] | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> InvestigationOutcome:
        out = InvestigationOutcome(evidence=list(evidence))
        allowlist = self._invoker.allowlist()
        seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
        called: list[str] = []
        invalid = 0

        for turn in range(1, self._max_turns + 1):
            context = {
                "allowlist": allowlist,
                "calls_remaining": self._max_calls - out.calls_used,
                "called": called,
                "task_id": incident.task_id,
                "signals": [s.model_dump(mode="json") for s in signals],
                "evidence": [_evidence_view(e) for e in out.evidence],
                "steps": [s.model_dump() for s in out.steps],
                **(context_extra or {}),
            }
            trusted = {k: v for k, v in context.items() if k != "evidence"}
            # Free text from outside the system (e.g. the reported failure message) is delimited exactly
            # like evidence: it is data, never instructions.
            extra_blocks = [wrap_evidence(key, text) for key, text in (untrusted_text or {}).items()]
            message = render_context(trusted, extra_blocks + EvidencePipeline.wrap(out.evidence))
            request = LLMRequest(role="investigator", system=INVESTIGATOR_SYSTEM,
                                 messages=[{"role": "user", "content": message}], context=context)
            try:
                response = self._provider.generate(request)
            except LLMUnavailableError as exc:
                out.limitations.append(f"LLM unavailable: {exc}; root cause left UNKNOWN")
                out.steps.append(InvestigationStep(turn=turn, action="llm_error", decision=str(exc)))
                break
            try:
                parsed = parse_llm_json(response.text, InvestigatorTurn)
                problem = None
                if parsed.action == "conclude" and parsed.conclusion is None:
                    problem = "conclude without conclusion"
                elif parsed.action == "call_tool" and parsed.tool_call is None:
                    problem = "call_tool without tool_call"
            except LLMOutputError as exc:
                problem = str(exc)
            if problem is not None:
                invalid += 1
                out.steps.append(InvestigationStep(turn=turn, action="invalid_output", decision=f"rejected: {problem}"))
                if invalid > self._max_invalid:
                    out.limitations.append("LLM produced repeated invalid output; investigation stopped")
                    break
                continue

            if parsed.hypotheses:
                out.hypotheses = parsed.hypotheses

            if parsed.action == "conclude" and parsed.conclusion is not None:
                out.conclusion = parsed.conclusion
                out.steps.append(InvestigationStep(turn=turn, action="conclude", decision="investigation concluded"))
                break

            call = parsed.tool_call
            if call is None:
                continue
            if call.tool not in allowlist:
                out.rejected_requests.append(call.tool)
                out.steps.append(InvestigationStep(turn=turn, action="call_tool", tool=call.tool,
                                                   decision="rejected: tool not on the capability allowlist"))
                _log.warning("tool_rejected", extra={"tool": call.tool})
                continue
            key = (call.tool, tuple(sorted((k, str(v)) for k, v in call.args.items())))
            if key in seen:
                out.steps.append(InvestigationStep(turn=turn, action="call_tool", tool=call.tool,
                                                   decision="duplicate request; not re-executed"))
                continue
            if out.calls_used >= self._max_calls:
                out.steps.append(InvestigationStep(turn=turn, action="call_tool", tool=call.tool,
                                                   decision=f"rejected: {self._max_calls}-call budget exhausted"))
                continue
            try:
                result = self._invoker.invoke(call.tool, incident, dict(call.args))
            except ToolInputError as exc:
                out.rejected_requests.append(call.tool)
                out.steps.append(InvestigationStep(turn=turn, action="call_tool", tool=call.tool,
                                                   decision=f"rejected: {exc}"))
                continue
            seen.add(key)
            called.append(call.tool)
            out.calls_used += 1
            new_items = self._pipeline.sanitize(EvidencePipeline.label(result.evidence, freshness))
            known = {e.evidence_id for e in out.evidence}
            # Re-reading a signal already collected this cycle yields the same deterministic id: keep one copy.
            out.evidence.extend(e for e in new_items if e.evidence_id not in known)
            hypothesis = next((h.hypothesis_id for h in out.hypotheses if h.status in ("OPEN", "CONFIRMED")), None)
            decision = f"{result.status.value}: {len(new_items)} evidence item(s)" + (
                f" ({result.detail})" if result.detail else "")
            out.tool_calls.append(ToolCallRecord(
                hypothesis_id=hypothesis, tool=call.tool, arguments=dict(call.args),
                evidence_ids=[e.evidence_id for e in new_items], decision=decision,
                investigation_cycle=incident.investigation_cycle))
            out.steps.append(InvestigationStep(turn=turn, action="call_tool", tool=call.tool, decision=decision))
            if on_event:
                on_event("tool_call", {"tool": call.tool, "status": result.status.value})
        else:
            out.limitations.append("investigation turn limit reached without a conclusion")

        if out.conclusion is None and not any("root cause" in l for l in out.limitations):
            out.limitations.append("no conclusion reached; root cause UNKNOWN")
        return out
