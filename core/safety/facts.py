"""Deterministic extraction of rerun-safety inputs from evidence (never from LLM output).

Every fact defaults to UNKNOWN and only moves away from it on qualifying evidence; the id of
the evidence that established each fact is recorded.
"""

from pydantic import BaseModel, Field

from core.evidence.conventions import CONCURRENCY, DQ_RESULT, parse_markers
from core.models.enums import (
    ConcurrencyStatus,
    DQGateFinding,
    EvidenceCategory,
    FailureStage,
    Reliability,
    TargetWrite,
    TemporalLabel,
    WriteMode,
)
from core.models.evidence import EvidenceItem
from core.models.policy import TaskExecutionPolicy


class SafetyFacts(BaseModel):
    target_write: TargetWrite = TargetWrite.UNKNOWN
    failure_stage: FailureStage = FailureStage.UNKNOWN
    concurrency: ConcurrencyStatus = ConcurrencyStatus.UNKNOWN
    dq_gate: DQGateFinding = DQGateFinding.NOT_APPLICABLE
    sources: dict[str, str] = Field(default_factory=dict)


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_text(v) for v in value.values())
    if isinstance(value, list):
        return "\n".join(_text(v) for v in value)
    return ""


def extract_safety_facts(
    evidence: list[EvidenceItem],
    policy: TaskExecutionPolicy,
    *,
    failed_attempt: int | None,
    dq_signal: bool,
) -> SafetyFacts:
    facts = SafetyFacts()
    current = [e for e in evidence if e.temporal_label is TemporalLabel.CURRENT]

    # A task that never writes cannot have written.
    if policy.write_mode is WriteMode.NONE:
        facts.target_write = TargetWrite.NONE_CONFIRMED
        facts.sources["target_write"] = "policy:write_mode=none"

    for item in current:
        if item.category is not EvidenceCategory.LOG or item.reliability is not Reliability.HIGH:
            continue
        if failed_attempt is not None and item.attempt_number not in (None, failed_attempt):
            continue
        markers = parse_markers(_text(item.value))
        if "target_write" in markers and "target_write" not in facts.sources:
            facts.target_write = TargetWrite(markers["target_write"].upper())
            facts.sources["target_write"] = item.evidence_id
        if "failure_stage" in markers:
            facts.failure_stage = FailureStage(markers["failure_stage"].upper())
            facts.sources["failure_stage"] = item.evidence_id

    for item in current:
        status = item.metadata.get(CONCURRENCY)
        if status in ("NONE_CONFIRMED", "OVERLAP_CONFIRMED"):
            observed = ConcurrencyStatus(status)
            # Any confirmed overlap wins over a 'none' reading.
            if facts.concurrency is not ConcurrencyStatus.OVERLAP_CONFIRMED:
                facts.concurrency = observed
                facts.sources["concurrency"] = item.evidence_id

    dq_items = [e for e in current if isinstance(e.metadata.get(DQ_RESULT), dict)]
    if dq_items:
        gate_failed = any(e.metadata[DQ_RESULT].get("gate_failed") is True for e in dq_items)
        facts.dq_gate = DQGateFinding.FAILED if gate_failed else DQGateFinding.PASSED
        facts.sources["dq_gate"] = dq_items[0].evidence_id
    elif dq_signal:
        facts.dq_gate = DQGateFinding.FAILED
        facts.sources["dq_gate"] = "preclassifier:DQ_GATE_FAILURE"
    return facts
