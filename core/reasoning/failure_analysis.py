"""Deterministic failure analysis (spec Part H): primary failures vs downstream symptoms,
transient-recovered detection, and data-quality assessment."""

from pydantic import BaseModel, Field

from core.evidence.conventions import DQ_RESULT, OBSERVED_TASK_STATES
from core.models.enums import TemporalLabel
from core.models.evidence import EvidenceItem
from core.remediation.selector import RunSnapshot

SYMPTOM_STATES = frozenset({"upstream_failed", "skipped"})


class FailureAnalysis(BaseModel):
    readable: bool
    primary_tasks: list[str] = Field(default_factory=list)
    symptom_tasks: list[str] = Field(default_factory=list)
    unexplained_symptoms: list[str] = Field(default_factory=list)
    detail: str = ""


def analyze_failures(snapshot: RunSnapshot | None) -> FailureAnalysis:
    """One primary failure per independent failed task; upstream_failed / skipped tasks that are
    downstream of a primary failure are symptoms. Unreadable state yields readable=False."""
    if snapshot is None:
        return FailureAnalysis(readable=False, detail="run snapshot not available for this platform")
    if snapshot.run_state is None or any(ti.state is None for ti in snapshot.task_instances):
        return FailureAnalysis(readable=False, detail="run or task state unreadable")
    children: dict[str, set[str]] = {}
    for ti in snapshot.task_instances:
        for parent in ti.upstream_task_ids:
            children.setdefault(parent, set()).add(ti.task_id)
    primaries = sorted({ti.task_id for ti in snapshot.task_instances if ti.state == "failed"})
    reach: set[str] = set()
    stack = list(primaries)
    while stack:
        for child in children.get(stack.pop(), ()):
            if child not in reach:
                reach.add(child)
                stack.append(child)
    symptoms = sorted({ti.task_id for ti in snapshot.task_instances
                       if ti.state in SYMPTOM_STATES and ti.task_id in reach})
    unexplained = sorted({ti.task_id for ti in snapshot.task_instances
                          if ti.state == "upstream_failed" and ti.task_id not in reach})
    return FailureAnalysis(readable=True, primary_tasks=primaries, symptom_tasks=symptoms,
                           unexplained_symptoms=unexplained)


class TransientAssessment(BaseModel):
    recovered: bool
    failed_attempt: int | None = None
    succeeded_attempt: int | None = None
    evidence_ids: list[str] = Field(default_factory=list)


def detect_transient_recovered(
    task_id: str | None, failed_attempt: int | None, evidence: list[EvidenceItem]
) -> TransientAssessment:
    """Attempt N failed and a later attempt of the same task instance succeeded -> recovered."""
    if task_id is None or failed_attempt is None:
        return TransientAssessment(recovered=False)
    for item in evidence:
        if item.temporal_label is not TemporalLabel.CURRENT:
            continue
        for obs in item.metadata.get(OBSERVED_TASK_STATES) or []:
            if (obs.get("task_id") == task_id and obs.get("state") == "success"
                    and isinstance(obs.get("attempt"), int) and obs["attempt"] > failed_attempt):
                return TransientAssessment(recovered=True, failed_attempt=failed_attempt,
                                           succeeded_attempt=obs["attempt"], evidence_ids=[item.evidence_id])
    return TransientAssessment(recovered=False, failed_attempt=failed_attempt)


class DQAssessment(BaseModel):
    present: bool
    gate_failed: bool = False
    worked_as_designed: bool = False
    target_corrupted: bool | None = None
    bad_records_quarantined: bool | None = None
    evidence_ids: list[str] = Field(default_factory=list)


def assess_data_quality(evidence: list[EvidenceItem]) -> DQAssessment:
    """'The DQ gate worked as designed' requires explicit evidence that the target is not
    corrupted and bad records were quarantined. Missing facts stay None (not assumed)."""
    items = [e for e in evidence
             if e.temporal_label is TemporalLabel.CURRENT and isinstance(e.metadata.get(DQ_RESULT), dict)]
    if not items:
        return DQAssessment(present=False)
    results = [e.metadata[DQ_RESULT] for e in items]
    gate_failed = any(r.get("gate_failed") is True for r in results)
    corrupted_values = [r.get("target_corrupted") for r in results if r.get("target_corrupted") is not None]
    quarantine_values = [r.get("bad_records_quarantined") for r in results
                         if r.get("bad_records_quarantined") is not None]
    corrupted = (True if any(corrupted_values) else False) if corrupted_values else None
    quarantined = all(quarantine_values) if quarantine_values else None
    return DQAssessment(
        present=True,
        gate_failed=gate_failed,
        worked_as_designed=gate_failed and corrupted is False and quarantined is True,
        target_corrupted=corrupted,
        bad_records_quarantined=quarantined,
        evidence_ids=[e.evidence_id for e in items],
    )
