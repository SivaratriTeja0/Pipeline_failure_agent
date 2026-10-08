"""Incident deduplication (spec Part N).

Grouping keys: pipeline, execution, task, failure signature, time window, lineage and primary
failure. One root cause -> one incident with linked symptoms:

- same pipeline + execution + task (any attempt)           -> DUPLICATE of that incident
- same pipeline + execution, task is a downstream symptom  -> SYMPTOM of that incident
  (event status upstream_failed/skipped, or task downstream of the incident's primary task)
- same pipeline + signature within the window, other run   -> NEW, but RELATED to that incident
- otherwise                                                -> NEW
"""

from datetime import datetime, timedelta
from enum import Enum

from pydantic import BaseModel, Field

from core.evidence.normalizer import normalize
from core.models.events import PipelineFailureEvent

SYMPTOM_STATUSES = frozenset({"upstream_failed", "skipped"})


class DedupOutcome(str, Enum):
    NEW = "NEW"
    DUPLICATE = "DUPLICATE"
    SYMPTOM = "SYMPTOM"


class DedupDecision(BaseModel):
    outcome: DedupOutcome
    incident_id: str | None = None
    related_incident_ids: list[str] = Field(default_factory=list)
    reason: str


class TrackedIncident(BaseModel):
    incident_id: str
    pipeline_id: str
    execution_id: str
    primary_task_id: str | None
    signature: str
    opened_at: datetime
    downstream_task_ids: set[str] = Field(default_factory=set)
    symptom_task_ids: set[str] = Field(default_factory=set)
    duplicate_event_ids: list[str] = Field(default_factory=list)


def failure_signature(event: PipelineFailureEvent) -> str:
    signals = sorted({m.normalized_signal.value for m in normalize(event.error_message or "")})
    return f"{event.pipeline_id}|{event.task_id or '-'}|{','.join(signals) or 'UNRECOGNIZED'}"


class IncidentIndex:
    def __init__(self, window: timedelta = timedelta(hours=6)) -> None:
        self._window = window
        self._incidents: dict[str, TrackedIncident] = {}

    def incidents(self) -> list[TrackedIncident]:
        return list(self._incidents.values())

    def classify(self, event: PipelineFailureEvent, now: datetime) -> DedupDecision:
        same_run = [i for i in self._incidents.values()
                    if i.pipeline_id == event.pipeline_id and i.execution_id == event.execution_id]
        for incident in same_run:
            if event.task_id is not None and event.task_id == incident.primary_task_id:
                return DedupDecision(outcome=DedupOutcome.DUPLICATE, incident_id=incident.incident_id,
                                     reason="same pipeline, execution and task")
        for incident in same_run:
            downstream = event.task_id is not None and event.task_id in incident.downstream_task_ids
            if event.status in SYMPTOM_STATUSES or downstream:
                return DedupDecision(outcome=DedupOutcome.SYMPTOM, incident_id=incident.incident_id,
                                     reason="downstream symptom of an open incident in the same run")
        signature = failure_signature(event)
        related = sorted(i.incident_id for i in self._incidents.values()
                         if i.signature == signature and now - i.opened_at <= self._window)
        return DedupDecision(outcome=DedupOutcome.NEW, related_incident_ids=related,
                             reason="related by signature" if related else "no matching incident")

    def register(self, incident_id: str, event: PipelineFailureEvent, now: datetime,
                 downstream_task_ids: set[str] | None = None) -> TrackedIncident:
        tracked = TrackedIncident(incident_id=incident_id, pipeline_id=event.pipeline_id,
                                  execution_id=event.execution_id, primary_task_id=event.task_id,
                                  signature=failure_signature(event), opened_at=now,
                                  downstream_task_ids=set(downstream_task_ids or set()))
        self._incidents[incident_id] = tracked
        return tracked

    def link(self, decision: DedupDecision, event: PipelineFailureEvent) -> None:
        if decision.incident_id is None:
            return
        incident = self._incidents[decision.incident_id]
        if decision.outcome is DedupOutcome.DUPLICATE:
            incident.duplicate_event_ids.append(event.event_id)
        elif decision.outcome is DedupOutcome.SYMPTOM and event.task_id:
            incident.symptom_task_ids.add(event.task_id)
