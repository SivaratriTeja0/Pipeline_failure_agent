"""Generic adapter: manual evidence upload, investigation only.

Users upload evidence (logs, run history, schema notes, ...). Uploaded items are user-provided
and therefore MEDIUM reliability. No executor exists for this platform, so healing is
NOT_APPLICABLE. Reads return only what was uploaded; nothing is fabricated.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from adapters.base.evidence import build_evidence
from adapters.base.interfaces import PipelineAdapter
from core.evidence.conventions import DQ_RESULT, OBSERVED_TASK_STATES
from core.models.base import utcnow
from core.models.enums import EvidenceCategory, ReadCapability, Reliability
from core.models.events import PipelineFailureEvent
from core.models.evidence import EvidenceItem
from core.models.reads import ReadRequest, ReadResult, ReadStatus

EC = EvidenceCategory
RC = ReadCapability

# tool -> (capability, evidence categories served)
_TOOL_MAP: dict[str, tuple[ReadCapability, frozenset[EvidenceCategory]]] = {
    "get_run_output": (RC.RUN_LOGS, frozenset({EC.LOG, EC.ERROR, EC.STACK_TRACE})),
    "get_run_history": (RC.RUN_HISTORY, frozenset({EC.RUN_HISTORY})),
    "get_schema": (RC.SCHEMA, frozenset({EC.SCHEMA})),
    "get_row_counts": (RC.ROW_COUNTS, frozenset({EC.ROW_COUNT})),
    "get_data_quality_results": (RC.DATA_QUALITY, frozenset({EC.DATA_QUALITY})),
    "get_configuration": (RC.CONFIGURATION, frozenset({EC.CONFIGURATION})),
}
GENERIC_READ_CAPABILITIES = frozenset(cap for cap, _ in _TOOL_MAP.values())
ALLOWED_FACTS = frozenset({DQ_RESULT, OBSERVED_TASK_STATES})


class ManualEvidence(BaseModel):
    category: EvidenceCategory
    description: str = Field(min_length=1)
    content: str
    timestamp: datetime | None = None
    attempt_number: int | None = None
    uploaded_by: str = Field(min_length=1)
    facts: dict[str, Any] = Field(
        default_factory=dict,
        description=f"Structured facts using the platform-neutral conventions; allowed keys: {sorted(ALLOWED_FACTS)}",
    )

    @field_validator("facts")
    @classmethod
    def _known_facts_only(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = set(value) - ALLOWED_FACTS
        if unknown:
            raise ValueError(f"unsupported fact keys {sorted(unknown)}")
        return value


class GenericAdapter(PipelineAdapter):
    platform = "generic"

    def __init__(self, clock: Callable[[], datetime] = utcnow) -> None:
        self._uploads: dict[tuple[str, str], list[ManualEvidence]] = {}
        self._clock = clock

    def read_capabilities(self) -> frozenset[ReadCapability]:
        return GENERIC_READ_CAPABILITIES

    def upload(self, pipeline_id: str, execution_id: str, items: list[ManualEvidence]) -> int:
        self._uploads.setdefault((pipeline_id, execution_id), []).extend(items)
        return len(items)

    def normalize_failure(self, payload: dict[str, Any]) -> PipelineFailureEvent:
        failure_time = payload.get("failure_time")
        return PipelineFailureEvent(
            event_id=str(payload.get("event_id") or f"generic-{payload['pipeline_id']}-{payload['execution_id']}"),
            platform=str(payload.get("platform") or "generic"),
            orchestrator=payload.get("orchestrator"),
            compute_engine=payload.get("compute_engine"),
            pipeline_id=str(payload["pipeline_id"]),
            pipeline_name=payload.get("pipeline_name"),
            task_id=payload.get("task_id"),
            execution_id=str(payload["execution_id"]),
            attempt_number=payload.get("attempt_number"),
            status=str(payload.get("status") or "failed"),
            failure_time=datetime.fromisoformat(failure_time) if isinstance(failure_time, str) else failure_time,
            error_message=payload.get("error_message"),
            environment=payload.get("environment"),
            metadata={"source": "manual_upload"},
        )

    def _serve(self, tool: str, req: ReadRequest) -> ReadResult:
        capability, categories = _TOOL_MAP[tool]
        uploaded = self._uploads.get((req.pipeline_id, req.execution_id), [])
        evidence: list[EvidenceItem] = []
        for index, item in enumerate(uploaded):
            if item.category not in categories:
                continue
            evidence.append(build_evidence(
                adapter="generic", platform="generic", capability=capability.value, tool=tool,
                source=f"manual_upload:{item.uploaded_by}", req=req, category=item.category,
                description=f"User-provided: {item.description}", value=item.content,
                reliability=Reliability.MEDIUM, collected_at=self._clock(), key=f"{index}",
                timestamp=item.timestamp, attempt_number=item.attempt_number, signal_text=item.content,
                metadata={"user_provided": True, "uploaded_by": item.uploaded_by, **item.facts}))
        detail = "" if evidence else "no manual evidence uploaded for this category"
        return ReadResult(tool=tool, status=ReadStatus.AVAILABLE, evidence=evidence, detail=detail)

    def get_run_output(self, req: ReadRequest) -> ReadResult:
        return self._serve("get_run_output", req)

    def get_run_history(self, req: ReadRequest) -> ReadResult:
        return self._serve("get_run_history", req)

    def get_schema(self, req: ReadRequest) -> ReadResult:
        return self._serve("get_schema", req)

    def get_row_counts(self, req: ReadRequest) -> ReadResult:
        return self._serve("get_row_counts", req)

    def get_data_quality_results(self, req: ReadRequest) -> ReadResult:
        return self._serve("get_data_quality_results", req)

    def get_configuration(self, req: ReadRequest) -> ReadResult:
        return self._serve("get_configuration", req)
