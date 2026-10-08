"""PipelineFailureEvent (spec C1): the universal, platform-neutral failure event."""

from datetime import datetime
from typing import Any

from pydantic import Field

from core.models.base import StrictModel


class PipelineFailureEvent(StrictModel):
    event_id: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    orchestrator: str | None = None
    compute_engine: str | None = None
    pipeline_id: str = Field(min_length=1)
    pipeline_name: str | None = None
    task_id: str | None = None
    task_name: str | None = None
    execution_id: str = Field(min_length=1, description="Universal execution identifier")
    platform_run_id: str | None = Field(
        default=None, description="Original platform identifier, e.g. Airflow dag_run_id"
    )
    attempt_number: int | None = Field(default=None, ge=0)
    status: str = Field(min_length=1)
    failure_time: datetime | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    error_message: str | None = None
    stack_trace: str | None = None
    log_reference: str | None = None
    environment: str | None = None
    source_system: str | None = None
    target_system: str | None = None
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Platform-specific identifiers (e.g. try_number, map_index) live here only",
    )
