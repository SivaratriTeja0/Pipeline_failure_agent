"""Response models for the subset of the Airflow 2.x stable REST API (v1) the read client uses.

Field names follow the published OpenAPI spec (airflow/api_connexion/openapi/v1.yaml, 2.10.x).
Only fields the system relies on are declared; unknown fields are ignored so minor-version
additions do not break parsing, while missing required fields fail validation (fail closed).
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Valid TaskState values per the OpenAPI enum. ``None`` (JSON null) = no state yet.
TASK_STATES = frozenset(
    {"success", "running", "failed", "upstream_failed", "skipped", "up_for_retry", "up_for_reschedule",
     "queued", "none", "scheduled", "deferred", "removed", "restarting"}
)
DAG_RUN_STATES = frozenset({"queued", "running", "success", "failed"})


class _AirflowModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class HealthComponent(_AirflowModel):
    status: str | None = None


class HealthInfo(_AirflowModel):
    metadatabase: HealthComponent | None = None
    scheduler: HealthComponent | None = None


class VersionInfo(_AirflowModel):
    version: str
    git_version: str | None = None


class AirflowDag(_AirflowModel):
    dag_id: str
    is_paused: bool | None = None
    is_active: bool | None = None
    fileloc: str | None = None
    owners: list[str] = Field(default_factory=list)
    max_active_runs: int | None = None
    max_active_tasks: int | None = None
    has_import_errors: bool | None = None
    tags: list[dict[str, Any]] | None = None


class AirflowDagDetail(AirflowDag):
    catchup: bool | None = None
    concurrency: int | None = None
    dag_run_timeout: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    timezone: str | None = None


class AirflowTask(_AirflowModel):
    task_id: str
    class_ref: dict[str, Any] | None = None
    downstream_task_ids: list[str] = Field(default_factory=list)
    is_mapped: bool | None = None
    retries: float | int | None = None
    pool: str | None = None
    queue: str | None = None
    trigger_rule: str | None = None
    depends_on_past: bool | None = None
    execution_timeout: dict[str, Any] | None = None


class AirflowTaskCollection(_AirflowModel):
    tasks: list[AirflowTask]
    total_entries: int | None = None


class AirflowDagRun(_AirflowModel):
    dag_run_id: str
    dag_id: str
    logical_date: datetime | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    run_type: str | None = None
    state: str | None = None
    external_trigger: bool | None = None


class AirflowDagRunCollection(_AirflowModel):
    dag_runs: list[AirflowDagRun]
    total_entries: int


class AirflowTaskInstance(_AirflowModel):
    task_id: str
    dag_id: str
    dag_run_id: str
    state: str | None = None
    try_number: int
    map_index: int = -1
    max_tries: int | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    duration: float | None = None
    hostname: str | None = None
    pool: str | None = None
    queue: str | None = None
    operator: str | None = None


class AirflowTaskInstanceCollection(_AirflowModel):
    task_instances: list[AirflowTaskInstance]
    total_entries: int
