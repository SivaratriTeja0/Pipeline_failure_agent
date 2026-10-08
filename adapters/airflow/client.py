"""AirflowReadClient: GET-only access to the Airflow 2.x stable REST API (v1).

Uses AIRFLOW_READ_* credentials only. Three independent guards keep it read-only:
1. the only method that performs HTTP is ``_get``, which calls ``httpx.Client.get``;
2. a request event hook refuses any non-GET request before it leaves the process;
3. an architecture test asserts this module contains no other HTTP verb.

Every path parameter is validated against a strict pattern and URL-encoded.
"""

from datetime import datetime
from typing import Any, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ValidationError

from adapters.airflow.schemas import (
    AirflowDag,
    AirflowDagDetail,
    AirflowDagRun,
    AirflowDagRunCollection,
    AirflowTask,
    AirflowTaskCollection,
    AirflowTaskInstance,
    AirflowTaskInstanceCollection,
    HealthInfo,
    VersionInfo,
)
from adapters.base.interfaces import AdapterError
from core.logging_setup import get_logger
from core.models.base import PIPELINE_ID_RE, RUN_ID_RE, TASK_ID_RE

_log = get_logger(__name__)

SUPPORTED_API_VERSIONS = frozenset({"v1"})
FAKE_AIRFLOW_HEADER = "x-fake-airflow"
_PAGE_SIZE = 100
_MAX_PAGES = 50

M = TypeVar("M", bound=BaseModel)


class AirflowUnavailableError(AdapterError):
    """Network failure, timeout or 5xx: Airflow cannot be read right now."""


class AirflowAuthError(AdapterError):
    """401/403 from Airflow."""


class AirflowNotFoundError(AdapterError):
    """404 from Airflow."""


class AirflowResponseError(AdapterError):
    """Unexpected status or a response that does not match the API contract."""


class ReadOnlyViolation(RuntimeError):
    """A non-GET request was attempted through the read client."""


class AirflowReadConfig(BaseModel):
    base_url: str
    api_version: str = "v1"
    username: str | None = None
    password: str | None = None
    token: str | None = None
    timeout_seconds: float = 15.0
    max_log_bytes: int = 200_000


def _enforce_get(request: httpx.Request) -> None:
    if request.method != "GET":
        raise ReadOnlyViolation(f"read client refused {request.method} {request.url.path}")


def _seg(value: str, pattern: Any, kind: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ValueError(f"invalid {kind}: {value!r}")
    return quote(value, safe="")


def _iso(value: datetime) -> str:
    return value.isoformat()


class LogText(BaseModel):
    text: str
    truncated: bool
    original_bytes: int


class AirflowReadClient:
    def __init__(self, config: AirflowReadConfig, http: httpx.Client | None = None) -> None:
        if config.api_version not in SUPPORTED_API_VERSIONS:
            raise ValueError(
                f"AIRFLOW_API_VERSION={config.api_version!r} is not supported; endpoints are verified "
                f"only for {sorted(SUPPORTED_API_VERSIONS)} (Airflow 2.x stable REST API)"
            )
        self._config = config
        self._prefix = f"/api/{config.api_version}"
        if http is None:
            auth: httpx.Auth | None = None
            headers: dict[str, str] = {"Accept": "application/json"}
            if config.token:
                headers["Authorization"] = f"Bearer {config.token}"
            elif config.username and config.password:
                auth = httpx.BasicAuth(config.username, config.password)
            http = httpx.Client(base_url=config.base_url, auth=auth, headers=headers,
                                timeout=config.timeout_seconds)
        hooks = dict(http.event_hooks)
        hooks["request"] = [*hooks.get("request", []), _enforce_get]
        http.event_hooks = hooks
        self._http = http
        self.fake_airflow_detected = False

    # ------------------------------------------------------------------ the only HTTP call

    def _get(self, path: str, params: dict[str, Any] | None = None, accept: str = "application/json") -> httpx.Response:
        url = f"{self._prefix}{path}"
        try:
            response = self._http.get(url, params=params, headers={"Accept": accept})
        except ReadOnlyViolation:
            raise
        except httpx.TransportError as exc:
            _log.warning("airflow_unreachable", extra={"path": path, "error": type(exc).__name__})
            raise AirflowUnavailableError(f"Airflow unreachable: {type(exc).__name__}") from exc
        if response.headers.get(FAKE_AIRFLOW_HEADER):
            self.fake_airflow_detected = True
        status = response.status_code
        if status in (401, 403):
            raise AirflowAuthError(f"Airflow refused read credentials ({status}) for {path}")
        if status == 404:
            raise AirflowNotFoundError(f"not found: {path}")
        if status >= 500:
            raise AirflowUnavailableError(f"Airflow error {status} for {path}")
        if status != 200:
            raise AirflowResponseError(f"unexpected status {status} for {path}")
        return response

    def _get_model(self, model: type[M], path: str, params: dict[str, Any] | None = None) -> M:
        response = self._get(path, params)
        try:
            return model.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise AirflowResponseError(f"response for {path} does not match {model.__name__}") from exc

    # ------------------------------------------------------------------ endpoints

    def health(self) -> HealthInfo:
        return self._get_model(HealthInfo, "/health")

    def version(self) -> VersionInfo:
        return self._get_model(VersionInfo, "/version")

    def get_dag(self, dag_id: str) -> AirflowDag:
        return self._get_model(AirflowDag, f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}")

    def get_dag_details(self, dag_id: str) -> AirflowDagDetail:
        return self._get_model(AirflowDagDetail, f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/details")

    def get_tasks(self, dag_id: str) -> list[AirflowTask]:
        return self._get_model(AirflowTaskCollection, f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/tasks").tasks

    def get_dag_run(self, dag_id: str, dag_run_id: str) -> AirflowDagRun:
        path = f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/dagRuns/{_seg(dag_run_id, RUN_ID_RE, 'dag_run_id')}"
        return self._get_model(AirflowDagRun, path)

    def list_dag_runs(self, dag_id: str, limit: int = 10, state: list[str] | None = None) -> list[AirflowDagRun]:
        params: dict[str, Any] = {"limit": limit, "order_by": "-start_date"}
        if state:
            params["state"] = state
        path = f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/dagRuns"
        return self._get_model(AirflowDagRunCollection, path, params).dag_runs

    def _paginate(self, path: str, params: dict[str, Any]) -> list[AirflowTaskInstance]:
        items: list[AirflowTaskInstance] = []
        for page in range(_MAX_PAGES):
            page_params = {**params, "limit": _PAGE_SIZE, "offset": page * _PAGE_SIZE}
            batch = self._get_model(AirflowTaskInstanceCollection, path, page_params)
            items.extend(batch.task_instances)
            if not batch.task_instances or len(items) >= batch.total_entries:
                return items
        raise AirflowResponseError(f"pagination exceeded {_MAX_PAGES} pages for {path}")

    def list_task_instances(self, dag_id: str, dag_run_id: str, state: list[str] | None = None) -> list[AirflowTaskInstance]:
        path = (f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/dagRuns/"
                f"{_seg(dag_run_id, RUN_ID_RE, 'dag_run_id')}/taskInstances")
        return self._paginate(path, {"state": state} if state else {})

    def get_task_instance(self, dag_id: str, dag_run_id: str, task_id: str, map_index: int | None = None) -> AirflowTaskInstance:
        path = (f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/dagRuns/{_seg(dag_run_id, RUN_ID_RE, 'dag_run_id')}"
                f"/taskInstances/{_seg(task_id, TASK_ID_RE, 'task_id')}")
        if map_index is not None and map_index >= 0:
            path += f"/{int(map_index)}"
        return self._get_model(AirflowTaskInstance, path)

    def list_mapped_task_instances(self, dag_id: str, dag_run_id: str, task_id: str) -> list[AirflowTaskInstance]:
        path = (f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/dagRuns/{_seg(dag_run_id, RUN_ID_RE, 'dag_run_id')}"
                f"/taskInstances/{_seg(task_id, TASK_ID_RE, 'task_id')}/listMapped")
        return self._paginate(path, {})

    def list_pool_task_instances(
        self, pool: str, *, state: list[str], start_date_gte: datetime, limit: int = 25
    ) -> list[AirflowTaskInstance]:
        """Task instances across all DAGs/runs in ``pool`` (the documented ``~`` wildcard)."""
        if not TASK_ID_RE.match(pool):
            raise ValueError(f"invalid pool: {pool!r}")
        params = {"pool": [pool], "state": state, "start_date_gte": _iso(start_date_gte),
                  "limit": limit, "offset": 0}
        return self._get_model(AirflowTaskInstanceCollection, "/dags/~/dagRuns/~/taskInstances", params).task_instances

    def get_task_log(self, dag_id: str, dag_run_id: str, task_id: str, try_number: int,
                     map_index: int | None = None) -> LogText:
        if try_number < 0:
            raise ValueError("try_number must be >= 0")
        path = (f"/dags/{_seg(dag_id, PIPELINE_ID_RE, 'dag_id')}/dagRuns/{_seg(dag_run_id, RUN_ID_RE, 'dag_run_id')}"
                f"/taskInstances/{_seg(task_id, TASK_ID_RE, 'task_id')}/logs/{int(try_number)}")
        params: dict[str, Any] = {"full_content": "true"}
        if map_index is not None and map_index >= 0:
            params["map_index"] = int(map_index)
        response = self._get(path, params, accept="text/plain")
        raw = response.content
        limit = self._config.max_log_bytes
        # Keep the tail: failures are reported at the end of a task log.
        clipped = raw[-limit:] if len(raw) > limit else raw
        return LogText(text=clipped.decode("utf-8", errors="replace"), truncated=len(raw) > limit,
                       original_bytes=len(raw))

    def close(self) -> None:
        self._http.close()

