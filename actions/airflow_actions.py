"""AirflowActionClient and the Airflow RemediationExecutor (spec B4, L2, L8).

AirflowActionClient is the ONLY mutating Airflow client. It uses AIRFLOW_WRITE_* credentials and can
issue exactly one request shape: ``POST /api/v1/dags/{dag_id}/clearTaskInstances`` (Airflow 2.x
stable REST API, verified against the 2.10.5 OpenAPI spec, operationId post_clear_task_instances).
A request hook refuses any other method or path before it leaves the process.

Mapping of both V1 actions to that one operation, per the published ClearTaskInstances schema:
  dag_run_id = the incident's run; task_ids = the enumerated task ids; only_failed = true;
  include_upstream/downstream/future/past = false (cascade symptoms are enumerated explicitly);
  reset_dag_runs = true (the existing run is re-queued; no new run is created).
``dry_run`` defaults to TRUE in Airflow, so it is always sent explicitly.

The schema's ``task_ids`` are plain strings: a single map_index cannot be targeted. Clearing a mapped
task with only_failed clears every failed map index of that task in the run. Before any mutating
call the executor therefore asks Airflow itself for the dry-run listing and proceeds only if it
equals the approved enumerated set (count per task id, same DAG and run). Otherwise nothing is
cleared.

Never auto-retries. Transport failures are classified: never sent (connection refused) vs.
ambiguous (timeout or drop after sending, 5xx, unparseable response) - ambiguous outcomes are
reported as such and are never resent.
"""

import os
import re
from collections import Counter
from collections.abc import Mapping
from typing import Annotated, Any, Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from adapters.base.interfaces import DispatchOutcome, RemediationExecutor
from core.logging_setup import get_logger
from core.models.base import PIPELINE_ID_RE, RUN_ID_PATTERN, TASK_ID_PATTERN
from core.models.enums import ActionCapability, ExecutionMode, RemediationClass
from core.models.remediation import RemediationPlan

_log = get_logger(__name__)

SUPPORTED_API_VERSIONS = frozenset({"v1"})
_CLEAR_PATH_RE = re.compile(r"^/api/v1/dags/[^/]+/clearTaskInstances$")


class ActionClientViolation(RuntimeError):
    """A request other than the single permitted clear operation was attempted."""


class ClearNotSentError(RuntimeError):
    """The request certainly never reached Airflow (e.g. connection refused). Nothing changed."""


class ClearAmbiguousError(RuntimeError):
    """The request may have been applied; the outcome is unknown. Never resend."""


class ClearRejectedError(RuntimeError):
    """Airflow answered with a 4xx: the request was refused and not applied."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"Airflow rejected the clear request ({status}): {detail}")
        self.status = status


class AirflowActionConfig(BaseModel):
    base_url: str
    api_version: str = "v1"
    username: str | None = None
    password: str | None = None
    token: str | None = None
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AirflowActionConfig":
        e = dict(os.environ if env is None else env)
        return cls(base_url=e.get("AIRFLOW_API_BASE_URL", ""), api_version=e.get("AIRFLOW_API_VERSION") or "v1",
                   username=e.get("AIRFLOW_WRITE_USERNAME") or None, password=e.get("AIRFLOW_WRITE_PASSWORD") or None,
                   token=e.get("AIRFLOW_WRITE_TOKEN") or None)


class ClearTaskInstancesBody(BaseModel):
    """The ClearTaskInstances request body. Every expansion flag is pinned to the safe value."""

    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    dag_run_id: str = Field(pattern=RUN_ID_PATTERN)
    task_ids: list[Annotated[str, Field(pattern=TASK_ID_PATTERN)]] = Field(min_length=1)
    only_failed: Literal[True] = True
    only_running: Literal[False] = False
    include_upstream: Literal[False] = False
    include_downstream: Literal[False] = False
    include_future: Literal[False] = False
    include_past: Literal[False] = False
    reset_dag_runs: Literal[True] = True


class TaskInstanceReference(BaseModel):
    model_config = ConfigDict(extra="ignore")

    task_id: str
    dag_id: str
    dag_run_id: str | None = None
    execution_date: str | None = None


class TaskInstanceReferenceCollection(BaseModel):
    model_config = ConfigDict(extra="ignore")

    task_instances: list[TaskInstanceReference]


def _enforce_clear_only(request: httpx.Request) -> None:
    if request.method != "POST" or not _CLEAR_PATH_RE.match(request.url.path):
        raise ActionClientViolation(f"action client refused {request.method} {request.url.path}")


class AirflowActionClient:
    """The only mutating Airflow client. Constructed only inside actions/ (architecture test)."""

    def __init__(self, config: AirflowActionConfig, http: httpx.Client | None = None) -> None:
        if config.api_version not in SUPPORTED_API_VERSIONS:
            raise ValueError(f"AIRFLOW_API_VERSION={config.api_version!r} is not supported for actions")
        if http is None:
            if not config.base_url:
                raise ValueError("AIRFLOW_API_BASE_URL is required for the action client")
            headers = {"Accept": "application/json"}
            auth: httpx.Auth | None = None
            if config.token:
                headers["Authorization"] = f"Bearer {config.token}"
            elif config.username and config.password:
                auth = httpx.BasicAuth(config.username, config.password)
            else:
                raise ValueError("AIRFLOW_WRITE_* credentials are required for the action client")
            http = httpx.Client(base_url=config.base_url, auth=auth, headers=headers, timeout=config.timeout_seconds)
        hooks = dict(http.event_hooks)
        hooks["request"] = [*hooks.get("request", []), _enforce_clear_only]
        http.event_hooks = hooks
        self._http = http
        self._prefix = f"/api/{config.api_version}"

    def clear_task_instances(self, dag_id: str, body: ClearTaskInstancesBody) -> list[TaskInstanceReference]:
        """The single mutating call (or its dry-run). Never retried."""
        if not PIPELINE_ID_RE.match(dag_id):
            raise ValueError(f"invalid dag_id {dag_id!r}")
        path = f"{self._prefix}/dags/{quote(dag_id, safe='')}/clearTaskInstances"
        try:
            response = self._http.post(path, json=body.model_dump())
        except ActionClientViolation:
            raise
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            raise ClearNotSentError(f"Airflow unreachable, request not sent: {type(exc).__name__}") from exc
        except httpx.TransportError as exc:
            raise ClearAmbiguousError(f"outcome unknown after sending: {type(exc).__name__}") from exc
        if response.status_code >= 500:
            raise ClearAmbiguousError(f"Airflow returned {response.status_code}; the clear may have been applied")
        if response.status_code != 200:
            raise ClearRejectedError(response.status_code, response.text[:300])
        try:
            return TaskInstanceReferenceCollection.model_validate(response.json()).task_instances
        except (ValueError, ValidationError) as exc:
            raise ClearAmbiguousError("unparseable response to the clear request") from exc

    def close(self) -> None:
        self._http.close()


def _listing(refs: list[TaskInstanceReference]) -> list[dict[str, Any]]:
    return [r.model_dump() for r in refs]


class AirflowRemediationExecutor(RemediationExecutor):
    platform = "airflow"

    def __init__(self, client: AirflowActionClient) -> None:
        self._client = client

    def action_capabilities(self) -> frozenset[ActionCapability]:
        return frozenset({ActionCapability.RETRY_FAILED_TASK, ActionCapability.RETRY_FAILED_DAG_RUN})

    @staticmethod
    def _matches(plan: RemediationPlan, refs: list[TaskInstanceReference]) -> bool:
        if plan.target is None:
            return False
        if any(r.dag_id != plan.target.dag_id or (r.dag_run_id not in (None, plan.target.dag_run_id)) for r in refs):
            return False
        return Counter(r.task_id for r in refs) == Counter(t.task_id for t in plan.task_instances_to_clear)

    def dispatch(self, plan: RemediationPlan) -> DispatchOutcome:
        if (plan.remediation_class is not RemediationClass.AUTOMATABLE or plan.target is None
                or plan.action_type is None or not plan.task_instances_to_clear):
            return DispatchOutcome(accepted=False, sent=False, detail="plan is not executable")
        if plan.execution_mode is not ExecutionMode.LIVE:
            return DispatchOutcome(accepted=False, sent=False, detail="DRY_RUN plans are never dispatched")
        dag_id = plan.target.dag_id
        task_ids = sorted({t.task_id for t in plan.task_instances_to_clear})

        # 1. Airflow's own dry-run listing must equal the approved enumerated set.
        try:
            preview = self._client.clear_task_instances(
                dag_id, ClearTaskInstancesBody(dry_run=True, dag_run_id=plan.target.dag_run_id, task_ids=task_ids))
        except (ClearNotSentError, ClearAmbiguousError, ClearRejectedError) as exc:
            return DispatchOutcome(accepted=False, sent=False, detail=f"dry-run listing failed; nothing cleared: {exc}")
        if not self._matches(plan, preview):
            _log.warning("clear_listing_mismatch", extra={"remediation_id": plan.remediation_id})
            return DispatchOutcome(accepted=False, sent=False, preflight=_listing(preview), listing_matches_plan=False,
                                   detail="Airflow's dry-run listing differs from the approved enumerated set; "
                                          "nothing cleared")

        # 2. The single mutating call. Never retried.
        body = ClearTaskInstancesBody(dry_run=False, dag_run_id=plan.target.dag_run_id, task_ids=task_ids)
        try:
            cleared = self._client.clear_task_instances(dag_id, body)
        except ClearNotSentError as exc:
            return DispatchOutcome(accepted=False, sent=False, preflight=_listing(preview), detail=str(exc))
        except ClearRejectedError as exc:
            return DispatchOutcome(accepted=False, preflight=_listing(preview), detail=str(exc))
        except ClearAmbiguousError as exc:
            return DispatchOutcome(accepted=False, ambiguous=True, preflight=_listing(preview), detail=str(exc))
        return DispatchOutcome(accepted=True, cleared=plan.task_instances_to_clear, preflight=_listing(preview),
                               listing_matches_plan=self._matches(plan, cleared),
                               detail=f"cleared {len(cleared)} task instance(s)",
                               raw_response={"task_instances": _listing(cleared), "request": body.model_dump()})


def build_airflow_executor(config: AirflowActionConfig, http: httpx.Client | None = None) -> AirflowRemediationExecutor:
    """Factory used by the API layer / tests: the action client is constructed only here."""
    return AirflowRemediationExecutor(AirflowActionClient(config, http=http))
