"""AirflowAdapter: read-only investigation adapter built on AirflowReadClient (GET only).

Execution identity: ``pipeline_id`` = dag_id, ``execution_id`` = ``platform_run_id`` = dag_run_id.
Airflow-specific identifiers (try_number, map_index, logical_date) live in event metadata.

Capability mapping (honest; Airflow's REST API exposes orchestration metadata only):
  run_logs            task logs                      -> get_run_output
  run_history         DAG run / task instance history -> get_run_history, get_task_state,
                                                         get_pipeline_state
  configuration       DAG details + task definition   -> get_configuration
  upstream_status     upstream task states in the run -> get_upstream_status
  downstream_status   downstream task states          -> get_downstream_status
Schema, row counts, data quality, lineage, state tracking, transactions, code changes,
infrastructure events and permissions are not available from Airflow and are UNAVAILABLE.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from adapters.airflow.client import AirflowReadClient
from adapters.airflow.schemas import AirflowTask, AirflowTaskInstance
from adapters.base.evidence import DEMO_LABEL, build_evidence
from adapters.base.interfaces import AdapterError, PipelineAdapter
from core.canonical import canonical_hash
from core.evidence.conventions import CAUSE_CLEARED_CANDIDATE, CAUSE_CLEARED_FOR, CONCURRENCY, OBSERVED_TASK_STATES
from core.evidence.log_extraction import extract_log_excerpt
from core.models.base import PIPELINE_ID_RE, RUN_ID_RE, TASK_ID_RE, utcnow
from core.models.enums import EvidenceCategory, ReadCapability, Reliability
from core.models.events import PipelineFailureEvent
from core.models.evidence import EvidenceItem
from core.models.reads import ReadRequest, ReadResult, ReadStatus
from core.remediation.selector import RunSnapshot, TaskInstanceSnapshot

RC = ReadCapability
AIRFLOW_READ_CAPABILITIES = frozenset(
    {RC.RUN_LOGS, RC.RUN_HISTORY, RC.CONFIGURATION, RC.UPSTREAM_STATUS, RC.DOWNSTREAM_STATUS}
)
_MAX_LOGS_PER_READ = 3
_FAILED = ("failed",)


def _parse_dt(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _ti_summary(ti: AirflowTaskInstance) -> dict[str, Any]:
    return {
        "dag_id": ti.dag_id,
        "dag_run_id": ti.dag_run_id,
        "task_id": ti.task_id,
        "map_index": ti.map_index,
        "state": ti.state,
        "try_number": ti.try_number,
        "start_date": ti.start_date.isoformat() if ti.start_date else None,
        "end_date": ti.end_date.isoformat() if ti.end_date else None,
        "pool": ti.pool,
        "queue": ti.queue,
        "hostname": ti.hostname,
        "operator": ti.operator,
    }


class AirflowAdapter(PipelineAdapter):
    platform = "airflow"

    def __init__(
        self,
        client: AirflowReadClient,
        *,
        demo: bool = False,
        max_log_bytes: int = 50_000,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._client = client
        self.demo = demo
        self._max_log_bytes = max_log_bytes
        self._clock = clock

    # ------------------------------------------------------------------ basics

    @property
    def is_demo(self) -> bool:
        return self.demo or self._client.fake_airflow_detected

    @property
    def _demo_label(self) -> str | None:
        return DEMO_LABEL if self.is_demo else None

    def read_capabilities(self) -> frozenset[ReadCapability]:
        return AIRFLOW_READ_CAPABILITIES

    def normalize_failure(self, payload: dict[str, Any]) -> PipelineFailureEvent:
        dag_id = payload.get("dag_id")
        run_id = payload.get("dag_run_id") or payload.get("run_id")
        task_id = payload.get("task_id")
        if not isinstance(dag_id, str) or not PIPELINE_ID_RE.match(dag_id):
            raise ValueError("payload has no valid dag_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
            raise ValueError("payload has no valid dag_run_id")
        if task_id is not None and (not isinstance(task_id, str) or not TASK_ID_RE.match(task_id)):
            raise ValueError("payload has an invalid task_id")
        try_number = payload.get("try_number")
        map_index = payload.get("map_index", -1)
        return PipelineFailureEvent(
            event_id="evt-" + canonical_hash(["airflow", dag_id, run_id, task_id, try_number, map_index])[:16],
            platform="airflow",
            orchestrator="airflow",
            pipeline_id=dag_id,
            pipeline_name=payload.get("dag_display_name") or dag_id,
            task_id=task_id,
            task_name=task_id,
            execution_id=run_id,
            platform_run_id=run_id,
            attempt_number=int(try_number) if try_number is not None else None,
            status=str(payload.get("state") or "failed"),
            failure_time=_parse_dt(payload.get("end_date")),
            start_time=_parse_dt(payload.get("start_date")),
            end_time=_parse_dt(payload.get("end_date")),
            error_message=payload.get("exception"),
            log_reference=payload.get("log_url"),
            environment=payload.get("environment"),
            metadata={
                "try_number": try_number,
                "map_index": map_index,
                "logical_date": payload.get("logical_date"),
                "demo": self._demo_label is not None,
            },
        )

    def _ev(self, req: ReadRequest, *, capability: RC, tool: str, source: str, **kw: Any) -> EvidenceItem:
        return build_evidence(
            adapter="airflow",
            platform="airflow",
            capability=capability.value,
            tool=tool,
            source=source,
            req=req,
            collected_at=self._clock(),
            demo_label=self._demo_label,
            **kw,
        )

    def _guard(self, tool: str, fn: Callable[[], list[EvidenceItem]]) -> ReadResult:
        try:
            return ReadResult(tool=tool, status=ReadStatus.AVAILABLE, evidence=fn())
        except (AdapterError, ValueError) as exc:
            return ReadResult.error(tool, f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------ run snapshot (selector input)

    def get_run_snapshot(self, pipeline_id: str, execution_id: str) -> RunSnapshot:
        """Raises AdapterError if anything cannot be read; callers must treat that as unreadable."""
        run = self._client.get_dag_run(pipeline_id, execution_id)
        tasks = self._client.get_tasks(pipeline_id)
        tis = self._client.list_task_instances(pipeline_id, execution_id)
        upstream: dict[str, list[str]] = {t.task_id: [] for t in tasks}
        for t in tasks:
            for child in t.downstream_task_ids:
                upstream.setdefault(child, []).append(t.task_id)
        return RunSnapshot(
            dag_id=pipeline_id,
            dag_run_id=execution_id,
            run_state=run.state,
            task_instances=[
                TaskInstanceSnapshot(
                    task_id=ti.task_id,
                    map_index=None if ti.map_index < 0 else ti.map_index,
                    try_number=ti.try_number,
                    state=ti.state if ti.state is not None else "none",
                    upstream_task_ids=sorted(upstream.get(ti.task_id, [])),
                    end_date=ti.end_date,
                )
                for ti in tis
            ],
        )

    def recent_failures(self, pipeline_id: str, limit: int = 5) -> list[dict[str, Any]]:
        """Failed task instances of recently failed DAG runs (GET only). Raises AdapterError."""
        payloads: list[dict[str, Any]] = []
        for run in self._client.list_dag_runs(pipeline_id, limit=limit, state=["failed"]):
            for ti in self._client.list_task_instances(pipeline_id, run.dag_run_id, state=["failed"]):
                payloads.append({
                    "dag_id": pipeline_id, "dag_run_id": run.dag_run_id, "task_id": ti.task_id,
                    "try_number": ti.try_number, "map_index": ti.map_index, "state": "failed",
                    "start_date": ti.start_date.isoformat() if ti.start_date else None,
                    "end_date": ti.end_date.isoformat() if ti.end_date else None,
                    "logical_date": run.logical_date.isoformat() if run.logical_date else None,
                    "source": "poller"})
        return payloads

    # ------------------------------------------------------------------ reads

    def _instances_for_task(self, req: ReadRequest) -> list[AirflowTaskInstance]:
        tis = self._client.list_task_instances(req.pipeline_id, req.execution_id)
        if req.task_id is not None:
            return [ti for ti in tis if ti.task_id == req.task_id]
        return [ti for ti in tis if ti.state in _FAILED]

    def get_run_output(self, req: ReadRequest) -> ReadResult:
        tool = "get_run_output"

        def run() -> list[EvidenceItem]:
            out: list[EvidenceItem] = []
            targets = self._instances_for_task(req)[:_MAX_LOGS_PER_READ]
            for ti in targets:
                try_number = req.attempt_number if (req.attempt_number and req.task_id) else ti.try_number
                if try_number is None or try_number < 1:
                    continue
                log = self._client.get_task_log(req.pipeline_id, req.execution_id, ti.task_id, try_number,
                                                ti.map_index)
                excerpt = extract_log_excerpt(log.text, max_bytes=self._max_log_bytes,
                                              original_reference=f"{ti.task_id}[{ti.map_index}]/try{try_number}")
                key = f"{ti.task_id}:{ti.map_index}:{try_number}"
                source = f"airflow:task_log:{ti.task_id}:{ti.map_index}:try{try_number}"
                common = dict(capability=RC.RUN_LOGS, tool=tool, source=source, timestamp=ti.end_date,
                              attempt_number=try_number, metadata={"task_id": ti.task_id, "map_index": ti.map_index})
                out.append(self._ev(
                    req, category=EvidenceCategory.LOG, key=key,
                    description=f"Task log excerpt for {ti.task_id} (map_index {ti.map_index}), try {try_number}",
                    value={"excerpt": excerpt.excerpt, "matched_signatures": excerpt.matched_signatures,
                           "truncated": excerpt.truncated or log.truncated,
                           "original_bytes": log.original_bytes},
                    reliability=Reliability.HIGH, signal_text=excerpt.excerpt, **common))
                if excerpt.stack_trace:
                    out.append(self._ev(
                        req, category=EvidenceCategory.STACK_TRACE, key=key + ":trace",
                        description=f"Stack trace from {ti.task_id}, try {try_number}",
                        value=excerpt.stack_trace, reliability=Reliability.HIGH,
                        signal_text=excerpt.stack_trace, **common))
            return out

        return self._guard(tool, run)

    def get_run_history(self, req: ReadRequest) -> ReadResult:
        tool = "get_run_history"

        def run() -> list[EvidenceItem]:
            out: list[EvidenceItem] = []
            runs = self._client.list_dag_runs(req.pipeline_id, limit=req.limit + 1)
            others = [r for r in runs if r.dag_run_id != req.execution_id][: req.limit]
            out.append(self._ev(
                req, capability=RC.RUN_HISTORY, tool=tool, key="dag_runs",
                source=f"airflow:dag_runs:{req.pipeline_id}", category=EvidenceCategory.RUN_HISTORY,
                description=f"{len(others)} most recent other runs of {req.pipeline_id}",
                value=[{"dag_run_id": r.dag_run_id, "state": r.state, "run_type": r.run_type,
                        "start_date": r.start_date.isoformat() if r.start_date else None,
                        "end_date": r.end_date.isoformat() if r.end_date else None} for r in others],
                reliability=Reliability.MEDIUM,
                timestamp=self._clock()))  # a current read of the history; run dates are in the value

            active = [r for r in self._client.list_dag_runs(req.pipeline_id, limit=25, state=["running", "queued"])
                      if r.dag_run_id != req.execution_id]
            out.append(self._ev(
                req, capability=RC.RUN_HISTORY, tool=tool, key="active_runs",
                source=f"airflow:dag_runs:{req.pipeline_id}:active", category=EvidenceCategory.RUN_HISTORY,
                description=f"{len(active)} other active (running/queued) run(s) of {req.pipeline_id}",
                value=[{"dag_run_id": r.dag_run_id, "state": r.state} for r in active],
                reliability=Reliability.HIGH, timestamp=self._clock(),
                metadata={CONCURRENCY: "OVERLAP_CONFIRMED" if active else "NONE_CONFIRMED"}))

            if req.task_id is None:
                return out
            current = self._instances_for_task(req)
            if not current:
                return out
            failed_ti = current[0]
            overlapping = [r for r in runs if r.dag_run_id != req.execution_id and failed_ti.start_date
                           and failed_ti.end_date and r.start_date and r.start_date < failed_ti.end_date
                           and (r.end_date is None or r.end_date > failed_ti.start_date)]
            if overlapping:
                finished = [r for r in overlapping if r.state in ("success", "failed") and r.end_date
                            and r.end_date > failed_ti.end_date]
                all_done = len(finished) == len(overlapping)
                out.append(self._ev(
                    req, capability=RC.RUN_HISTORY, tool=tool, key="overlapping_runs",
                    source=f"airflow:dag_runs:{req.pipeline_id}:overlapping", category=EvidenceCategory.RUN_HISTORY,
                    description=(f"{len(overlapping)} other run(s) of {req.pipeline_id} overlapped the failed task; "
                                 f"{len(finished)} have since reached a terminal state"),
                    value=[{"dag_run_id": r.dag_run_id, "state": r.state,
                            "start_date": r.start_date.isoformat() if r.start_date else None,
                            "end_date": r.end_date.isoformat() if r.end_date else None} for r in overlapping],
                    reliability=Reliability.HIGH,
                    timestamp=max((r.end_date for r in finished if r.end_date), default=None) if all_done else None,
                    metadata={CAUSE_CLEARED_CANDIDATE: all_done, CAUSE_CLEARED_FOR: ["CONCURRENCY"]}))
            if failed_ti.pool and failed_ti.end_date:
                later = self._client.list_pool_task_instances(
                    failed_ti.pool, state=["success"], start_date_gte=failed_ti.end_date, limit=req.limit)
                later = [ti for ti in later if not (ti.dag_run_id == req.execution_id and ti.task_id == req.task_id)]
                out.append(self._ev(
                    req, capability=RC.RUN_HISTORY, tool=tool, key=f"pool:{failed_ti.pool}",
                    source=f"airflow:pool_task_instances:{failed_ti.pool}", category=EvidenceCategory.RUN_HISTORY,
                    description=(f"{len(later)} task instance(s) in pool '{failed_ti.pool}' succeeded after the "
                                 f"failure at {failed_ti.end_date.isoformat()}"),
                    value={"pool": failed_ti.pool, "failure_end": failed_ti.end_date.isoformat(),
                           "later_successes": [_ti_summary(ti) for ti in later]},
                    reliability=Reliability.HIGH if later else Reliability.MEDIUM,
                    timestamp=max((ti.end_date for ti in later if ti.end_date), default=None),
                    metadata={CAUSE_CLEARED_CANDIDATE: bool(later), "shared_resource": "pool",
                              # later successes on a shared pool speak to transient infra causes only
                              CAUSE_CLEARED_FOR: ["NETWORK_CONNECTIVITY", "INFRASTRUCTURE", "RESOURCE_QUOTA"]}))
            return out

        return self._guard(tool, run)

    def get_task_state(self, req: ReadRequest) -> ReadResult:
        tool = "get_task_state"
        if req.task_id is None:
            return ReadResult.error(tool, "task_id is required")

        def run() -> list[EvidenceItem]:
            tis = self._instances_for_task(req)
            return [self._ev(
                req, capability=RC.RUN_HISTORY, tool=tool, key=f"ti:{req.task_id}",
                source=f"airflow:task_instances:{req.task_id}", category=EvidenceCategory.STATE,
                description=f"Current state of task {req.task_id} in run {req.execution_id} (orchestrator state)",
                value=[_ti_summary(ti) for ti in tis], reliability=Reliability.HIGH,
                timestamp=self._clock(),
                metadata={"state_kind": "orchestrator_task_state",
                          OBSERVED_TASK_STATES: [{"task_id": ti.task_id, "map_index": ti.map_index,
                                                  "attempt": ti.try_number, "state": ti.state} for ti in tis]})]

        return self._guard(tool, run)

    def get_pipeline_state(self, req: ReadRequest) -> ReadResult:
        tool = "get_pipeline_state"

        def run() -> list[EvidenceItem]:
            dag_run = self._client.get_dag_run(req.pipeline_id, req.execution_id)
            tis = self._client.list_task_instances(req.pipeline_id, req.execution_id)
            counts: dict[str, int] = {}
            for ti in tis:
                counts[ti.state or "none"] = counts.get(ti.state or "none", 0) + 1
            return [self._ev(
                req, capability=RC.RUN_HISTORY, tool=tool, key="dag_run",
                source=f"airflow:dag_run:{req.execution_id}", category=EvidenceCategory.STATE,
                description=f"DAG run {req.execution_id} state {dag_run.state}",
                value={"state": dag_run.state, "run_type": dag_run.run_type, "task_state_counts": counts,
                       "failed_tasks": sorted({ti.task_id for ti in tis if ti.state == "failed"})},
                reliability=Reliability.HIGH, timestamp=self._clock(),
                metadata={"state_kind": "orchestrator_run_state"})]

        return self._guard(tool, run)

    def get_configuration(self, req: ReadRequest) -> ReadResult:
        tool = "get_configuration"

        def run() -> list[EvidenceItem]:
            details = self._client.get_dag_details(req.pipeline_id)
            value: dict[str, Any] = {
                "dag": {"max_active_runs": details.max_active_runs, "max_active_tasks": details.max_active_tasks,
                        "catchup": details.catchup, "is_paused": details.is_paused,
                        "has_import_errors": details.has_import_errors,
                        "param_names": sorted((details.params or {}).keys())},
            }
            if req.task_id is not None:
                task = self._task(req.pipeline_id, req.task_id)
                value["task"] = {"retries": task.retries, "pool": task.pool, "queue": task.queue,
                                 "trigger_rule": task.trigger_rule, "depends_on_past": task.depends_on_past,
                                 "is_mapped": task.is_mapped, "execution_timeout": task.execution_timeout}
            return [self._ev(
                req, capability=RC.CONFIGURATION, tool=tool, key=f"config:{req.task_id}",
                source=f"airflow:dag_details:{req.pipeline_id}", category=EvidenceCategory.CONFIGURATION,
                description=f"DAG configuration for {req.pipeline_id} (param values withheld)",
                value=value, reliability=Reliability.HIGH, timestamp=self._clock())]

        return self._guard(tool, run)

    def _task(self, dag_id: str, task_id: str) -> AirflowTask:
        for task in self._client.get_tasks(dag_id):
            if task.task_id == task_id:
                return task
        raise AdapterError(f"task {task_id} not found in DAG {dag_id}")

    def _neighbour_status(self, req: ReadRequest, tool: str, upstream: bool) -> ReadResult:
        if req.task_id is None:
            return ReadResult.error(tool, "task_id is required")

        def run() -> list[EvidenceItem]:
            tasks = self._client.get_tasks(req.pipeline_id)
            if upstream:
                related = sorted(t.task_id for t in tasks if req.task_id in t.downstream_task_ids)
            else:
                related = sorted(self._task(req.pipeline_id, req.task_id).downstream_task_ids)
            tis = self._client.list_task_instances(req.pipeline_id, req.execution_id)
            states = [_ti_summary(ti) for ti in tis if ti.task_id in related]
            direction = "upstream" if upstream else "downstream"
            return [self._ev(
                req, capability=RC.UPSTREAM_STATUS if upstream else RC.DOWNSTREAM_STATUS, tool=tool,
                key=f"{direction}:{req.task_id}", source=f"airflow:{direction}:{req.task_id}",
                category=EvidenceCategory.UPSTREAM if upstream else EvidenceCategory.DOWNSTREAM,
                description=f"{direction.capitalize()} tasks of {req.task_id} in run {req.execution_id}",
                value={"task_ids": related, "task_instances": states}, reliability=Reliability.HIGH,
                timestamp=self._clock())]

        return self._guard(tool, run)

    def get_upstream_status(self, req: ReadRequest) -> ReadResult:
        return self._neighbour_status(req, "get_upstream_status", upstream=True)

    def get_downstream_status(self, req: ReadRequest) -> ReadResult:
        return self._neighbour_status(req, "get_downstream_status", upstream=False)
