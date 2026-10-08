"""FAKE AIRFLOW (DEMO): a small FastAPI app implementing the subset of the Airflow 2.x stable REST
API (v1) used by AirflowReadClient (GET endpoints) and AirflowActionClient (the clear endpoint,
``POST /dags/{dag_id}/clearTaskInstances``, following the 2.10.5 ClearTaskInstances schema:
``dry_run`` defaults to true; ``only_failed`` clears failed and upstream_failed instances).

Every response carries ``X-Fake-Airflow``. Every request (any method) is recorded so tests can
assert which endpoints were or were not called. Run locally:

    uvicorn demo.fake_airflow.app:app --port 8081
"""

import os
from datetime import datetime
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from demo.fake_airflow.state import FAKE_LABEL, FakeAirflowState, RecordedRequest, load_scenario

API = "/api/v1"
TASK_FIELDS = ("task_id", "downstream_task_ids", "pool", "queue", "retries", "trigger_rule", "depends_on_past",
               "is_mapped", "class_ref", "execution_timeout")


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def create_app(state: FakeAirflowState) -> FastAPI:
    app = FastAPI(title=f"{FAKE_LABEL} - scenario {state.scenario}", version="2.10.5-fake")
    app.state.fake = state

    @app.middleware("http")
    async def record_and_label(request: Request, call_next: Any) -> Response:
        state.request_log.append(
            RecordedRequest(method=request.method, path=request.url.path, query=request.url.query)
        )
        path = request.url.path
        if (state.down or any(path.endswith(p) for p in state.fail_paths)) and not path.startswith("/_fake"):
            response: Response = JSONResponse({"detail": "Airflow unavailable (simulated)"}, status_code=503)
        else:
            if request.method == "GET" and "/dagRuns/" in path:
                state.advance()
            response = await call_next(request)
        response.headers["X-Fake-Airflow"] = FAKE_LABEL
        return response

    def _dag_or_404(dag_id: str) -> dict[str, Any]:
        dag = state.dag(dag_id)
        if dag is None:
            raise HTTPException(404, f"DAG {dag_id} not found")
        return dag

    # ------------------------------------------------------------------ meta

    @app.get(f"{API}/health")
    def health() -> dict[str, Any]:
        return {"metadatabase": {"status": "healthy"},
                "scheduler": {"status": "healthy", "latest_scheduler_heartbeat": None}}

    @app.get(f"{API}/version")
    def version() -> dict[str, Any]:
        return {"version": "2.10.5", "git_version": f"fake ({FAKE_LABEL})"}

    @app.get("/_fake/requests")
    def requests_log() -> list[dict[str, str]]:
        return [r.model_dump() for r in state.request_log]

    # ------------------------------------------------------------------ dags

    def _dag_view(dag: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in dag.items() if k not in ("tasks", "params", "catchup", "concurrency", "timezone")}

    @app.get(f"{API}/dags/{{dag_id}}")
    def get_dag(dag_id: str) -> dict[str, Any]:
        return _dag_view(_dag_or_404(dag_id))

    @app.get(f"{API}/dags/{{dag_id}}/details")
    def get_dag_details(dag_id: str) -> dict[str, Any]:
        dag = _dag_or_404(dag_id)
        return {k: v for k, v in dag.items() if k != "tasks"}

    @app.get(f"{API}/dags/{{dag_id}}/tasks")
    def get_tasks(dag_id: str) -> dict[str, Any]:
        tasks = [{k: t.get(k) for k in TASK_FIELDS if k in t} for t in _dag_or_404(dag_id)["tasks"]]
        return {"tasks": tasks, "total_entries": len(tasks)}

    # ------------------------------------------------------------------ dag runs

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns")
    def list_dag_runs(
        dag_id: str,
        limit: int = 100,
        offset: int = 0,
        order_by: str | None = None,
        state_filter: list[str] | None = Query(None, alias="state"),
    ) -> dict[str, Any]:
        if dag_id != "~":
            _dag_or_404(dag_id)
        runs = [r for r in state.dag_runs if dag_id == "~" or r["dag_id"] == dag_id]
        if state_filter:
            runs = [r for r in runs if r["state"] in state_filter]
        if order_by:
            key = order_by.lstrip("-")
            runs.sort(key=lambda r: r.get(key) or "", reverse=order_by.startswith("-"))
        return {"dag_runs": runs[offset: offset + limit], "total_entries": len(runs)}

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns/{{dag_run_id}}")
    def get_dag_run(dag_id: str, dag_run_id: str) -> dict[str, Any]:
        run = state.dag_run(dag_id, dag_run_id)
        if run is None:
            raise HTTPException(404, "DAGRun not found")
        return run

    # ------------------------------------------------------------------ task instances

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns/{{dag_run_id}}/taskInstances")
    def list_task_instances(
        dag_id: str,
        dag_run_id: str,
        limit: int = 100,
        offset: int = 0,
        state_filter: list[str] | None = Query(None, alias="state"),
        pool: list[str] | None = Query(None),
        start_date_gte: str | None = None,
    ) -> dict[str, Any]:
        if dag_run_id != "~" and state.dag_run(dag_id, dag_run_id) is None:
            raise HTTPException(404, "DAGRun not found")
        tis = state.task_instances_for(dag_id, dag_run_id)
        if state_filter:
            tis = [ti for ti in tis if ti["state"] in state_filter]
        if pool:
            tis = [ti for ti in tis if ti.get("pool") in pool]
        if start_date_gte:
            floor = _dt(start_date_gte)
            tis = [ti for ti in tis if ti.get("start_date") and _dt(ti["start_date"]) >= floor]
        tis = sorted(tis, key=lambda t: (t["dag_id"], t["dag_run_id"], t["task_id"], t.get("map_index", -1)))
        return {"task_instances": tis[offset: offset + limit], "total_entries": len(tis)}

    def _tis_for_task(dag_id: str, dag_run_id: str, task_id: str) -> list[dict[str, Any]]:
        tis = [ti for ti in state.task_instances_for(dag_id, dag_run_id) if ti["task_id"] == task_id]
        if not tis:
            raise HTTPException(404, "Task instance not found")
        return tis

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns/{{dag_run_id}}/taskInstances/{{task_id}}/listMapped")
    def list_mapped(dag_id: str, dag_run_id: str, task_id: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        tis = [ti for ti in _tis_for_task(dag_id, dag_run_id, task_id) if ti.get("map_index", -1) >= 0]
        return {"task_instances": tis[offset: offset + limit], "total_entries": len(tis)}

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns/{{dag_run_id}}/taskInstances/{{task_id}}/logs/{{task_try_number}}")
    def get_log(
        request: Request,
        dag_id: str,
        dag_run_id: str,
        task_id: str,
        task_try_number: int,
        map_index: int = -1,
        full_content: bool = False,
    ) -> Response:
        content = state.log(dag_id, dag_run_id, task_id, task_try_number, map_index)
        if content is None:
            raise HTTPException(404, "Log not found")
        if "text/plain" in request.headers.get("accept", ""):
            return PlainTextResponse(content)
        return JSONResponse({"content": content, "continuation_token": None})

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns/{{dag_run_id}}/taskInstances/{{task_id}}")
    def get_task_instance(dag_id: str, dag_run_id: str, task_id: str) -> dict[str, Any]:
        tis = [ti for ti in _tis_for_task(dag_id, dag_run_id, task_id) if ti.get("map_index", -1) == -1]
        if not tis:
            raise HTTPException(404, "Task instance is mapped; use the map_index endpoint")
        return tis[0]

    @app.get(f"{API}/dags/{{dag_id}}/dagRuns/{{dag_run_id}}/taskInstances/{{task_id}}/{{map_index}}")
    def get_mapped_task_instance(dag_id: str, dag_run_id: str, task_id: str, map_index: int) -> dict[str, Any]:
        for ti in _tis_for_task(dag_id, dag_run_id, task_id):
            if ti.get("map_index", -1) == map_index:
                return ti
        raise HTTPException(404, "Mapped task instance not found")

    # ------------------------------------------------------------------ the one write endpoint

    @app.post(f"{API}/dags/{{dag_id}}/clearTaskInstances")
    def clear_task_instances(dag_id: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        state.request_log[-1].body = body
        _dag_or_404(dag_id)
        for flag in ("include_upstream", "include_downstream", "include_future", "include_past", "only_running",
                     "include_subdags", "include_parentdag"):
            if body.get(flag):
                raise HTTPException(400, f"{FAKE_LABEL}: {flag}=true is not simulated")
        dag_run_id = body.get("dag_run_id")
        task_ids = body.get("task_ids")
        if not dag_run_id or state.dag_run(dag_id, dag_run_id) is None:
            raise HTTPException(404, "DAGRun not found")
        if not isinstance(task_ids, list) or not task_ids:
            raise HTTPException(400, "task_ids must be a non-empty list")
        only_failed = body.get("only_failed", True)
        tis = [ti for ti in state.task_instances_for(dag_id, dag_run_id) if ti["task_id"] in task_ids
               and (not only_failed or ti["state"] in ("failed", "upstream_failed"))]
        refs = [{"task_id": ti["task_id"], "dag_id": dag_id, "dag_run_id": dag_run_id, "execution_date": None}
                for ti in tis]
        if body.get("dry_run", True) is False:
            state.apply_clear(dag_id, dag_run_id, [(ti["task_id"], ti.get("map_index", -1)) for ti in tis])
        return {"task_instances": refs}

    return app


app = create_app(load_scenario(os.environ.get("FAKE_AIRFLOW_SCENARIO", "hero_transient_network")))
