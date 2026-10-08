"""AirflowReadClient is GET-only (B4): static, runtime and hook-level guarantees."""

import ast
import inspect
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

import adapters.airflow.client as client_module
from adapters.airflow.client import (
    AirflowAuthError,
    AirflowNotFoundError,
    AirflowReadClient,
    AirflowReadConfig,
    AirflowResponseError,
    AirflowUnavailableError,
    ReadOnlyViolation,
)

CLIENT_SOURCE = Path(client_module.__file__).read_text(encoding="utf-8")
NON_GET_ATTRS = {"post", "put", "patch", "delete", "request", "send", "stream", "build_request", "options", "head"}
NON_GET_LITERALS = {"POST", "PUT", "PATCH", "DELETE"}


def test_module_has_no_code_path_issuing_non_get_requests():
    tree = ast.parse(CLIENT_SOURCE)
    attr_calls = {
        node.func.attr for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not (attr_calls & NON_GET_ATTRS), attr_calls & NON_GET_ATTRS
    literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not (literals & NON_GET_LITERALS)


def test_only_one_method_performs_http():
    tree = ast.parse(CLIENT_SOURCE)
    callers = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "_http"
                        and node.func.attr != "close"):
                    callers.add(fn.name)
    assert callers == {"_get"}


def _recording_client(status: int = 200, body: object | None = None) -> tuple[AirflowReadClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path.endswith("/logs/1"):
            return httpx.Response(status, text="log")
        payload = body
        if payload is None:
            if path.endswith("/health"):
                payload = {}
            elif path.endswith("/version"):
                payload = {"version": "2.10.5"}
            elif path.endswith("/tasks"):
                payload = {"tasks": [], "total_entries": 0}
            elif path.endswith("/dagRuns"):
                payload = {"dag_runs": [], "total_entries": 0}
            elif path.endswith("/taskInstances") or path.endswith("/listMapped"):
                payload = {"task_instances": [], "total_entries": 0}
            elif "/taskInstances/" in path:
                payload = {"task_id": "t", "dag_id": "d", "dag_run_id": "r", "try_number": 1}
            elif "/dagRuns/" in path:
                payload = {"dag_run_id": "r", "dag_id": "d"}
            else:
                payload = {"dag_id": "d"}
        return httpx.Response(status, json=payload)

    http = httpx.Client(base_url="http://airflow", transport=httpx.MockTransport(handler))
    return AirflowReadClient(AirflowReadConfig(base_url="http://airflow"), http=http), seen


def _call_every_public_method(client: AirflowReadClient) -> None:
    since = datetime(2026, 10, 1, tzinfo=timezone.utc)
    client.health()
    client.version()
    client.get_dag("d")
    client.get_dag_details("d")
    client.get_tasks("d")
    client.get_dag_run("d", "r")
    client.list_dag_runs("d", limit=3, state=["failed"])
    client.list_task_instances("d", "r", state=["failed"])
    client.get_task_instance("d", "r", "t")
    client.get_task_instance("d", "r", "t", map_index=2)
    client.list_mapped_task_instances("d", "r", "t")
    client.list_pool_task_instances("default_pool", state=["success"], start_date_gte=since)
    client.get_task_log("d", "r", "t", 1)


def test_every_public_method_issues_only_get():
    client, seen = _recording_client()
    _call_every_public_method(client)
    public = {n for n, _ in inspect.getmembers(AirflowReadClient, inspect.isfunction) if not n.startswith("_")}
    assert public == {"health", "version", "get_dag", "get_dag_details", "get_tasks", "get_dag_run", "list_dag_runs",
                      "list_task_instances", "get_task_instance", "list_mapped_task_instances",
                      "list_pool_task_instances", "get_task_log", "close"}
    assert len(seen) == 13
    assert {r.method for r in seen} == {"GET"}


def test_request_hook_refuses_non_get_even_through_the_underlying_client():
    client, seen = _recording_client()
    with pytest.raises(ReadOnlyViolation):
        client._http.post("/api/v1/dags/d/clearTaskInstances", json={"dry_run": False})
    assert seen == []


def test_path_parameters_validated_before_any_request():
    client, seen = _recording_client()
    for bad in ("../admin", "d?x=1", "d/../../x", "", "a b"):
        with pytest.raises(ValueError):
            client.get_dag(bad)
    with pytest.raises(ValueError):
        client.get_dag_run("d", "run/../../")
    assert seen == []


def test_run_id_is_url_encoded():
    client, seen = _recording_client()
    client.get_dag_run("d", "scheduled__2026-10-08T00:00:00+00:00")
    assert seen[0].url.raw_path.decode().endswith("/dagRuns/scheduled__2026-10-08T00%3A00%3A00%2B00%3A00")


@pytest.mark.parametrize(
    "status,error",
    [(401, AirflowAuthError), (403, AirflowAuthError), (404, AirflowNotFoundError),
     (500, AirflowUnavailableError), (503, AirflowUnavailableError), (409, AirflowResponseError)],
)
def test_status_mapping(status, error):
    client, _ = _recording_client(status=status)
    with pytest.raises(error):
        client.get_dag("d")


def test_transport_failure_is_unavailable():
    def boom(request):
        raise httpx.ConnectError("refused", request=request)

    http = httpx.Client(base_url="http://airflow", transport=httpx.MockTransport(boom))
    client = AirflowReadClient(AirflowReadConfig(base_url="http://airflow"), http=http)
    with pytest.raises(AirflowUnavailableError):
        client.health()


def test_contract_violation_is_response_error():
    client, _ = _recording_client(body={"unexpected": True})
    with pytest.raises(AirflowResponseError):
        client.get_dag_run("d", "r")


def test_unverified_api_version_refused():
    with pytest.raises(ValueError, match="not supported"):
        AirflowReadClient(AirflowReadConfig(base_url="http://x", api_version="v2"))


def test_log_is_bounded_keeping_the_tail():
    def handler(request):
        return httpx.Response(200, text="A" * 1000 + "ERROR at the end")

    http = httpx.Client(base_url="http://airflow", transport=httpx.MockTransport(handler))
    client = AirflowReadClient(AirflowReadConfig(base_url="http://airflow", max_log_bytes=50), http=http)
    log = client.get_task_log("d", "r", "t", 1)
    assert log.truncated and log.text.endswith("ERROR at the end") and len(log.text) == 50
    assert log.original_bytes == 1016
