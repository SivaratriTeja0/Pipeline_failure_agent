"""Contract tests: the read client against Airflow v1 response fixtures, and FAKE AIRFLOW against
the same schemas. Fixtures are authored from the OpenAPI spec (see manifest.json), not recorded
from a live instance; that limitation is asserted so it cannot silently disappear."""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from adapters.airflow.schemas import (
    TASK_STATES,
    AirflowDagDetail,
    AirflowDagRun,
    AirflowDagRunCollection,
    AirflowTaskCollection,
    AirflowTaskInstance,
    AirflowTaskInstanceCollection,
    HealthInfo,
    VersionInfo,
)
from tests.airflow_helpers import HERO_DAG, HERO_RUN, hero

FIXTURES = Path(__file__).parent / "fixtures" / "airflow_v1"
RUN = "manual__2026-10-01T10:00:00+00:00"
RUN_ENC = "manual__2026-10-01T10%3A00%3A00%2B00%3A00"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_manifest_labels_fixture_provenance_honestly():
    manifest = fixture("manifest.json")
    assert "NOT RECORDED FROM A LIVE AIRFLOW" in manifest["provenance"]
    assert set(manifest["files"]) == {p.name for p in FIXTURES.iterdir() if p.name != "manifest.json"}


@pytest.mark.parametrize(
    "name,model",
    [
        ("health.json", HealthInfo),
        ("version.json", VersionInfo),
        ("dag_details.json", AirflowDagDetail),
        ("tasks.json", AirflowTaskCollection),
        ("dag_run.json", AirflowDagRun),
        ("task_instances.json", AirflowTaskInstanceCollection),
        ("task_instance.json", AirflowTaskInstance),
        ("pool_task_instances.json", AirflowTaskInstanceCollection),
    ],
)
def test_fixtures_match_schema_models(name, model):
    model.model_validate(fixture(name))


def test_fixture_task_states_are_valid_enum_values():
    for ti in fixture("task_instances.json")["task_instances"]:
        assert ti["state"] is None or ti["state"] in TASK_STATES


# (raw path, query) -> fixture. Exact paths and query params are part of the contract.
ROUTES = {
    ("/api/v1/health", ""): "health.json",
    ("/api/v1/version", ""): "version.json",
    ("/api/v1/dags/orders_daily/details", ""): "dag_details.json",
    ("/api/v1/dags/orders_daily/tasks", ""): "tasks.json",
    (f"/api/v1/dags/orders_daily/dagRuns/{RUN_ENC}", ""): "dag_run.json",
    (f"/api/v1/dags/orders_daily/dagRuns/{RUN_ENC}/taskInstances", "limit=100&offset=0"): "task_instances.json",
    (f"/api/v1/dags/orders_daily/dagRuns/{RUN_ENC}/taskInstances/extract", ""): "task_instance.json",
    ("/api/v1/dags/~/dagRuns/~/taskInstances",
     "pool=default_pool&state=success&start_date_gte=2026-10-01T10%3A01%3A07%2B00%3A00&limit=25&offset=0"):
        "pool_task_instances.json",
    (f"/api/v1/dags/orders_daily/dagRuns/{RUN_ENC}/taskInstances/transform/logs/2", "full_content=true&map_index=1"):
        "task_log.txt",
}


@pytest.fixture
def contract_client():
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.url.raw_path.decode().split("?")[0], request.url.query.decode())
        seen.append(key)
        name = ROUTES.get(key)
        if name is None:
            return httpx.Response(404, json={"detail": f"no contract route for {key}"})
        if name.endswith(".txt"):
            return httpx.Response(200, text=(FIXTURES / name).read_text(encoding="utf-8"))
        return httpx.Response(200, json=fixture(name))

    http = httpx.Client(base_url="http://airflow", transport=httpx.MockTransport(handler))
    return AirflowReadClient(AirflowReadConfig(base_url="http://airflow"), http=http), seen


def test_client_requests_exact_contract_paths_and_parses(contract_client):
    client, seen = contract_client
    assert client.health().metadatabase.status == "healthy"
    assert client.version().version == "2.10.5"
    assert client.get_dag_details("orders_daily").max_active_runs == 1
    tasks = client.get_tasks("orders_daily")
    assert [t.task_id for t in tasks] == ["extract", "transform"] and tasks[1].is_mapped
    assert client.get_dag_run("orders_daily", RUN).state == "failed"
    tis = client.list_task_instances("orders_daily", RUN)
    assert len(tis) == 4
    mapped = [ti for ti in tis if ti.task_id == "transform"]
    assert sorted(ti.map_index for ti in mapped) == [0, 1]
    assert next(ti for ti in tis if ti.task_id == "report").state is None
    assert client.get_task_instance("orders_daily", RUN, "extract").state == "success"
    since = datetime(2026, 10, 1, 10, 1, 7, tzinfo=timezone.utc)
    pool = client.list_pool_task_instances("default_pool", state=["success"], start_date_gte=since)
    assert pool[0].dag_id == "inventory"
    log = client.get_task_log("orders_daily", RUN, "transform", 2, map_index=1)
    assert "Connection refused" in log.text
    assert len(seen) == len(ROUTES)
    assert all(ROUTES.get(k) for k in seen), [k for k in seen if k not in ROUTES]


def test_contract_query_param_names_match_openapi(contract_client):
    client, seen = contract_client
    client.get_task_log("orders_daily", RUN, "transform", 2, map_index=1)
    query = parse_qs(seen[-1][1])
    assert set(query) == {"full_content", "map_index"}


# ---------------------------------------------------------------- FAKE AIRFLOW honours the same contract


def test_fake_airflow_responses_validate_against_contract_models():
    adapter, state = hero()
    client = adapter._client
    client.health()
    client.version()
    client.get_dag_details(HERO_DAG)
    client.get_tasks(HERO_DAG)
    client.get_dag_run(HERO_DAG, HERO_RUN)
    AirflowDagRunCollection.model_validate({"dag_runs": [r.model_dump() for r in client.list_dag_runs(HERO_DAG)],
                                            "total_entries": 3})
    assert len(client.list_task_instances(HERO_DAG, HERO_RUN)) == 3
    assert client.get_task_instance(HERO_DAG, HERO_RUN, "load").state == "failed"
    assert "Connection reset by peer" in client.get_task_log(HERO_DAG, HERO_RUN, "load", 1).text
    assert client.fake_airflow_detected
    assert state.mutating_requests() == []
