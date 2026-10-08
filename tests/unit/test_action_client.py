"""AirflowActionClient / AirflowRemediationExecutor in isolation (httpx MockTransport, no Airflow)."""

import json

import httpx
import pytest
from pydantic import ValidationError

from actions.airflow_actions import (
    ActionClientViolation,
    AirflowActionClient,
    AirflowActionConfig,
    ClearAmbiguousError,
    ClearNotSentError,
    ClearRejectedError,
    ClearTaskInstancesBody,
    build_airflow_executor,
)
from core.models import ExecutionMode
from tests.factories import automatable_plan

RUN = "scheduled__2026-10-08T00:00:00+00:00"
CONFIG = AirflowActionConfig(base_url="http://airflow.test")


def client_with(handler) -> tuple[AirflowActionClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.Client(base_url="http://airflow.test", transport=httpx.MockTransport(record))
    return AirflowActionClient(CONFIG, http=http), seen


def refs(*task_ids, dag="sales_etl", run=RUN):
    return {"task_instances": [{"task_id": t, "dag_id": dag, "dag_run_id": run, "execution_date": None}
                               for t in task_ids]}


def ok(payload):
    return lambda request: httpx.Response(200, json=payload)


def live_plan(**kw):
    return automatable_plan(execution_mode=ExecutionMode.LIVE, **kw)


# ---------------------------------------------------------------- the client can only clear


def test_request_hook_refuses_anything_but_the_clear_endpoint():
    client, seen = client_with(ok(refs("load")))
    for method, path in [("GET", "/api/v1/dags/sales_etl"), ("POST", "/api/v1/dags/sales_etl/dagRuns"),
                         ("PATCH", "/api/v1/dags/sales_etl"), ("DELETE", "/api/v1/dags/sales_etl/dagRuns/x"),
                         ("POST", "/api/v1/dags/sales_etl/updateTaskInstancesState")]:
        with pytest.raises(ActionClientViolation):
            client._http.request(method, path)
    assert seen == []


def test_body_pins_every_expansion_flag_and_sends_dry_run_explicitly():
    client, seen = client_with(ok(refs("load")))
    client.clear_task_instances("sales_etl", ClearTaskInstancesBody(dry_run=False, dag_run_id=RUN, task_ids=["load"]))
    sent = json.loads(seen[0].content)
    assert seen[0].method == "POST" and seen[0].url.path == "/api/v1/dags/sales_etl/clearTaskInstances"
    assert sent == {"dry_run": False, "dag_run_id": RUN, "task_ids": ["load"], "only_failed": True,
                    "only_running": False, "include_upstream": False, "include_downstream": False,
                    "include_future": False, "include_past": False, "reset_dag_runs": True}
    for flag in ("include_downstream", "include_upstream", "include_future", "include_past", "only_running"):
        with pytest.raises(ValidationError):
            ClearTaskInstancesBody(dry_run=False, dag_run_id=RUN, task_ids=["load"], **{flag: True})
    with pytest.raises(ValidationError):
        ClearTaskInstancesBody(dry_run=False, dag_run_id=RUN, task_ids=["load"], only_failed=False)
    with pytest.raises(ValidationError):
        ClearTaskInstancesBody(dry_run=False, dag_run_id=RUN, task_ids=["../etc"])
    with pytest.raises(ValueError):
        client.clear_task_instances("../other", ClearTaskInstancesBody(dry_run=True, dag_run_id=RUN, task_ids=["x"]))


@pytest.mark.parametrize("handler,error", [
    (lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r)), ClearNotSentError),
    (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("lost", request=r)), ClearAmbiguousError),
    (lambda r: (_ for _ in ()).throw(httpx.RemoteProtocolError("drop", request=r)), ClearAmbiguousError),
    (lambda r: httpx.Response(503, json={}), ClearAmbiguousError),
    (lambda r: httpx.Response(200, text="not json"), ClearAmbiguousError),
    (lambda r: httpx.Response(403, json={"detail": "forbidden"}), ClearRejectedError),
    (lambda r: httpx.Response(404, json={"detail": "nope"}), ClearRejectedError),
])
def test_transport_outcomes_are_classified_and_never_retried(handler, error):
    client, seen = client_with(handler)
    with pytest.raises(error):
        client.clear_task_instances("sales_etl", ClearTaskInstancesBody(dry_run=False, dag_run_id=RUN, task_ids=["load"]))
    assert len(seen) == 1  # never auto-retried


def test_action_client_requires_write_credentials_and_supported_version():
    with pytest.raises(ValueError):
        AirflowActionClient(AirflowActionConfig(base_url="http://airflow.test"))
    with pytest.raises(ValueError):
        AirflowActionClient(AirflowActionConfig(base_url="http://a", api_version="v2", token="t"))
    assert AirflowActionConfig.from_env({"AIRFLOW_API_BASE_URL": "http://a", "AIRFLOW_WRITE_TOKEN": "t"}).token == "t"


# ---------------------------------------------------------------- dispatch: dry-run listing must equal the plan


def executor_with(handler):
    seen: list[httpx.Request] = []

    def record(request):
        seen.append(request)
        return handler(request)

    http = httpx.Client(base_url="http://airflow.test", transport=httpx.MockTransport(record))
    return build_airflow_executor(CONFIG, http=http), seen


def test_dispatch_previews_then_clears_exactly_once():
    executor, seen = executor_with(ok(refs("load", "publish")))
    outcome = executor.dispatch(live_plan())
    assert outcome.accepted and outcome.listing_matches_plan
    assert [json.loads(r.content)["dry_run"] for r in seen] == [True, False]


def test_listing_mismatch_clears_nothing():
    # Airflow would clear an extra task (e.g. another failed map index of a mapped task)
    executor, seen = executor_with(ok(refs("load", "load", "publish")))
    outcome = executor.dispatch(live_plan())
    assert not outcome.accepted and not outcome.sent and outcome.listing_matches_plan is False
    assert [json.loads(r.content)["dry_run"] for r in seen] == [True]


def test_listing_from_another_dag_or_run_clears_nothing():
    for wrong in (refs("load", "publish", dag="other_dag"), refs("load", "publish", run="manual__x")):
        executor, seen = executor_with(ok(wrong))
        assert not executor.dispatch(live_plan()).accepted
        assert len(seen) == 1


def test_dry_run_and_non_executable_plans_are_never_sent():
    executor, seen = executor_with(ok(refs("load", "publish")))
    assert not executor.dispatch(automatable_plan()).accepted  # DRY_RUN plan
    assert seen == []


def test_ambiguous_live_call_is_reported_not_resent():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if json.loads(request.content)["dry_run"]:
            return httpx.Response(200, json=refs("load", "publish"))
        raise httpx.ReadTimeout("lost", request=request)

    executor, seen = executor_with(handler)
    outcome = executor.dispatch(live_plan())
    assert outcome.ambiguous and not outcome.accepted
    assert calls["n"] == 2
