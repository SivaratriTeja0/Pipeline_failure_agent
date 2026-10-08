"""AirflowAdapter end-to-end against FAKE AIRFLOW (DEMO), read side only."""

import pytest

from adapters.base.evidence import DEMO_LABEL
from adapters.base.interfaces import AdapterError
from core.models import ActionType, EvidenceCategory, Reliability, TemporalLabel
from core.models.reads import ReadRequest, ReadStatus
from core.remediation.classification import check_cause_cleared
from core.remediation.selector import select_action
from core.taxonomy import FailureCategory
from tests.airflow_helpers import HERO_DAG, HERO_RUN, hero

REQ = ReadRequest(pipeline_id=HERO_DAG, execution_id=HERO_RUN, task_id="load", attempt_number=1)


def test_normalize_failure_callback_payload():
    adapter, _ = hero()
    event = adapter.normalize_failure({
        "dag_id": HERO_DAG, "dag_run_id": HERO_RUN, "task_id": "load", "try_number": 1, "map_index": -1,
        "state": "failed", "end_date": "2026-10-09T00:04:10+00:00",
        "exception": "OperationalError: Connection reset by peer", "environment": "production",
    })
    assert event.platform == "airflow" and event.pipeline_id == HERO_DAG
    assert event.execution_id == HERO_RUN == event.platform_run_id
    assert event.attempt_number == 1 and event.metadata["try_number"] == 1 and event.metadata["map_index"] == -1
    assert event.failure_time.isoformat() == "2026-10-09T00:04:10+00:00"


@pytest.mark.parametrize("bad", [{"dag_id": "../x", "dag_run_id": "r"}, {"dag_id": "d"}, {"dag_id": "d", "dag_run_id": "r", "task_id": "a b"}])
def test_normalize_rejects_invalid_ids(bad):
    adapter, _ = hero()
    with pytest.raises(ValueError):
        adapter.normalize_failure(bad)


def test_run_output_extracts_bounded_log_with_signal_and_stack_trace():
    adapter, _ = hero()
    result = adapter.get_run_output(REQ)
    assert result.status is ReadStatus.AVAILABLE
    log, trace = result.evidence
    assert log.category is EvidenceCategory.LOG and trace.category is EvidenceCategory.STACK_TRACE
    assert log.normalized_signal == "NETWORK_CONNECTIVITY_FAILURE"
    assert "Connection reset by peer" in log.raw_signal
    assert log.reliability is Reliability.HIGH and log.attempt_number == 1
    assert log.provenance.adapter == "airflow" and log.provenance.tool == "get_run_output"
    assert log.provenance.capability == "run_logs"


def test_run_history_finds_later_success_in_shared_pool_as_cause_cleared_candidate():
    adapter, _ = hero()
    result = adapter.get_run_history(REQ)
    runs, active, pool = result.evidence
    assert active.metadata["concurrency"] == "NONE_CONFIRMED" and active.value == []
    assert [r["dag_run_id"] for r in runs.value] == ["scheduled__2026-10-07T00:00:00+00:00",
                                                    "scheduled__2026-10-06T00:00:00+00:00"]
    assert pool.metadata["cause_cleared_candidate"] is True
    assert [ti["dag_id"] for ti in pool.value["later_successes"]] == ["inventory_sync"]
    failure_time = adapter.normalize_failure(
        {"dag_id": HERO_DAG, "dag_run_id": HERO_RUN, "end_date": "2026-10-09T00:04:10+00:00"}).failure_time
    cleared = check_cause_cleared(FailureCategory.NETWORK_CONNECTIVITY, [pool], failure_time)
    assert cleared.accepted_ids == [pool.evidence_id]


def test_state_configuration_and_neighbours():
    adapter, _ = hero()
    task_state = adapter.get_task_state(REQ).evidence[0]
    assert task_state.value[0]["state"] == "failed"
    run_state = adapter.get_pipeline_state(REQ).evidence[0]
    assert run_state.value["state"] == "failed" and run_state.value["failed_tasks"] == ["load"]
    config = adapter.get_configuration(REQ).evidence[0]
    assert config.value["task"]["pool"] == "warehouse_pool"
    assert "never-exposed" not in str(config.value)  # DAG param values withheld
    up = adapter.get_upstream_status(REQ).evidence[0]
    assert up.value["task_ids"] == ["extract"] and up.value["task_instances"][0]["state"] == "success"
    down = adapter.get_downstream_status(REQ).evidence[0]
    assert down.value["task_instances"][0]["state"] == "upstream_failed"


def test_unsupported_reads_are_unavailable_not_fabricated():
    adapter, state = hero()
    before = len(state.request_log)
    for method in ("get_schema", "get_row_counts", "get_lineage", "get_state", "get_permissions"):
        result = getattr(adapter, method)(REQ)
        assert result.status is ReadStatus.UNAVAILABLE and result.evidence == []
    assert len(state.request_log) == before


def test_run_snapshot_feeds_deterministic_selector():
    adapter, _ = hero()
    snapshot = adapter.get_run_snapshot(HERO_DAG, HERO_RUN)
    selection = select_action(snapshot)
    assert selection.action_type is ActionType.RETRY_FAILED_TASK
    assert selection.target.task_id == "load"
    assert [(t.task_id, t.observed_state) for t in selection.task_instances_to_clear] == [
        ("load", "failed"), ("publish", "upstream_failed")]


def test_mock_data_is_labeled_even_when_demo_flag_not_set():
    adapter, _ = hero(demo=False)
    item = adapter.get_run_output(REQ).evidence[0]
    assert item.metadata["demo"] is True and item.metadata["demo_label"] == DEMO_LABEL
    assert item.description.startswith(f"[{DEMO_LABEL}]")


def test_evidence_is_current_execution_scoped():
    adapter, _ = hero()
    for item in adapter.get_run_history(REQ).evidence:
        assert item.execution_id == HERO_RUN and item.temporal_label is TemporalLabel.CURRENT
        assert item.metadata["pipeline_id"] == HERO_DAG


def test_airflow_down_yields_error_never_evidence_and_snapshot_unreadable():
    adapter, state = hero(down=True)
    result = adapter.get_run_output(REQ)
    assert result.status is ReadStatus.ERROR and result.evidence == []
    assert "Unavailable" in result.detail
    with pytest.raises(AdapterError):
        adapter.get_run_snapshot(HERO_DAG, HERO_RUN)


def test_no_mutating_request_reaches_fake_airflow_during_investigation():
    adapter, state = hero()
    for method in ("get_run_output", "get_run_history", "get_task_state", "get_pipeline_state",
                   "get_configuration", "get_upstream_status", "get_downstream_status"):
        getattr(adapter, method)(REQ)
    adapter.get_run_snapshot(HERO_DAG, HERO_RUN)
    assert state.request_log and state.mutating_requests() == []
