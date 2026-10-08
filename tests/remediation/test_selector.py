"""Deterministic action selector (L3)."""

from core.models import ActionType, RecoveryScope
from core.remediation.selector import RunSnapshot, TaskInstanceSnapshot, select_action


def ti(task_id, state, upstream=(), try_number=1, map_index=None):
    return TaskInstanceSnapshot(task_id=task_id, state=state, upstream_task_ids=list(upstream),
                                try_number=try_number, map_index=map_index)


def snap(*tis, run_state="failed"):
    return RunSnapshot(dag_id="sales_etl", dag_run_id="scheduled__2026-10-08T00:00:00+00:00",
                       run_state=run_state, task_instances=list(tis))


def keys(result):
    return [(t.task_id, t.map_index) for t in result.task_instances_to_clear]


def test_one_failure_selects_retry_failed_task():
    r = select_action(snap(ti("extract", "success"), ti("load", "failed", ["extract"])))
    assert r.selected
    assert r.action_type is ActionType.RETRY_FAILED_TASK
    assert r.recovery_scope is RecoveryScope.FAILED_TASK
    assert r.target.task_id == "load" and r.target.dag_id == "sales_etl"
    assert keys(r) == [("load", None)]


def test_cascade_symptoms_included_with_single_primary():
    r = select_action(snap(
        ti("extract", "success"),
        ti("load", "failed", ["extract"]),
        ti("transform", "upstream_failed", ["load"], try_number=0),
        ti("publish", "upstream_failed", ["transform"], try_number=0),
    ))
    assert r.action_type is ActionType.RETRY_FAILED_TASK
    assert r.primary_failures == ["load"]
    assert r.cascade_symptoms == ["publish", "transform"]
    assert keys(r) == [("load", None), ("publish", None), ("transform", None)]


def test_multiple_independent_failures_select_retry_failed_dag_run():
    r = select_action(snap(
        ti("a", "failed"), ti("b", "failed"),
        ti("c", "upstream_failed", ["a"], try_number=0), ti("d", "success"),
    ))
    assert r.action_type is ActionType.RETRY_FAILED_DAG_RUN
    assert r.recovery_scope is RecoveryScope.FAILED_DAG_RUN
    assert r.target.task_id is None
    assert keys(r) == [("a", None), ("b", None), ("c", None)]


def test_success_tasks_are_never_in_the_list():
    r = select_action(snap(ti("x", "success"), ti("y", "failed", ["x"]), ti("z", "success", ["x"]),
                           ti("w", "skipped", ["y"])))
    assert all(t.task_id not in {"x", "z", "w"} for t in r.task_instances_to_clear)
    assert all(t.observed_state in {"failed", "upstream_failed"} for t in r.task_instances_to_clear)


def test_unreadable_task_state_yields_no_plan():
    r = select_action(snap(ti("a", "failed"), ti("b", None)))
    assert not r.selected and "unreadable" in r.block_reason


def test_unreadable_try_number_yields_no_plan():
    r = select_action(snap(ti("a", "failed", try_number=None)))
    assert not r.selected


def test_unreadable_run_state_yields_no_plan():
    r = select_action(snap(ti("a", "failed"), run_state=None))
    assert not r.selected and "unreadable" in r.block_reason


def test_run_not_failed_yields_no_plan():
    r = select_action(snap(ti("a", "failed"), run_state="running"))
    assert not r.selected


def test_no_failed_tasks_yields_no_plan():
    assert not select_action(snap(ti("a", "success"))).selected


def test_unexplained_upstream_failed_yields_no_plan():
    r = select_action(snap(ti("a", "failed"), ti("b", "upstream_failed", ["zzz"])))
    assert not r.selected and "trace back" in r.block_reason


def test_mapped_task_instances_enumerated_with_map_index():
    r = select_action(snap(
        ti("fan", "failed", map_index=0), ti("fan", "success", map_index=1), ti("fan", "failed", map_index=2),
    ))
    assert r.action_type is ActionType.RETRY_FAILED_TASK
    assert keys(r) == [("fan", 0), ("fan", 2)]


def test_identical_previously_failed_action_not_reproposed_without_new_evidence():
    s = snap(ti("load", "failed"))
    first = select_action(s)
    again = select_action(s, previously_failed_signatures=frozenset({first.signature}))
    assert not again.selected
    with_new = select_action(s, previously_failed_signatures=frozenset({first.signature}),
                             new_current_evidence=True)
    assert with_new.selected


def test_selection_is_deterministic():
    s = snap(ti("b", "failed"), ti("a", "failed"))
    assert select_action(s) == select_action(s)
