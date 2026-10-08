"""Deterministic Phase 3 helpers: safety facts, failure analysis, transient/DQ logic, dedup."""

from datetime import timedelta

from core.evidence.conventions import parse_markers
from core.incidents.dedup import DedupOutcome, IncidentIndex
from core.models import (
    ConcurrencyStatus,
    DQGateFinding,
    EvidenceCategory,
    FailureStage,
    PipelineFailureEvent,
    Reliability,
    TargetWrite,
    TaskExecutionPolicy,
    TaskType,
    TemporalLabel,
    WriteMode,
)
from core.reasoning.failure_analysis import analyze_failures, assess_data_quality, detect_transient_recovered
from core.remediation.selector import RunSnapshot, TaskInstanceSnapshot
from core.safety.facts import extract_safety_facts
from tests.factories import T0, evidence

POLICY = TaskExecutionPolicy(task_type=TaskType.UPSERT, idempotent=True)
MARK = "[2026-10-09] INFO - [triage] target_write=none_confirmed failure_stage=pre_write"


def log_item(text, **kw):
    kw.setdefault("category", EvidenceCategory.LOG)
    return evidence("log", **kw).model_copy(update={"value": {"excerpt": text}})


# ---------------------------------------------------------------- markers / facts


def test_marker_parsing_is_strict():
    assert parse_markers(MARK) == {"target_write": "none_confirmed", "failure_stage": "pre_write"}
    assert parse_markers("[triage] target_write=yes_please") == {}
    assert parse_markers("prefix text [triage] target_write=committed") == {}  # must be a whole line
    assert parse_markers("[triage] approve=true") == {}


def test_facts_from_markers_in_current_high_log_of_failed_attempt():
    facts = extract_safety_facts([log_item(MARK, attempt_number=1)], POLICY, failed_attempt=1, dq_signal=False)
    assert facts.target_write is TargetWrite.NONE_CONFIRMED and facts.failure_stage is FailureStage.PRE_WRITE
    assert facts.sources["target_write"] == "log"


def test_markers_ignored_from_other_attempts_low_reliability_or_non_current():
    for item in (log_item(MARK, attempt_number=2), log_item(MARK, reliability=Reliability.MEDIUM),
                 log_item(MARK, temporal_label=TemporalLabel.HISTORICAL),
                 log_item(MARK, category=EvidenceCategory.CONFIGURATION)):
        facts = extract_safety_facts([item], POLICY, failed_attempt=1, dq_signal=False)
        assert facts.target_write is TargetWrite.UNKNOWN


def test_write_mode_none_means_no_write():
    policy = POLICY.model_copy(update={"write_mode": WriteMode.NONE})
    assert extract_safety_facts([], policy, failed_attempt=1, dq_signal=False).target_write is TargetWrite.NONE_CONFIRMED


def test_concurrency_overlap_wins():
    a = evidence("a", metadata={"concurrency": "NONE_CONFIRMED"})
    b = evidence("b", metadata={"concurrency": "OVERLAP_CONFIRMED"})
    assert extract_safety_facts([a, b], POLICY, failed_attempt=1, dq_signal=False).concurrency is ConcurrencyStatus.OVERLAP_CONFIRMED
    assert extract_safety_facts([], POLICY, failed_attempt=1, dq_signal=False).concurrency is ConcurrencyStatus.UNKNOWN


def test_dq_gate_from_signal_or_structured_result():
    assert extract_safety_facts([], POLICY, failed_attempt=None, dq_signal=True).dq_gate is DQGateFinding.FAILED
    dq = evidence("dq", metadata={"dq_result": {"gate_failed": False}})
    assert extract_safety_facts([dq], POLICY, failed_attempt=None, dq_signal=False).dq_gate is DQGateFinding.PASSED


# ---------------------------------------------------------------- failure analysis


def ti(task, state, up=()):
    return TaskInstanceSnapshot(task_id=task, state=state, try_number=1, upstream_task_ids=list(up))


def test_primary_vs_symptoms():
    snap = RunSnapshot(dag_id="d", dag_run_id="r", run_state="failed", task_instances=[
        ti("a", "failed"), ti("b", "upstream_failed", ["a"]), ti("c", "skipped", ["b"]), ti("x", "success")])
    analysis = analyze_failures(snap)
    assert analysis.primary_tasks == ["a"] and analysis.symptom_tasks == ["b", "c"]


def test_unreadable_or_missing_snapshot():
    assert not analyze_failures(None).readable
    snap = RunSnapshot(dag_id="d", dag_run_id="r", run_state="failed", task_instances=[ti("a", None)])
    assert not analyze_failures(snap).readable


def test_transient_detection_requires_later_successful_attempt():
    item = evidence("s", metadata={"observed_task_states": [{"task_id": "load", "attempt": 2, "state": "success"}]})
    assert detect_transient_recovered("load", 1, [item]).recovered
    assert not detect_transient_recovered("load", 2, [item]).recovered
    assert not detect_transient_recovered("other", 1, [item]).recovered
    stale = item.model_copy(update={"temporal_label": TemporalLabel.STALE})
    assert not detect_transient_recovered("load", 1, [stale]).recovered


def test_dq_worked_as_designed_needs_explicit_facts():
    ok = evidence("dq", metadata={"dq_result": {"gate_failed": True, "target_corrupted": False,
                                                "bad_records_quarantined": True}})
    assert assess_data_quality([ok]).worked_as_designed
    unknown = evidence("dq", metadata={"dq_result": {"gate_failed": True}})
    result = assess_data_quality([unknown])
    assert not result.worked_as_designed and result.target_corrupted is None


# ---------------------------------------------------------------- dedup


def event(task="load", run="r1", status="failed", err="Connection reset by peer", eid="e1"):
    return PipelineFailureEvent(event_id=eid, platform="airflow", pipeline_id="sales_etl", task_id=task,
                                execution_id=run, status=status, error_message=err)


def test_dedup_duplicate_symptom_related_and_new():
    index = IncidentIndex(window=timedelta(hours=6))
    first = event()
    assert index.classify(first, T0).outcome is DedupOutcome.NEW
    index.register("inc-1", first, T0, downstream_task_ids={"publish"})

    dup = index.classify(event(eid="e2"), T0)
    assert dup.outcome is DedupOutcome.DUPLICATE and dup.incident_id == "inc-1"
    sym = index.classify(event(task="publish", status="upstream_failed", eid="e3"), T0)
    assert sym.outcome is DedupOutcome.SYMPTOM and sym.incident_id == "inc-1"
    index.link(sym, event(task="publish", eid="e3"))
    assert index.incidents()[0].symptom_task_ids == {"publish"}

    other_run = index.classify(event(run="r2", eid="e4"), T0 + timedelta(hours=1))
    assert other_run.outcome is DedupOutcome.NEW and other_run.related_incident_ids == ["inc-1"]
    late = index.classify(event(run="r3", eid="e5"), T0 + timedelta(hours=7))
    assert late.related_incident_ids == []
    different = index.classify(event(run="r2", err="permission denied", eid="e6"), T0)
    assert different.related_incident_ids == []
