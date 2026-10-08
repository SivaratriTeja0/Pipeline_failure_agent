"""Evidence freshness (Part H)."""

from datetime import timedelta

from core.evidence.freshness import (
    FreshnessContext,
    FreshnessIssue,
    apply_freshness,
    assess_freshness,
    confidence_eligible,
)
from core.models import TemporalLabel
from tests.factories import T0, evidence

CTX = FreshnessContext(pipeline_id="sales_etl", execution_id="run-1", attempt_number=2,
                       investigation_cycle=1, now=T0 + timedelta(minutes=10))


def test_current():
    a = assess_freshness(evidence(attempt_number=2), CTX)
    assert a.label is TemporalLabel.CURRENT and a.issues == []


def test_mismatched_execution():
    a = assess_freshness(evidence(execution_id="run-OTHER", attempt_number=2), CTX)
    assert a.label is TemporalLabel.MISMATCHED and FreshnessIssue.MISMATCHED_EXECUTION in a.issues


def test_mismatched_attempt_from_the_future():
    a = assess_freshness(evidence(attempt_number=3), CTX)
    assert a.label is TemporalLabel.MISMATCHED and FreshnessIssue.MISMATCHED_ATTEMPT in a.issues


def test_earlier_attempt_is_historical_and_preserved():
    a = assess_freshness(evidence(attempt_number=1), CTX)
    assert a.label is TemporalLabel.HISTORICAL


def test_unrelated_run():
    a = assess_freshness(evidence(attempt_number=2, metadata={"pipeline_id": "other_pipeline"}), CTX)
    assert a.label is TemporalLabel.MISMATCHED and FreshnessIssue.UNRELATED_RUN in a.issues


def test_stale():
    old = evidence(attempt_number=2, timestamp=T0 - timedelta(days=3))
    a = assess_freshness(old, CTX)
    assert a.label is TemporalLabel.STALE and FreshnessIssue.STALE in a.issues


def test_earlier_investigation_cycle_is_historical():
    ctx = CTX.model_copy(update={"investigation_cycle": 2})
    assert assess_freshness(evidence(attempt_number=2, cycle=1), ctx).label is TemporalLabel.HISTORICAL
    assert assess_freshness(evidence(attempt_number=2, cycle=2), ctx).label is TemporalLabel.CURRENT


def test_mismatch_takes_precedence_over_stale():
    item = evidence(execution_id="x", attempt_number=2, timestamp=T0 - timedelta(days=3))
    assert assess_freshness(item, CTX).label is TemporalLabel.MISMATCHED


def test_apply_freshness_relabels_copies_and_excludes_mismatched_from_confidence():
    items = [evidence("a", attempt_number=2), evidence("b", execution_id="zzz", attempt_number=2)]
    labeled = apply_freshness(items, CTX)
    assert [i.temporal_label for i in labeled] == [TemporalLabel.CURRENT, TemporalLabel.MISMATCHED]
    assert items[1].temporal_label is TemporalLabel.CURRENT  # originals untouched
    assert [confidence_eligible(i) for i in labeled] == [True, False]
    assert labeled[1].metadata["freshness_issues"] == ["MISMATCHED_EXECUTION"]
