"""Remediation classification table (L1) and cause-cleared check."""

from datetime import timedelta

import pytest

from core.models import ConfidenceLevel, EvidenceCategory, RemediationClass, RerunSafety, TemporalLabel
from core.remediation.classification import (
    ClassificationInput,
    check_cause_cleared,
    classify_remediation,
)
from core.taxonomy import FailureCategory as FC
from tests.factories import FAILURE_TIME, evidence

R = RemediationClass


def inp(category, subcategory=None, **kw) -> ClassificationInput:
    data = dict(
        category=category,
        subcategory=subcategory,
        root_cause_known=True,
        diagnostic_confidence=ConfidenceLevel.HIGH,
        rerun_safety=RerunSafety.SAFE,
        remediation_confidence=ConfidenceLevel.HIGH,
        cause_cleared_evidence_ids=["cc-1"],
    )
    data.update(kw)
    return ClassificationInput(**data)


@pytest.mark.parametrize(
    "category,subcategory",
    [
        (FC.NETWORK_CONNECTIVITY, "connection_refused"),          # network, cause cleared
        (FC.NETWORK_CONNECTIVITY, None),
        (FC.INFRASTRUCTURE, "node_loss"),                         # transient infra
        (FC.RESOURCE_QUOTA, "throttling"),                        # throttling
        (FC.ORCHESTRATION_STATE, "stuck_state"),                  # task stuck
        (FC.ORCHESTRATION_STATE, "scheduler_issue"),              # scheduler issue
        (FC.UPSTREAM_DEPENDENCY, "upstream_failed"),              # upstream now succeeded
        (FC.CONCURRENCY, "overlapping_run"),                      # overlapping run finished
    ],
)
def test_automatable_rows(category, subcategory):
    extra = {"overlapping_run_active": False} if category is FC.CONCURRENCY else {}
    assert classify_remediation(inp(category, subcategory, **extra)).remediation_class is R.AUTOMATABLE


def test_concurrency_overlap_still_active_is_blocked():
    r = classify_remediation(inp(FC.CONCURRENCY, "overlapping_run", overlapping_run_active=True))
    assert r.remediation_class is R.BLOCKED


def test_transient_recovered_is_no_action():
    assert classify_remediation(inp(FC.TRANSIENT_RECOVERED, "succeeded_on_retry")).remediation_class is R.NO_ACTION_REQUIRED
    assert classify_remediation(inp(FC.NETWORK_CONNECTIVITY, transient_recovered=True)).remediation_class is R.NO_ACTION_REQUIRED


def test_dq_gate_worked_as_designed_is_no_action():
    r = classify_remediation(inp(FC.DATA_QUALITY, "rule_violation", dq_gate_worked_as_designed=True,
                                 dq_target_corrupted=False, dq_bad_records_quarantined=True))
    assert r.remediation_class is R.NO_ACTION_REQUIRED


@pytest.mark.parametrize(
    "kw",
    [
        {"dq_gate_worked_as_designed": True, "dq_target_corrupted": True, "dq_bad_records_quarantined": True},
        {"dq_gate_worked_as_designed": True, "dq_target_corrupted": False, "dq_bad_records_quarantined": False},
        {"dq_gate_worked_as_designed": True, "dq_target_corrupted": None, "dq_bad_records_quarantined": True},
        {"dq_gate_worked_as_designed": False},
    ],
)
def test_dq_violation_with_corruption_or_unquarantined_data_is_manual(kw):
    assert classify_remediation(inp(FC.DATA_QUALITY, "rule_violation", **kw)).remediation_class is R.MANUAL_FIX_REQUIRED


@pytest.mark.parametrize(
    "category,subcategory",
    [
        (FC.SOURCE_SCHEMA_DRIFT, "column_missing"),
        (FC.CODE_LOGIC_BUG, "recent_change"),
        (FC.CONFIGURATION, "wrong_parameter"),
        (FC.SECURITY_AUTHORIZATION, "permission_denied"),
        (FC.VOLUME_ANOMALY, "row_count_drop"),
        (FC.INFRASTRUCTURE, "disk_full"),
        (FC.RESOURCE_QUOTA, "memory"),
        (FC.ORCHESTRATION_STATE, "bad_checkpoint"),
    ],
)
def test_manual_rows(category, subcategory):
    assert classify_remediation(inp(category, subcategory)).remediation_class is R.MANUAL_FIX_REQUIRED


def test_unknown_failure_is_manual_no_plan():
    r = classify_remediation(inp(FC.OTHER_UNKNOWN, root_cause_known=False,
                                 diagnostic_confidence=ConfidenceLevel.LOW))
    assert r.remediation_class is R.MANUAL_FIX_REQUIRED and r.rule == "L1.unknown_failure"


@pytest.mark.parametrize("safety", [RerunSafety.UNSAFE, RerunSafety.UNKNOWN])
def test_automatable_category_with_unsafe_or_unknown_rerun_is_blocked(safety):
    r = classify_remediation(inp(FC.NETWORK_CONNECTIVITY, rerun_safety=safety,
                                 remediation_confidence=ConfidenceLevel.LOW))
    assert r.remediation_class is R.BLOCKED


def test_automatable_category_with_low_remediation_confidence_is_manual():
    r = classify_remediation(inp(FC.UPSTREAM_DEPENDENCY, "upstream_failed",
                                 remediation_confidence=ConfidenceLevel.LOW))
    assert r.remediation_class is R.MANUAL_FIX_REQUIRED and r.rule == "L1.low_remediation_confidence"


def test_automatable_category_without_cause_cleared_evidence_is_manual():
    r = classify_remediation(inp(FC.NETWORK_CONNECTIVITY, cause_cleared_evidence_ids=[]))
    assert r.remediation_class is R.MANUAL_FIX_REQUIRED and r.rule == "L1.cause_not_cleared"


def test_safe_with_conditions_still_automatable():
    r = classify_remediation(inp(FC.NETWORK_CONNECTIVITY, rerun_safety=RerunSafety.SAFE_WITH_CONDITIONS,
                                 remediation_confidence=ConfidenceLevel.MEDIUM))
    assert r.remediation_class is R.AUTOMATABLE


# ---------------------------------------------------------------- cause-cleared check


def test_cause_cleared_accepts_current_post_failure_relevant_item():
    item = evidence("cc", category=EvidenceCategory.RUN_HISTORY,
                    timestamp=FAILURE_TIME + timedelta(minutes=3))
    res = check_cause_cleared(FC.NETWORK_CONNECTIVITY, [item], FAILURE_TIME)
    assert res.cleared and res.accepted_ids == ["cc"]


@pytest.mark.parametrize(
    "item,why",
    [
        (evidence("a", category=EvidenceCategory.RUN_HISTORY, temporal_label=TemporalLabel.HISTORICAL), "CURRENT"),
        (evidence("b", category=EvidenceCategory.RUN_HISTORY, collected_at=FAILURE_TIME - timedelta(minutes=1)),
         "before"),
        (evidence("c", category=EvidenceCategory.RUN_HISTORY, timestamp=FAILURE_TIME - timedelta(minutes=1)),
         "predates"),
        (evidence("d", category=EvidenceCategory.SCHEMA), "cannot show"),
    ],
)
def test_cause_cleared_rejects(item, why):
    res = check_cause_cleared(FC.NETWORK_CONNECTIVITY, [item], FAILURE_TIME)
    assert not res.cleared and why in res.rejected[item.evidence_id]


def test_cause_cleared_requires_known_failure_time():
    item = evidence("cc", category=EvidenceCategory.RUN_HISTORY)
    assert not check_cause_cleared(FC.NETWORK_CONNECTIVITY, [item], None).cleared


def test_cause_cleared_per_category_examples():
    up = evidence("u", category=EvidenceCategory.UPSTREAM)
    assert check_cause_cleared(FC.UPSTREAM_DEPENDENCY, [up], FAILURE_TIME).cleared
    st = evidence("s", category=EvidenceCategory.STATE)
    assert check_cause_cleared(FC.CONCURRENCY, [st], FAILURE_TIME).cleared
    assert check_cause_cleared(FC.ORCHESTRATION_STATE, [st], FAILURE_TIME).cleared
    assert not check_cause_cleared(FC.SOURCE_SCHEMA_DRIFT, [up], FAILURE_TIME).cleared
