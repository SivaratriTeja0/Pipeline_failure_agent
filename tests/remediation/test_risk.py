"""Deterministic risk level (L2)."""

import pytest

from core.models import RecoveryScope, RiskLevel
from core.remediation.risk import ROLLBACK_DESCRIPTION, compute_risk_level, required_approvals


@pytest.mark.parametrize(
    "env,scope,expected",
    [
        ("dev", RecoveryScope.FAILED_TASK, RiskLevel.LOW),
        ("staging", RecoveryScope.FAILED_DAG_RUN, RiskLevel.MEDIUM),
        ("production", RecoveryScope.FAILED_TASK, RiskLevel.MEDIUM),
        ("prod", RecoveryScope.FAILED_DAG_RUN, RiskLevel.HIGH),
        (None, RecoveryScope.FAILED_DAG_RUN, RiskLevel.HIGH),   # unknown env treated as production
        (None, RecoveryScope.FAILED_TASK, RiskLevel.MEDIUM),
    ],
)
def test_risk_matrix(env, scope, expected):
    assert compute_risk_level(env, scope) is expected


def test_high_risk_needs_configured_distinct_approvers():
    assert required_approvals(RiskLevel.HIGH, 2) == 2
    assert required_approvals(RiskLevel.MEDIUM, 2) == 1


def test_rollback_description_is_honest():
    assert "cannot be undone" in ROLLBACK_DESCRIPTION
