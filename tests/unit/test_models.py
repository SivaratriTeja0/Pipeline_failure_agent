"""Universal data models (Part C)."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from core.models import (
    ApprovalDecision,
    ApprovalRecord,
    Capabilities,
    Claim,
    ClaimKind,
    Hypothesis,
    PipelineFailureEvent,
    Principal,
    PrincipalType,
    Role,
)
from core.taxonomy import SUBCATEGORIES, FailureCategory
from tests.factories import T0, evidence


def test_failure_event_keeps_platform_ids_in_metadata():
    ev = PipelineFailureEvent(event_id="e1", platform="airflow", pipeline_id="sales_etl", execution_id="x",
                              platform_run_id="scheduled__x", status="failed",
                              metadata={"try_number": 2, "map_index": -1})
    assert ev.metadata["try_number"] == 2
    assert "try_number" not in PipelineFailureEvent.model_fields
    assert "dag_run_id" not in PipelineFailureEvent.model_fields


def test_models_reject_unknown_fields():
    with pytest.raises(ValidationError):
        PipelineFailureEvent(event_id="e", platform="p", pipeline_id="x", execution_id="x", status="f",
                             dag_run_id="nope")


def test_evidence_item_has_provenance():
    item = evidence()
    assert item.provenance.adapter and item.provenance.tool and item.provenance.capability


@pytest.mark.parametrize("kind", [ClaimKind.FACT, ClaimKind.INFERENCE])
def test_fact_and_inference_require_evidence(kind):
    with pytest.raises(ValidationError):
        Claim(claim_id="c", text="t", kind=kind, evidence_ids=[])


def test_recommendation_may_have_no_evidence():
    Claim(claim_id="c", text="t", kind=ClaimKind.RECOMMENDATION)


def test_taxonomy_has_exactly_14_categories():
    assert len(FailureCategory) == 14
    assert set(SUBCATEGORIES) == set(FailureCategory)


def test_hypothesis_rejects_wrong_subcategory():
    with pytest.raises(ValidationError):
        Hypothesis(hypothesis_id="h", category=FailureCategory.NETWORK_CONNECTIVITY,
                   subcategory="column_missing", statement="s")
    Hypothesis(hypothesis_id="h", category=FailureCategory.OTHER_UNKNOWN, subcategory="anything", statement="s")


def _approval(**kw):
    data = dict(approval_id="a1", remediation_id="rem-1", plan_version=1, plan_hash="a" * 64,
                decision=ApprovalDecision.APPROVED, decided_by="alice", role=Role.APPROVER,
                decided_at=T0, expires_at=T0 + timedelta(hours=1))
    data.update(kw)
    return ApprovalRecord(**data)


def test_approval_record_rejects_service_principal():
    with pytest.raises(ValidationError):
        _approval(principal_type=PrincipalType.SERVICE)


@pytest.mark.parametrize("role", [Role.VIEWER, Role.ENGINEER])
def test_approval_record_rejects_non_approver_roles(role):
    with pytest.raises(ValidationError):
        _approval(role=role)


def test_approval_record_requires_server_hash_format():
    with pytest.raises(ValidationError):
        _approval(plan_hash="client-supplied")


def test_approval_expiry_boundary_is_inclusive():
    rec = _approval()
    assert not rec.is_expired(T0 + timedelta(minutes=59))
    assert rec.is_expired(T0 + timedelta(hours=1))  # now >= expires_at -> EXPIRED


def test_service_principal_can_never_approve():
    svc = Principal(principal_id="agent", principal_type=PrincipalType.SERVICE,
                    roles=frozenset({Role.APPROVER, Role.ADMIN}), auth_method="token")
    human = Principal(principal_id="alice", principal_type=PrincipalType.HUMAN,
                      roles=frozenset({Role.APPROVER}), auth_method="token")
    assert not svc.can_approve
    assert human.can_approve


def test_generic_platform_without_action_capabilities_is_not_healing_applicable():
    assert not Capabilities().healing_applicable
