"""Test factories for domain models."""

from datetime import datetime, timedelta, timezone
from typing import Any

from core.models import (
    ActionType,
    Claim,
    ClaimKind,
    ConfidenceLevel,
    EvidenceCategory,
    EvidenceItem,
    PlanCondition,
    PlanTarget,
    Precondition,
    Provenance,
    RecoveryScope,
    Reliability,
    RemediationClass,
    RemediationPlan,
    RerunSafety,
    TaskInstanceRef,
    TemporalLabel,
)

T0 = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
FAILURE_TIME = T0


def evidence(
    evidence_id: str = "ev-1",
    *,
    category: EvidenceCategory = EvidenceCategory.LOG,
    reliability: Reliability = Reliability.HIGH,
    temporal_label: TemporalLabel = TemporalLabel.CURRENT,
    execution_id: str = "run-1",
    attempt_number: int | None = 1,
    timestamp: datetime | None = None,
    collected_at: datetime | None = None,
    cycle: int = 1,
    metadata: dict[str, Any] | None = None,
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=evidence_id,
        category=category,
        source="test",
        platform="airflow",
        timestamp=timestamp,
        execution_id=execution_id,
        attempt_number=attempt_number,
        description=f"evidence {evidence_id}",
        value={"k": "v"},
        reliability=reliability,
        temporal_label=temporal_label,
        provenance=Provenance(
            adapter="test-adapter",
            capability="run_logs",
            tool="get_run_output",
            source="test",
            collected_at=collected_at or T0 + timedelta(minutes=5),
            investigation_cycle=cycle,
        ),
        metadata=metadata or {},
    )


def reason_claim() -> Claim:
    return Claim(
        claim_id="c-reason",
        text="Connection reset; later runs on the same connection succeeded.",
        kind=ClaimKind.INFERENCE,
        evidence_ids=["ev-1"],
    )


def automatable_plan(**overrides: Any) -> RemediationPlan:
    data: dict[str, Any] = dict(
        remediation_id="rem-1",
        incident_id="inc-1",
        investigation_cycle=1,
        remediation_class=RemediationClass.AUTOMATABLE,
        action_type=ActionType.RETRY_FAILED_TASK,
        recovery_scope=RecoveryScope.FAILED_TASK,
        target=PlanTarget(dag_id="sales_etl", dag_run_id="scheduled__2026-10-08T00:00:00+00:00", task_id="load"),
        task_instances_to_clear=[
            TaskInstanceRef(task_id="load", try_number=1, observed_state="failed"),
            TaskInstanceRef(task_id="publish", try_number=0, observed_state="upstream_failed"),
        ],
        reason=reason_claim(),
        supporting_evidence_ids=["ev-1", "ev-2"],
        cause_cleared_evidence_ids=["ev-3"],
        remediation_confidence=ConfidenceLevel.HIGH,
        rerun_safety=RerunSafety.SAFE,
        preconditions=[Precondition(check="run_state_failed", description="DAG run is still failed")],
        conditions=[],
        expires_at=T0 + timedelta(hours=1),
    )
    data.update(overrides)
    return RemediationPlan(**data)


def condition(cid: str = "cond-R7") -> PlanCondition:
    return PlanCondition(condition_id=cid, text="Confirm no concurrent run.", source_rule="R7",
                         machine_check="no_concurrent_run")
