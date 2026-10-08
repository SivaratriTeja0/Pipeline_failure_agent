"""RemediationPlan (C9) and ApprovalRecord (C10).

The plan is DATA. Nothing here can perform an action. ``plan_hash`` is always computed
server-side from the plan's own hashed fields; any client-supplied value is discarded.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from core.canonical import canonical_hash
from core.models.base import RUN_ID_PATTERN, TASK_ID_PATTERN, PIPELINE_ID_PATTERN, StrictModel
from core.models.enums import (
    ActionType,
    ApprovalDecision,
    ApprovalStatus,
    ConfidenceLevel,
    ExecutionMode,
    ExecutionStatus,
    PrincipalType,
    RecoveryScope,
    RemediationClass,
    RerunSafety,
    RiskLevel,
    Role,
    VerificationDepth,
    VerificationStatus,
)
from core.models.reasoning import BasisCondition, Claim, RuleEvaluation

HASH_PATTERN = r"^[0-9a-f]{64}$"

ACTION_SCOPE: dict[ActionType, RecoveryScope] = {
    ActionType.RETRY_FAILED_TASK: RecoveryScope.FAILED_TASK,
    ActionType.RETRY_FAILED_DAG_RUN: RecoveryScope.FAILED_DAG_RUN,
}

# Exactly the fields listed in spec C9. Order is irrelevant (canonical JSON sorts keys).
HASHED_FIELDS: tuple[str, ...] = (
    "incident_id",
    "investigation_cycle",
    "action_type",
    "recovery_scope",
    "target",
    "task_instances_to_clear",
    "parameters",
    "preconditions",
    "conditions",
    "risk_level",
    "supporting_evidence_ids",
    "cause_cleared_evidence_ids",
    "rerun_safety",
    "remediation_confidence",
    "execution_mode",
)


class PlanTarget(StrictModel):
    dag_id: str = Field(pattern=PIPELINE_ID_PATTERN)
    dag_run_id: str = Field(pattern=RUN_ID_PATTERN)
    task_id: str | None = Field(default=None, pattern=TASK_ID_PATTERN)


class TaskInstanceRef(StrictModel):
    """An enumerated task instance to clear. Only failed / upstream_failed instances are allowed."""

    task_id: str = Field(pattern=TASK_ID_PATTERN)
    map_index: int | None = Field(default=None, ge=-1)
    try_number: int = Field(ge=0)
    observed_state: Literal["failed", "upstream_failed"]

    @property
    def key(self) -> tuple[str, int]:
        return (self.task_id, -1 if self.map_index is None else self.map_index)


class PlanParameters(StrictModel):
    """Derived by code. ``only_failed`` is fixed to True."""

    only_failed: Literal[True] = True
    include_downstream: bool = False
    include_upstream: Literal[False] = False
    dry_run: bool = True


class Precondition(StrictModel):
    """A machine-checkable precondition re-checked at execution time."""

    check: str = Field(min_length=1)
    description: str = Field(min_length=1)
    params: dict[str, str] = Field(default_factory=dict)


class PlanCondition(StrictModel):
    """A condition from SAFE_WITH_CONDITIONS. Each must be acknowledged by the approver."""

    condition_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    source_rule: str = Field(min_length=1)
    machine_check: str | None = None


def _sorted_ids(ids: list[str]) -> list[str]:
    return sorted(set(ids))


def plan_hash_payload(plan: "RemediationPlan") -> dict[str, Any]:
    """The canonical payload that is hashed. Id lists and task lists are order-normalized."""
    data = plan.model_dump(mode="json", include=set(HASHED_FIELDS))
    data["supporting_evidence_ids"] = _sorted_ids(plan.supporting_evidence_ids)
    data["cause_cleared_evidence_ids"] = _sorted_ids(plan.cause_cleared_evidence_ids)
    data["task_instances_to_clear"] = [
        ti.model_dump(mode="json") for ti in sorted(plan.task_instances_to_clear, key=lambda t: t.key)
    ]
    data["preconditions"] = sorted(
        (p.model_dump(mode="json") for p in plan.preconditions), key=lambda p: (p["check"], p["description"])
    )
    data["conditions"] = sorted(
        (c.model_dump(mode="json") for c in plan.conditions), key=lambda c: c["condition_id"]
    )
    return data


def compute_plan_hash(plan: "RemediationPlan") -> str:
    """SHA-256 over canonical JSON of the hashed fields (spec C9)."""
    return canonical_hash(plan_hash_payload(plan))


class RemediationPlan(StrictModel):
    remediation_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    investigation_cycle: int = Field(ge=1)
    plan_version: int = Field(default=1, ge=1)
    plan_hash: str = Field(
        default="",
        description="Always recomputed server-side on validation; client-supplied values are discarded",
    )

    remediation_class: RemediationClass
    action_type: ActionType | None = None
    recovery_scope: RecoveryScope | None = None
    target: PlanTarget | None = None
    task_instances_to_clear: list[TaskInstanceRef] = Field(default_factory=list)
    parameters: PlanParameters = Field(default_factory=PlanParameters)

    reason: Claim
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    cause_cleared_evidence_ids: list[str] = Field(default_factory=list)

    remediation_confidence: ConfidenceLevel
    remediation_confidence_basis: list[BasisCondition] = Field(default_factory=list)
    rerun_safety: RerunSafety
    rerun_safety_rule_trace: list[RuleEvaluation] = Field(default_factory=list)

    preconditions: list[Precondition] = Field(default_factory=list)
    conditions: list[PlanCondition] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    expected_effect: str = ""
    rollback_description: str = ""

    requires_approval: bool = True
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: list[str] = Field(default_factory=list)
    approved_at: AwareDatetime | None = None
    rejected_by: str | None = None
    rejected_at: AwareDatetime | None = None
    rejection_reason: str | None = None
    expires_at: AwareDatetime

    action_execution_id: str | None = None
    idempotency_key: str | None = None
    execution_status: ExecutionStatus = ExecutionStatus.NOT_EXECUTED
    execution_mode: ExecutionMode = ExecutionMode.DRY_RUN
    execution_started_at: AwareDatetime | None = None
    execution_completed_at: AwareDatetime | None = None
    execution_result: dict[str, Any] | None = None
    block_reason: str | None = None
    dispatch_confirmed: bool = False

    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    verification_depth: VerificationDepth = VerificationDepth.STATE_ONLY
    verification_result: dict[str, Any] | None = None

    executed: bool = Field(
        default=False, description="Derived: true only if a LIVE dispatch was confirmed"
    )

    @field_validator("requires_approval")
    @classmethod
    def _approval_always_required(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("requires_approval must be True; plans can never bypass approval")
        return value

    @model_validator(mode="after")
    def _invariants_and_derived_fields(self) -> "RemediationPlan":
        if self.remediation_class is RemediationClass.AUTOMATABLE:
            self._check_automatable()
        else:
            if self.action_type is not None:
                raise ValueError("non-AUTOMATABLE plans carry no action_type")
            if self.task_instances_to_clear:
                raise ValueError("non-AUTOMATABLE plans carry no task instances to clear")
            if self.execution_status not in (ExecutionStatus.NOT_EXECUTED, ExecutionStatus.BLOCKED):
                raise ValueError("non-AUTOMATABLE plans can never be executed")

        keys = [ti.key for ti in self.task_instances_to_clear]
        if len(keys) != len(set(keys)):
            raise ValueError("task_instances_to_clear contains duplicates")

        # Derived fields: never trusted from input.
        object.__setattr__(
            self, "executed", self.execution_mode is ExecutionMode.LIVE and self.dispatch_confirmed
        )
        object.__setattr__(self, "plan_hash", compute_plan_hash(self))
        return self

    def _check_automatable(self) -> None:
        if self.action_type is None or self.recovery_scope is None or self.target is None:
            raise ValueError("AUTOMATABLE plans require action_type, recovery_scope and target")
        if ACTION_SCOPE[self.action_type] is not self.recovery_scope:
            raise ValueError(
                f"scope {self.recovery_scope.value} does not match action {self.action_type.value}"
            )
        if self.recovery_scope is RecoveryScope.FAILED_TASK and self.target.task_id is None:
            raise ValueError("FAILED_TASK scope requires target.task_id")
        if self.recovery_scope is RecoveryScope.FAILED_DAG_RUN and self.target.task_id is not None:
            raise ValueError("target.task_id is only allowed for FAILED_TASK scope")
        if not self.task_instances_to_clear:
            raise ValueError("AUTOMATABLE plans require an explicit enumerated task list")
        if not self.cause_cleared_evidence_ids:
            raise ValueError("AUTOMATABLE plans require cause_cleared_evidence_ids (L1)")
        if self.remediation_confidence is ConfidenceLevel.LOW:
            raise ValueError("LOW remediation confidence can never yield an AUTOMATABLE plan")
        if self.rerun_safety not in (RerunSafety.SAFE, RerunSafety.SAFE_WITH_CONDITIONS):
            raise ValueError("AUTOMATABLE plans require rerun_safety SAFE or SAFE_WITH_CONDITIONS")

    def hash_is_current(self) -> bool:
        """False if a hashed field was mutated after validation (the stored hash is stale)."""
        return self.plan_hash == compute_plan_hash(self)


class ApprovalRecord(StrictModel):
    """An authenticated human decision bound to an exact plan hash. Single-use."""

    approval_id: str = Field(min_length=1)
    remediation_id: str = Field(min_length=1)
    plan_version: int = Field(ge=1)
    plan_hash: str = Field(pattern=HASH_PATTERN, description="Server-computed hash")
    decision: ApprovalDecision
    decided_by: str = Field(min_length=1, description="principal_id from the auth layer only")
    principal_type: Literal[PrincipalType.HUMAN] = PrincipalType.HUMAN
    role: Role
    decided_at: AwareDatetime
    conditions_acknowledged: list[str] = Field(default_factory=list)
    comment: str | None = None
    expires_at: AwareDatetime
    consumed: bool = False

    @field_validator("role")
    @classmethod
    def _role_may_decide(cls, value: Role) -> Role:
        if value not in (Role.APPROVER, Role.ADMIN):
            raise ValueError("only APPROVER or ADMIN roles can record an approval decision")
        return value

    def is_expired(self, now: datetime) -> bool:
        """``now >= expires_at`` means EXPIRED (spec C10)."""
        return now >= self.expires_at
