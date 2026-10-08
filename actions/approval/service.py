"""Approval service (spec L5, C10; invariants I2, I4, I5).

- Identity comes only from the authenticated ``Principal`` handed in by the API layer. Identity
  fields found in a request body are discarded and logged as suspicious.
- Only HUMAN principals with APPROVER or ADMIN, listed in the pipeline's approver_ids (or ADMIN),
  can approve or reject. SERVICE principals (the agent included) never can.
- The hash in the ApprovalRecord is recomputed by the server from the persisted plan. The hash
  the engineer saw is used only to detect a stale view (StaleViewError -> HTTP 409).
- Every condition must be acknowledged. HIGH risk needs HIGH_RISK_APPROVALS distinct approvers.
- Expiry is enforced here and again at execution time. Plan edits create a new version and void
  every prior approval (records are bound to version + hash).
"""

import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from actions.lifecycle import Lifecycle
from actions.store import HealingStore, revalidated
from core.config import Settings
from core.models.auth import Principal
from core.models.base import StrictModel, utcnow
from core.models.enums import (
    ApprovalDecision,
    ApprovalStatus,
    AuditEventType,
    ExecutionStatus,
    IncidentState,
    PrincipalType,
    RemediationClass,
    Role,
)
from core.models.remediation import HASH_PATTERN, ApprovalRecord, RemediationPlan, compute_plan_hash
from core.remediation.audit import AuditLog
from core.remediation.hashing import revise_plan
from core.remediation.risk import compute_risk_level, required_approvals

# Body keys that would claim an identity. They are never used; their presence is suspicious.
IDENTITY_FIELDS = frozenset({
    "approved_by", "decided_by", "approver", "approver_id", "principal", "principal_id", "principal_type",
    "user", "user_id", "username", "identity", "actor", "role", "roles", "rejected_by", "cancelled_by",
})
# A revision may change only descriptive / additive fields. Executable fields come from the selector.
EDITABLE_FIELDS = frozenset({"conditions", "preconditions", "expected_effect"})
_MAX_TEXT = 2000


class ApprovalError(RuntimeError):
    """A refused approval operation. ``status`` mirrors the HTTP status the API layer returns."""

    status = 422

    def __init__(self, message: str) -> None:
        super().__init__(message)


class UnauthenticatedError(ApprovalError):
    status = 401


class ForbiddenError(ApprovalError):
    status = 403


class StaleViewError(ApprovalError):
    """The engineer approved a plan version/hash that is no longer current (HTTP 409)."""

    status = 409


class PlanStateError(ApprovalError):
    status = 409


class PlanExpiredError(ApprovalError):
    status = 410


class ApprovalRequest(StrictModel):
    """POST /remediation/{id}/approve body. There is deliberately no identity field."""

    plan_version: int = Field(ge=1)
    displayed_plan_hash: str = Field(pattern=HASH_PATTERN)
    conditions_acknowledged: list[str] = Field(default_factory=list)
    comment: str | None = Field(default=None, max_length=_MAX_TEXT)


class ApprovalOutcome(BaseModel):
    plan: RemediationPlan
    record: ApprovalRecord | None = None
    complete: bool = False
    approvals: int = 0
    required: int = 1


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


class ApprovalService:
    def __init__(self, store: HealingStore, audit: AuditLog, settings: Settings,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._store = store
        self._audit = audit
        self._settings = settings
        self._clock = clock
        self._life = Lifecycle(store, audit)

    # ------------------------------------------------------------------ helpers

    def _plan(self, remediation_id: str) -> RemediationPlan:
        return self._store.get_plan(remediation_id)

    def required(self, plan: RemediationPlan) -> int:
        registration = self._store.get_incident(plan.incident_id).registration
        derived = compute_risk_level(registration.environment, plan.recovery_scope) if plan.recovery_scope else plan.risk_level
        return max(required_approvals(plan.risk_level, self._settings.high_risk_approvals),
                   required_approvals(derived, self._settings.high_risk_approvals))

    def _require_human(self, principal: Principal | None, plan: RemediationPlan, action: str) -> Principal:
        if principal is None:
            self._life.record(plan.incident_id, AuditEventType.AUTH_FAILURE,
                              {"action": action, "reason": "unauthenticated"}, remediation_id=plan.remediation_id)
            raise UnauthenticatedError(f"{action} requires an authenticated principal")
        if principal.principal_type is not PrincipalType.HUMAN:
            self._life.record(plan.incident_id, AuditEventType.AUTH_FAILURE,
                              {"action": action, "principal_id": principal.principal_id,
                               "reason": "SERVICE principals can never approve, reject or edit plans"},
                              remediation_id=plan.remediation_id)
            raise ForbiddenError(f"SERVICE principal {principal.principal_id} cannot {action}")
        return principal

    def _require_approver(self, principal: Principal | None, plan: RemediationPlan, action: str) -> Principal:
        human = self._require_human(principal, plan, action)
        if not human.can_approve:
            self._life.record(plan.incident_id, AuditEventType.AUTH_FAILURE,
                              {"action": action, "principal_id": human.principal_id, "reason": "missing role"},
                              remediation_id=plan.remediation_id)
            raise ForbiddenError(f"{human.principal_id} lacks the APPROVER or ADMIN role")
        registration = self._store.get_incident(plan.incident_id).registration
        if human.principal_id not in registration.approver_ids and not human.has_role(Role.ADMIN):
            self._life.record(plan.incident_id, AuditEventType.AUTH_FAILURE,
                              {"action": action, "principal_id": human.principal_id,
                               "reason": "not an approver for this pipeline"}, remediation_id=plan.remediation_id)
            raise ForbiddenError(f"{human.principal_id} is not an approver for pipeline {registration.pipeline_id}")
        return human

    def _scrub_body(self, body: Mapping[str, Any], plan: RemediationPlan, principal: Principal | None) -> dict[str, Any]:
        claimed = sorted(k for k in body if k.lower() in IDENTITY_FIELDS)
        if claimed:
            self._life.record(plan.incident_id, AuditEventType.SUSPICIOUS_REQUEST,
                              {"reason": "identity supplied in request body was ignored", "fields": claimed,
                               "authenticated_principal": principal.principal_id if principal else None},
                              remediation_id=plan.remediation_id)
        return {k: v for k, v in body.items() if k.lower() not in IDENTITY_FIELDS}

    def _expire(self, plan: RemediationPlan, reason: str) -> RemediationPlan:
        expired = revalidated(plan, approval_status=ApprovalStatus.EXPIRED)
        self._store.save_plan(expired)
        self._life.record(plan.incident_id, AuditEventType.APPROVAL_EXPIRED, {"reason": reason,
                          "expires_at": plan.expires_at.isoformat()}, remediation_id=plan.remediation_id)
        self._life.move_if_legal(plan.incident_id, IncidentState.EXPIRED, reason=reason,
                                 remediation_id=plan.remediation_id)
        return expired

    @staticmethod
    def _require_open(plan: RemediationPlan, action: str) -> None:
        if plan.remediation_class is not RemediationClass.AUTOMATABLE:
            raise PlanStateError(f"cannot {action}: plan is {plan.remediation_class.value} (not executable)")
        if plan.execution_status is not ExecutionStatus.NOT_EXECUTED:
            raise PlanStateError(f"cannot {action}: execution status is {plan.execution_status.value}")
        if plan.approval_status not in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
            raise PlanStateError(f"cannot {action}: plan is {plan.approval_status.value}")

    def valid_approvals(self, plan: RemediationPlan, now: datetime | None = None) -> list[ApprovalRecord]:
        """APPROVED, unconsumed, unexpired records bound to this exact version and recomputed hash."""
        now = now or self._clock()
        current_hash = compute_plan_hash(plan)
        seen: set[str] = set()
        out: list[ApprovalRecord] = []
        for record in self._store.approvals_for(plan.remediation_id):
            if (record.decision is ApprovalDecision.APPROVED and record.plan_version == plan.plan_version
                    and record.plan_hash == current_hash and not record.consumed and not record.is_expired(now)
                    and record.decided_by not in seen):
                seen.add(record.decided_by)
                out.append(record)
        return out

    # ------------------------------------------------------------------ operations

    def request_approval(self, remediation_id: str) -> RemediationPlan:
        plan = self._plan(remediation_id)
        self._require_open(plan, "request approval")
        self._life.record(plan.incident_id, AuditEventType.APPROVAL_REQUESTED,
                          {"plan_version": plan.plan_version, "plan_hash": compute_plan_hash(plan),
                           "risk_level": plan.risk_level.value, "required_approvals": self.required(plan),
                           "expires_at": plan.expires_at.isoformat(),
                           "conditions": [c.condition_id for c in plan.conditions]},
                          remediation_id=plan.remediation_id)
        self._life.move(plan.incident_id, IncidentState.AWAITING_APPROVAL, reason="approval requested",
                        remediation_id=plan.remediation_id)
        return plan

    def approve(self, remediation_id: str, principal: Principal | None, body: Mapping[str, Any]) -> ApprovalOutcome:
        plan = self._plan(remediation_id)
        clean = self._scrub_body(body, plan, principal)
        approver = self._require_approver(principal, plan, "approve")
        try:
            request = ApprovalRequest.model_validate(clean)
        except ValidationError as exc:
            raise ApprovalError(f"invalid approval request: {exc.errors()[0]['msg']}") from exc
        self._require_open(plan, "approve")
        now = self._clock()
        if now >= plan.expires_at:
            self._expire(plan, "approval attempted after the plan expired")
            raise PlanExpiredError("the plan has expired; a new plan and approval are required")

        server_hash = compute_plan_hash(plan)
        if request.plan_version != plan.plan_version or request.displayed_plan_hash != server_hash:
            raise StaleViewError(f"stale view: current plan is version {plan.plan_version} with hash "
                                 f"{server_hash[:12]}..; reload and review the current plan")
        required_ids = {c.condition_id for c in plan.conditions}
        acknowledged = set(request.conditions_acknowledged)
        if acknowledged - required_ids:
            raise ApprovalError(f"unknown conditions acknowledged: {sorted(acknowledged - required_ids)}")
        if required_ids - acknowledged:
            raise ApprovalError(f"every condition must be acknowledged; missing {sorted(required_ids - acknowledged)}")
        if any(r.decided_by == approver.principal_id for r in self.valid_approvals(plan, now)):
            raise PlanStateError(f"{approver.principal_id} already approved this plan version")

        record = ApprovalRecord(
            approval_id=_new_id("apr"), remediation_id=plan.remediation_id, plan_version=plan.plan_version,
            plan_hash=server_hash, decision=ApprovalDecision.APPROVED, decided_by=approver.principal_id,
            principal_type=PrincipalType.HUMAN, role=Role.APPROVER if approver.has_role(Role.APPROVER) else Role.ADMIN,
            decided_at=now, conditions_acknowledged=sorted(acknowledged), comment=request.comment,
            expires_at=plan.expires_at)
        self._store.add_approval(record)

        valid = self.valid_approvals(plan, now)
        required = self.required(plan)
        complete = len(valid) >= required
        payload = {"approval_id": record.approval_id, "plan_version": plan.plan_version, "plan_hash": server_hash,
                   "approvals": len(valid), "required": required,
                   "conditions_acknowledged": record.conditions_acknowledged}
        if not complete:
            self._life.record(plan.incident_id, AuditEventType.APPROVAL_RECORDED, payload,
                              actor=approver.audit_actor, remediation_id=plan.remediation_id)
            return ApprovalOutcome(plan=plan, record=record, complete=False, approvals=len(valid), required=required)

        approved = revalidated(plan, approval_status=ApprovalStatus.APPROVED,
                               approved_by=[r.decided_by for r in valid], approved_at=now)
        self._store.save_plan(approved)
        self._life.record(plan.incident_id, AuditEventType.APPROVAL_GRANTED, payload, actor=approver.audit_actor,
                          remediation_id=plan.remediation_id)
        self._life.move(plan.incident_id, IncidentState.APPROVED, actor=approver.audit_actor,
                        reason=f"approved by {', '.join(approved.approved_by)}", remediation_id=plan.remediation_id)
        return ApprovalOutcome(plan=approved, record=record, complete=True, approvals=len(valid), required=required)

    def reject(self, remediation_id: str, principal: Principal | None, reason: str,
               body: Mapping[str, Any] | None = None) -> RemediationPlan:
        plan = self._plan(remediation_id)
        self._scrub_body(body or {}, plan, principal)
        approver = self._require_approver(principal, plan, "reject")
        if not reason or not reason.strip():
            raise ApprovalError("a rejection reason is required")
        self._require_open(plan, "reject")
        now = self._clock()
        self._store.add_approval(ApprovalRecord(
            approval_id=_new_id("apr"), remediation_id=plan.remediation_id, plan_version=plan.plan_version,
            plan_hash=compute_plan_hash(plan), decision=ApprovalDecision.REJECTED, decided_by=approver.principal_id,
            role=Role.APPROVER if approver.has_role(Role.APPROVER) else Role.ADMIN, decided_at=now,
            comment=reason.strip()[:_MAX_TEXT], expires_at=plan.expires_at))
        rejected = revalidated(plan, approval_status=ApprovalStatus.REJECTED, rejected_by=approver.principal_id,
                               rejected_at=now, rejection_reason=reason.strip()[:_MAX_TEXT])
        self._store.save_plan(rejected)
        self._life.record(plan.incident_id, AuditEventType.APPROVAL_REJECTED, {"reason": rejected.rejection_reason},
                          actor=approver.audit_actor, remediation_id=plan.remediation_id)
        self._life.move(plan.incident_id, IncidentState.REJECTED, actor=approver.audit_actor,
                        reason=rejected.rejection_reason or "", remediation_id=plan.remediation_id)
        return rejected

    def cancel(self, remediation_id: str, principal: Principal | None, reason: str) -> RemediationPlan:
        plan = self._plan(remediation_id)
        human = self._require_human(principal, plan, "cancel")
        if not human.roles & {Role.ENGINEER, Role.APPROVER, Role.ADMIN}:
            raise ForbiddenError(f"{human.principal_id} cannot cancel plans")
        if not reason or not reason.strip():
            raise ApprovalError("a cancellation reason is required")
        self._require_open(plan, "cancel")
        cancelled = revalidated(plan, approval_status=ApprovalStatus.CANCELLED,
                                block_reason=f"cancelled: {reason.strip()[:_MAX_TEXT]}")
        self._store.save_plan(cancelled)
        self._life.record(plan.incident_id, AuditEventType.APPROVAL_CANCELLED, {"reason": reason.strip()[:_MAX_TEXT]},
                          actor=human.audit_actor, remediation_id=plan.remediation_id)
        self._life.move(plan.incident_id, IncidentState.CANCELLED, actor=human.audit_actor, reason=reason.strip(),
                        remediation_id=plan.remediation_id)
        return cancelled

    def expire_due(self) -> list[str]:
        """Sweep: mark open plans past their expiry EXPIRED. Execution re-checks expiry regardless."""
        now = self._clock()
        expired = []
        for plan in self._store.all_plans():
            if (plan.remediation_class is RemediationClass.AUTOMATABLE
                    and plan.execution_status is ExecutionStatus.NOT_EXECUTED
                    and plan.approval_status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)
                    and now >= plan.expires_at):
                self._expire(plan, "approval window elapsed")
                expired.append(plan.remediation_id)
        return expired

    def revise(self, remediation_id: str, principal: Principal | None, changes: Mapping[str, Any]) -> RemediationPlan:
        """Edit a plan (I5): new version and hash, every prior approval void, fresh approval needed."""
        plan = self._plan(remediation_id)
        human = self._require_human(principal, plan, "edit")
        if not human.roles & {Role.ENGINEER, Role.ADMIN}:
            raise ForbiddenError(f"{human.principal_id} cannot edit plans")
        forbidden = set(changes) - EDITABLE_FIELDS
        if forbidden:
            raise ApprovalError(f"fields {sorted(forbidden)} are computed deterministically and cannot be edited")
        self._require_open(plan, "edit")
        voided = [r.approval_id for r in self._store.approvals_for(remediation_id)
                  if r.decision is ApprovalDecision.APPROVED and r.plan_version == plan.plan_version]
        revised = revise_plan(plan, **dict(changes),
                              expires_at=self._clock() + timedelta(minutes=self._settings.approval_ttl_minutes))
        self._store.save_plan(revised)
        self._life.record(plan.incident_id, AuditEventType.PLAN_REVISED,
                          {"from_version": plan.plan_version, "to_version": revised.plan_version,
                           "old_hash": compute_plan_hash(plan), "new_hash": compute_plan_hash(revised),
                           "fields": sorted(changes)}, actor=human.audit_actor, remediation_id=plan.remediation_id)
        self._life.record(plan.incident_id, AuditEventType.APPROVAL_VOIDED,
                          {"voided_approval_ids": voided, "reason": "plan edited"}, actor=human.audit_actor,
                          remediation_id=plan.remediation_id)
        self._life.move(plan.incident_id, IncidentState.PLAN_PROPOSED, actor=human.audit_actor,
                        reason=f"plan edited to version {revised.plan_version}; approvals void",
                        remediation_id=plan.remediation_id)
        return self.request_approval(remediation_id)
