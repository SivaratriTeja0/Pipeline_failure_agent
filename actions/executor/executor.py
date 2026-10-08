"""The healing executor (spec L8; invariants I1, I4, I6, I7, I8, I9, I13, I15, I16, I18).

Single entry point ``execute_approved(remediation_id)``:

1. load the persisted plan; recompute its hash; check approval validity and expiry (expiry is
   checked here, at execution time, not only by a sweeper);
2. policy validation (L6), then live-state re-validation (L7) - any failure -> BLOCKED;
3. write-ahead: atomic compare-and-set NOT_EXECUTED -> QUEUED with action_execution_id,
   idempotency_key = SHA-256(incident_id || plan_hash), approvals consumed - persisted before any
   HTTP call, so a plan executes at most once;
4. DRY_RUN records what would be cleared and calls nothing mutating; LIVE dispatches once through
   the platform's RemediationExecutor, never auto-retried;
5. an ambiguous outcome is UNCERTAIN and is reconciled by reading state, never resent;
6. a confirmed dispatch is verified (L9).

Every step writes an audit event. Exceptions end in BLOCKED / FAILED / UNCERTAIN - never in a
silent partial success. Only api/ may import this module (architecture test).
"""

import hashlib
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

from actions.lifecycle import Lifecycle
from actions.policy.engine import PolicyContext, PolicyEngine
from actions.revalidation.revalidator import LiveStateRevalidator
from actions.store import HealingStore, StoreError, revalidated
from actions.verification.verifier import Verifier, VerificationResult
from adapters.base.interfaces import AdapterError, DispatchOutcome, PipelineAdapter, RemediationExecutor
from core.config import Settings
from core.logging_setup import get_logger
from core.models.base import utcnow
from core.models.enums import (
    ApprovalDecision,
    ApprovalStatus,
    AuditEventType,
    ExecutionMode,
    ExecutionStatus,
    IncidentState,
    VerificationStatus,
)
from core.models.remediation import ApprovalRecord, RemediationPlan, compute_plan_hash
from core.remediation.audit import AuditLog
from core.remediation.selector import CLEARABLE_STATES

_log = get_logger(__name__)

# Incident states in which an execution outcome may still be reconciled automatically.
_RECONCILABLE = frozenset({IncidentState.EXECUTION_UNCERTAIN, IncidentState.RECONCILING})

Outcome = Literal["REFUSED", "BLOCKED", "EXPIRED", "DRY_RUN", "DISPATCHED", "FAILED", "UNCERTAIN_ESCALATED"]


class ExecutionReport(BaseModel):
    remediation_id: str
    outcome: Outcome
    detail: str = ""
    plan: RemediationPlan | None = None
    verification: VerificationResult | None = None


def idempotency_key(incident_id: str, plan_hash: str) -> str:
    return hashlib.sha256(f"{incident_id}\x1f{plan_hash}".encode()).hexdigest()


class HealingExecutor:
    def __init__(
        self,
        *,
        store: HealingStore,
        audit: AuditLog,
        settings: Settings,
        policy: PolicyEngine,
        revalidator: LiveStateRevalidator,
        backend: RemediationExecutor,
        reader: PipelineAdapter,
        verifier: Verifier,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None],
    ) -> None:
        self._store = store
        self._audit = audit
        self._settings = settings
        self._policy = policy
        self._revalidator = revalidator
        self._backend = backend
        self._reader = reader
        self._verifier = verifier
        self._clock = clock
        self._sleep = sleep
        self._life = Lifecycle(store, audit)

    # ------------------------------------------------------------------ helpers

    def _save(self, plan: RemediationPlan, **updates: Any) -> RemediationPlan:
        updated = revalidated(plan, **updates)
        self._store.save_plan(updated)
        return updated

    def _block(self, plan: RemediationPlan, reason: str, event: AuditEventType, payload: dict | None = None) -> ExecutionReport:
        """Fail closed: BLOCKED, audited, never executed."""
        _log.warning("execution_blocked", extra={"remediation_id": plan.remediation_id, "reason": reason})
        try:
            if plan.execution_status is ExecutionStatus.NOT_EXECUTED:
                plan = self._save(plan, execution_status=ExecutionStatus.BLOCKED, block_reason=reason)
        except Exception as exc:  # recording the block must not turn it into anything else
            reason = f"{reason}; additionally failed to persist block: {type(exc).__name__}"
        self._life.record(plan.incident_id, event, {"reason": reason, **(payload or {})},
                          remediation_id=plan.remediation_id)
        if event is not AuditEventType.EXECUTION_BLOCKED:
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_BLOCKED, {"reason": reason},
                              remediation_id=plan.remediation_id)
        try:
            self._life.move_if_legal(plan.incident_id, IncidentState.BLOCKED, reason=reason,
                                     remediation_id=plan.remediation_id)
        except StoreError:
            _log.error("incident_state_unrecorded", extra={"remediation_id": plan.remediation_id})
        return ExecutionReport(remediation_id=plan.remediation_id, outcome="BLOCKED", detail=reason, plan=plan)

    def _approvals(self, plan: RemediationPlan) -> list[ApprovalRecord]:
        return [a for a in self._store.approvals_for(plan.remediation_id)
                if a.decision is ApprovalDecision.APPROVED and a.plan_version == plan.plan_version]

    # ------------------------------------------------------------------ entry point

    def execute_approved(self, remediation_id: str) -> ExecutionReport:
        try:
            plan = self._store.get_plan(remediation_id)
        except StoreError as exc:
            return ExecutionReport(remediation_id=remediation_id, outcome="REFUSED", detail=str(exc))

        # A plan executes at most once: anything already past NOT_EXECUTED is refused outright.
        if plan.execution_status is not ExecutionStatus.NOT_EXECUTED or plan.action_execution_id is not None:
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_BLOCKED,
                              {"reason": f"duplicate submit refused; execution status {plan.execution_status.value}"},
                              remediation_id=remediation_id)
            return ExecutionReport(remediation_id=remediation_id, outcome="REFUSED", plan=plan,
                                   detail=f"plan already {plan.execution_status.value}")
        if plan.approval_status is not ApprovalStatus.APPROVED:
            return self._block(plan, f"plan is {plan.approval_status.value}; only APPROVED plans can execute",
                               AuditEventType.EXECUTION_BLOCKED)
        try:
            incident = self._store.get_incident(plan.incident_id)
            approvals = self._approvals(plan)
        except Exception as exc:
            return self._block(plan, f"approval lookup failed: {type(exc).__name__}: {exc}",
                               AuditEventType.EXECUTION_BLOCKED)

        now = self._clock()
        if not approvals:
            return self._block(plan, "no approval records for this plan version", AuditEventType.EXECUTION_BLOCKED)
        if now >= plan.expires_at or any(a.is_expired(now) for a in approvals):
            plan = self._save(plan, approval_status=ApprovalStatus.EXPIRED, execution_status=ExecutionStatus.BLOCKED,
                              block_reason="approval expired before execution")
            self._life.record(plan.incident_id, AuditEventType.APPROVAL_EXPIRED,
                              {"expires_at": plan.expires_at.isoformat(), "checked_at": now.isoformat()},
                              remediation_id=remediation_id)
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_BLOCKED, {"reason": "approval expired"},
                              remediation_id=remediation_id)
            self._life.move_if_legal(plan.incident_id, IncidentState.EXPIRED, reason="approval expired",
                                     remediation_id=remediation_id)
            return ExecutionReport(remediation_id=remediation_id, outcome="EXPIRED", plan=plan,
                                   detail="approval expired; never executed")

        recomputed = compute_plan_hash(plan)
        mismatched = [a.approval_id for a in approvals if a.plan_hash != recomputed]
        if mismatched or not plan.hash_is_current():
            return self._block(plan, "plan hash mismatch: the persisted plan no longer matches the approved hash",
                               AuditEventType.EXECUTION_BLOCKED,
                               {"recomputed_hash": recomputed, "approval_ids": mismatched})

        # ---------------------------------------------------------- L6 policy
        self._life.move(plan.incident_id, IncidentState.POLICY_VALIDATING, remediation_id=remediation_id)
        try:
            decision = self._policy.validate(
                plan, approvals, incident.registration,
                PolicyContext(incident_id=incident.incident_id, pipeline_id=incident.event.pipeline_id,
                              execution_id=incident.event.execution_id, category=incident.category,
                              executions_for_incident=self._store.executions_for_incident(plan.incident_id),
                              actions_for_dag_last_hour=self._store.actions_for_dag_last_hour(
                                  plan.target.dag_id if plan.target else "", now),
                              halted=self._store.is_halted()),
                now)
        except Exception as exc:
            return self._block(plan, f"policy validation error: {type(exc).__name__}: {exc}",
                               AuditEventType.POLICY_BLOCKED)
        if not decision.allowed:
            return self._block(plan, decision.block_reason or "policy refused", AuditEventType.POLICY_BLOCKED,
                               {"checks": [c.model_dump() for c in decision.checks if not c.passed]})
        self._life.record(plan.incident_id, AuditEventType.POLICY_VALIDATED,
                          {"checks": [c.name for c in decision.checks], "approval_ids": decision.approval_ids},
                          remediation_id=remediation_id)
        used = [a for a in approvals if a.approval_id in decision.approval_ids]

        # ---------------------------------------------------------- L7 live re-validation
        self._life.move(plan.incident_id, IncidentState.REVALIDATING, remediation_id=remediation_id)
        live = self._revalidator.revalidate(plan, used, incident.registration, halted=self._store.is_halted())
        if not live.passed:
            return self._block(plan, live.block_reason or "live re-validation failed",
                               AuditEventType.REVALIDATION_BLOCKED,
                               {"checks": [c.model_dump() for c in live.checks if not c.passed]})
        self._life.record(plan.incident_id, AuditEventType.LIVE_STATE_REVALIDATED,
                          {"checks": [c.name for c in live.checks], "concurrency": live.concurrency.value,
                           "fresh_rerun_safety": live.fresh_rerun_safety.value if live.fresh_rerun_safety else None},
                          remediation_id=remediation_id)

        # ---------------------------------------------------------- write-ahead (compare-and-set)
        self._life.move(plan.incident_id, IncidentState.EXECUTING, remediation_id=remediation_id)
        key = idempotency_key(plan.incident_id, recomputed)
        execution_id = f"aex-{uuid.uuid4().hex[:16]}"
        try:
            queued = self._store.write_ahead(remediation_id, expected_hash=recomputed,
                                             approval_ids=decision.approval_ids, action_execution_id=execution_id,
                                             idempotency_key=key, now=now)
        except Exception as exc:
            return self._block(plan, f"write-ahead failed: {type(exc).__name__}: {exc}",
                               AuditEventType.EXECUTION_BLOCKED)
        if queued is None:
            return self._block(plan, "write-ahead compare-and-set refused (already queued, consumed or changed)",
                               AuditEventType.EXECUTION_BLOCKED)
        self._life.record(plan.incident_id, AuditEventType.EXECUTION_QUEUED,
                          {"action_execution_id": execution_id, "idempotency_key": key,
                           "consumed_approval_ids": decision.approval_ids, "mode": queued.execution_mode.value,
                           "task_instances": [t.model_dump() for t in queued.task_instances_to_clear]},
                          remediation_id=remediation_id)

        if queued.execution_mode is ExecutionMode.DRY_RUN:
            return self._dry_run(queued)
        return self._dispatch(queued)

    # ------------------------------------------------------------------ DRY_RUN

    def _dry_run(self, plan: RemediationPlan) -> ExecutionReport:
        would = [f"{t.task_id}" + (f"[{t.map_index}]" if t.map_index is not None else "") +
                 f" (try {t.try_number}, {t.observed_state})" for t in plan.task_instances_to_clear]
        target = plan.target
        result = {"mode": "DRY_RUN", "dispatched": False,
                  "would_have": f"cleared {len(would)} task instance(s) in "
                                f"{target.dag_id if target else '?'}/{target.dag_run_id if target else '?'}",
                  "dry_run_listing": would}
        plan = self._save(plan, execution_status=ExecutionStatus.NOT_EXECUTED, execution_result=result,
                          execution_completed_at=self._clock())
        self._life.record(plan.incident_id, AuditEventType.EXECUTION_DRY_RUN, result, remediation_id=plan.remediation_id)
        self._life.escalate(plan.incident_id, "DRY_RUN complete: nothing was dispatched; a human decides next steps",
                            remediation_id=plan.remediation_id)
        return ExecutionReport(remediation_id=plan.remediation_id, outcome="DRY_RUN", plan=plan,
                               detail=result["would_have"])

    # ------------------------------------------------------------------ LIVE

    def _dispatch(self, plan: RemediationPlan) -> ExecutionReport:
        plan = self._save(plan, execution_status=ExecutionStatus.RUNNING, execution_started_at=self._clock())
        try:
            outcome = self._backend.dispatch(plan)
        except Exception as exc:  # the request may or may not have gone out: never resend
            outcome = DispatchOutcome(accepted=False, ambiguous=True, detail=f"dispatch raised {type(exc).__name__}: {exc}")

        result = {"detail": outcome.detail, "preflight": outcome.preflight, "sent": outcome.sent,
                  "listing_matches_plan": outcome.listing_matches_plan, "response": outcome.raw_response}
        if outcome.ambiguous:
            plan = self._save(plan, execution_status=ExecutionStatus.UNCERTAIN, execution_result=result)
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_UNCERTAIN, result,
                              remediation_id=plan.remediation_id)
            self._life.move(plan.incident_id, IncidentState.EXECUTION_UNCERTAIN, reason=outcome.detail,
                            remediation_id=plan.remediation_id)
            return self.reconcile(plan.remediation_id)
        if not outcome.accepted:
            if not outcome.sent:
                plan = self._save(plan, execution_status=ExecutionStatus.BLOCKED, execution_result=result,
                                  block_reason=f"nothing was cleared: {outcome.detail}",
                                  execution_completed_at=self._clock())
                self._life.record(plan.incident_id, AuditEventType.EXECUTION_BLOCKED, result,
                                  remediation_id=plan.remediation_id)
                self._life.move(plan.incident_id, IncidentState.BLOCKED, reason=outcome.detail,
                                remediation_id=plan.remediation_id)
                return ExecutionReport(remediation_id=plan.remediation_id, outcome="BLOCKED", plan=plan,
                                       detail=outcome.detail)
            plan = self._save(plan, execution_status=ExecutionStatus.FAILED, execution_result=result,
                              execution_completed_at=self._clock())
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_FAILED, result,
                              remediation_id=plan.remediation_id)
            self._life.escalate(plan.incident_id, f"dispatch refused by the platform: {outcome.detail}",
                                remediation_id=plan.remediation_id)
            return ExecutionReport(remediation_id=plan.remediation_id, outcome="FAILED", plan=plan, detail=outcome.detail)

        plan = self._save(plan, execution_status=ExecutionStatus.SUCCESS, dispatch_confirmed=True,
                          execution_result=result, execution_completed_at=self._clock())
        self._life.record(plan.incident_id, AuditEventType.EXECUTION_DISPATCHED,
                          {"action_execution_id": plan.action_execution_id,
                           "cleared": [t.model_dump() for t in outcome.cleared],
                           "listing_matches_plan": outcome.listing_matches_plan},
                          remediation_id=plan.remediation_id)
        self._life.move(plan.incident_id, IncidentState.VERIFYING, reason="dispatch confirmed",
                        remediation_id=plan.remediation_id)
        return self._verify(plan)

    # ------------------------------------------------------------------ verification

    def _verify(self, plan: RemediationPlan) -> ExecutionReport:
        self._life.record(plan.incident_id, AuditEventType.VERIFICATION_STARTED,
                          {"poll_seconds": self._settings.verify_poll_seconds,
                           "timeout_seconds": self._settings.verify_timeout_seconds},
                          remediation_id=plan.remediation_id)

        def on_extend(detail: str) -> None:
            self._life.record(plan.incident_id, AuditEventType.VERIFICATION_INCONCLUSIVE,
                              {"detail": detail, "action": "extending the verification window once"},
                              remediation_id=plan.remediation_id)

        try:
            verification = self._verifier.verify(plan, on_extend=on_extend)
        except Exception as exc:
            verification = VerificationResult(status=VerificationStatus.INCONCLUSIVE,
                                              detail=f"verification error: {type(exc).__name__}: {exc}")
        plan = self._save(plan, verification_status=verification.status, verification_depth=verification.depth,
                          verification_result=verification.as_record())
        event = {VerificationStatus.VERIFIED: AuditEventType.VERIFICATION_PASSED,
                 VerificationStatus.RECOVERY_FAILED: AuditEventType.VERIFICATION_FAILED}.get(
            verification.status, AuditEventType.VERIFICATION_INCONCLUSIVE)
        self._life.record(plan.incident_id, event, verification.as_record(), remediation_id=plan.remediation_id)
        return ExecutionReport(remediation_id=plan.remediation_id, outcome="DISPATCHED", plan=plan,
                               verification=verification, detail=verification.detail)

    # ------------------------------------------------------------------ reconciliation

    def _evidence_of_clear(self, plan: RemediationPlan) -> bool | None:
        """True: every enumerated instance shows the clear; False: none or only some do; None: unreadable."""
        if plan.target is None:
            return None
        try:
            snapshot = self._reader.get_run_snapshot(plan.target.dag_id, plan.target.dag_run_id)
        except AdapterError:
            return None
        if snapshot is None or snapshot.run_state is None:
            return None
        live = {ti.key: ti for ti in snapshot.task_instances}
        shown = [ref.key in live and ((live[ref.key].try_number or 0) > ref.try_number
                                      or live[ref.key].state not in CLEARABLE_STATES)
                 for ref in plan.task_instances_to_clear]
        return all(shown)

    def reconcile(self, remediation_id: str) -> ExecutionReport:
        """Resolve an UNCERTAIN dispatch by reading state. Never re-dispatches."""
        plan = self._store.get_plan(remediation_id)
        if self._life.state(plan.incident_id) not in _RECONCILABLE:
            return ExecutionReport(remediation_id=remediation_id, outcome="REFUSED", plan=plan,
                                   detail=f"incident is {self._life.state(plan.incident_id).value}; not reconciling")
        self._life.record(plan.incident_id, AuditEventType.RECONCILIATION_STARTED,
                          {"attempts": self._settings.reconcile_attempts,
                           "interval_seconds": self._settings.reconcile_interval_seconds},
                          remediation_id=remediation_id)
        if self._life.state(plan.incident_id) is IncidentState.EXECUTION_UNCERTAIN:
            self._life.move(plan.incident_id, IncidentState.RECONCILING, remediation_id=remediation_id)
        verdict: bool | None = None
        for attempt in range(1, self._settings.reconcile_attempts + 1):
            verdict = self._evidence_of_clear(plan)
            if verdict:
                break
            if attempt < self._settings.reconcile_attempts:
                self._sleep(self._settings.reconcile_interval_seconds)
        if verdict:
            plan = self._save(plan, execution_status=ExecutionStatus.SUCCESS, dispatch_confirmed=True,
                              execution_completed_at=self._clock())
            self._life.record(plan.incident_id, AuditEventType.RECONCILIATION_COMPLETED,
                              {"outcome": "dispatch confirmed by observed state"}, remediation_id=remediation_id)
            self._life.move(plan.incident_id, IncidentState.VERIFYING, reason="reconciled: the clear took effect",
                            remediation_id=remediation_id)
            return self._verify(plan)
        detail = ("state unreadable" if verdict is None else "no evidence the clear took effect") + \
            "; not resent - a human must decide (any new attempt needs a new plan version and approval)"
        self._life.record(plan.incident_id, AuditEventType.RECONCILIATION_COMPLETED,
                          {"outcome": "unresolved", "detail": detail}, remediation_id=remediation_id)
        self._life.escalate(plan.incident_id, f"uncertain execution: {detail}", remediation_id=remediation_id)
        return ExecutionReport(remediation_id=remediation_id, outcome="UNCERTAIN_ESCALATED", plan=plan, detail=detail)

    def reconcile_on_startup(self) -> list[ExecutionReport]:
        """Plans found QUEUED, RUNNING or UNCERTAIN (e.g. after a crash) are reconciled, never re-dispatched."""
        reports = []
        for plan in self._store.plans_with_status(
                {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING, ExecutionStatus.UNCERTAIN}):
            if self._life.state(plan.incident_id) not in _RECONCILABLE | {IncidentState.EXECUTING}:
                continue  # already escalated to a human (or otherwise settled): leave it for them
            found = plan.execution_status
            if found is not ExecutionStatus.UNCERTAIN:
                plan = self._save(plan, execution_status=ExecutionStatus.UNCERTAIN)
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_UNCERTAIN,
                              {"reason": f"found {found.value} at startup; outcome unknown"},
                              remediation_id=plan.remediation_id)
            self._life.move_if_legal(plan.incident_id, IncidentState.EXECUTION_UNCERTAIN,
                                     reason="startup reconciliation", remediation_id=plan.remediation_id)
            reports.append(self.reconcile(plan.remediation_id))
        return reports
