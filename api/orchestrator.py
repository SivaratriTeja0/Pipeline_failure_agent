"""Healing orchestrator: the only caller of ``actions.executor`` (spec B2).

Wires the investigation side (TriageAgent - produces data only) to the healing boundary
(approval -> policy -> live re-validation -> executor -> verification) and owns the incident loop:

  VERIFIED          -> RESOLVED
  RECOVERY_FAILED   -> re-investigate (new cycle, own 5-call budget) until MAX_HEALING_CYCLES -> ESCALATED
  INCONCLUSIVE      -> ESCALATED (never closes the incident)
  MANUAL_FIX_REQUIRED -> engineer attests the fix (POST /incidents/{id}/fix-applied) -> re-investigate

Principals are passed in by the API layer after authentication; nothing here accepts an identity
from a request body. Phase 5 exposes these operations over HTTP.
"""

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from actions.approval.service import ApprovalOutcome, ApprovalService, ForbiddenError, PlanStateError, UnauthenticatedError
from actions.executor.executor import ExecutionReport, HealingExecutor
from actions.lifecycle import Lifecycle
from actions.policy.engine import PolicyEngine
from actions.registry import ACTION_REGISTRY
from actions.revalidation.revalidator import LiveStateRevalidator
from actions.store import HealingStore, IncidentRecord, revalidated
from actions.verification.verifier import Verifier
from adapters.base.interfaces import AdapterError, PipelineAdapter, RemediationExecutor
from agent.llm_provider import LLMProvider
from agent.triage_agent import TriageAgent, TriageContext, TriageResult
from core.config import Settings
from core.evidence.conventions import CAUSE_CLEARED_CANDIDATE, FIX_ATTESTATION
from core.models.auth import Principal
from core.models.base import utcnow
from core.models.enums import (
    ApprovalStatus,
    AuditEventType,
    EvidenceCategory,
    ExecutionStatus,
    IncidentState,
    PrincipalType,
    Reliability,
    Role,
    Sensitivity,
    VerificationStatus,
)
from core.models.events import PipelineFailureEvent
from core.models.evidence import EvidenceItem, Provenance
from core.models.pipeline import PipelineRegistration
from core.models.report import UniversalTriageReport
from core.remediation.audit import AuditLog
from core.remediation.selector import FAILED, action_signature
from notifications.notifier import (
    NotificationKind,
    Notifier,
    approval_request_notification,
    outcome_notification,
    triage_notification,
)
from security.auth import AuthProvider

_MAX_NOTE = 2000


class HealingOutcome(BaseModel):
    """What happened after an approval / execution request, end to end."""

    execution: ExecutionReport | None = None
    approval: ApprovalOutcome | None = None
    reinvestigation: TriageResult | None = None
    incident_state: IncidentState


class HealingOrchestrator:
    def __init__(
        self,
        *,
        adapter: PipelineAdapter,
        provider: LLMProvider,
        settings: Settings,
        audit: AuditLog,
        store: HealingStore,
        auth: AuthProvider,
        backend: RemediationExecutor | None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None],
        notifier: Notifier | None = None,
        report_sink: Callable[[UniversalTriageReport], None] | None = None,
        ui_base_url: str = "http://localhost:8501",
    ) -> None:
        self.settings = settings
        self._notifier = notifier
        self._report_sink = report_sink
        self._ui = ui_base_url
        self.audit = audit
        self.store = store
        self._adapter = adapter
        self._clock = clock
        capabilities = backend.action_capabilities() if backend is not None else frozenset()
        self._agent = TriageAgent(adapter, provider, settings, audit, action_capabilities=capabilities, clock=clock)
        self.approvals = ApprovalService(store, audit, settings, clock)
        self._life = Lifecycle(store, audit)
        self._executor = None if backend is None else HealingExecutor(
            store=store, audit=audit, settings=settings,
            policy=PolicyEngine(settings, ACTION_REGISTRY, capabilities),
            revalidator=LiveStateRevalidator(adapter, auth, settings, clock),
            backend=backend, reader=adapter, verifier=Verifier(adapter, settings, clock=clock, sleep=sleep),
            clock=clock, sleep=sleep)

    # ------------------------------------------------------------------ intake

    def _persist(self, result: TriageResult, event: PipelineFailureEvent, registration: PipelineRegistration,
                 previous: IncidentRecord | None) -> TriageResult:
        report = result.report
        record = IncidentRecord(
            incident_id=report.incident_id, event=event, registration=registration, state=report.incident_state,
            investigation_cycle=report.investigation_cycles[-1].cycle if report.investigation_cycles else 1,
            category=report.failure_category, evidence=report.evidence,
            plan_ids=(previous.plan_ids if previous else []) + ([result.plan.remediation_id] if result.plan else []),
            failed_signatures=previous.failed_signatures if previous else [])
        self.store.save_incident(record)
        if self._report_sink is not None:
            self._report_sink(report)
        self._notify(triage_notification(report, self._ui))
        if result.plan is not None:
            self.store.save_plan(result.plan)
            self.approvals.request_approval(result.plan.remediation_id)
            self._notify(approval_request_notification(result.plan, self.approvals.required(result.plan), self._ui))
        return result

    def _notify(self, notification) -> None:
        if self._notifier is not None:
            self._notifier.send(notification)

    def _notify_outcome(self, outcome: "HealingOutcome") -> "HealingOutcome":
        report = outcome.execution
        if report is None or report.plan is None:
            return outcome
        plan = report.plan
        fields = {"plan": f"{plan.remediation_id} v{plan.plan_version}", "outcome": report.outcome,
                  "execution_status": plan.execution_status.value, "execution_mode": plan.execution_mode.value,
                  "executed": plan.executed, "detail": report.detail, "incident_state": outcome.incident_state.value}
        if plan.execution_status is ExecutionStatus.UNCERTAIN:
            self._notify(outcome_notification(NotificationKind.EXECUTION_UNCERTAIN, plan.incident_id,
                                              "Execution outcome UNCERTAIN (not resent)", fields, self._ui))
        else:
            self._notify(outcome_notification(NotificationKind.EXECUTION_RESULT, plan.incident_id,
                                              f"Execution {report.outcome}", fields, self._ui))
        if report.verification is not None:
            self._notify(outcome_notification(
                NotificationKind.VERIFICATION_RESULT, plan.incident_id,
                f"Verification {report.verification.status.value}",
                {**fields, "verification_depth": report.verification.depth.value}, self._ui))
        if self._life.state(plan.incident_id) is IncidentState.ESCALATED:
            self._notify(outcome_notification(NotificationKind.ESCALATION, plan.incident_id, "Incident escalated",
                                              fields, self._ui))
        return outcome

    def handle_failure(self, event: PipelineFailureEvent, registration: PipelineRegistration) -> TriageResult:
        return self._persist(self._agent.triage(event, registration), event, registration, None)

    # ------------------------------------------------------------------ approval API

    def approve(self, remediation_id: str, principal: Principal | None, body: Mapping[str, Any], *,
                execute: bool = True) -> HealingOutcome:
        outcome = self.approvals.approve(remediation_id, principal, body)
        plan = outcome.plan
        if outcome.complete and execute:
            result = self.execute(remediation_id)
            return result.model_copy(update={"approval": outcome})
        return HealingOutcome(approval=outcome, incident_state=self._life.state(plan.incident_id))

    def reject(self, remediation_id: str, principal: Principal | None, reason: str,
               body: Mapping[str, Any] | None = None) -> IncidentState:
        plan = self.approvals.reject(remediation_id, principal, reason, body)
        return self._life.state(plan.incident_id)

    def cancel(self, remediation_id: str, principal: Principal | None, reason: str) -> IncidentState:
        plan = self.approvals.cancel(remediation_id, principal, reason)
        return self._life.state(plan.incident_id)

    def revise(self, remediation_id: str, principal: Principal | None, changes: Mapping[str, Any]):
        return self.approvals.revise(remediation_id, principal, changes)

    # ------------------------------------------------------------------ execution + loop

    def execute(self, remediation_id: str) -> HealingOutcome:
        plan = self.store.get_plan(remediation_id)
        if self._executor is None:
            self._life.record(plan.incident_id, AuditEventType.EXECUTION_BLOCKED,
                              {"reason": "no remediation executor for this platform (healing NOT_APPLICABLE)"},
                              remediation_id=remediation_id)
            return HealingOutcome(incident_state=self._life.state(plan.incident_id))
        report = self._executor.execute_approved(remediation_id)
        return self._notify_outcome(self._after_execution(report))

    def _after_execution(self, report: ExecutionReport) -> HealingOutcome:
        plan = report.plan
        if plan is None:
            return HealingOutcome(execution=report, incident_state=IncidentState.BLOCKED)
        incident_id = plan.incident_id
        verification = report.verification
        if verification is None:
            return HealingOutcome(execution=report, incident_state=self._life.state(incident_id))
        listing_ok = (plan.execution_result or {}).get("listing_matches_plan") is not False
        if verification.status is VerificationStatus.VERIFIED and listing_ok:
            self._life.move(incident_id, IncidentState.RESOLVED, reason="verified: " + verification.detail,
                            remediation_id=plan.remediation_id)
            self._life.record(incident_id, AuditEventType.INCIDENT_RESOLVED,
                              {"verification_depth": verification.depth.value, "detail": verification.detail},
                              remediation_id=plan.remediation_id)
            return HealingOutcome(execution=report, incident_state=IncidentState.RESOLVED)
        if verification.status is VerificationStatus.RECOVERY_FAILED:
            return self._recovery_failed(report)
        reason = ("platform cleared a different set than approved" if not listing_ok
                  else f"verification {verification.status.value}: {verification.detail}")
        self._life.escalate(incident_id, reason, remediation_id=plan.remediation_id)
        return HealingOutcome(execution=report, incident_state=IncidentState.ESCALATED)

    def _recovery_failed(self, report: ExecutionReport) -> HealingOutcome:
        plan = report.plan
        if plan is None or plan.target is None or plan.action_type is None:
            return HealingOutcome(execution=report, incident_state=IncidentState.ESCALATED)
        incident = self.store.get_incident(plan.incident_id)
        signature = action_signature(plan.action_type, plan.target, plan.task_instances_to_clear)
        incident = incident.model_copy(update={"failed_signatures": [*incident.failed_signatures, signature]})
        self.store.save_incident(incident)
        cycles = self.store.executions_for_incident(plan.incident_id)
        if cycles >= self.settings.max_healing_cycles:
            self._life.escalate(plan.incident_id, f"recovery failed after {cycles} healing cycle(s) "
                                f"(MAX_HEALING_CYCLES={self.settings.max_healing_cycles})",
                                remediation_id=plan.remediation_id)
            return HealingOutcome(execution=report, incident_state=IncidentState.ESCALATED)

        self._life.move(plan.incident_id, IncidentState.RE_INVESTIGATING, reason="recovery failed; new cycle",
                        remediation_id=plan.remediation_id)
        event = self._event_after_failure(incident, plan.task_instances_to_clear)
        if event is None:
            self._life.escalate(plan.incident_id, "run state unreadable after the failed recovery")
            return HealingOutcome(execution=report, incident_state=IncidentState.ESCALATED)
        result = self._reinvestigate(incident, event, attestations=[])
        return HealingOutcome(execution=report, reinvestigation=result,
                              incident_state=self._life.state(plan.incident_id))

    def _event_after_failure(self, incident: IncidentRecord, refs: list) -> PipelineFailureEvent | None:
        """The new failure of the primary task becomes the event for the next cycle."""
        event = incident.event
        try:
            snapshot = self._adapter.get_run_snapshot(event.pipeline_id, event.execution_id)
        except AdapterError:
            return None
        if snapshot is None:
            return None
        primary = event.task_id or next((r.task_id for r in refs if r.observed_state == FAILED), None)
        ti = next((t for t in snapshot.task_instances if t.task_id == primary and t.state == FAILED), None)
        if ti is None:
            return None
        return event.model_copy(update={
            "attempt_number": ti.try_number, "failure_time": ti.end_date, "end_time": ti.end_date,
            "metadata": {**event.metadata, "try_number": ti.try_number}})

    def _reinvestigate(self, incident: IncidentRecord, event: PipelineFailureEvent,
                       attestations: list[EvidenceItem]) -> TriageResult:
        ctx = TriageContext(
            incident_id=incident.incident_id, investigation_cycle=incident.investigation_cycle + 1,
            start_state=IncidentState.RE_INVESTIGATING,
            previously_failed_signatures=frozenset(incident.failed_signatures),
            evidence_after=event.failure_time, historical_evidence=incident.evidence, attestations=attestations)
        result = self._agent.triage(event, incident.registration, ctx)
        self._persist(result, event, incident.registration, incident)
        if result.report.incident_state is IncidentState.BLOCKED and incident.failed_signatures:
            self._life.escalate(incident.incident_id, "re-investigation found no safe action after a failed recovery")
        return result

    # ------------------------------------------------------------------ manual-fix loop (L10)

    def _require_engineer(self, principal: Principal | None, incident_id: str, action: str) -> Principal:
        if principal is None:
            self._life.record(incident_id, AuditEventType.AUTH_FAILURE, {"action": action, "reason": "unauthenticated"})
            raise UnauthenticatedError(f"{action} requires an authenticated principal")
        if principal.principal_type is not PrincipalType.HUMAN or not principal.roles & {Role.ENGINEER, Role.ADMIN}:
            self._life.record(incident_id, AuditEventType.AUTH_FAILURE,
                              {"action": action, "principal_id": principal.principal_id, "reason": "not permitted"})
            raise ForbiddenError(f"{principal.principal_id} cannot {action}")
        return principal

    def fix_applied(self, incident_id: str, principal: Principal | None, note: str) -> TriageResult:
        """Record the engineer's attestation (MEDIUM reliability - not proof) and re-investigate."""
        engineer = self._require_engineer(principal, incident_id, "attest a fix")
        incident = self.store.get_incident(incident_id)
        if incident.state is not IncidentState.MANUAL_FIX_REQUIRED:
            raise PlanStateError(f"incident is {incident.state.value}; a fix can only be attested for MANUAL_FIX_REQUIRED")
        if not note or not note.strip():
            raise PlanStateError("a note describing the fix is required")
        now = self._clock()
        cycle = incident.investigation_cycle + 1
        attestation = EvidenceItem(
            evidence_id=f"ev-attest-{incident_id}-{cycle}", category=EvidenceCategory.OTHER,
            source=f"human_attestation:{engineer.principal_id}", platform=incident.event.platform, timestamp=now,
            execution_id=incident.event.execution_id, attempt_number=None,
            description=f"Engineer {engineer.principal_id} attests a fix was applied (attestation, not proof)",
            value={"note": note.strip()[:_MAX_NOTE], "attested_by": engineer.principal_id},
            reliability=Reliability.MEDIUM, sensitivity=Sensitivity.INTERNAL,
            provenance=Provenance(adapter="human", capability="fix_attestation", tool="fix_applied",
                                  source=f"POST /incidents/{incident_id}/fix-applied", collected_at=now,
                                  investigation_cycle=cycle),
            metadata={"pipeline_id": incident.event.pipeline_id, FIX_ATTESTATION: True, CAUSE_CLEARED_CANDIDATE: True,
                      "user_provided": True})
        self._life.move(incident_id, IncidentState.AWAITING_FIX_CONFIRMATION, actor=engineer.audit_actor,
                        reason="engineer attested a fix")
        self._life.record(incident_id, AuditEventType.FIX_APPLIED,
                          {"evidence_id": attestation.evidence_id, "note": note.strip()[:_MAX_NOTE]},
                          actor=engineer.audit_actor)
        self._life.move(incident_id, IncidentState.RE_INVESTIGATING, reason="re-collecting fresh evidence")
        return self._reinvestigate(incident, incident.event, attestations=[attestation])

    def manual_close(self, incident_id: str, principal: Principal | None, note: str) -> IncidentState:
        engineer = self._require_engineer(principal, incident_id, "close an incident")
        if not note or not note.strip():
            raise PlanStateError("a closing note is required")
        self._life.record(incident_id, AuditEventType.MANUAL_CLOSE, {"note": note.strip()[:_MAX_NOTE]},
                          actor=engineer.audit_actor)
        self._life.move(incident_id, IncidentState.RESOLVED, actor=engineer.audit_actor, reason="closed manually")
        return IncidentState.RESOLVED

    # ------------------------------------------------------------------ kill switch + startup

    def halt(self, principal: Principal | None, reason: str) -> list[str]:
        """POST /admin/healing/halt: blocks every pending plan immediately (ADMIN only)."""
        if principal is None or principal.principal_type is not PrincipalType.HUMAN or not principal.has_role(Role.ADMIN):
            raise ForbiddenError("only a HUMAN ADMIN can halt healing")
        self.store.set_halted(True)
        blocked = []
        for plan in self.store.all_plans():
            if (plan.execution_status is ExecutionStatus.NOT_EXECUTED and plan.action_execution_id is None
                    and plan.approval_status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)):
                self.store.save_plan(revalidated(plan, execution_status=ExecutionStatus.BLOCKED,
                                                 block_reason=f"healing halted: {reason}"))
                self._life.move_if_legal(plan.incident_id, IncidentState.BLOCKED, actor=principal.audit_actor,
                                         reason="healing halted", remediation_id=plan.remediation_id)
                blocked.append(plan.remediation_id)
        self.audit.record(incident_id="GLOBAL", actor=principal.audit_actor, event_type=AuditEventType.HEALING_HALTED,
                          payload={"reason": reason, "blocked_plans": blocked})
        return blocked

    def startup(self) -> list[ExecutionReport]:
        """Reconcile anything left QUEUED / RUNNING / UNCERTAIN. Never re-dispatches."""
        if self._executor is None:
            return []
        return [self._notify_outcome(self._after_execution(r)).execution or r
                for r in self._executor.reconcile_on_startup()]
