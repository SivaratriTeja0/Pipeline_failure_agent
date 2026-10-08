"""HTTP API (spec Part O). Every endpoint except /health requires authentication; the webhook is
authenticated by its HMAC signature instead.

Identity comes only from the configured AuthProvider (bearer token, or the demo header in DEMO MODE).
Role checks happen here and again inside the healing services (defence in depth):

  read endpoints                         any authenticated principal (HUMAN or SERVICE)
  POST /triage                           ENGINEER or ADMIN (HUMAN or SERVICE, e.g. an agent account)
  POST /pipelines/register               ENGINEER or ADMIN; enabling healing requires a HUMAN ADMIN
  POST /feedback, fix-applied, close     HUMAN ENGINEER or ADMIN
  approve / reject                       HUMAN APPROVER or ADMIN, listed as pipeline approver (or ADMIN)
  cancel                                 HUMAN ENGINEER, APPROVER or ADMIN
  POST /admin/healing/halt               HUMAN ADMIN

An approved plan executes in a background task after the approval response is returned; the
approval call itself never dispatches anything synchronously.
"""

import json
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from actions.approval.service import ApprovalError
from actions.store import StoreError
from adapters.generic.adapter import GenericAdapter, ManualEvidence
from api.container import AppContainer
from api.webhooks import SIGNATURE_HEADER, verify_webhook
from core.incidents.dedup import DedupOutcome
from core.logging_setup import get_logger
from core.models.auth import Principal
from core.models.enums import (
    ApprovalStatus,
    AuditEventType,
    ExecutionStatus,
    PrincipalType,
    RemediationClass,
    Role,
)
from core.models.pipeline import PipelineRegistration
from core.models.remediation import RemediationPlan, compute_plan_hash
from core.models.report import UniversalTriageReport
from core.remediation.audit import verify_audit_chain
from security.auth import AuthProviderUnavailableError
from tools.invoker import tool_availability

_log = get_logger(__name__)
READERS = frozenset(Role)
ENGINEERS = frozenset({Role.ENGINEER, Role.ADMIN})


# ----------------------------------------------------------------------------- request bodies


class TriageRequest(BaseModel):
    pipeline_id: str
    failure: dict[str, Any] = Field(description="platform failure payload (e.g. Airflow callback context)")
    manual_evidence: list[ManualEvidence] = Field(default_factory=list, description="generic platform only")


class FeedbackRequest(BaseModel):
    incident_id: str
    feedback_status: str = Field(pattern="^(CONFIRMED|INCORRECT|PARTIALLY_CORRECT)$")
    actual_root_cause: str | None = Field(default=None, max_length=2000)
    human_note: str | None = Field(default=None, max_length=2000)


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class NoteRequest(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


# ----------------------------------------------------------------------------- app factory


def create_app(container: AppContainer, *, start_background: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        container.rebuild_index()
        with container.lock:
            for orchestrator in container.orchestrators.values():
                orchestrator.startup()  # reconcile QUEUED / RUNNING / UNCERTAIN plans; never re-dispatch
        poller = None
        if start_background and container.env.get("POLLER_ENABLED", "").lower() == "true":
            from api.poller import FailurePoller

            poller = FailurePoller(container, interval=float(container.env.get("POLL_INTERVAL_SECONDS") or 60))
            poller.start()
        yield
        if poller is not None:
            poller.stop()

    app = FastAPI(title="Pipeline Failure Triage & Human-Approved Self-Healing", version="0.5.0", lifespan=lifespan)
    app.state.container = container
    c = container

    @app.exception_handler(ApprovalError)
    async def approval_error(request: Request, exc: ApprovalError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.exception_handler(StoreError)
    async def store_error(request: Request, exc: StoreError) -> JSONResponse:
        status = 404 if "unknown" in str(exc) else 503
        return JSONResponse({"detail": str(exc)}, status_code=status)

    # ------------------------------------------------------------------ authentication

    def authenticated(request: Request) -> Principal:
        try:
            principal = c.auth.authenticate(request)
        except AuthProviderUnavailableError as exc:
            raise HTTPException(503, "authentication provider unavailable") from exc
        if principal is None:
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
        return principal

    def require(roles: frozenset[Role], *, human: bool = False) -> Callable[..., Principal]:
        def dependency(principal: Principal = Depends(authenticated)) -> Principal:
            if human and principal.principal_type is not PrincipalType.HUMAN:
                raise HTTPException(403, "this action requires a HUMAN principal")
            if not principal.roles & roles:
                raise HTTPException(403, f"requires one of {sorted(r.value for r in roles)}")
            return principal
        return dependency

    reader = Depends(require(READERS))
    engineer = Depends(require(ENGINEERS))
    human_engineer = Depends(require(ENGINEERS, human=True))
    human_admin = Depends(require(frozenset({Role.ADMIN}), human=True))
    any_principal = Depends(authenticated)  # approve/reject/cancel: role checks live in ApprovalService

    def registration(pipeline_id: str) -> PipelineRegistration:
        reg = c.repo.get_pipeline(pipeline_id)
        if reg is None:
            raise HTTPException(404, f"pipeline {pipeline_id} is not registered")
        return reg

    def orchestrator_for(reg: PipelineRegistration):
        orch = c.orchestrator(reg.platform)
        if orch is None:
            raise HTTPException(503, f"platform {reg.platform!r} is not configured")
        return orch

    def plan_view(plan: RemediationPlan) -> dict[str, Any]:
        orch = c.orchestrator("airflow") or c.orchestrator("generic")
        required = orch.approvals.required(plan) if orch else 1
        approvals = c.store.approvals_for(plan.remediation_id)
        return {"plan": plan.model_dump(mode="json"), "server_plan_hash": compute_plan_hash(plan),
                "approvals_required": required,
                "valid_approvals": len(orch.approvals.valid_approvals(plan)) if orch else 0,
                "approval_records": [a.model_dump(mode="json") for a in approvals],
                "executed": plan.executed, "not_executed_banner": not plan.executed}

    def live_report(report: UniversalTriageReport) -> dict[str, Any]:
        """The stored report overlaid with live incident and plan state."""
        data = report.model_dump(mode="json")
        try:
            record = c.store.get_incident(report.incident_id)
            data["incident_state"] = record.state.value
        except StoreError:
            return data
        if report.remediation_plan is not None:
            plan = c.store.get_plan(report.remediation_plan.remediation_id)
            data["remediation_plan"] = plan.model_dump(mode="json")
            data["approval_status"] = plan.approval_status.value
            data["healing_status"] = plan.execution_status.value
            data["verification_status"] = plan.verification_status.value
            data["verification_depth"] = plan.verification_depth.value
        return data

    # ------------------------------------------------------------------ intake (triage + webhook + poller)

    def intake(reg: PipelineRegistration, failure: dict[str, Any], manual: list[ManualEvidence],
               source: str) -> dict[str, Any]:
        orch = orchestrator_for(reg)
        adapter = c.adapters[reg.platform]
        payload = {**failure, "environment": reg.environment}
        if reg.platform == "generic":
            payload.setdefault("pipeline_id", reg.pipeline_id)
        try:
            event = adapter.normalize_failure(payload)
        except (ValueError, KeyError, ValidationError) as exc:
            raise HTTPException(422, f"invalid failure payload: {exc}") from exc
        if event.pipeline_id != reg.pipeline_id:
            raise HTTPException(422, "failure payload belongs to a different pipeline")
        with c.lock:
            decision = c.index.classify(event, c.clock())
            if decision.outcome is not DedupOutcome.NEW:
                c.index.link(decision, event)
                return {"deduplicated": decision.outcome.value, "incident_id": decision.incident_id,
                        "reason": decision.reason, "source": source}
            if manual and isinstance(adapter, GenericAdapter):
                adapter.upload(event.pipeline_id, event.execution_id, manual)
            result = orch.handle_failure(event, reg)
            report = result.report
            symptoms = {s.claim_id.removeprefix("c-symptom-") for s in report.downstream_symptoms}
            c.index.register(report.incident_id, event, c.clock(), symptoms)
        return {"incident_id": report.incident_id, "deduplicated": None,
                "related_incident_ids": decision.related_incident_ids, "source": source,
                "report": live_report(report)}

    # ------------------------------------------------------------------ health / me / settings

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok" if c.db.ping() else "degraded", "database": c.db.ping(),
                "banners": c.banners().model_dump(mode="json"),
                "platforms": sorted(c.orchestrators)}

    @app.get("/me")
    def me(principal: Principal = reader) -> dict[str, Any]:
        return {"principal_id": principal.principal_id, "principal_type": principal.principal_type.value,
                "roles": sorted(r.value for r in principal.roles), "auth_method": principal.auth_method,
                "can_approve": principal.can_approve}

    @app.get("/settings")
    def settings_view(principal: Principal = reader) -> dict[str, Any]:
        s = c.settings
        return {"banners": c.banners().model_dump(mode="json"),
                "kill_switches": {"HEALING_ENABLED": s.healing_enabled, "halted": c.store.is_halted()},
                "execution_mode": s.healing_execution_mode.value, "auth_provider": s.auth_provider.value,
                "auth_provider_ok": True, "demo_mode": s.demo_mode,
                "limits": {"MAX_HEALING_CYCLES": s.max_healing_cycles, "APPROVAL_TTL_MINUTES": s.approval_ttl_minutes,
                           "HIGH_RISK_APPROVALS": s.high_risk_approvals, "MAX_TASKS_CLEARED": s.max_tasks_cleared,
                           "MAX_ACTIONS_PER_DAG_PER_HOUR": s.max_actions_per_dag_per_hour},
                "verification": {"VERIFY_POLL_SECONDS": s.verify_poll_seconds,
                                 "VERIFY_TIMEOUT_SECONDS": s.verify_timeout_seconds,
                                 "caveat": "State-only verification: success does not prove the data is correct."}}

    # ------------------------------------------------------------------ pipelines

    @app.post("/pipelines/register", status_code=201)
    def register_pipeline(body: PipelineRegistration, principal: Principal = engineer) -> dict[str, Any]:
        existing = c.repo.get_pipeline(body.pipeline_id)
        changes_healing = body.healing_enabled and not (existing and existing.healing_enabled)
        changes_approvers = existing is not None and set(existing.approver_ids) != set(body.approver_ids)
        if (changes_healing or changes_approvers) and not (
                principal.principal_type is PrincipalType.HUMAN and principal.has_role(Role.ADMIN)):
            raise HTTPException(403, "enabling healing or changing approvers requires a HUMAN ADMIN")
        c.repo.save_pipeline(body, principal.principal_id)
        c.audit.record(incident_id=f"pipeline:{body.pipeline_id}", actor=principal.audit_actor,
                       event_type=AuditEventType.PIPELINE_REGISTERED,
                       payload={"healing_enabled": body.healing_enabled,
                                "allowed_actions": [a.value for a in body.allowed_actions],
                                "approver_ids": body.approver_ids})
        return {"pipeline_id": body.pipeline_id, "registered_by": principal.principal_id}

    @app.get("/pipelines")
    def list_pipelines(principal: Principal = reader) -> list[dict[str, Any]]:
        return [p.model_dump(mode="json") for p in c.repo.list_pipelines()]

    @app.get("/pipelines/{pipeline_id}")
    def get_pipeline(pipeline_id: str, principal: Principal = reader) -> dict[str, Any]:
        return registration(pipeline_id).model_dump(mode="json")

    @app.get("/capabilities/{pipeline_id}")
    def capabilities(pipeline_id: str, principal: Principal = reader) -> dict[str, Any]:
        reg = registration(pipeline_id)
        adapter = c.adapters.get(reg.platform)
        if adapter is None:
            raise HTTPException(503, f"platform {reg.platform!r} is not configured")
        backend = c.backends.get(reg.platform)
        actions = sorted(a.value for a in backend.action_capabilities()) if backend else []
        return {"pipeline_id": pipeline_id, "platform": reg.platform,
                "read_capabilities": sorted(r.value for r in adapter.read_capabilities()),
                "tools": {k: v.value for k, v in tool_availability(adapter.read_capabilities()).items()},
                "action_capabilities": actions,
                "healing": "AVAILABLE" if actions else "NOT_APPLICABLE",
                "demo": adapter.is_demo}

    # ------------------------------------------------------------------ triage / reports / feedback

    @app.post("/triage", status_code=201)
    def triage(body: TriageRequest, principal: Principal = engineer) -> dict[str, Any]:
        reg = registration(body.pipeline_id)
        return intake(reg, body.failure, body.manual_evidence, source=f"api:{principal.principal_id}")

    @app.get("/triage/{incident_id}")
    def get_triage(incident_id: str, principal: Principal = reader) -> dict[str, Any]:
        report = c.repo.latest_report(incident_id)
        if report is None:
            raise HTTPException(404, f"no report for incident {incident_id}")
        return live_report(report)

    @app.get("/reports")
    def reports(pipeline_id: str | None = None, principal: Principal = reader) -> list[dict[str, Any]]:
        out = []
        for report in c.repo.latest_reports():
            if pipeline_id and report.pipeline_id != pipeline_id:
                continue
            live = live_report(report)
            out.append({k: live[k] for k in (
                "incident_id", "pipeline_id", "task_id", "execution_id", "platform", "failure_category",
                "confidence", "remediation_class", "remediation_confidence", "rerun_safety", "incident_state",
                "status", "llm_mode", "created_at", "approval_status", "healing_status", "verification_status",
                "feedback_status")})
        return out

    @app.get("/incidents/{incident_id}/reports")
    def incident_reports(incident_id: str, principal: Principal = reader) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in c.repo.reports(incident_id)]

    @app.post("/feedback", status_code=201)
    def feedback(body: FeedbackRequest, principal: Principal = human_engineer) -> dict[str, Any]:
        if c.repo.latest_report(body.incident_id) is None:
            raise HTTPException(404, f"no report for incident {body.incident_id}")
        c.repo.add_feedback(body.incident_id, principal.principal_id, body.model_dump(exclude={"incident_id"}))
        c.repo.update_latest_report(body.incident_id, feedback_status=body.feedback_status,
                                    actual_root_cause=body.actual_root_cause, human_note=body.human_note)
        return {"incident_id": body.incident_id, "feedback": c.repo.feedback(body.incident_id)}

    # ------------------------------------------------------------------ webhook

    @app.post("/webhooks/failure", status_code=202)
    async def webhook(request: Request) -> JSONResponse:
        raw = await request.body()
        verdict = verify_webhook(raw, request.headers.get(SIGNATURE_HEADER), c.env.get("WEBHOOK_SECRET"),
                                 c.settings.demo_mode)
        if not verdict.accepted:
            return JSONResponse({"detail": f"webhook rejected: {verdict.reason}"}, status_code=401)
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            return JSONResponse({"detail": "body is not JSON"}, status_code=422)
        if not isinstance(payload, dict):
            return JSONResponse({"detail": "body must be a JSON object"}, status_code=422)
        pipeline_id = str(payload.get("pipeline_id") or payload.get("dag_id") or "")
        reg = c.repo.get_pipeline(pipeline_id)
        if reg is None:
            return JSONResponse({"detail": f"pipeline {pipeline_id!r} is not registered"}, status_code=404)
        failure = {k: v for k, v in payload.items() if k != "pipeline_id"} if reg.platform != "generic" else payload
        try:
            result = intake(reg, failure, [], source="webhook")
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        result["signed"] = verdict.signed
        if not verdict.signed:
            result["warning"] = verdict.reason
        return JSONResponse(result, status_code=202)

    # ------------------------------------------------------------------ remediation / approvals

    def execute_in_background(remediation_id: str, platform: str) -> None:
        with c.lock:
            try:
                c.orchestrators[platform].execute(remediation_id)
            except Exception as exc:  # the executor already failed closed; never crash the server
                _log.error("background_execution_error", extra={"remediation_id": remediation_id,
                                                                "error": type(exc).__name__})

    def platform_of(plan: RemediationPlan) -> str:
        return c.store.get_incident(plan.incident_id).registration.platform

    @app.get("/incidents/{incident_id}/remediation")
    def incident_remediation(incident_id: str, principal: Principal = reader) -> dict[str, Any]:
        record = c.store.get_incident(incident_id)
        plans = sorted(c.store.plans_for_incident(incident_id), key=lambda p: p.investigation_cycle, reverse=True)
        return {"incident_id": incident_id, "incident_state": record.state.value,
                "plans": [plan_view(p) for p in plans]}

    @app.get("/remediation/{remediation_id}")
    def get_remediation(remediation_id: str, principal: Principal = reader) -> dict[str, Any]:
        return plan_view(c.store.get_plan(remediation_id))

    @app.post("/remediation/{remediation_id}/approve")
    def approve(remediation_id: str, background: BackgroundTasks, body: dict[str, Any] = Body(...),
                principal: Principal = any_principal) -> dict[str, Any]:
        plan = c.store.get_plan(remediation_id)
        platform = platform_of(plan)
        with c.lock:
            outcome = c.orchestrators[platform].approve(remediation_id, principal, body, execute=False)
        if outcome.approval and outcome.approval.complete:
            background.add_task(execute_in_background, remediation_id, platform)
        approval = outcome.approval
        return {"remediation_id": remediation_id, "complete": bool(approval and approval.complete),
                "approvals": approval.approvals if approval else 0, "required": approval.required if approval else 1,
                "decided_by": approval.record.decided_by if approval and approval.record else None,
                "server_plan_hash": approval.record.plan_hash if approval and approval.record else None,
                "execution": "scheduled" if approval and approval.complete else "awaiting further approvals"}

    @app.post("/remediation/{remediation_id}/reject")
    def reject(remediation_id: str, body: dict[str, Any] = Body(...),
               principal: Principal = any_principal) -> dict[str, Any]:
        try:
            reason = ReasonRequest.model_validate({"reason": body.get("reason", "")}).reason
        except ValidationError as exc:
            raise HTTPException(422, "a rejection reason is required") from exc
        plan = c.store.get_plan(remediation_id)
        with c.lock:
            state = c.orchestrators[platform_of(plan)].reject(remediation_id, principal, reason, body)
        return {"remediation_id": remediation_id, "incident_state": state.value}

    @app.post("/remediation/{remediation_id}/cancel")
    def cancel(remediation_id: str, body: ReasonRequest, principal: Principal = any_principal) -> dict[str, Any]:
        plan = c.store.get_plan(remediation_id)
        with c.lock:
            state = c.orchestrators[platform_of(plan)].cancel(remediation_id, principal, body.reason)
        return {"remediation_id": remediation_id, "incident_state": state.value}

    @app.get("/remediation/{remediation_id}/verification")
    def verification(remediation_id: str, principal: Principal = reader) -> dict[str, Any]:
        plan = c.store.get_plan(remediation_id)
        return {"remediation_id": remediation_id, "verification_status": plan.verification_status.value,
                "verification_depth": plan.verification_depth.value, "verification_result": plan.verification_result,
                "execution_status": plan.execution_status.value, "executed": plan.executed,
                "caveat": "State-only verification: success does not prove the data is correct."}

    @app.get("/approvals/pending")
    def pending(principal: Principal = reader) -> list[dict[str, Any]]:
        out = []
        for plan in c.store.all_plans():
            if (plan.remediation_class is RemediationClass.AUTOMATABLE and plan.approval_status is ApprovalStatus.PENDING
                    and plan.execution_status is ExecutionStatus.NOT_EXECUTED):
                reg = c.store.get_incident(plan.incident_id).registration
                view = plan_view(plan)
                view["caller_may_approve"] = principal.can_approve and (
                    principal.principal_id in reg.approver_ids or principal.has_role(Role.ADMIN))
                out.append(view)
        return out

    # ------------------------------------------------------------------ manual fix loop

    @app.post("/incidents/{incident_id}/fix-applied")
    def fix_applied(incident_id: str, body: NoteRequest, principal: Principal = human_engineer) -> dict[str, Any]:
        record = c.store.get_incident(incident_id)
        with c.lock:
            result = c.orchestrators[record.registration.platform].fix_applied(incident_id, principal, body.note)
        return {"incident_id": incident_id, "report": live_report(result.report),
                "plan_id": result.plan.remediation_id if result.plan else None}

    @app.post("/incidents/{incident_id}/manual-close")
    def manual_close(incident_id: str, body: NoteRequest, principal: Principal = human_engineer) -> dict[str, Any]:
        record = c.store.get_incident(incident_id)
        with c.lock:
            state = c.orchestrators[record.registration.platform].manual_close(incident_id, principal, body.note)
        return {"incident_id": incident_id, "incident_state": state.value}

    @app.get("/incidents")
    def incidents(principal: Principal = reader) -> list[dict[str, Any]]:
        return [{"incident_id": r.incident_id, "pipeline_id": r.event.pipeline_id, "task_id": r.event.task_id,
                 "execution_id": r.event.execution_id, "platform": r.registration.platform,
                 "state": r.state.value, "investigation_cycle": r.investigation_cycle,
                 "category": r.category.value if r.category else None} for r in c.store.list_incidents()]

    # ------------------------------------------------------------------ audit

    @app.get("/incidents/{incident_id}/audit")
    def incident_audit(incident_id: str, principal: Principal = reader) -> dict[str, Any]:
        events = c.audit_store.for_incident(incident_id)
        if not events:
            raise HTTPException(404, f"no audit events for {incident_id}")
        return {"incident_id": incident_id, "events": [e.model_dump(mode="json") for e in events]}

    @app.get("/audit/verify")
    def audit_verify(principal: Principal = reader) -> dict[str, Any]:
        return verify_audit_chain(c.audit_store.all()).model_dump()

    # ------------------------------------------------------------------ admin

    @app.post("/admin/healing/halt")
    def halt(body: ReasonRequest, principal: Principal = human_admin) -> dict[str, Any]:
        with c.lock:  # the store is shared, so one orchestrator halts every pending plan on every platform
            blocked = next(iter(c.orchestrators.values())).halt(principal, body.reason)
        return {"halted": True, "blocked_plans": sorted(blocked)}

    return app
