"""Deterministic policy validation (spec L6). Every check must pass, else BLOCKED with block_reason.

Inputs are persisted facts only (plan, approval records, registration, settings, counters). The
risk level used for the approval count is the stricter of the plan's and the one re-derived from
the registration, so an edited or tampered risk level can never reduce the approvals required.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from actions.registry import ActionRegistry
from core.config import Settings
from core.models.base import PIPELINE_ID_RE, RUN_ID_RE, TASK_ID_RE
from core.models.enums import (
    ActionCapability,
    ApprovalDecision,
    ApprovalStatus,
    ConfidenceLevel,
    RemediationClass,
    RerunSafety,
    Role,
)
from core.models.pipeline import PipelineRegistration
from core.models.remediation import ACTION_SCOPE, ApprovalRecord, RemediationPlan, compute_plan_hash
from core.remediation.plan_builder import PRECONDITION_CHECKS
from core.remediation.risk import compute_risk_level, required_approvals
from core.taxonomy.categories import FailureCategory


class Check(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class PolicyDecision(BaseModel):
    allowed: bool
    checks: list[Check] = Field(default_factory=list)
    approval_ids: list[str] = Field(default_factory=list)

    @property
    def block_reason(self) -> str | None:
        failed = [f"{c.name}: {c.detail}" if c.detail else c.name for c in self.checks if not c.passed]
        return "; ".join(failed) if failed else None


class PolicyContext(BaseModel):
    """Facts about the incident the plan must be bound to, plus counters."""

    incident_id: str
    pipeline_id: str
    execution_id: str
    category: FailureCategory | None = None
    executions_for_incident: int = 0
    actions_for_dag_last_hour: int = 0
    halted: bool = False


class PolicyEngine:
    def __init__(self, settings: Settings, registry: ActionRegistry,
                 executor_capabilities: frozenset[ActionCapability]) -> None:
        self._settings = settings
        self._registry = registry
        self._capabilities = executor_capabilities

    def validate(
        self,
        plan: RemediationPlan,
        approvals: list[ApprovalRecord],
        registration: PipelineRegistration,
        ctx: PolicyContext,
        now: datetime,
    ) -> PolicyDecision:
        s = self._settings
        checks: list[Check] = []

        def check(name: str, passed: bool, detail: str = "") -> None:
            checks.append(Check(name=name, passed=bool(passed), detail="" if passed else detail))

        # kill switches and mode
        check("healing_enabled_global", s.healing_enabled, "HEALING_ENABLED=false")
        check("healing_enabled_pipeline", registration.healing_enabled,
              f"pipeline {registration.pipeline_id} has healing_enabled=false")
        check("not_halted", not ctx.halted, "healing halted by an administrator")
        check("execution_mode_matches", plan.execution_mode is s.healing_execution_mode,
              f"plan was made for {plan.execution_mode.value} but HEALING_EXECUTION_MODE="
              f"{s.healing_execution_mode.value}")

        # action
        action = plan.action_type
        spec = self._registry.get(action) if action else None
        check("action_allowed_for_pipeline", action is not None and action in registration.allowed_actions,
              f"{action.value if action else None} not in the pipeline's allowed_actions")
        check("action_registered", spec is not None, "action not in the ActionRegistry")
        check("executor_capability", spec is not None and spec.required_action_capability in self._capabilities,
              "the executor does not declare the required action capability")
        if ctx.category is not None:
            check("category_eligible", spec is not None and ctx.category in spec.eligible_categories,
                  f"{ctx.category.value} is not eligible for {action.value if action else None}")

        # class, confidence, safety
        check("remediation_class_automatable", plan.remediation_class is RemediationClass.AUTOMATABLE,
              plan.remediation_class.value)
        check("remediation_confidence", plan.remediation_confidence in (ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH),
              f"remediation confidence {plan.remediation_confidence.value}")
        check("rerun_safety", plan.rerun_safety in (RerunSafety.SAFE, RerunSafety.SAFE_WITH_CONDITIONS),
              f"rerun safety {plan.rerun_safety.value}")

        # approvals
        current_hash = compute_plan_hash(plan)
        valid: dict[str, ApprovalRecord] = {}
        for record in approvals:
            if (record.decision is ApprovalDecision.APPROVED and record.plan_version == plan.plan_version
                    and record.plan_hash == current_hash and not record.consumed and not record.is_expired(now)
                    and (record.decided_by in registration.approver_ids or record.role is Role.ADMIN)):
                valid.setdefault(record.decided_by, record)
        derived_risk = compute_risk_level(registration.environment, plan.recovery_scope) if plan.recovery_scope \
            else plan.risk_level
        required = max(required_approvals(plan.risk_level, s.high_risk_approvals),
                       required_approvals(derived_risk, s.high_risk_approvals))
        check("approval_status", plan.approval_status is ApprovalStatus.APPROVED, plan.approval_status.value)
        check("approvals_sufficient", len(valid) >= required,
              f"{len(valid)} valid distinct approval(s) for this version and hash; {required} required "
              f"(risk {plan.risk_level.value}/{derived_risk.value})")

        # limits
        check("healing_cycles", ctx.executions_for_incident < s.max_healing_cycles,
              f"{ctx.executions_for_incident} execution(s) already; MAX_HEALING_CYCLES={s.max_healing_cycles}")
        check("dag_action_rate", ctx.actions_for_dag_last_hour < s.max_actions_per_dag_per_hour,
              f"{ctx.actions_for_dag_last_hour} action(s) on this DAG in the last hour; "
              f"MAX_ACTIONS_PER_DAG_PER_HOUR={s.max_actions_per_dag_per_hour}")
        check("tasks_cleared_limit", 0 < len(plan.task_instances_to_clear) <= s.max_tasks_cleared,
              f"{len(plan.task_instances_to_clear)} task instances; MAX_TASKS_CLEARED={s.max_tasks_cleared}")

        # binding to the incident
        target = plan.target
        check("bound_to_incident", plan.incident_id == ctx.incident_id, "plan belongs to another incident")
        check("target_pipeline", target is not None and target.dag_id == ctx.pipeline_id == registration.pipeline_id,
              "target DAG is not the incident's DAG")
        check("target_execution", target is not None and target.dag_run_id == ctx.execution_id,
              "target run is not the incident's run")
        check("scope_matches_action", action is not None and plan.recovery_scope is ACTION_SCOPE[action],
              "recovery scope does not match the action")
        ids_ok = target is not None and bool(PIPELINE_ID_RE.match(target.dag_id)) and bool(
            RUN_ID_RE.match(target.dag_run_id)) and all(TASK_ID_RE.match(t.task_id) for t in plan.task_instances_to_clear)
        check("identifiers_strict", ids_ok, "an identifier does not match its strict pattern")
        if target is not None and target.task_id is not None:
            check("target_task_enumerated", any(t.task_id == target.task_id for t in plan.task_instances_to_clear),
                  "target task is not in the enumerated list")
        params = plan.parameters
        check("parameters", params.only_failed is True and params.include_upstream is False
              and params.include_downstream is False, "only_failed must be true; no upstream/downstream expansion")
        unknown = sorted({p.check for p in plan.preconditions} - PRECONDITION_CHECKS)
        check("preconditions_known", not unknown, f"unknown precondition checks {unknown}")

        return PolicyDecision(allowed=all(c.passed for c in checks), checks=checks,
                              approval_ids=[r.approval_id for r in valid.values()])
