"""Live-state re-validation (spec L7, invariants I8, I16, I18). Read-only; runs immediately before
every execution. Any error, timeout, unreadable state or difference -> BLOCKED. The plan is never
"adjusted" to match the world: the world must match the plan exactly.

Reads go through the platform-neutral ``PipelineAdapter`` (backed by the GET-only read client).
"""

from collections.abc import Callable
from datetime import datetime

from pydantic import BaseModel, Field

from actions.policy.engine import Check
from adapters.base.interfaces import AdapterError, PipelineAdapter
from core.config import ConfigurationError, ExecutionMode, Settings, validate_startup
from core.evidence.conventions import CONCURRENCY
from core.evidence.freshness import FreshnessContext, apply_freshness
from core.evidence.normalizer import NormalizedSignal
from core.models.base import utcnow
from core.models.enums import (
    ApprovalDecision,
    ConcurrencyStatus,
    EvidenceCategory,
    PrincipalType,
    RerunSafety,
    Role,
)
from core.models.evidence import EvidenceItem
from core.models.pipeline import PipelineRegistration
from core.models.reads import ReadRequest, ReadStatus
from core.models.remediation import ApprovalRecord, RemediationPlan, compute_plan_hash
from core.remediation.hashing import verify_plan_hash
from core.remediation.selector import RunSnapshot, select_action
from core.safety.facts import extract_safety_facts
from core.safety.rerun_safety import SEVERITY, RerunSafetyInput, evaluate_rerun_safety, most_conservative
from security.auth import AuthProvider, AuthProviderUnavailableError

# Machine-checkable plan conditions this module knows how to evaluate.
KNOWN_MACHINE_CHECKS = frozenset({"no_concurrent_run"})


class RevalidationResult(BaseModel):
    passed: bool
    checks: list[Check] = Field(default_factory=list)
    fresh_rerun_safety: RerunSafety | None = None
    concurrency: ConcurrencyStatus = ConcurrencyStatus.UNKNOWN
    snapshot: RunSnapshot | None = None

    @property
    def block_reason(self) -> str | None:
        failed = [f"{c.name}: {c.detail}" if c.detail else c.name for c in self.checks if not c.passed]
        return "; ".join(failed) if failed else None


class LiveStateRevalidator:
    def __init__(self, adapter: PipelineAdapter, auth: AuthProvider, settings: Settings,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._adapter = adapter
        self._auth = auth
        self._settings = settings
        self._clock = clock

    def revalidate(
        self,
        plan: RemediationPlan,
        approvals: list[ApprovalRecord],
        registration: PipelineRegistration,
        *,
        halted: bool,
    ) -> RevalidationResult:
        result = RevalidationResult(passed=False)
        try:
            self._run(plan, approvals, registration, halted, result)
        except Exception as exc:  # Rule 7: any error in the healing path blocks
            result.checks.append(Check(name="revalidation_error", passed=False, detail=f"{type(exc).__name__}: {exc}"))
        result.passed = bool(result.checks) and all(c.passed for c in result.checks)
        return result

    # ------------------------------------------------------------------ the checks

    def _run(self, plan: RemediationPlan, approvals: list[ApprovalRecord], registration: PipelineRegistration,
             halted: bool, result: RevalidationResult) -> None:
        now = self._clock()
        checks = result.checks

        def check(name: str, passed: bool, detail: str = "") -> bool:
            checks.append(Check(name=name, passed=bool(passed), detail="" if passed else detail))
            return bool(passed)

        # 1. kill switches and mode
        s = self._settings
        check("kill_switches", s.healing_enabled and registration.healing_enabled and not halted,
              "healing disabled globally, for this pipeline, or halted")
        check("execution_mode", plan.execution_mode is s.healing_execution_mode, "plan mode differs from configured mode")
        if s.healing_execution_mode is ExecutionMode.LIVE:
            try:
                validate_startup(s)
                check("live_mode_configuration", True)
            except ConfigurationError as exc:
                check("live_mode_configuration", False, str(exc))

        # 2. hash and approvals (the hash is recomputed from the persisted plan, never trusted)
        current_hash = compute_plan_hash(plan)
        bound = [a for a in approvals if a.decision is ApprovalDecision.APPROVED]
        check("approvals_present", bool(bound), "no approval records supplied")
        check("plan_hash_matches_approvals", bool(bound) and all(verify_plan_hash(plan, a.plan_hash) for a in bound),
              f"recomputed plan hash {current_hash[:12]}.. differs from an approval record")
        check("approvals_current", all(a.plan_version == plan.plan_version and not a.consumed and not a.is_expired(now)
                                       for a in bound), "an approval is for another version, consumed or expired")
        condition_ids = {c.condition_id for c in plan.conditions}
        check("conditions_acknowledged", all(condition_ids <= set(a.conditions_acknowledged) for a in bound),
              "a condition was not acknowledged by every approver")
        for approval in bound:
            try:
                principal = self._auth.lookup(approval.decided_by)
            except AuthProviderUnavailableError as exc:
                check("approver_lookup", False, f"auth provider unavailable: {exc}")
                continue
            still_ok = (principal is not None and principal.principal_type is PrincipalType.HUMAN
                        and principal.can_approve
                        and (principal.principal_id in registration.approver_ids or principal.has_role(Role.ADMIN)))
            check(f"approver_still_authorized:{approval.decided_by}", still_ok,
                  f"{approval.decided_by} no longer holds an approving role for this pipeline")

        # 3. live run state
        target = plan.target
        if target is None or plan.action_type is None:
            check("plan_target", False, "plan has no target")
            return
        try:
            snapshot = self._adapter.get_run_snapshot(target.dag_id, target.dag_run_id)
        except AdapterError as exc:
            check("run_state_readable", False, f"live state unreadable: {exc}")
            return
        if snapshot is None or snapshot.run_state is None:
            check("run_state_readable", False, "live state unreadable")
            return
        result.snapshot = snapshot
        check("run_state_readable", True)
        check("run_state_failed", snapshot.run_state == "failed", f"run is now {snapshot.run_state!r}")

        live = {ti.key: ti for ti in snapshot.task_instances}
        changed = []
        for ref in plan.task_instances_to_clear:
            ti = live.get(ref.key)
            if ti is None or ti.state != ref.observed_state or ti.try_number != ref.try_number:
                observed = None if ti is None else f"{ti.state}/try {ti.try_number}"
                changed.append(f"{ref.task_id}[{ref.map_index}] expected {ref.observed_state}/try {ref.try_number}, "
                               f"now {observed}")
        check("task_instances_unchanged", not changed, "; ".join(changed))

        fresh = select_action(snapshot)
        same = (fresh.selected and fresh.action_type is plan.action_type and fresh.recovery_scope is plan.recovery_scope
                and fresh.target == target
                and sorted(fresh.task_instances_to_clear, key=lambda t: t.key)
                == sorted(plan.task_instances_to_clear, key=lambda t: t.key))
        check("live_set_equals_plan", same,
              fresh.block_reason or "the live set of failed/upstream_failed instances differs from the approved list")

        # 4. concurrency (must be resolved now; unknown -> BLOCKED)
        primaries = sorted({t.task_id for t in plan.task_instances_to_clear if t.observed_state == "failed"})
        req = ReadRequest(pipeline_id=target.dag_id, execution_id=target.dag_run_id,
                          task_id=target.task_id or (primaries[0] if primaries else None),
                          investigation_cycle=plan.investigation_cycle)
        history = self._adapter.get_run_history(req)
        concurrency = ConcurrencyStatus.UNKNOWN
        concurrency_items: list[EvidenceItem] = []
        if history.status is ReadStatus.AVAILABLE:
            concurrency_items = [e for e in history.evidence if e.metadata.get(CONCURRENCY)]
            values = {e.metadata[CONCURRENCY] for e in concurrency_items}
            if "OVERLAP_CONFIRMED" in values:
                concurrency = ConcurrencyStatus.OVERLAP_CONFIRMED
            elif values == {"NONE_CONFIRMED"}:
                concurrency = ConcurrencyStatus.NONE_CONFIRMED
        result.concurrency = concurrency
        overlap_allowed = all(registration.policy_for(t).concurrency_behavior == "allow_overlap" for t in primaries)
        check("concurrency_resolved", concurrency is not ConcurrencyStatus.UNKNOWN,
              f"concurrency cannot be determined ({history.status.value}: {history.detail})")
        check("no_forbidden_concurrent_run",
              concurrency is ConcurrencyStatus.NONE_CONFIRMED
              or (concurrency is ConcurrencyStatus.OVERLAP_CONFIRMED and overlap_allowed),
              "another run of this pipeline is active and the task's concurrency policy forbids overlap")

        # 5. rerun safety recomputed from fresh state, for every primary failure in the plan
        outcomes: list[RerunSafety] = []
        new_conditions: set[str] = set()
        for task in primaries:
            ref = next(t for t in plan.task_instances_to_clear if t.task_id == task and t.observed_state == "failed")
            task_req = req.model_copy(update={"task_id": task, "attempt_number": ref.try_number})
            logs = self._adapter.get_run_output(task_req)
            items = logs.evidence if logs.status is ReadStatus.AVAILABLE else []
            labelled = apply_freshness(
                [e for e in items if e.category in (EvidenceCategory.LOG, EvidenceCategory.STACK_TRACE)
                 and e.metadata.get("task_id") in (None, task)] + concurrency_items,
                FreshnessContext(pipeline_id=target.dag_id, execution_id=target.dag_run_id,
                                 attempt_number=ref.try_number, investigation_cycle=plan.investigation_cycle, now=now))
            dq_signal = any(e.normalized_signal == NormalizedSignal.DQ_GATE_FAILURE.value for e in labelled)
            policy = registration.policy_for(task)
            facts = extract_safety_facts(labelled, policy, failed_attempt=ref.try_number, dq_signal=dq_signal)
            fresh_safety = evaluate_rerun_safety(RerunSafetyInput(
                policy=policy, target_write=facts.target_write, concurrency=concurrency,
                failure_stage=facts.failure_stage, dq_gate=facts.dq_gate, retry_supported=True,
                at_execution_time=True))
            outcomes.append(fresh_safety.outcome)
            new_conditions |= {c.condition_id for c in fresh_safety.conditions} - condition_ids
        fresh_outcome = most_conservative(outcomes) if outcomes else RerunSafety.UNKNOWN
        result.fresh_rerun_safety = fresh_outcome
        check("rerun_safety_still_permits",
              fresh_outcome in (RerunSafety.SAFE, RerunSafety.SAFE_WITH_CONDITIONS)
              and SEVERITY[fresh_outcome] <= SEVERITY[plan.rerun_safety],
              f"rerun safety {plan.rerun_safety.value} -> {fresh_outcome.value} on fresh state")
        check("no_new_conditions", not new_conditions, f"fresh state adds unacknowledged conditions {sorted(new_conditions)}")

        # 6. machine-checkable conditions and preconditions
        for condition in plan.conditions:
            if condition.machine_check is None:
                continue
            if condition.machine_check not in KNOWN_MACHINE_CHECKS:
                check(f"condition:{condition.condition_id}", False, f"unknown machine check {condition.machine_check}")
            else:
                check(f"condition:{condition.condition_id}", concurrency is ConcurrencyStatus.NONE_CONFIRMED,
                      "a concurrent run may be active")
        by_name = {c.name: c.passed for c in checks}
        for pre in plan.preconditions:
            check(f"precondition:{pre.check}", by_name.get(pre.check, False),
                  f"precondition {pre.check} not satisfied or not checkable")
