"""Hero demo in LIVE mode against the LOCAL live-test Airflow (demo/live_test/docker-compose.yml).

    python -m demo.live_test.run_live_hero <dag_run_id>

Required environment (see README 'First live test'):
    AIRFLOW_API_BASE_URL=http://localhost:8080     (only localhost / 127.0.0.1 is accepted)
    AIRFLOW_READ_USERNAME / AIRFLOW_READ_PASSWORD   (triage_reader, Viewer)
    AIRFLOW_WRITE_USERNAME / AIRFLOW_WRITE_PASSWORD (triage_writer, TriageClear)
    HEALING_ENABLED=true HEALING_EXECUTION_MODE=LIVE DEMO_MODE=false AUTH_PROVIDER=token

The operator is the human approver: the plan is printed and nothing is dispatched unless the operator
types the exact approval phrase containing the plan hash prefix. Uses the MOCK LLM unless
ANTHROPIC_API_KEY is set.
"""

import os
import sys
import time
from collections.abc import Callable, Mapping
from urllib.parse import urlparse

from actions.airflow_actions import AirflowActionConfig, build_airflow_executor
from actions.store import InMemoryHealingStore
from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from agent.llm_provider import build_provider
from agent.mock_llm import scripted_triage
from api.orchestrator import HealingOrchestrator
from core.config import ConfigurationError, Settings, validate_startup
from core.models.enums import ActionType, PrincipalType, Role, StateMechanism, TaskType, WriteMode
from core.models.pipeline import PipelineRegistration
from core.models.policy import TaskExecutionPolicy
from core.models.remediation import compute_plan_hash
from core.remediation.audit import AuditLog
from security.auth import InMemoryPrincipalStore, TokenAuthProvider, create_principal

DAG_ID = "triage_live_test"
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_POLICY = TaskExecutionPolicy(task_type=TaskType.OVERWRITE, write_mode=WriteMode.OVERWRITE, idempotent=True,
                              state_mechanism=StateMechanism.NONE, concurrency_behavior="forbid_overlap")


class Refused(RuntimeError):
    """The live run refuses to start (unsafe or incomplete configuration)."""


class _Headers:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


def check_environment(env: Mapping[str, str]) -> Settings:
    """Refuse anything but a fully configured LIVE run against a local Airflow."""
    host = urlparse(env.get("AIRFLOW_API_BASE_URL", "")).hostname
    if host not in LOCAL_HOSTS:
        raise Refused(f"AIRFLOW_API_BASE_URL host {host!r} is not local; the live kit only targets the throwaway "
                      "local Airflow")
    for key in ("AIRFLOW_READ_USERNAME", "AIRFLOW_READ_PASSWORD", "AIRFLOW_WRITE_USERNAME", "AIRFLOW_WRITE_PASSWORD"):
        if not env.get(key):
            raise Refused(f"{key} is required")
    if env.get("AIRFLOW_READ_USERNAME") == env.get("AIRFLOW_WRITE_USERNAME"):
        raise Refused("read and write credentials must be different users (least privilege)")
    settings = Settings.from_env(dict(env))
    try:
        validate_startup(settings)
    except ConfigurationError as exc:
        raise Refused(str(exc)) from exc
    if settings.healing_execution_mode.value != "LIVE":
        raise Refused("set HEALING_EXECUTION_MODE=LIVE (with HEALING_ENABLED=true, DEMO_MODE=false, AUTH_PROVIDER=token)")
    return settings


def run(dag_run_id: str, env: Mapping[str, str], ask: Callable[[str], str] = input) -> int:
    settings = check_environment(env)
    base = env["AIRFLOW_API_BASE_URL"]
    reader = AirflowReadClient(AirflowReadConfig(base_url=base, username=env["AIRFLOW_READ_USERNAME"],
                                                 password=env["AIRFLOW_READ_PASSWORD"]))
    adapter = AirflowAdapter(reader)
    backend = build_airflow_executor(AirflowActionConfig.from_env(dict(env)))
    principals = InMemoryPrincipalStore()
    auth = TokenAuthProvider(principals)
    operator = env.get("USERNAME") or env.get("USER") or "operator"
    operator_id = "".join(c for c in operator if c.isalnum() or c in "._-") or "operator"
    _, token = create_principal(principals, operator_id, PrincipalType.HUMAN, frozenset({Role.ENGINEER, Role.APPROVER}))
    me = auth.authenticate(_Headers({"Authorization": f"Bearer {token}"}))
    registration = PipelineRegistration(
        pipeline_id=DAG_ID, platform="airflow", environment="local-live-test", healing_enabled=True,
        allowed_actions=[ActionType.RETRY_FAILED_TASK], approver_ids=[operator_id],
        task_policies={t: _POLICY for t in ("extract", "load", "publish")})
    orch = HealingOrchestrator(adapter=adapter, provider=build_provider(settings.anthropic_api_key_present,
                                                                        scripted_triage),
                               settings=settings, audit=AuditLog(), store=InMemoryHealingStore(), auth=auth,
                               backend=backend, sleep=time.sleep)

    snapshot = adapter.get_run_snapshot(DAG_ID, dag_run_id)
    failed = next((ti for ti in snapshot.task_instances if ti.state == "failed"), None)
    if failed is None:
        print(f"run {dag_run_id} has no failed task instance yet; wait for 'load' to fail and retry")
        return 1
    event = adapter.normalize_failure({"dag_id": DAG_ID, "dag_run_id": dag_run_id, "task_id": failed.task_id,
                                       "try_number": failed.try_number, "state": "failed",
                                       "end_date": failed.end_date.isoformat() if failed.end_date else None,
                                       "exception": "see task log", "environment": "local-live-test"})
    result = orch.handle_failure(event, registration)
    report, plan = result.report, result.plan
    print(f"diagnosis {report.failure_category.value}; rerun safety {report.rerun_safety.value}; "
          f"class {report.remediation_class.value}; root cause: {report.root_cause.text}")
    if plan is None:
        print("no executable plan; nothing will be dispatched")
        return 1
    digest = compute_plan_hash(plan)
    print(f"PLAN {plan.action_type.value} {plan.recovery_scope.value} on {DAG_ID}/{dag_run_id}: "
          + ", ".join(f"{t.task_id}[try {t.try_number}, {t.observed_state}]" for t in plan.task_instances_to_clear))
    print(f"risk {plan.risk_level.value}; rollback: {plan.rollback_description}")
    phrase = f"APPROVE {digest[:12]}"
    if ask(f"Type '{phrase}' to approve this exact plan (anything else rejects): ").strip() != phrase:
        orch.reject(plan.remediation_id, me, "operator did not approve in the live-test runner")
        print("not approved; nothing dispatched")
        return 1
    outcome = orch.approve(plan.remediation_id, me, {"plan_version": plan.plan_version, "displayed_plan_hash": digest,
                                                     "conditions_acknowledged": [c.condition_id for c in plan.conditions]})
    final = orch.store.get_plan(plan.remediation_id)
    print(f"outcome {outcome.execution.outcome if outcome.execution else '-'}; incident {outcome.incident_state.value}; "
          f"verification {final.verification_status.value} ({final.verification_depth.value})")
    return 0 if outcome.incident_state.value == "RESOLVED" else 1


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    try:
        return run(sys.argv[1], os.environ)
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
