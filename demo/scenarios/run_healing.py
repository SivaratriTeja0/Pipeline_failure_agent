"""Hero healing demo against FAKE AIRFLOW (DEMO), with the scripted MOCK LLM.

    python -m demo.scenarios.run_healing            # DRY_RUN (default): approves, makes zero mutating calls
    python -m demo.scenarios.run_healing --live     # LIVE against the in-process FAKE AIRFLOW only

LIVE mode refuses the demo auth provider, so the --live run mints throwaway in-memory bearer-token
principals (labeled DEMO) and placeholder write credentials that only the fake server receives.
Nothing here talks to a real Airflow.
"""

import sys
from datetime import timedelta

from fastapi.testclient import TestClient

from actions.airflow_actions import AirflowActionConfig, build_airflow_executor
from actions.store import InMemoryHealingStore
from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from agent.llm_provider import MockLLMProvider
from agent.mock_llm import scripted_triage
from api.orchestrator import HealingOrchestrator
from core.config import Settings
from core.models.enums import PrincipalType, Role
from core.models.remediation import compute_plan_hash
from core.remediation.audit import AuditLog
from demo.fake_airflow.app import create_app
from demo.fake_airflow.state import load_scenario
from demo.scenarios.registrations import SALES_ETL
from demo.scenarios.run_triage import DEMO_NOW, FAILURE_PAYLOADS
from security.auth import DemoAuthProvider, InMemoryPrincipalStore, TokenAuthProvider, create_principal


class _Clock:
    def __init__(self) -> None:
        self.now = DEMO_NOW

    def __call__(self):
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class _Headers:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


def run(live: bool = False) -> str:
    clock = _Clock()
    state = load_scenario("hero_transient_network")
    state.sim_clock = clock
    env = {"HEALING_ENABLED": "true", "HEALING_EXECUTION_MODE": "LIVE" if live else "DRY_RUN"}
    if live:
        env.update({"DEMO_MODE": "false", "AUTH_PROVIDER": "token",
                    "AIRFLOW_WRITE_USERNAME": "fake-writer (DEMO)", "AIRFLOW_WRITE_PASSWORD": "fake-only (DEMO)"})
    settings = Settings.from_env(env)
    if live:
        principals = InMemoryPrincipalStore()
        auth = TokenAuthProvider(principals)
        _, token = create_principal(principals, "demo-engineer", PrincipalType.HUMAN,
                                    frozenset({Role.ENGINEER, Role.APPROVER}))
        approver = auth.authenticate(_Headers({"Authorization": f"Bearer {token}"}))
    else:
        auth = DemoAuthProvider(settings)
        approver = auth.authenticate(_Headers({"X-Demo-Principal": "demo-engineer"}))

    app = create_app(state)
    adapter = AirflowAdapter(AirflowReadClient(AirflowReadConfig(base_url="http://fake-airflow"),
                                               http=TestClient(app, base_url="http://fake-airflow")),
                             demo=True, clock=clock)
    backend = build_airflow_executor(AirflowActionConfig(base_url="http://fake-airflow"),
                                     http=TestClient(app, base_url="http://fake-airflow"))
    audit = AuditLog(clock=clock)
    orch = HealingOrchestrator(adapter=adapter, provider=MockLLMProvider(scripted_triage), settings=settings,
                               audit=audit, store=InMemoryHealingStore(), auth=auth, backend=backend, clock=clock,
                               sleep=clock.sleep)
    registration = SALES_ETL.model_copy(update={"healing_enabled": True})
    event = adapter.normalize_failure({"dag_id": "sales_etl", "dag_run_id": "scheduled__2026-10-08T00:00:00+00:00",
                                       "state": "failed", "environment": "production",
                                       **FAILURE_PAYLOADS["hero_transient_network"]})
    triage = orch.handle_failure(event, registration)
    plan = triage.plan
    lines = ["=" * 78, f"HERO HEALING DEMO  [FAKE AIRFLOW (DEMO) - llm_mode=MOCK - {settings.healing_execution_mode.value}]",
             "=" * 78]
    if plan is None:
        return "\n".join(lines + [f"no plan: {triage.report.remediation_class.value}"])
    lines += [f"plan {plan.remediation_id} v{plan.plan_version} hash={compute_plan_hash(plan)[:16]}..  "
              f"{plan.action_type.value}/{plan.recovery_scope.value}  risk={plan.risk_level.value}",
              "  tasks: " + ", ".join(f"{t.task_id}[try {t.try_number}, {t.observed_state}]"
                                      for t in plan.task_instances_to_clear),
              f"approver: {approver.principal_id} ({approver.principal_type.value}, via {approver.auth_method})"]
    outcome = orch.approve(plan.remediation_id, approver, {
        "plan_version": plan.plan_version, "displayed_plan_hash": compute_plan_hash(plan),
        "conditions_acknowledged": [c.condition_id for c in plan.conditions]})
    final = orch.store.get_plan(plan.remediation_id)
    lines += [f"outcome: {outcome.execution.outcome if outcome.execution else '-'}  incident={outcome.incident_state.value}",
              f"execution_status={final.execution_status.value} executed={final.executed} "
              f"verification={final.verification_status.value} ({final.verification_depth.value})"]
    if final.execution_result and final.execution_result.get("mode") == "DRY_RUN":
        lines.append(f"DRY_RUN: would have {final.execution_result['would_have']}")
    lines += ["-" * 78, "FAKE AIRFLOW REQUEST LOG (non-GET)"]
    lines += [f"  {r.method} {r.path} dry_run={r.body.get('dry_run') if r.body else '-'} "
              f"task_ids={r.body.get('task_ids') if r.body else '-'}" for r in state.mutating_requests()] or ["  (none)"]
    lines += ["-" * 78, "AUDIT CHAIN"]
    lines += [f"  #{e.seq:<3} {e.actor:<12} {e.event_type.value}"
              + (f"  {e.payload['from']} -> {e.payload['to']}" if e.event_type.value == "INCIDENT_STATE_CHANGED" else "")
              for e in audit.events(plan.incident_id)]
    lines.append(f"  chain valid: {audit.verify().valid}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(run(live="--live" in sys.argv))
