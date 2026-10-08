"""Harness for end-to-end healing scenarios against FAKE AIRFLOW (DEMO).

One fake Airflow state serves two in-process clients: the GET-only read client (adapter) and the
action client (executor). Principals authenticate through a real TokenAuthProvider (bearer tokens,
hashed store) - LIVE mode refuses the demo provider - or through the DemoAuthProvider in DRY_RUN.
Time is a controllable clock; sleeping advances it, so polling loops run instantly.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import httpx
from fastapi.testclient import TestClient

from actions.airflow_actions import AirflowActionConfig, build_airflow_executor
from actions.store import InMemoryHealingStore
from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from agent.llm_provider import LLMRequest, MockLLMProvider
from agent.mock_llm import scripted_triage
from agent.triage_agent import TriageResult
from api.orchestrator import HealingOrchestrator
from core.config import Settings
from core.models import ExecutionMode, PrincipalType, Role
from core.models.auth import Principal
from core.models.pipeline import PipelineRegistration
from core.models.remediation import RemediationPlan, compute_plan_hash
from core.remediation.audit import AuditLog
from demo.fake_airflow.app import create_app
from demo.fake_airflow.state import FakeAirflowState, load_scenario
from demo.scenarios.registrations import ORDERS_ETL, SALES_ETL
from demo.scenarios.run_triage import DEMO_NOW, FAILURE_PAYLOADS
from security.auth import DemoAuthProvider, InMemoryPrincipalStore, TokenAuthProvider, create_principal

HERO_RUN = "scheduled__2026-10-08T00:00:00+00:00"
APPROVERS = ["alice", "bob", "demo-engineer", "demo-approver-2"]
FAKE_WRITE_ENV = {"AIRFLOW_WRITE_USERNAME": "fake-writer (DEMO)", "AIRFLOW_WRITE_PASSWORD": "fake-only (DEMO)"}

HERO_HEALING_AUDIT = [
    "FAILURE_RECEIVED", "INCIDENT_CREATED", "EVIDENCE_COLLECTED", "INJECTION_SCAN_COMPLETED",
    "INVESTIGATION_COMPLETED", "ROOT_CAUSE_DETERMINED", "RERUN_SAFETY_COMPUTED",
    "REMEDIATION_CONFIDENCE_COMPUTED", "REMEDIATION_PROPOSED", "APPROVAL_REQUESTED", "APPROVAL_GRANTED",
    "POLICY_VALIDATED", "LIVE_STATE_REVALIDATED", "EXECUTION_QUEUED", "EXECUTION_DISPATCHED",
    "VERIFICATION_STARTED", "VERIFICATION_PASSED", "INCIDENT_RESOLVED",
]


class Clock:
    def __init__(self, start: datetime = DEMO_NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)

    sleep = advance


class Req:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class FaultTransport(httpx.BaseTransport):
    """Wraps the in-process transport to simulate a dropped response after Airflow applied a clear."""

    def __init__(self, inner: httpx.BaseTransport, state: FakeAirflowState, *, after_clear: str) -> None:
        self._inner = inner
        self._state = state
        self._after_clear = after_clear  # "timeout" | "timeout_then_down" | "connect_refused"

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        mutating = request.method == "POST" and b'"dry_run":false' in request.content.replace(b" ", b"")
        if mutating and self._after_clear == "connect_refused":
            raise httpx.ConnectError("connection refused (simulated)", request=request)
        response = self._inner.handle_request(request)
        if mutating:
            if self._after_clear == "timeout_then_down":
                self._state.down = True
            raise httpx.ReadTimeout("response lost after Airflow received the request (simulated)", request=request)
        return response


def is_subsequence(needle: list[str], hay: list[str]) -> bool:
    it = iter(hay)
    return all(any(x == y for y in it) for x in needle)


@dataclass
class Harness:
    orch: HealingOrchestrator
    state: FakeAirflowState
    audit: AuditLog
    store: InMemoryHealingStore
    clock: Clock
    settings: Settings
    registration: PipelineRegistration
    auth: Any
    adapter: AirflowAdapter
    principals: dict[str, Principal] = field(default_factory=dict)
    triage: TriageResult | None = None

    # ------------------------------------------------------------------ conveniences

    def who(self, name: str) -> Principal:
        return self.principals[name]

    @property
    def plan(self) -> RemediationPlan:
        assert self.triage is not None and self.triage.plan is not None, "triage produced no plan"
        return self.store.get_plan(self.triage.plan.remediation_id)

    @property
    def incident_id(self) -> str:
        assert self.triage is not None
        return self.triage.report.incident_id

    def body(self, plan: RemediationPlan | None = None, **overrides: Any) -> dict[str, Any]:
        p = plan or self.plan
        return {"plan_version": p.plan_version, "displayed_plan_hash": compute_plan_hash(p),
                "conditions_acknowledged": [c.condition_id for c in p.conditions], **overrides}

    def approve(self, who: str = "alice", *, execute: bool = True, plan: RemediationPlan | None = None, **body: Any):
        p = plan or self.plan
        return self.orch.approve(p.remediation_id, self.who(who), self.body(p, **body), execute=execute)

    def state_of(self) -> str:
        return self.store.get_incident(self.incident_id).state.value

    def audit_types(self) -> list[str]:
        return [e.event_type.value for e in self.audit.events(self.incident_id)]

    def clears(self):
        return self.state.clears()


def _token_auth(names: dict[str, tuple[PrincipalType, frozenset[Role]]]) -> tuple[TokenAuthProvider, dict[str, Principal], InMemoryPrincipalStore]:
    store = InMemoryPrincipalStore()
    auth = TokenAuthProvider(store)
    principals = {}
    for name, (ptype, roles) in names.items():
        _, token = create_principal(store, name, ptype, roles)
        principal = auth.authenticate(Req({"Authorization": f"Bearer {token}"}))
        assert principal is not None
        principals[name] = principal
    return auth, principals, store


PRINCIPALS = {
    "alice": (PrincipalType.HUMAN, frozenset({Role.ENGINEER, Role.APPROVER})),
    "bob": (PrincipalType.HUMAN, frozenset({Role.APPROVER})),
    "carol": (PrincipalType.HUMAN, frozenset({Role.APPROVER})),       # approver, not listed for the pipeline
    "erin": (PrincipalType.HUMAN, frozenset({Role.ENGINEER})),        # engineer without approval rights
    "victor": (PrincipalType.HUMAN, frozenset({Role.VIEWER})),
    "root": (PrincipalType.HUMAN, frozenset({Role.ADMIN})),
    "triage-bot": (PrincipalType.SERVICE, frozenset({Role.APPROVER, Role.ENGINEER})),
}


def build(
    scenario: str = "hero_transient_network",
    *,
    mode: ExecutionMode = ExecutionMode.LIVE,
    healing_enabled: bool = True,
    pipeline_healing: bool = True,
    registration: PipelineRegistration | None = None,
    script: Callable[[LLMRequest], str] | list[str] = scripted_triage,
    mutate: Callable[[FakeAirflowState], None] | None = None,
    env: dict[str, str] | None = None,
    fault: str | None = None,
    demo_auth: bool = False,
    clear_behavior: str = "success",
    payload: dict[str, Any] | None = None,
    run_triage: bool = True,
    sql: bool = False,
) -> Harness:
    clock = Clock()
    state = load_scenario(scenario)
    state.clear_behavior = clear_behavior
    state.sim_clock = clock
    if mutate:
        mutate(state)

    base_env = {"HEALING_ENABLED": str(healing_enabled).lower(), "HEALING_EXECUTION_MODE": mode.value}
    if mode is ExecutionMode.LIVE:
        base_env.update({"DEMO_MODE": "false", "AUTH_PROVIDER": "token", **FAKE_WRITE_ENV})
    settings = Settings.from_env({**base_env, **(env or {})})

    if demo_auth:
        auth: Any = DemoAuthProvider(settings)
        principals = {p: auth.lookup(p) for p in ("demo-engineer", "demo-approver-2", "demo-viewer", "demo-admin",
                                                  "demo-agent")}
    else:
        auth, principals, _ = _token_auth(PRINCIPALS)

    if registration is None:
        registration = ORDERS_ETL if scenario == "multi_failure" else SALES_ETL
    registration = registration.model_copy(update={"healing_enabled": pipeline_healing, "approver_ids": APPROVERS})

    app = create_app(state)
    reader = TestClient(app, base_url="http://fake-airflow")
    adapter = AirflowAdapter(AirflowReadClient(AirflowReadConfig(base_url="http://fake-airflow"), http=reader),
                             demo=True, clock=clock)
    writer = TestClient(app, base_url="http://fake-airflow")
    if fault:
        writer._transport = FaultTransport(writer._transport, state, after_clear=fault)
    backend = build_airflow_executor(AirflowActionConfig(base_url="http://fake-airflow"), http=writer)

    if sql:  # the database-backed stores used by the API (fresh in-memory SQLite per harness)
        from database.repository import Database, SqlAuditStore, SqlHealingStore

        db = Database("sqlite://")
        audit = AuditLog(SqlAuditStore(db), clock=clock)
        store: Any = SqlHealingStore(db)
    else:
        audit = AuditLog(clock=clock)
        store = InMemoryHealingStore()
    orch = HealingOrchestrator(adapter=adapter, provider=MockLLMProvider(script), settings=settings, audit=audit,
                               store=store, auth=auth, backend=backend, clock=clock, sleep=clock.sleep)
    harness = Harness(orch=orch, state=state, audit=audit, store=store, clock=clock, settings=settings,
                      registration=registration, auth=auth, adapter=adapter, principals=principals)
    if run_triage:
        harness.triage = trigger(harness, scenario, payload)
    return harness


def trigger(h: Harness, scenario: str, payload: dict[str, Any] | None = None) -> TriageResult:
    event = h.adapter.normalize_failure({"dag_id": "sales_etl", "dag_run_id": HERO_RUN, "state": "failed",
                                         "environment": "production", **FAILURE_PAYLOADS.get(scenario, FAILURE_PAYLOADS[
                                             "hero_transient_network"]), **(payload or {})})
    return h.orch.handle_failure(event, h.registration)
