"""Scenario world for evaluation and the DEMO MODE scenario runner.

Wires one FAKE AIRFLOW (DEMO) state to the GET-only read client and to the action client, the real
healing boundary (approval -> policy -> re-validation -> executor -> verification) on in-memory
stores, bearer-token principals, and a controllable clock (sleeping advances it, so polling loops
finish instantly). Everything here is demo data and is labeled as such.
"""

import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import httpx
from fastapi.testclient import TestClient

from actions.airflow_actions import AirflowActionConfig, build_airflow_executor
from actions.store import InMemoryHealingStore
from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from adapters.base.interfaces import PipelineAdapter
from agent.llm_provider import LLMProvider, LLMRequest, LLMResponse
from api.orchestrator import HealingOrchestrator
from core.config import Settings
from core.models.auth import Principal
from core.models.enums import ExecutionMode, PrincipalType, Role
from core.models.pipeline import PipelineRegistration
from core.models.remediation import RemediationPlan, compute_plan_hash
from core.remediation.audit import AuditLog
from demo.fake_airflow.app import create_app
from demo.fake_airflow.state import FakeAirflowState, load_scenario
from demo.scenarios.registrations import ORDERS_ETL, SALES_ETL
from demo.scenarios.run_triage import DEMO_NOW, FAILURE_PAYLOADS
from security.auth import InMemoryPrincipalStore, TokenAuthProvider, create_principal

HERO_RUN = "scheduled__2026-10-08T00:00:00+00:00"
FAKE_WRITE_ENV = {"AIRFLOW_WRITE_USERNAME": "fake-writer (DEMO)", "AIRFLOW_WRITE_PASSWORD": "fake-only (DEMO)"}
APPROVERS = ["alice", "bob"]
PRINCIPALS = {
    "alice": (PrincipalType.HUMAN, frozenset({Role.ENGINEER, Role.APPROVER})),
    "bob": (PrincipalType.HUMAN, frozenset({Role.APPROVER})),
    "erin": (PrincipalType.HUMAN, frozenset({Role.ENGINEER})),
    "root": (PrincipalType.HUMAN, frozenset({Role.ADMIN})),
}


class Clock:
    def __init__(self, start: datetime = DEMO_NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


class _Headers:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class RecordingProvider(LLMProvider):
    """Wraps a provider and records request/response sizes for the approximate-cost metric."""

    def __init__(self, inner: LLMProvider) -> None:
        self.inner = inner
        self.mode = inner.mode
        self.model = getattr(inner, "model", "mock")
        self.calls: list[tuple[int, int]] = []  # (input chars, output chars)

    def generate(self, request: LLMRequest) -> LLMResponse:
        response = self.inner.generate(request)
        chars_in = len(request.system) + sum(len(str(m.get("content", ""))) for m in request.messages)
        self.calls.append((chars_in, len(response.text)))
        return response


class DroppedResponseTransport(httpx.BaseTransport):
    """Simulates a response lost after Airflow applied the clear ('timeout after receiving')."""

    def __init__(self, inner: httpx.BaseTransport, state: FakeAirflowState, *, then_down: bool) -> None:
        self._inner, self._state, self._then_down = inner, state, then_down

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        mutating = request.method == "POST" and b'"dry_run":false' in request.content.replace(b" ", b"")
        response = self._inner.handle_request(request)
        if mutating:
            if self._then_down:
                self._state.down = True
            raise httpx.ReadTimeout("response lost after Airflow received the request (simulated)", request=request)
        return response


class World:
    def __init__(
        self,
        scenario: str = "hero_transient_network",
        *,
        provider: LLMProvider,
        registration: PipelineRegistration | None = None,
        mutate: Callable[[FakeAirflowState], None] | None = None,
        clear_behavior: str = "success",
        dropped_response: str | None = None,
        env: dict[str, str] | None = None,
        adapter_factory: Callable[[Clock], PipelineAdapter] | None = None,
    ) -> None:
        self.clock = Clock()
        adapter = adapter_factory(self.clock) if adapter_factory else None
        self.scenario = scenario
        base = {"HEALING_ENABLED": "true", "HEALING_EXECUTION_MODE": ExecutionMode.LIVE.value, "DEMO_MODE": "false",
                "AUTH_PROVIDER": "token", **FAKE_WRITE_ENV, **(env or {})}
        self.settings = Settings.from_env(base)
        principal_store = InMemoryPrincipalStore()
        self.auth = TokenAuthProvider(principal_store)
        self.principals: dict[str, Principal] = {}
        for name, (ptype, roles) in PRINCIPALS.items():
            _, token = create_principal(principal_store, name, ptype, roles)
            principal = self.auth.authenticate(_Headers({"Authorization": f"Bearer {token}"}))
            assert principal is not None
            self.principals[name] = principal

        self.provider = RecordingProvider(provider)
        self.audit = AuditLog(clock=self.clock)
        self.store = InMemoryHealingStore()
        backend = None
        self.state: FakeAirflowState | None = None
        if adapter is None:
            self.state = load_scenario(scenario)
            self.state.clear_behavior = clear_behavior
            self.state.sim_clock = self.clock
            if mutate:
                mutate(self.state)
            app = create_app(self.state)
            adapter = AirflowAdapter(AirflowReadClient(AirflowReadConfig(base_url="http://fake-airflow"),
                                                       http=TestClient(app, base_url="http://fake-airflow")),
                                     demo=True, clock=self.clock)
            writer = TestClient(app, base_url="http://fake-airflow")
            if dropped_response:
                writer._transport = DroppedResponseTransport(writer._transport, self.state,
                                                             then_down=dropped_response == "then_down")
            backend = build_airflow_executor(AirflowActionConfig(base_url="http://fake-airflow"), http=writer)
        self.adapter = adapter
        default = ORDERS_ETL if scenario == "multi_failure" else SALES_ETL
        self.registration = (registration or default).model_copy(
            update={"healing_enabled": True, "approver_ids": APPROVERS})
        self.orch = HealingOrchestrator(adapter=adapter, provider=self.provider, settings=self.settings,
                                        audit=self.audit, store=self.store, auth=self.auth, backend=backend,
                                        clock=self.clock, sleep=self.clock.sleep)
        self.triage = None
        self.first_triage = None
        self.diagnosis_seconds: float | None = None

    # ------------------------------------------------------------------ actions

    def trigger(self, payload: dict[str, Any] | None = None, *, fixture_payload: str | None = None):
        key = fixture_payload or (self.scenario if self.scenario in FAILURE_PAYLOADS else "hero_transient_network")
        event = self.adapter.normalize_failure({"dag_id": "sales_etl", "dag_run_id": HERO_RUN, "state": "failed",
                                                "environment": self.registration.environment,
                                                **FAILURE_PAYLOADS[key], **(payload or {})})
        return self.trigger_event(event)

    def trigger_event(self, event):
        started = time.perf_counter()
        self.triage = self.orch.handle_failure(event, self.registration)
        if self.first_triage is None:
            self.first_triage = self.triage
            self.diagnosis_seconds = time.perf_counter() - started
        return self.triage

    @property
    def incident_id(self) -> str:
        return self.triage.report.incident_id

    def current_plan(self) -> RemediationPlan | None:
        record = self.store.get_incident(self.incident_id)
        return self.store.get_plan(record.plan_ids[-1]) if record.plan_ids else None

    def approve(self, who: str = "alice", *, execute: bool = True, plan: RemediationPlan | None = None, **body: Any):
        p = plan or self.current_plan()
        payload = {"plan_version": p.plan_version, "displayed_plan_hash": compute_plan_hash(p),
                   "conditions_acknowledged": [c.condition_id for c in p.conditions], **body}
        return self.orch.approve(p.remediation_id, self.principals[who], payload, execute=execute)

    def state_value(self) -> str:
        return self.store.get_incident(self.incident_id).state.value

    def clears(self) -> list[list[str]]:
        return [sorted(r.body["task_ids"]) for r in self.state.clears()] if self.state else []

    def mutating_paths(self) -> list[str]:
        return [r.path for r in self.state.mutating_requests()] if self.state else []
