"""Harness for API tests: the real FastAPI app over an in-memory SQLite database, wired to
FAKE AIRFLOW (DEMO) in-process, with bearer-token principals for every role x type."""

from dataclasses import dataclass, field
from typing import Any

from fastapi.testclient import TestClient

from api.container import AppContainer
from api.routes import create_app
from core.config import Settings
from core.models.enums import PrincipalType, Role
from core.models.remediation import compute_plan_hash
from demo.fake_airflow.app import create_app as create_fake_airflow
from demo.fake_airflow.state import FakeAirflowState, load_scenario
from demo.scenarios.run_triage import FAILURE_PAYLOADS
from notifications.notifier import ConsoleNotifier, FanoutNotifier
from security.auth import create_principal
from tests.healing_helpers import FAKE_WRITE_ENV, HERO_RUN, Clock

ROLES = (Role.VIEWER, Role.ENGINEER, Role.APPROVER, Role.ADMIN)
TYPES = (PrincipalType.HUMAN, PrincipalType.SERVICE)
MATRIX = [(t, r) for t in TYPES for r in ROLES]


def pid(ptype: PrincipalType, role: Role) -> str:
    return f"{ptype.value.lower()}-{role.value.lower()}"


# Listed approvers for the demo pipeline: every APPROVER principal (HUMAN and SERVICE) plus alice.
LISTED = ["alice", pid(PrincipalType.HUMAN, Role.APPROVER), pid(PrincipalType.SERVICE, Role.APPROVER)]


@dataclass
class Api:
    client: TestClient
    container: AppContainer
    state: FakeAirflowState
    clock: Clock
    tokens: dict[str, str] = field(default_factory=dict)
    console: ConsoleNotifier | None = None

    def h(self, who: str | None) -> dict[str, str]:
        return {} if who is None else {"Authorization": f"Bearer {self.tokens[who]}"}

    def get(self, path: str, who: str | None = "alice", **kw: Any):
        return self.client.get(path, headers=self.h(who), **kw)

    def post(self, path: str, who: str | None = "alice", json: Any = None, **kw: Any):
        return self.client.post(path, headers=self.h(who), json=json, **kw)

    # ------------------------------------------------------------------ scenario helpers

    def register(self, pipeline_id: str = "sales_etl", healing: bool = True, **overrides: Any):
        from demo.scenarios.registrations import ORDERS_ETL, SALES_ETL

        base = ORDERS_ETL if pipeline_id == "orders_etl" else SALES_ETL
        body = base.model_copy(update={"healing_enabled": healing, "approver_ids": LISTED, **overrides})
        return self.post("/pipelines/register", who="human-admin", json=body.model_dump(mode="json"))

    def triage(self, scenario: str = "hero_transient_network", who: str = "alice", **payload: Any):
        failure = {"dag_id": "sales_etl", "dag_run_id": HERO_RUN, "state": "failed",
                   **FAILURE_PAYLOADS[scenario], **payload}
        return self.post("/triage", who=who, json={"pipeline_id": failure["dag_id"], "failure": failure})

    def plan(self, incident_id: str) -> dict[str, Any]:
        plans = self.get(f"/incidents/{incident_id}/remediation").json()["plans"]
        return plans[0]

    def approval_body(self, view: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        plan = view["plan"]
        return {"plan_version": plan["plan_version"], "displayed_plan_hash": view["server_plan_hash"],
                "conditions_acknowledged": [c["condition_id"] for c in plan["conditions"]], **overrides}

    def hero_plan(self) -> tuple[str, dict[str, Any]]:
        assert self.register().status_code == 201
        response = self.triage()
        assert response.status_code == 201, response.text
        incident_id = response.json()["incident_id"]
        return incident_id, self.plan(incident_id)


def build_api(*, live: bool = False, env: dict[str, str] | None = None, scenario: str = "hero_transient_network",
              clear_behavior: str = "success", demo_auth: bool = False) -> Api:
    clock = Clock()
    state = load_scenario(scenario)
    state.clear_behavior = clear_behavior
    state.sim_clock = clock
    base = {"DATABASE_URL": "sqlite://", "HEALING_ENABLED": "true",
            "AUTH_PROVIDER": "demo" if demo_auth else "token",
            "HEALING_EXECUTION_MODE": "LIVE" if live else "DRY_RUN", "DEMO_MODE": "false" if live else "true",
            "UI_BASE_URL": "https://triage-ui.example.internal"}
    if live:
        base.update(FAKE_WRITE_ENV)
    full_env = {**base, **(env or {})}
    settings = Settings.from_env(full_env)
    fake = create_fake_airflow(state)
    console = ConsoleNotifier()
    container = AppContainer(
        settings, full_env, clock=clock, sleep=clock.sleep,
        airflow_http=TestClient(fake, base_url="http://fake-airflow"),
        airflow_write_http=TestClient(fake, base_url="http://fake-airflow"),
        fake_airflow_state=state, notifier=FanoutNotifier([console]))
    api = Api(client=TestClient(create_app(container, start_background=False)), container=container, state=state,
              clock=clock, console=console)
    if not demo_auth:
        principals = {"alice": (PrincipalType.HUMAN, frozenset({Role.ENGINEER, Role.APPROVER})),
                      "carol": (PrincipalType.HUMAN, frozenset({Role.APPROVER}))}
        principals.update({pid(t, r): (t, frozenset({r})) for t, r in MATRIX})
        for name, (ptype, roles) in principals.items():
            _, api.tokens[name] = create_principal(container.principals, name, ptype, roles)
    api.client.__enter__()  # run the lifespan (startup reconciliation, dedup index rebuild)
    return api


def plan_hash(view: dict[str, Any]) -> str:
    from core.models.remediation import RemediationPlan

    return compute_plan_hash(RemediationPlan.model_validate(view["plan"]))
