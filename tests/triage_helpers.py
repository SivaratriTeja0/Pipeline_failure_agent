"""Harness to run TriageAgent against FAKE AIRFLOW (DEMO) with a scriptable mock LLM."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent.llm_provider import LLMRequest, MockLLMProvider
from agent.mock_llm import scripted_triage
from agent.triage_agent import TriageAgent, TriageContext, TriageResult
from core.config import Settings
from core.models import ActionCapability
from core.models.pipeline import PipelineRegistration
from core.remediation.audit import AuditLog
from demo.fake_airflow.state import FakeAirflowState, load_scenario
from demo.scenarios.registrations import SALES_ETL
from demo.scenarios.run_triage import DEMO_NOW, FAILURE_PAYLOADS
from tests.airflow_helpers import HERO_RUN, fake_client

from adapters.airflow.adapter import AirflowAdapter

ALL_ACTIONS = frozenset(ActionCapability)


@dataclass
class Run:
    result: TriageResult
    audit: AuditLog
    state: FakeAirflowState
    provider: MockLLMProvider
    adapter: AirflowAdapter

    @property
    def report(self):
        return self.result.report


def run_airflow(
    scenario: str = "hero_transient_network",
    *,
    script: Callable[[LLMRequest], str] | list[str] = scripted_triage,
    registration: PipelineRegistration = SALES_ETL,
    actions: frozenset[ActionCapability] = ALL_ACTIONS,
    mutate: Callable[[FakeAirflowState], None] | None = None,
    payload: dict[str, Any] | None = None,
    ctx: TriageContext | None = None,
) -> Run:
    state = load_scenario(scenario)
    if mutate:
        mutate(state)
    adapter = AirflowAdapter(fake_client(state), demo=True, clock=lambda: DEMO_NOW)
    event = adapter.normalize_failure({"dag_id": "sales_etl", "dag_run_id": HERO_RUN, "state": "failed",
                                       "environment": "production", **FAILURE_PAYLOADS[scenario], **(payload or {})})
    provider = MockLLMProvider(script)
    audit = AuditLog(clock=lambda: DEMO_NOW)
    agent = TriageAgent(adapter, provider, Settings.from_env({}), audit, action_capabilities=actions,
                        clock=lambda: DEMO_NOW)
    return Run(agent.triage(event, registration, ctx), audit, state, provider, adapter)


DEFAULT = "__DEFAULT__"  # a turn that defers to the standard scripted mock


def investigator(turns: list[dict[str, Any] | str], planner: dict[str, Any] | None = None) -> Callable[[LLMRequest], str]:
    """Replay investigator turns in order (the last repeats); planner falls back to the default mock."""
    count = {"n": 0}

    def script(request: LLMRequest) -> str:
        if request.role == "planner":
            return json.dumps(planner) if planner is not None else scripted_triage(request)
        turn = turns[min(count["n"], len(turns) - 1)]
        count["n"] += 1
        if turn == DEFAULT:
            return scripted_triage(request)
        return json.dumps(turn) if isinstance(turn, dict) else turn

    return script


def call(tool: str, **args: Any) -> dict[str, Any]:
    return {"action": "call_tool", "reasoning": "", "hypotheses": [], "tool_call": {"tool": tool, "args": args},
            "conclusion": None}


def default_conclusion_turn(request: LLMRequest) -> dict[str, Any]:
    """The scripted mock's conclusion for the current context, with tool calls exhausted."""
    ctx = dict(request.context, calls_remaining=0)
    return json.loads(scripted_triage(LLMRequest(role="investigator", system="", messages=[], context=ctx)))
