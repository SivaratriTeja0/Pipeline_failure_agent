"""Run a DEMO triage against FAKE AIRFLOW (DEMO) with the scripted MOCK LLM and print the report.

    python -m demo.scenarios.run_triage [scenario] [--json]

Scenarios: hero_transient_network (default), cascade_upstream_failed, transient_recovered.
Everything printed here is demo data produced by a mock LLM; it is labeled as such.
"""

import sys
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from agent.llm_provider import MockLLMProvider
from agent.mock_llm import scripted_triage
from agent.triage_agent import TriageAgent, TriageResult
from core.config import Settings
from core.models.enums import ActionCapability
from core.remediation.audit import AuditLog
from demo.fake_airflow.app import create_app
from demo.fake_airflow.state import load_scenario
from demo.scenarios.registrations import SALES_ETL

DEMO_NOW = datetime(2026, 10, 9, 0, 30, tzinfo=timezone.utc)
FAILURE_PAYLOADS = {
    "hero_transient_network": {"task_id": "load", "try_number": 1, "end_date": "2026-10-09T00:04:10+00:00",
                               "exception": "psycopg2.OperationalError: Connection reset by peer"},
    "cascade_upstream_failed": {"task_id": "extract", "try_number": 1, "end_date": "2026-10-09T00:00:40+00:00",
                                "exception": "InsufficientPrivilege: permission denied for table crm.orders"},
    "transient_recovered": {"task_id": "load", "try_number": 1, "end_date": "2026-10-09T00:04:10+00:00",
                            "exception": "psycopg2.OperationalError: Connection reset by peer"},
    "schema_drift": {"task_id": "load", "try_number": 1, "end_date": "2026-10-09T00:04:10+00:00",
                     "exception": "KeyError: Column not found: amount_usd in source crm.orders"},
    "multi_failure": {"dag_id": "orders_etl", "task_id": "extract_customers", "try_number": 1,
                      "end_date": "2026-10-09T00:04:10+00:00",
                      "exception": "psycopg2.OperationalError: Connection reset by peer"},
}


def run(scenario: str = "hero_transient_network",
        action_capabilities: frozenset[ActionCapability] = frozenset(ActionCapability)) -> tuple[TriageResult, AuditLog]:
    state = load_scenario(scenario)
    http = TestClient(create_app(state), base_url="http://fake-airflow")
    adapter = AirflowAdapter(AirflowReadClient(AirflowReadConfig(base_url="http://fake-airflow"), http=http),
                             demo=True, clock=lambda: DEMO_NOW)
    payload = {"dag_id": "sales_etl", "dag_run_id": "scheduled__2026-10-08T00:00:00+00:00", "state": "failed",
               "environment": "production", **FAILURE_PAYLOADS[scenario]}
    event = adapter.normalize_failure(payload)
    audit = AuditLog(clock=lambda: DEMO_NOW)
    agent = TriageAgent(adapter, MockLLMProvider(scripted_triage), Settings.from_env({}), audit,
                        action_capabilities=action_capabilities, clock=lambda: DEMO_NOW)
    return agent.triage(event, SALES_ETL), audit


def render(result: TriageResult, audit: AuditLog) -> str:
    r = result.report
    lines = [
        "=" * 78,
        "TRIAGE REPORT  [DEMO - FAKE AIRFLOW (DEMO) - llm_mode=" + r.llm_mode.value + "]",
        "=" * 78,
        f"incident        {r.incident_id}   state={r.incident_state.value}   status={r.status.value}",
        f"pipeline/task   {r.pipeline_id}.{r.task_id}   run={r.execution_id}   attempt={r.attempt_number}",
        f"category        {r.failure_category.value}/{r.failure_subcategory or '-'}",
        f"root cause      {r.root_cause.text}",
        f"primary         {r.primary_failure.text}",
    ]
    lines += [f"symptom         {s.text}" for s in r.downstream_symptoms]
    lines += [
        f"confidence      root-cause={r.confidence.value} | remediation={r.remediation_confidence.value} "
        f"| rerun-safety={r.rerun_safety.value}",
        f"rerun safety    {r.rerun_safety_reason}",
        f"remediation     {r.remediation_class.value}   suggested fix (not executed): {r.suggested_fix.claim.text}",
    ]
    if r.remediation_plan:
        p = r.remediation_plan
        lines += [
            "-" * 78,
            f"PLAN {p.remediation_id} v{p.plan_version}  hash={p.plan_hash[:16]}...  NOT EXECUTED ({p.execution_mode.value})",
            f"  action={p.action_type.value} scope={p.recovery_scope.value} target={p.target.dag_id}/{p.target.dag_run_id}"
            f"/{p.target.task_id or '*'}",
            "  task instances: " + ", ".join(f"{t.task_id}[try {t.try_number}, {t.observed_state}]"
                                             for t in p.task_instances_to_clear),
            f"  risk={p.risk_level.value} requires_approval={p.requires_approval} approval={p.approval_status.value} "
            f"expires={p.expires_at.isoformat()}",
            f"  reason: {p.reason.text}",
            f"  rollback: {p.rollback_description}",
        ]
    lines += ["-" * 78, "EVIDENCE TRAIL (Hypothesis -> Tool -> Evidence -> Decision)"]
    for tc in r.tool_calls:
        lines.append(f"  [{tc.hypothesis_id or '-'}] {tc.tool} -> {tc.evidence_ids} -> {tc.decision}")
    lines += ["-" * 78, "EVIDENCE"]
    for e in r.evidence:
        lines.append(f"  {e.evidence_id} {e.category.value:<12} {e.reliability.value:<6} {e.temporal_label.value:<8} "
                     f"{e.provenance.tool}: {e.description[:70]}")
    lines += ["-" * 78, "LIMITATIONS"] + [f"  - {x}" for x in r.limitations]
    lines += ["-" * 78, "AUDIT"] + [f"  #{e.seq:<3} {e.event_type.value}" for e in audit.events(r.incident_id)]
    lines.append(f"  chain valid: {audit.verify().valid}")
    return "\n".join(lines)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    triage_result, log = run(args[0] if args else "hero_transient_network")
    if "--json" in sys.argv:
        print(triage_result.report.model_dump_json(indent=2))
    else:
        print(render(triage_result, log))
