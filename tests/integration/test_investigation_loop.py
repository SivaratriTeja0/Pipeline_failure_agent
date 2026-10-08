"""Investigation loop (Part I): call cap, dedup, allowlist, invalid output, LLM failure."""

from agent.llm_provider import LLMRequest, LLMResponse, LLMUnavailableError, MockLLMProvider
from core.models import RemediationClass, ReportStatus
from core.taxonomy import FailureCategory
from tests.triage_helpers import DEFAULT, call, investigator, run_airflow


def steps(run):
    return run.result.investigation.steps


def test_call_cap_is_five_per_cycle_and_duplicates_are_not_reexecuted():
    turns = [
        call("get_upstream_status"),
        call("get_upstream_status"),          # duplicate
        call("get_configuration"),
        call("get_downstream_status"),
        call("get_task_state"),
        call("get_pipeline_state"),           # 5th distinct call
        call("get_run_history", limit=3),     # 6th distinct -> budget exhausted
        call("get_run_output", task_id="publish"),
        DEFAULT,
    ]
    run = run_airflow(script=investigator(turns))
    inv = run.result.investigation
    assert inv.calls_used == 5
    assert [tc.tool for tc in inv.tool_calls] == ["get_upstream_status", "get_configuration",
                                                  "get_downstream_status", "get_task_state", "get_pipeline_state"]
    decisions = [s.decision for s in inv.steps]
    assert "duplicate request; not re-executed" in decisions
    assert decisions.count("rejected: 5-call budget exhausted") == 2
    assert inv.conclusion is not None


def test_initial_collection_does_not_count_against_the_budget():
    run = run_airflow()
    inv = run.result.investigation
    assert inv.calls_used == 3
    assert {"get_run_output", "get_run_history"} <= {e.provenance.tool for e in run.report.evidence}


def test_non_allowlisted_tools_are_rejected_and_never_run():
    turns = [call("get_schema"), call("get_lineage"), call("clear_task_instances"), DEFAULT]
    run = run_airflow(script=investigator(turns))
    inv = run.result.investigation
    assert inv.rejected_requests[:3] == ["get_schema", "get_lineage", "clear_task_instances"]
    assert all(s.decision == "rejected: tool not on the capability allowlist" for s in inv.steps[:3])
    assert all(tc.tool not in {"get_schema", "get_lineage"} for tc in inv.tool_calls)
    assert run.state.mutating_requests() == []


def test_identifier_arguments_from_llm_are_rejected():
    turns = [call("get_run_output", pipeline_id="other_dag"), call("get_task_state", task_id="../../x"), DEFAULT]
    run = run_airflow(script=investigator(turns))
    assert run.result.investigation.rejected_requests[:2] == ["get_run_output", "get_task_state"]
    assert all("other_dag" not in r.path for r in run.state.request_log)


def test_repeated_invalid_output_stops_with_unknown_root_cause():
    run = run_airflow(script=investigator(["not json", '{"action": "dance"}', '{"action": "conclude"}']))
    inv = run.result.investigation
    assert inv.conclusion is None
    assert sum(s.action == "invalid_output" for s in inv.steps) == 3
    r = run.report
    assert r.failure_category is FailureCategory.OTHER_UNKNOWN
    assert r.status is ReportStatus.INSUFFICIENT_EVIDENCE
    assert r.remediation_class is RemediationClass.MANUAL_FIX_REQUIRED and run.result.plan is None


def test_llm_output_trying_to_set_unknown_fields_is_rejected():
    rogue = {"action": "call_tool", "tool_call": {"tool": "get_task_state", "args": {}}, "approve": True}
    run = run_airflow(script=investigator([rogue, DEFAULT]))
    assert run.result.investigation.steps[0].action == "invalid_output"


class Unavailable(MockLLMProvider):
    def generate(self, request: LLMRequest) -> LLMResponse:
        raise LLMUnavailableError("simulated outage")


def test_llm_unavailable_yields_unknown_and_manual(monkeypatch):
    import tests.triage_helpers as helpers

    monkeypatch.setattr(helpers, "MockLLMProvider", Unavailable)
    run = run_airflow()
    assert run.result.investigation.conclusion is None
    assert any("LLM unavailable" in l for l in run.report.limitations)
    assert run.report.remediation_class is RemediationClass.MANUAL_FIX_REQUIRED


def test_every_tool_call_records_hypothesis_tool_evidence_decision():
    run = run_airflow()
    for tc in run.report.tool_calls:
        assert tc.hypothesis_id and tc.tool and tc.evidence_ids and tc.decision.startswith("AVAILABLE")


def test_rereading_already_collected_evidence_does_not_duplicate_it():
    # schema drift: deterministic follow-up collects configuration; the LLM then asks for it again
    run = run_airflow("schema_drift")
    ids = [e.evidence_id for e in run.report.evidence]
    assert len(ids) == len(set(ids))
    assert "get_configuration" in [tc.tool for tc in run.report.tool_calls]
