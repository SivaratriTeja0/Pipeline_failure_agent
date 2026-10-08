"""Generic and ExamplePlatform produce the same report schema; ExamplePlatform runs with zero
changes under core/ and agent/ (checksum before/after + no references to it)."""

import hashlib
from datetime import datetime, timezone

from adapters.generic.adapter import GenericAdapter, ManualEvidence
from agent.llm_provider import MockLLMProvider
from agent.mock_llm import scripted_triage
from agent.triage_agent import TriageAgent
from core.config import Settings
from core.models import EvidenceCategory, RemediationClass, UniversalTriageReport
from core.models.pipeline import PipelineRegistration
from core.remediation.audit import AuditLog
from core.taxonomy import FailureCategory
from tests.architecture import scanner as sc
from tests.fakes.example_platform import ExamplePlatformAdapter

NOW = datetime(2026, 10, 9, 1, 0, tzinfo=timezone.utc)


def checksum(*dirs: str) -> dict[str, str]:
    return {str(p.relative_to(sc.REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sc.python_files(*dirs)}


def triage(adapter, event, registration):
    agent = TriageAgent(adapter, MockLLMProvider(scripted_triage), Settings.from_env({}), AuditLog(clock=lambda: NOW),
                        clock=lambda: NOW)
    return agent.triage(event, registration)


def run_example():
    adapter = ExamplePlatformAdapter()
    event = adapter.normalize_failure({"job_name": "nightly_billing", "run_uid": "uid-7f3a", "step": "aggregate",
                                       "err": "quota exceeded for compute pool"})
    return triage(adapter, event, PipelineRegistration(pipeline_id="nightly_billing", platform="exampleplatform"))


def run_generic(dq: bool = False):
    adapter = GenericAdapter(clock=lambda: NOW)
    items = [ManualEvidence(category=EvidenceCategory.LOG, description="console", uploaded_by="alice",
                            content="ERROR DQ gate failed: null_rate 7% > 5% on orders.amount" if dq
                            else "ERROR: permission denied for schema finance")]
    if dq:
        items.append(ManualEvidence(category=EvidenceCategory.DATA_QUALITY, description="dq run", uploaded_by="alice",
                                    content="rule null_rate failed; 412 rows quarantined; target untouched",
                                    facts={"dq_result": {"gate_failed": True, "target_corrupted": False,
                                                         "bad_records_quarantined": True}}))
    adapter.upload("legacy_job", "2026-10-08", items)
    event = adapter.normalize_failure({"pipeline_id": "legacy_job", "execution_id": "2026-10-08",
                                       "error_message": items[0].content,
                                       "failure_time": "2026-10-08T23:00:00+00:00"})
    return triage(adapter, event, PipelineRegistration(pipeline_id="legacy_job", platform="generic"))


def test_example_platform_runs_with_zero_changes_under_core_and_agent():
    before = checksum("core", "agent")
    result = run_example()
    assert checksum("core", "agent") == before
    assert result.report.platform == "exampleplatform"
    assert result.report.failure_category is FailureCategory.RESOURCE_QUOTA
    for path in sc.python_files("core", "agent"):
        text = path.read_text(encoding="utf-8").lower()
        assert "exampleplatform" not in text and "tests.fakes" not in text, path


def test_generic_and_example_platform_produce_the_same_report_schema():
    reports = [run_example().report, run_generic().report]
    for r in reports:
        assert isinstance(r, UniversalTriageReport)
        UniversalTriageReport.model_validate_json(r.model_dump_json())
    assert reports[0].model_dump().keys() == reports[1].model_dump().keys()
    assert {r.platform for r in reports} == {"exampleplatform", "generic"}


def test_platforms_without_executor_never_get_a_plan():
    for result in (run_example(), run_generic()):
        assert result.plan is None and result.report.action_capabilities == []
        assert result.report.remediation_class is not RemediationClass.AUTOMATABLE


def test_generic_dq_gate_worked_as_designed_is_no_action():
    result = run_generic(dq=True)
    assert result.report.failure_category is FailureCategory.DATA_QUALITY
    assert result.report.remediation_class is RemediationClass.NO_ACTION_REQUIRED
