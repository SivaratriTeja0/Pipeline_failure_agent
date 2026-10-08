"""Capability discovery (read + action), Generic adapter and ExamplePlatform independence."""

from datetime import datetime, timezone

import pytest

from adapters.base.interfaces import DispatchOutcome, RemediationExecutor
from adapters.generic.adapter import GenericAdapter, ManualEvidence
from core.models import ActionCapability, EvidenceCategory, ReadCapability, Reliability
from core.models.reads import ReadRequest, ReadStatus
from core.registry import AdapterRegistry, CapabilityStatus
from core.taxonomy.preclassifier import preclassify
from tests.airflow_helpers import hero
from tests.fakes.example_platform import ExamplePlatformAdapter
from tools.invoker import ToolInvoker

A = CapabilityStatus.AVAILABLE
U = CapabilityStatus.UNAVAILABLE
NA = CapabilityStatus.NOT_APPLICABLE


class DeclaringExecutor(RemediationExecutor):
    """Test double that only declares capabilities; dispatch refuses (never used here)."""

    def __init__(self, platform: str, caps: frozenset[ActionCapability]) -> None:
        self.platform = platform
        self._caps = caps

    def action_capabilities(self) -> frozenset[ActionCapability]:
        return self._caps

    def dispatch(self, plan) -> DispatchOutcome:
        return DispatchOutcome(accepted=False, detail="test double never dispatches")


def registry() -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register_adapter(hero(demo=True)[0])
    reg.register_adapter(GenericAdapter())
    reg.register_adapter(ExamplePlatformAdapter())
    return reg


def matrix(reg: AdapterRegistry) -> dict[str, dict[str, str]]:
    out = {}
    for platform in reg.platforms():
        report = reg.discover(platform)
        row = {c.value: s.value for c, s in report.read.items()}
        row.update({c.value: s.value for c, s in report.action.items()})
        row["healing"] = report.healing.value
        out[platform] = row
    return out


def test_airflow_read_capabilities():
    report = registry().discover("airflow")
    available = {c for c, s in report.read.items() if s is A}
    assert available == {ReadCapability.RUN_LOGS, ReadCapability.RUN_HISTORY, ReadCapability.CONFIGURATION,
                         ReadCapability.UPSTREAM_STATUS, ReadCapability.DOWNSTREAM_STATUS}
    assert report.read[ReadCapability.SCHEMA] is U
    assert report.demo


def test_demo_flag_flips_once_fake_airflow_is_detected():
    adapter, _ = hero(demo=False)
    assert not adapter.is_demo
    adapter.get_pipeline_state(ReadRequest(pipeline_id="sales_etl", execution_id="scheduled__2026-10-08T00:00:00+00:00"))
    assert adapter.is_demo


def test_no_executor_means_healing_not_applicable():
    reg = registry()
    for platform in ("airflow", "generic", "exampleplatform"):
        report = reg.discover(platform)
        assert report.healing is NA
        assert set(report.action.values()) == {NA}
        assert not report.capabilities().healing_applicable


def test_action_capabilities_come_only_from_the_registered_executor():
    reg = registry()
    reg.register_executor(DeclaringExecutor("airflow", frozenset(ActionCapability)))
    report = reg.discover("airflow")
    assert report.action == {ActionCapability.RETRY_FAILED_TASK: A, ActionCapability.RETRY_FAILED_DAG_RUN: A}
    assert report.healing is A
    partial = AdapterRegistry()
    partial.register_adapter(GenericAdapter())
    partial.register_executor(DeclaringExecutor("generic", frozenset({ActionCapability.RETRY_FAILED_TASK})))
    assert partial.discover("generic").action[ActionCapability.RETRY_FAILED_DAG_RUN] is U


def test_executor_requires_adapter_and_no_duplicates():
    reg = AdapterRegistry()
    with pytest.raises(ValueError):
        reg.register_executor(DeclaringExecutor("airflow", frozenset()))
    reg.register_adapter(GenericAdapter())
    with pytest.raises(ValueError):
        reg.register_adapter(GenericAdapter())


def test_capability_matrix_shape():
    m = matrix(registry())
    assert set(m) == {"airflow", "exampleplatform", "generic"}
    assert all(len(row) == len(ReadCapability) + len(ActionCapability) + 1 for row in m.values())


# ---------------------------------------------------------------- Generic


def test_generic_manual_upload_is_medium_reliability_user_provided():
    adapter = GenericAdapter()
    req = ReadRequest(pipeline_id="legacy_job", execution_id="2026-10-08")
    assert adapter.get_run_output(req).evidence == []
    adapter.upload("legacy_job", "2026-10-08", [
        ManualEvidence(category=EvidenceCategory.LOG, description="console output",
                       content="ERROR: permission denied for schema finance", uploaded_by="alice"),
        ManualEvidence(category=EvidenceCategory.SCHEMA, description="ddl", content="CREATE TABLE ...",
                       uploaded_by="alice"),
    ])
    logs = adapter.get_run_output(req).evidence
    assert len(logs) == 1 and logs[0].reliability is Reliability.MEDIUM
    assert logs[0].metadata["user_provided"] is True
    assert logs[0].normalized_signal == "AUTHORIZATION_FAILURE"
    assert adapter.get_lineage(req).status is ReadStatus.UNAVAILABLE


def test_generic_normalize():
    event = GenericAdapter().normalize_failure({"pipeline_id": "legacy_job", "execution_id": "2026-10-08",
                                                "error_message": "boom", "failure_time": "2026-10-08T01:00:00+00:00"})
    assert event.platform == "generic" and event.failure_time == datetime(2026, 10, 8, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------- ExamplePlatform


def test_example_platform_runs_through_core_tools_unchanged():
    adapter = ExamplePlatformAdapter()
    event = adapter.normalize_failure({"job_name": "nightly_billing", "run_uid": "uid-7f3a", "step": "aggregate",
                                       "err": "quota exceeded"})
    incident = ReadRequest(pipeline_id=event.pipeline_id, execution_id=event.execution_id, task_id=event.task_id)
    invoker = ToolInvoker(adapter)
    assert set(invoker.allowlist()) == {"get_run_output", "get_run_history", "get_task_state", "get_pipeline_state"}
    out = invoker.invoke("get_run_output", incident)
    assert out.status is ReadStatus.AVAILABLE
    assert out.evidence[0].normalized_signal == "QUOTA_EXCEEDED"
    assert {s.normalized_signal.value for s in preclassify(out.evidence[0].value)} >= {"QUOTA_EXCEEDED"}
    assert invoker.invoke("get_schema", incident).status is ReadStatus.UNAVAILABLE
    assert adapter.calls == ["get_run_output"]
    # get_task_state is in its allowlist (run_history) but not implemented -> UNAVAILABLE default, not fabricated
    assert invoker.invoke("get_task_state", incident).status is ReadStatus.UNAVAILABLE
