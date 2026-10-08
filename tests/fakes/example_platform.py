"""ExamplePlatform: a fake, non-Airflow orchestrator that exists only in tests.

It has its own vocabulary (jobs, run UIDs, steps) and plugs into the core via PipelineAdapter
alone, proving the core is platform-independent. It has no executor -> healing NOT_APPLICABLE.
"""

from datetime import datetime, timezone
from typing import Any

from adapters.base.evidence import build_evidence
from adapters.base.interfaces import PipelineAdapter
from core.models import EvidenceCategory, PipelineFailureEvent, ReadCapability, Reliability
from core.models.reads import ReadRequest, ReadResult, ReadStatus

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


class ExamplePlatformAdapter(PipelineAdapter):
    platform = "exampleplatform"

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._jobs = {
            ("nightly_billing", "uid-7f3a"): {
                "step": "aggregate",
                "log": "step aggregate: ERROR quota exceeded for compute pool (429 rate limit)",
                "history": [{"run_uid": "uid-7f39", "result": "OK"}, {"run_uid": "uid-7f38", "result": "OK"}],
            }
        }

    def read_capabilities(self) -> frozenset[ReadCapability]:
        return frozenset({ReadCapability.RUN_LOGS, ReadCapability.RUN_HISTORY})

    def normalize_failure(self, payload: dict[str, Any]) -> PipelineFailureEvent:
        return PipelineFailureEvent(
            event_id=f"ex-{payload['run_uid']}",
            platform=self.platform,
            orchestrator="example-scheduler",
            compute_engine="example-compute",
            pipeline_id=payload["job_name"],
            task_id=payload.get("step"),
            execution_id=payload["run_uid"],
            platform_run_id=payload["run_uid"],
            status="failed",
            error_message=payload.get("err"),
            metadata={"example_attempt_token": payload.get("attempt_token")},
        )

    def _job(self, req: ReadRequest) -> dict[str, Any]:
        return self._jobs[(req.pipeline_id, req.execution_id)]

    def get_run_output(self, req: ReadRequest) -> ReadResult:
        self.calls.append("get_run_output")
        job = self._job(req)
        item = build_evidence(
            adapter="exampleplatform", platform=self.platform, capability="run_logs", tool="get_run_output",
            source="example:step_log", req=req, category=EvidenceCategory.LOG,
            description=f"Step log for {job['step']}", value=job["log"], reliability=Reliability.HIGH,
            collected_at=NOW, key="log", signal_text=job["log"])
        return ReadResult(tool="get_run_output", status=ReadStatus.AVAILABLE, evidence=[item])

    def get_run_history(self, req: ReadRequest) -> ReadResult:
        self.calls.append("get_run_history")
        item = build_evidence(
            adapter="exampleplatform", platform=self.platform, capability="run_history", tool="get_run_history",
            source="example:job_history", req=req, category=EvidenceCategory.RUN_HISTORY,
            description="Previous runs", value=self._job(req)["history"], reliability=Reliability.MEDIUM,
            collected_at=NOW, key="history")
        return ReadResult(tool="get_run_history", status=ReadStatus.AVAILABLE, evidence=[item])
