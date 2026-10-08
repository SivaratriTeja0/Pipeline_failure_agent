"""PipelineAdapter and RemediationExecutor interfaces.

A ``PipelineAdapter`` is read-only: it normalizes failures, declares its read capabilities and
answers read requests. Every read method has a default that returns UNAVAILABLE without doing
anything, so an adapter implements only what its platform supports and nothing is fabricated.

A ``RemediationExecutor`` declares action capabilities and is the only thing that may mutate a
platform. Executors live under ``actions/`` (Phase 4); this module only defines the contract.
Platforms with no executor declare no action capabilities -> healing NOT_APPLICABLE.
"""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from core.models.enums import ActionCapability, ReadCapability
from core.models.events import PipelineFailureEvent
from core.models.reads import ReadRequest, ReadResult
from core.models.remediation import RemediationPlan, TaskInstanceRef
from core.remediation.selector import RunSnapshot


class AdapterError(RuntimeError):
    """A read could not be completed. Callers record ERROR / treat state as unreadable."""


class PipelineAdapter(ABC):
    platform: str
    demo: bool = False

    @property
    def is_demo(self) -> bool:
        """True when evidence from this adapter is mock / demo data and must be labeled."""
        return self.demo

    @abstractmethod
    def read_capabilities(self) -> frozenset[ReadCapability]:
        """Read capabilities this adapter actually supports for the configured platform."""

    @abstractmethod
    def normalize_failure(self, payload: dict[str, Any]) -> PipelineFailureEvent:
        """Normalize a platform-specific failure payload to the universal event."""

    def get_run_snapshot(self, pipeline_id: str, execution_id: str) -> RunSnapshot | None:
        """Observed run state for deterministic action selection. None = not supported."""
        return None

    def recent_failures(self, pipeline_id: str, limit: int = 5) -> list[dict[str, Any]]:
        """Failure payloads (as accepted by ``normalize_failure``) for recently failed executions,
        used by the optional poller. Default: polling not supported."""
        return []

    # --------------------------------------------------------------- read methods (default: UNAVAILABLE)

    def get_run_output(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_run_output")

    def get_run_history(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_run_history")

    def get_task_state(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_task_state")

    def get_pipeline_state(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_pipeline_state")

    def get_schema(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_schema")

    def compare_schema(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("compare_schema")

    def get_row_counts(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_row_counts")

    def get_data_quality_results(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_data_quality_results")

    def get_transaction_history(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_transaction_history")

    def get_state(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_state")

    def get_code_changes(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_code_changes")

    def get_lineage(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_lineage")

    def get_upstream_status(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_upstream_status")

    def get_downstream_status(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_downstream_status")

    def get_infrastructure_events(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_infrastructure_events")

    def get_configuration(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_configuration")

    def get_permissions(self, req: ReadRequest) -> ReadResult:
        return ReadResult.unavailable("get_permissions")


class DispatchOutcome(BaseModel):
    """Result of a single mutating dispatch.

    ``ambiguous``: the request may have been applied but the outcome is unknown; never resend.
    ``sent``: False only when the mutating request certainly never reached the platform.
    ``preflight``: the platform's own non-mutating listing of what the action would touch.
    ``listing_matches_plan``: whether the platform's listing equals the approved enumerated set.
    """

    accepted: bool
    ambiguous: bool = False
    sent: bool = True
    cleared: list[TaskInstanceRef] = Field(default_factory=list)
    preflight: list[dict[str, Any]] = Field(default_factory=list)
    listing_matches_plan: bool | None = None
    detail: str = ""
    raw_response: dict[str, Any] | None = None


class RemediationExecutor(ABC):
    """Mutating side of a platform. Implementations live only under actions/."""

    platform: str

    @abstractmethod
    def action_capabilities(self) -> frozenset[ActionCapability]:
        """Action capabilities this executor can perform."""

    @abstractmethod
    def dispatch(self, plan: RemediationPlan) -> DispatchOutcome:
        """Perform the plan's enumerated action exactly once. Called only by the executor
        boundary after approval, policy and live re-validation."""
