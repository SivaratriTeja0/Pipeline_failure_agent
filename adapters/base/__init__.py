"""PipelineAdapter and RemediationExecutor interfaces."""

from adapters.base.interfaces import (
    AdapterError,
    DispatchOutcome,
    PipelineAdapter,
    RemediationExecutor,
)

__all__ = ["AdapterError", "DispatchOutcome", "PipelineAdapter", "RemediationExecutor"]
