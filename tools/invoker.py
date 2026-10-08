"""Capability-filtered allowlist and the read-only tool invoker.

LLM-facing allowlist = registry ∩ adapter read capabilities. A tool whose capability is not
supported is never called; it yields UNAVAILABLE. Tool names outside the allowlist and
malformed arguments are rejected. Identifiers (pipeline, execution, cycle) are bound to the
incident; the LLM may only supply ``task_id``, ``attempt_number`` and ``limit``.
"""

from typing import Any

from pydantic import ValidationError

from adapters.base.interfaces import PipelineAdapter
from core.logging_setup import get_logger
from core.models.base import TASK_ID_RE
from core.models.enums import ReadCapability
from core.models.reads import ReadRequest, ReadResult, ReadStatus
from tools.catalog import READ_ONLY_TOOLS
from tools.registry import ToolRegistry, ToolSpec

_log = get_logger(__name__)

LLM_SETTABLE_ARGS = frozenset({"task_id", "attempt_number", "limit"})


class ToolNotAllowedError(ValueError):
    """The requested tool is not on the capability-filtered allowlist."""


class ToolInputError(ValueError):
    """Tool arguments are malformed or try to set incident-bound identifiers."""


def llm_allowlist(capabilities: frozenset[ReadCapability], registry: ToolRegistry = READ_ONLY_TOOLS) -> list[ToolSpec]:
    return [spec for spec in registry if spec.required_capability in capabilities]


def tool_availability(
    capabilities: frozenset[ReadCapability], registry: ToolRegistry = READ_ONLY_TOOLS
) -> dict[str, ReadStatus]:
    return {
        spec.name: ReadStatus.AVAILABLE if spec.required_capability in capabilities else ReadStatus.UNAVAILABLE
        for spec in registry
    }


class ToolInvoker:
    def __init__(self, adapter: PipelineAdapter, registry: ToolRegistry = READ_ONLY_TOOLS) -> None:
        self._adapter = adapter
        self._registry = registry
        self._capabilities = adapter.read_capabilities()

    def allowlist(self) -> list[str]:
        return [spec.name for spec in llm_allowlist(self._capabilities, self._registry)]

    def _bind(self, incident: ReadRequest, llm_args: dict[str, Any]) -> ReadRequest:
        extra = set(llm_args) - LLM_SETTABLE_ARGS
        if extra:
            raise ToolInputError(f"arguments not settable by the investigator: {sorted(extra)}")
        task_id = llm_args.get("task_id", incident.task_id)
        if task_id is not None and (not isinstance(task_id, str) or not TASK_ID_RE.match(task_id)):
            raise ToolInputError(f"invalid task_id {task_id!r}")
        data = incident.model_dump()
        data.update({k: v for k, v in llm_args.items() if k in LLM_SETTABLE_ARGS})
        try:
            return ReadRequest.model_validate(data)
        except ValidationError as exc:
            raise ToolInputError(str(exc)) from exc

    def invoke(self, name: str, incident: ReadRequest, llm_args: dict[str, Any] | None = None) -> ReadResult:
        spec = self._registry.get(name)
        if spec is None:
            raise ToolNotAllowedError(f"unknown tool {name!r}")
        if spec.required_capability not in self._capabilities:
            _log.info("tool_unavailable", extra={"tool": name, "capability": spec.required_capability.value})
            return ReadResult.unavailable(name, f"capability {spec.required_capability.value} not supported")
        request = self._bind(incident, llm_args or {})
        try:
            result = getattr(self._adapter, spec.adapter_method)(request)
        except Exception as exc:  # adapter bugs never crash the investigation or fabricate evidence
            _log.error("tool_failed", extra={"tool": name, "error": type(exc).__name__})
            return ReadResult.error(name, f"{type(exc).__name__}: {exc}")
        if not isinstance(result, ReadResult):
            return ReadResult.error(name, "adapter returned a non-ReadResult value")
        return result
