"""Adapter registry and capability discovery.

Read capabilities come from the platform's PipelineAdapter; action capabilities come only from
a registered RemediationExecutor. A platform without an executor has no action capabilities,
so healing is NOT_APPLICABLE. Concrete adapters/executors are injected by the composition root
(api/); core never imports a platform module.
"""

from enum import Enum

from pydantic import BaseModel

from adapters.base.interfaces import PipelineAdapter, RemediationExecutor
from core.models.enums import ActionCapability, ReadCapability
from core.models.policy import Capabilities


class CapabilityStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CapabilityReport(BaseModel):
    platform: str
    read: dict[ReadCapability, CapabilityStatus]
    action: dict[ActionCapability, CapabilityStatus]
    healing: CapabilityStatus
    demo: bool

    def capabilities(self) -> Capabilities:
        return Capabilities(
            read=frozenset(c for c, s in self.read.items() if s is CapabilityStatus.AVAILABLE),
            action=frozenset(c for c, s in self.action.items() if s is CapabilityStatus.AVAILABLE),
        )


class UnknownPlatformError(KeyError):
    pass


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, PipelineAdapter] = {}
        self._executors: dict[str, RemediationExecutor] = {}

    def register_adapter(self, adapter: PipelineAdapter) -> None:
        if adapter.platform in self._adapters:
            raise ValueError(f"adapter for {adapter.platform!r} already registered")
        self._adapters[adapter.platform] = adapter

    def register_executor(self, executor: RemediationExecutor) -> None:
        if executor.platform not in self._adapters:
            raise ValueError(f"register the {executor.platform!r} adapter before its executor")
        if executor.platform in self._executors:
            raise ValueError(f"executor for {executor.platform!r} already registered")
        self._executors[executor.platform] = executor

    def adapter(self, platform: str) -> PipelineAdapter:
        try:
            return self._adapters[platform]
        except KeyError as exc:
            raise UnknownPlatformError(platform) from exc

    def platforms(self) -> list[str]:
        return sorted(self._adapters)

    def discover(self, platform: str) -> CapabilityReport:
        adapter = self.adapter(platform)
        supported = adapter.read_capabilities()
        executor = self._executors.get(platform)
        declared = executor.action_capabilities() if executor is not None else frozenset()
        read = {c: CapabilityStatus.AVAILABLE if c in supported else CapabilityStatus.UNAVAILABLE
                for c in ReadCapability}
        if executor is None:
            action = {c: CapabilityStatus.NOT_APPLICABLE for c in ActionCapability}
        else:
            action = {c: CapabilityStatus.AVAILABLE if c in declared else CapabilityStatus.UNAVAILABLE
                      for c in ActionCapability}
        healing = CapabilityStatus.AVAILABLE if declared else CapabilityStatus.NOT_APPLICABLE
        return CapabilityReport(platform=platform, read=read, action=action, healing=healing,
                                demo=adapter.is_demo)
