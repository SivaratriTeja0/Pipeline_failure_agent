"""Adapter registry and capability discovery."""

from core.registry.registry import AdapterRegistry, CapabilityReport, CapabilityStatus, UnknownPlatformError

__all__ = ["AdapterRegistry", "CapabilityReport", "CapabilityStatus", "UnknownPlatformError"]
