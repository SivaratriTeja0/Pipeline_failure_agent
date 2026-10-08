"""Confidence-level ordering helpers. The LLM may lower a level, never raise it."""

from core.models.enums import ConfidenceLevel, Reliability

_ORDER = {ConfidenceLevel.LOW: 0, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.HIGH: 2}


def at_least(level: ConfidenceLevel, floor: ConfidenceLevel) -> bool:
    return _ORDER[level] >= _ORDER[floor]


def apply_llm_ceiling(deterministic: ConfidenceLevel, llm_suggested: ConfidenceLevel | None) -> ConfidenceLevel:
    """Return the lower of the two. An LLM suggestion above the deterministic level is ignored."""
    if llm_suggested is None:
        return deterministic
    return llm_suggested if _ORDER[llm_suggested] < _ORDER[deterministic] else deterministic


def reliability_at_least_medium(reliability: Reliability) -> bool:
    return reliability in (Reliability.HIGH, Reliability.MEDIUM)
