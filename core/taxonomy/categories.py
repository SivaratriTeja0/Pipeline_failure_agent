"""Failure taxonomy (spec Part D): exactly 14 top-level categories."""

from enum import Enum


class FailureCategory(str, Enum):
    SOURCE_SCHEMA_DRIFT = "SOURCE_SCHEMA_DRIFT"
    DATA_QUALITY = "DATA_QUALITY"
    VOLUME_ANOMALY = "VOLUME_ANOMALY"
    CODE_LOGIC_BUG = "CODE_LOGIC_BUG"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    ORCHESTRATION_STATE = "ORCHESTRATION_STATE"
    UPSTREAM_DEPENDENCY = "UPSTREAM_DEPENDENCY"
    CONFIGURATION = "CONFIGURATION"
    SECURITY_AUTHORIZATION = "SECURITY_AUTHORIZATION"
    NETWORK_CONNECTIVITY = "NETWORK_CONNECTIVITY"
    RESOURCE_QUOTA = "RESOURCE_QUOTA"
    CONCURRENCY = "CONCURRENCY"
    TRANSIENT_RECOVERED = "TRANSIENT_RECOVERED"
    OTHER_UNKNOWN = "OTHER_UNKNOWN"


SUBCATEGORIES: dict[FailureCategory, frozenset[str]] = {
    FailureCategory.SOURCE_SCHEMA_DRIFT: frozenset({"column_missing", "column_renamed", "type_changed"}),
    FailureCategory.DATA_QUALITY: frozenset(
        {"rule_violation", "null_spike", "duplicate_keys", "rejected_records"}
    ),
    FailureCategory.VOLUME_ANOMALY: frozenset({"row_count_drop", "row_count_spike", "empty_source"}),
    FailureCategory.CODE_LOGIC_BUG: frozenset({"recent_change", "unhandled_case"}),
    FailureCategory.INFRASTRUCTURE: frozenset({"node_loss", "cluster_terminated", "disk_full"}),
    FailureCategory.ORCHESTRATION_STATE: frozenset({"stuck_state", "bad_checkpoint", "scheduler_issue"}),
    FailureCategory.UPSTREAM_DEPENDENCY: frozenset(
        {"upstream_failed", "source_unavailable", "late_arrival"}
    ),
    FailureCategory.CONFIGURATION: frozenset(
        {"missing_object", "wrong_parameter", "bad_connection_config"}
    ),
    FailureCategory.SECURITY_AUTHORIZATION: frozenset({"permission_denied", "expired_credential"}),
    FailureCategory.NETWORK_CONNECTIVITY: frozenset({"connection_refused", "dns", "timeout_network"}),
    FailureCategory.RESOURCE_QUOTA: frozenset({"memory", "quota_exceeded", "throttling"}),
    FailureCategory.CONCURRENCY: frozenset({"overlapping_run", "lock_contention", "write_conflict"}),
    FailureCategory.TRANSIENT_RECOVERED: frozenset({"succeeded_on_retry"}),
    FailureCategory.OTHER_UNKNOWN: frozenset(),
}


def is_valid_subcategory(category: FailureCategory, subcategory: str | None) -> bool:
    """A subcategory is valid if absent, or listed for its category. OTHER_UNKNOWN accepts any."""
    if subcategory is None:
        return True
    if category is FailureCategory.OTHER_UNKNOWN:
        return True
    return subcategory in SUBCATEGORIES[category]
