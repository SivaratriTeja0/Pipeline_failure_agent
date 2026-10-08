"""Deterministic risk level (spec L2).

MEDIUM baseline; LOW if non-production and FAILED_TASK; HIGH if production and FAILED_DAG_RUN.
An unknown/blank environment is treated as production (fail closed toward more approvals).
"""

from core.models.enums import RecoveryScope, RiskLevel

PRODUCTION_ENVIRONMENTS = frozenset({"prod", "production", "prd", "live"})


def is_production(environment: str | None) -> bool:
    if environment is None or environment.strip() == "":
        return True
    return environment.strip().lower() in PRODUCTION_ENVIRONMENTS


def compute_risk_level(environment: str | None, scope: RecoveryScope) -> RiskLevel:
    production = is_production(environment)
    if not production and scope is RecoveryScope.FAILED_TASK:
        return RiskLevel.LOW
    if production and scope is RecoveryScope.FAILED_DAG_RUN:
        return RiskLevel.HIGH
    return RiskLevel.MEDIUM


def required_approvals(risk: RiskLevel, high_risk_approvals: int) -> int:
    return high_risk_approvals if risk is RiskLevel.HIGH else 1


ROLLBACK_DESCRIPTION = (
    "Clearing task instances cannot be undone by this system. Mitigations: only the enumerated "
    "failed task instances in the existing run are cleared (only_failed=true, no new run is created), "
    "live state is re-validated immediately before dispatch, and the outcome is verified afterwards."
)
