"""Plan hashing and plan revision (spec C9).

- ``compute_plan_hash`` is the single source of truth for plan hashes.
- ``verify_plan_hash`` compares a recomputed hash with a recorded one (e.g. the approval record's).
- ``revise_plan`` applies an edit: new plan_version, new hash, approvals voided.
"""

import hmac
from typing import Any

from core.models.enums import ApprovalStatus
from core.models.remediation import HASHED_FIELDS, RemediationPlan, compute_plan_hash, plan_hash_payload

__all__ = [
    "HASHED_FIELDS",
    "PlanRevisionError",
    "compute_plan_hash",
    "plan_hash_payload",
    "revise_plan",
    "verify_plan_hash",
]


class PlanRevisionError(ValueError):
    """Raised when a revision attempts to change identity or derived fields."""


_IMMUTABLE_ON_REVISION = frozenset({"remediation_id", "incident_id", "plan_version", "plan_hash", "executed"})


def verify_plan_hash(plan: RemediationPlan, recorded_hash: str) -> bool:
    """Recompute the plan hash from the plan itself and compare in constant time.

    The hash stored on the plan object is ignored: only the recomputed value is trusted.
    """
    return hmac.compare_digest(compute_plan_hash(plan), recorded_hash)


def revise_plan(plan: RemediationPlan, **changes: Any) -> RemediationPlan:
    """Return a new plan version with ``changes`` applied.

    Any edit creates a new plan_version and a new hash and voids prior approvals (I5):
    approval status returns to PENDING and approver fields are cleared.
    """
    forbidden = _IMMUTABLE_ON_REVISION & changes.keys()
    if forbidden:
        raise PlanRevisionError(f"cannot set {sorted(forbidden)} in a revision")
    data = plan.model_dump()
    data.update(changes)
    data.update(
        plan_version=plan.plan_version + 1,
        approval_status=ApprovalStatus.PENDING,
        approved_by=[],
        approved_at=None,
        rejected_by=None,
        rejected_at=None,
        rejection_reason=None,
    )
    data.pop("plan_hash", None)
    data.pop("executed", None)
    return RemediationPlan.model_validate(data)
