"""Principal: the authenticated identity produced by the auth layer (spec L5)."""

from pydantic import ConfigDict, Field

from core.models.base import StrictModel
from core.models.enums import PrincipalType, Role


class Principal(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@\-]{0,127}$")
    principal_type: PrincipalType
    roles: frozenset[Role]
    auth_method: str = Field(min_length=1)

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    @property
    def can_approve(self) -> bool:
        """SERVICE principals (including the agent) can never approve."""
        return self.principal_type is PrincipalType.HUMAN and bool(
            self.roles & {Role.APPROVER, Role.ADMIN}
        )

    @property
    def audit_actor(self) -> str:
        return f"HUMAN:{self.principal_id}" if self.principal_type is PrincipalType.HUMAN else "SYSTEM"
