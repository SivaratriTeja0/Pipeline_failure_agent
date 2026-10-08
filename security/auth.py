"""Authentication (spec L5).

``AuthProvider.authenticate(request) -> Principal | None``. Identity comes only from the
authenticated request (headers), never from a request body.

- ``DemoAuthProvider``: fixed demo principals selected by the ``X-Demo-Principal`` header.
  Constructing it raises if HEALING_EXECUTION_MODE=LIVE or DEMO_MODE=false (invariant I14).
- ``TokenAuthProvider``: opaque bearer tokens stored only as SHA-256 hashes in a
  ``PrincipalStore``. ``create_principal`` mints a token (shown once). An OIDC provider can be
  added later as another ``AuthProvider`` without touching approval code.

A provider failure raises ``AuthProviderUnavailableError`` so callers fail closed (Rule 7).
"""

import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from core.config import ExecutionMode, Settings
from core.logging_setup import get_logger
from core.models.auth import Principal
from core.models.enums import PrincipalType, Role

__all__ = [
    "AuthProvider",
    "AuthProviderUnavailableError",
    "DemoAuthNotAllowedError",
    "DemoAuthProvider",
    "InMemoryPrincipalStore",
    "Principal",
    "PrincipalStore",
    "RequestLike",
    "StoredPrincipal",
    "TokenAuthProvider",
    "create_principal",
    "hash_token",
]

_log = get_logger(__name__)

DEMO_HEADER = "x-demo-principal"


class RequestLike(Protocol):
    """Anything with case-insensitive-or-lowercase ``headers`` (FastAPI/Starlette requests qualify)."""

    @property
    def headers(self) -> Mapping[str, str]: ...


class AuthProviderUnavailableError(RuntimeError):
    """The auth backend could not be consulted. Callers must treat this as BLOCKED."""


class DemoAuthNotAllowedError(RuntimeError):
    """DemoAuthProvider cannot run under LIVE execution or with DEMO_MODE=false."""


def _header(request: RequestLike, name: str) -> str | None:
    headers = request.headers
    value = headers.get(name)
    if value is None:
        for key, val in headers.items():
            if key.lower() == name.lower():
                return val
    return value


class AuthProvider(ABC):
    name: str

    @abstractmethod
    def authenticate(self, request: RequestLike) -> Principal | None:
        """Return the authenticated principal, None if unauthenticated.

        Raises AuthProviderUnavailableError if the backend cannot be consulted.
        """

    @abstractmethod
    def lookup(self, principal_id: str) -> Principal | None:
        """Current definition of a principal (re-checked before execution: does the approver
        still hold the role?). None if unknown or disabled.

        Raises AuthProviderUnavailableError if the backend cannot be consulted.
        """


# ----------------------------------------------------------------------------- demo

DEMO_PRINCIPALS: Mapping[str, Principal] = {
    p.principal_id: p
    for p in (
        Principal(principal_id="demo-engineer", principal_type=PrincipalType.HUMAN,
                  roles=frozenset({Role.ENGINEER, Role.APPROVER}), auth_method="demo"),
        Principal(principal_id="demo-approver-2", principal_type=PrincipalType.HUMAN,
                  roles=frozenset({Role.APPROVER}), auth_method="demo"),
        Principal(principal_id="demo-viewer", principal_type=PrincipalType.HUMAN,
                  roles=frozenset({Role.VIEWER}), auth_method="demo"),
        Principal(principal_id="demo-admin", principal_type=PrincipalType.HUMAN,
                  roles=frozenset({Role.ADMIN}), auth_method="demo"),
        Principal(principal_id="demo-agent", principal_type=PrincipalType.SERVICE,
                  roles=frozenset({Role.ENGINEER}), auth_method="demo"),
    )
}


class DemoAuthProvider(AuthProvider):
    name = "demo"

    def __init__(self, settings: Settings) -> None:
        if settings.healing_execution_mode is ExecutionMode.LIVE:
            raise DemoAuthNotAllowedError("DemoAuthProvider is refused when HEALING_EXECUTION_MODE=LIVE")
        if not settings.demo_mode:
            raise DemoAuthNotAllowedError("DemoAuthProvider requires DEMO_MODE=true")
        self._principals = dict(DEMO_PRINCIPALS)

    def authenticate(self, request: RequestLike) -> Principal | None:
        selected = _header(request, DEMO_HEADER)
        if not selected:
            return None
        return self._principals.get(selected.strip())

    def lookup(self, principal_id: str) -> Principal | None:
        return self._principals.get(principal_id)


# ----------------------------------------------------------------------------- token


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class StoredPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    principal: Principal
    token_hash: str
    disabled: bool = False


class PrincipalStore(ABC):
    """Persistence for token principals. Phase 5 provides a database-backed store."""

    @abstractmethod
    def add(self, stored: StoredPrincipal) -> None: ...

    @abstractmethod
    def find_by_token_hash(self, token_hash: str) -> StoredPrincipal | None: ...

    def find_by_id(self, principal_id: str) -> StoredPrincipal | None:
        """Look a principal up by id. Stores that cannot must fail closed (raise)."""
        raise LookupError(f"{type(self).__name__} does not support lookup by principal id")


class InMemoryPrincipalStore(PrincipalStore):
    def __init__(self) -> None:
        self._by_hash: dict[str, StoredPrincipal] = {}

    def add(self, stored: StoredPrincipal) -> None:
        if any(s.principal.principal_id == stored.principal.principal_id for s in self._by_hash.values()):
            raise ValueError(f"principal {stored.principal.principal_id!r} already exists")
        self._by_hash[stored.token_hash] = stored

    def find_by_token_hash(self, token_hash: str) -> StoredPrincipal | None:
        for known_hash, stored in self._by_hash.items():
            if hmac.compare_digest(known_hash, token_hash):
                return stored
        return None

    def find_by_id(self, principal_id: str) -> StoredPrincipal | None:
        return next((s for s in self._by_hash.values() if s.principal.principal_id == principal_id), None)

    def update(self, principal_id: str, *, roles: frozenset[Role] | None = None, disabled: bool | None = None) -> None:
        """Change a principal's roles or disable it (ADMIN operation; Phase 5 exposes it)."""
        for token_hash, stored in self._by_hash.items():
            if stored.principal.principal_id == principal_id:
                principal = stored.principal if roles is None else stored.principal.model_copy(update={"roles": roles})
                self._by_hash[token_hash] = StoredPrincipal(
                    principal=principal, token_hash=token_hash,
                    disabled=stored.disabled if disabled is None else disabled)
                return
        raise KeyError(principal_id)


def create_principal(
    store: PrincipalStore,
    principal_id: str,
    principal_type: PrincipalType,
    roles: frozenset[Role],
) -> tuple[Principal, str]:
    """Create a principal and return it with its raw bearer token. Only the hash is stored."""
    token = secrets.token_urlsafe(32)
    principal = Principal(
        principal_id=principal_id, principal_type=principal_type, roles=roles, auth_method="token"
    )
    store.add(StoredPrincipal(principal=principal, token_hash=hash_token(token)))
    return principal, token


class TokenAuthProvider(AuthProvider):
    name = "token"

    def __init__(self, store: PrincipalStore) -> None:
        self._store = store

    def authenticate(self, request: RequestLike) -> Principal | None:
        header = _header(request, "authorization")
        if not header:
            return None
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        try:
            stored = self._store.find_by_token_hash(hash_token(token.strip()))
        except Exception as exc:  # backend failure must fail closed, never authenticate
            _log.error("auth_store_unavailable", extra={"error": type(exc).__name__})
            raise AuthProviderUnavailableError("principal store unavailable") from exc
        if stored is None or stored.disabled:
            return None
        return stored.principal

    def lookup(self, principal_id: str) -> Principal | None:
        try:
            stored = self._store.find_by_id(principal_id)
        except Exception as exc:  # backend failure must fail closed
            _log.error("auth_store_unavailable", extra={"error": type(exc).__name__})
            raise AuthProviderUnavailableError("principal store unavailable") from exc
        if stored is None or stored.disabled:
            return None
        return stored.principal
