"""AuthProvider, DemoAuthProvider, TokenAuthProvider (L5, I14)."""

from dataclasses import dataclass, field

import pytest

from core.config import Settings
from core.models import PrincipalType, Role
from security.auth import (
    AuthProviderUnavailableError,
    DemoAuthNotAllowedError,
    DemoAuthProvider,
    InMemoryPrincipalStore,
    PrincipalStore,
    TokenAuthProvider,
    create_principal,
    hash_token,
)


@dataclass
class Req:
    headers: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------- demo


def test_demo_provider_refuses_live_mode():
    settings = Settings.from_env({"HEALING_EXECUTION_MODE": "LIVE"})
    with pytest.raises(DemoAuthNotAllowedError, match="LIVE"):
        DemoAuthProvider(settings)


def test_demo_provider_refuses_when_demo_mode_off():
    with pytest.raises(DemoAuthNotAllowedError, match="DEMO_MODE"):
        DemoAuthProvider(Settings.from_env({"DEMO_MODE": "false"}))


def test_demo_provider_selects_principal_by_header():
    provider = DemoAuthProvider(Settings.from_env({}))
    p = provider.authenticate(Req({"X-Demo-Principal": "demo-engineer"}))
    assert p is not None and p.principal_type is PrincipalType.HUMAN and Role.APPROVER in p.roles
    assert provider.authenticate(Req()) is None
    assert provider.authenticate(Req({"X-Demo-Principal": "nobody"})) is None


def test_demo_agent_is_a_service_principal_that_cannot_approve():
    provider = DemoAuthProvider(Settings.from_env({}))
    agent = provider.authenticate(Req({"x-demo-principal": "demo-agent"}))
    assert agent.principal_type is PrincipalType.SERVICE and not agent.can_approve


# ---------------------------------------------------------------- token


def test_token_round_trip_and_only_hash_stored():
    store = InMemoryPrincipalStore()
    principal, token = create_principal(store, "alice", PrincipalType.HUMAN, frozenset({Role.APPROVER}))
    provider = TokenAuthProvider(store)
    assert provider.authenticate(Req({"Authorization": f"Bearer {token}"})) == principal
    stored = store.find_by_token_hash(hash_token(token))
    assert stored is not None and stored.token_hash != token and token not in stored.model_dump_json()


@pytest.mark.parametrize(
    "header",
    [None, "Bearer ", "Basic abc", "Bearer wrong-token", "bearer"],
)
def test_token_rejects_bad_credentials(header):
    store = InMemoryPrincipalStore()
    create_principal(store, "alice", PrincipalType.HUMAN, frozenset({Role.APPROVER}))
    headers = {} if header is None else {"Authorization": header}
    assert TokenAuthProvider(store).authenticate(Req(headers)) is None


def test_disabled_principal_rejected():
    store = InMemoryPrincipalStore()
    _, token = create_principal(store, "bob", PrincipalType.HUMAN, frozenset({Role.VIEWER}))
    stored = store.find_by_token_hash(hash_token(token))
    store._by_hash[stored.token_hash] = stored.model_copy(update={"disabled": True})
    assert TokenAuthProvider(store).authenticate(Req({"Authorization": f"Bearer {token}"})) is None


def test_duplicate_principal_rejected():
    store = InMemoryPrincipalStore()
    create_principal(store, "alice", PrincipalType.HUMAN, frozenset({Role.APPROVER}))
    with pytest.raises(ValueError):
        create_principal(store, "alice", PrincipalType.HUMAN, frozenset({Role.APPROVER}))


class BrokenStore(PrincipalStore):
    def add(self, stored):
        raise RuntimeError("db down")

    def find_by_token_hash(self, token_hash):
        raise RuntimeError("db down")


def test_store_failure_fails_closed():
    with pytest.raises(AuthProviderUnavailableError):
        TokenAuthProvider(BrokenStore()).authenticate(Req({"Authorization": "Bearer abc"}))
