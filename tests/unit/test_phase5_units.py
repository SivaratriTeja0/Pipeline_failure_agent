"""Notifications, startup validation of unsafe configuration, and the optional poller."""

import httpx
import pytest

from api.container import AppContainer
from api.poller import FailurePoller
from core.config import ConfigurationError, Settings, validate_startup
from notifications.notifier import (
    ConsoleNotifier,
    EmailNotifier,
    FanoutNotifier,
    Notification,
    NotificationKind,
    SlackNotifier,
    build_notifier,
)
from tests.api_helpers import build_api

# ---------------------------------------------------------------- startup validation (B5)

UNSAFE = [
    ({"AUTH_PROVIDER": "demo", "HEALING_EXECUTION_MODE": "LIVE"}, "AUTH_PROVIDER=demo"),
    ({"AUTH_PROVIDER": "demo", "DEMO_MODE": "false"}, "requires DEMO_MODE=true"),
    ({"AUTH_PROVIDER": "token", "HEALING_EXECUTION_MODE": "LIVE", "DEMO_MODE": "false",
      "AIRFLOW_WRITE_TOKEN": "x"}, "HEALING_ENABLED=true"),
    ({"AUTH_PROVIDER": "token", "HEALING_EXECUTION_MODE": "LIVE", "DEMO_MODE": "false",
      "HEALING_ENABLED": "true"}, "AIRFLOW_WRITE_"),
    ({"AUTH_PROVIDER": "token", "HEALING_EXECUTION_MODE": "LIVE", "HEALING_ENABLED": "true",
      "AIRFLOW_WRITE_TOKEN": "x"}, "DEMO_MODE=false"),
    ({"HEALING_EXECUTION_MODE": "SOMETIMES"}, ""),
    ({"HEALING_ENABLED": "maybe"}, ""),
]


@pytest.mark.parametrize("env,message", UNSAFE)
def test_startup_refuses_unsafe_configuration(env, message):
    with pytest.raises(ConfigurationError) as err:
        validate_startup(Settings.from_env({"DATABASE_URL": "sqlite://", **env}))
    assert message in str(err.value)


@pytest.mark.parametrize("env,message", UNSAFE[:5])
def test_the_api_container_refuses_to_start_with_unsafe_configuration(env, message):
    with pytest.raises(ConfigurationError):
        AppContainer(Settings.from_env({"DATABASE_URL": "sqlite://", **env}), {"DATABASE_URL": "sqlite://", **env})


def test_safe_defaults_start():
    validate_startup(Settings.from_env({}))
    live = {"AUTH_PROVIDER": "token", "HEALING_EXECUTION_MODE": "LIVE", "DEMO_MODE": "false",
            "HEALING_ENABLED": "true", "AIRFLOW_WRITE_TOKEN": "x"}
    validate_startup(Settings.from_env(live))


# ---------------------------------------------------------------- notifications (Part Q)


def note() -> Notification:
    return Notification(kind=NotificationKind.TRIAGE, incident_id="inc-1", title="t", fields={"a": 1},
                        link="https://ui/?page=Incident+Details&incident=inc-1")


def test_console_is_the_default_and_channels_come_from_env():
    assert [type(n) for n in build_notifier({}).notifiers] == [ConsoleNotifier]
    env = {"NOTIFY_SLACK_WEBHOOK_URL": "https://hooks.slack.test/x", "NOTIFY_SMTP_HOST": "smtp.test",
           "NOTIFY_EMAIL_FROM": "triage@test", "NOTIFY_EMAIL_TO": "a@test, b@test"}
    assert [type(n) for n in build_notifier(env).notifiers] == [ConsoleNotifier, SlackNotifier, EmailNotifier]


def test_slack_posts_text_and_failures_never_raise():
    seen = []
    ok = SlackNotifier("https://hooks.slack.test/x", http=httpx.Client(transport=httpx.MockTransport(
        lambda r: seen.append(r) or httpx.Response(200))))
    ok.send(note())
    assert b"[TRIAGE]" in seen[0].content
    broken = SlackNotifier("https://hooks.slack.test/x", http=httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(500))))
    broken.send(note())  # logged, not raised
    EmailNotifier("127.0.0.1", 1, "a@test", ["b@test"]).send(note())  # unreachable SMTP: logged, not raised


def test_fanout_isolates_a_failing_channel():
    class Boom(ConsoleNotifier):
        def send(self, notification):
            raise RuntimeError("down")

    console = ConsoleNotifier()
    FanoutNotifier([Boom(), console]).send(note())
    assert len(console.sent) == 1


def test_escalation_and_uncertain_notifications():
    api = build_api(live=True, clear_behavior="running")
    _, view = api.hero_plan()
    api.post(f"/remediation/{view['plan']['remediation_id']}/approve", json=api.approval_body(view))
    kinds = [n.kind.value for n in api.console.sent]
    assert kinds[-2:] == ["VERIFICATION_RESULT", "ESCALATION"]


# ---------------------------------------------------------------- poller (Part N)


def test_poller_finds_failures_through_reads_only_and_dedups():
    api = build_api()
    api.register()
    poller = FailurePoller(api.container)
    first = poller.poll_once()
    assert len(first) == 1 and first[0]["deduplicated"] is None
    second = poller.poll_once()
    assert second[0]["deduplicated"] == "DUPLICATE" and second[0]["incident_id"] == first[0]["incident_id"]
    assert api.state.mutating_requests() == []
    assert len(api.get("/incidents").json()) == 1


# ---------------------------------------------------------------- principal CLI (TokenAuthProvider)


def test_cli_creates_token_principals_and_stores_only_the_hash(tmp_path, monkeypatch, capsys):
    from api.cli import main
    from database.repository import Database, SqlPrincipalStore
    from security.auth import TokenAuthProvider
    from tests.healing_helpers import Req

    url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)
    assert main(["create-principal", "--id", "alice", "--type", "HUMAN", "--roles", "APPROVER,ENGINEER"]) == 0
    token = capsys.readouterr().out.strip().rsplit(": ", 1)[1]
    store = SqlPrincipalStore(Database(url))
    assert store.find_by_id("alice").token_hash != token
    assert TokenAuthProvider(store).authenticate(Req({"Authorization": f"Bearer {token}"})).principal_id == "alice"
    main(["disable-principal", "--id", "alice"])
    assert TokenAuthProvider(store).authenticate(Req({"Authorization": f"Bearer {token}"})) is None
    with pytest.raises(SystemExit):
        main(["create-principal", "--id", "bob", "--roles", "BOSS"])
