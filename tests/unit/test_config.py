"""Settings defaults (Rule 6) and startup validation (B5)."""

import pytest

from core.config import AuthProviderName, ConfigurationError, ExecutionMode, Settings, validate_startup


def test_safe_defaults():
    s = Settings.from_env({})
    assert s.demo_mode is True
    assert s.healing_enabled is False
    assert s.healing_execution_mode is ExecutionMode.DRY_RUN
    assert s.auth_provider is AuthProviderName.DEMO
    assert s.max_healing_cycles == 2 and s.high_risk_approvals == 2
    validate_startup(s)


LIVE_OK = {
    "HEALING_EXECUTION_MODE": "LIVE",
    "HEALING_ENABLED": "true",
    "DEMO_MODE": "false",
    "AUTH_PROVIDER": "token",
    "AIRFLOW_WRITE_USERNAME": "w",
    "AIRFLOW_WRITE_PASSWORD": "p",
}


def test_live_with_everything_deliberately_set_is_accepted():
    validate_startup(Settings.from_env(LIVE_OK))


@pytest.mark.parametrize(
    "override,msg",
    [
        ({"AUTH_PROVIDER": "demo"}, "AUTH_PROVIDER=demo"),
        ({"HEALING_ENABLED": "false"}, "HEALING_ENABLED"),
        ({"DEMO_MODE": "true"}, "DEMO_MODE"),
        ({"AIRFLOW_WRITE_PASSWORD": ""}, "AIRFLOW_WRITE"),
    ],
)
def test_live_refuses_unsafe_combinations(override, msg):
    env = {**LIVE_OK, **override}
    with pytest.raises(ConfigurationError, match=msg):
        validate_startup(Settings.from_env(env))


def test_invalid_values_fail_fast():
    with pytest.raises(ConfigurationError):
        Settings.from_env({"HEALING_EXECUTION_MODE": "YOLO"})
    with pytest.raises(ConfigurationError):
        Settings.from_env({"HEALING_ENABLED": "maybe"})
    with pytest.raises(ConfigurationError):
        Settings.from_env({"MAX_TASKS_CLEARED": "lots"})
