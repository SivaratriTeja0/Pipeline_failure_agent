"""The optional live-test kit: its safety guards and the throwaway DAG's fail-once logic (no Docker needed)."""

import importlib.util
from pathlib import Path

import pytest

from core.evidence.conventions import parse_markers
from demo.live_test.run_live_hero import Refused, check_environment

REPO = Path(__file__).resolve().parents[2]
LIVE = {"AIRFLOW_API_BASE_URL": "http://localhost:8080", "AIRFLOW_READ_USERNAME": "triage_reader",
        "AIRFLOW_READ_PASSWORD": "r", "AIRFLOW_WRITE_USERNAME": "triage_writer", "AIRFLOW_WRITE_PASSWORD": "w",
        "HEALING_ENABLED": "true", "HEALING_EXECUTION_MODE": "LIVE", "DEMO_MODE": "false", "AUTH_PROVIDER": "token"}


def test_live_runner_accepts_only_a_fully_configured_local_live_setup():
    assert check_environment(LIVE).healing_execution_mode.value == "LIVE"


@pytest.mark.parametrize("override", [
    {"AIRFLOW_API_BASE_URL": "https://airflow.prod.example.com"},
    {"AIRFLOW_API_BASE_URL": ""},
    {"AIRFLOW_WRITE_PASSWORD": ""},
    {"AIRFLOW_WRITE_USERNAME": "triage_reader"},
    {"HEALING_EXECUTION_MODE": "DRY_RUN"},
    {"AUTH_PROVIDER": "demo"},
    {"HEALING_ENABLED": "false"},
])
def test_live_runner_refuses_unsafe_or_incomplete_setups(override):
    with pytest.raises(Refused):
        check_environment({**LIVE, **override})


def _logic():
    spec = importlib.util.spec_from_file_location("live_test_logic", REPO / "demo/live_test/dags/live_test_logic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_live_dag_fails_once_with_a_connection_reset_then_succeeds(tmp_path):
    logic = _logic()
    logged = []
    with pytest.raises(ConnectionResetError, match="Connection reset by peer"):
        logic.load("manual__2026-10-09T10:00:00+00:00", log=logged.append, marker_dir=tmp_path)
    assert logic.load("manual__2026-10-09T10:00:00+00:00", log=logged.append, marker_dir=tmp_path) == "loaded"
    assert parse_markers(logged[0]) == {"target_write": "none_confirmed", "failure_stage": "pre_write"}


def test_live_kit_pins_versions_and_never_uses_admin_for_the_agent():
    compose = (REPO / "demo/live_test/docker-compose.yml").read_text(encoding="utf-8")
    assert "apache/airflow:2.10.5" in compose and "basic_auth" in compose
    setup = (REPO / "demo/live_test/setup_users.sh").read_text(encoding="utf-8")
    assert "--role Viewer --username triage_reader" in setup and "--role TriageClear --username triage_writer" in setup
    assert "Admin" not in setup
