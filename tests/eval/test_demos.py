"""All demos run in DEMO MODE (as real processes, exactly as documented in the README)."""

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def run(*args: str) -> str:
    proc = subprocess.run([sys.executable, "-m", *args], cwd=REPO, capture_output=True, text=True, timeout=600,
                          env={"PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
                               "PYTHONPATH": str(REPO)})
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    return proc.stdout


@pytest.mark.parametrize("scenario", ["hero_transient_network", "cascade_upstream_failed", "transient_recovered",
                                      "schema_drift"])
def test_triage_demo_runs(scenario):
    out = run("demo.scenarios.run_triage", scenario)
    assert "DEMO - FAKE AIRFLOW (DEMO) - llm_mode=MOCK" in out and "chain valid: True" in out


def test_hero_healing_demo_runs_in_dry_run_and_live_against_the_fake():
    dry = run("demo.scenarios.run_healing")
    assert "DRY_RUN" in dry and "(none)" in dry and "would have cleared 2 task instance(s)" in dry
    live = run("demo.scenarios.run_healing", "--live")
    assert "incident=RESOLVED" in live and "dry_run=False task_ids=['load', 'publish']" in live
    assert "INCIDENT_RESOLVED" in live and "chain valid: True" in live


def test_all_scenarios_demo_runs():
    out = run("demo.scenarios.run_all")
    assert "25/25 scenarios behaved as expected." in out and "MOCK CAVEAT" in out


def test_evaluator_cli_runs_in_mock_mode():
    out = run("evaluation.evaluator", "--only", "S01,S17")
    assert "MOCK CAVEAT" in out and '"approval_bypass_count": 0' in out
