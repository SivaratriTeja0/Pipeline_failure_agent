"""README completeness (Phase 6): every required section, Mermaid diagrams, the positioning statement,
and the mock caveat."""

from pathlib import Path

README = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")

SECTIONS = [
    "Problem", "Architecture", "Investigation vs healing: the trust boundary", "Why adapters",
    "Capability discovery", "Evidence model and provenance", "Failure taxonomy", "Hypothesis loop",
    "State abstraction", "Rerun safety", "Remediation classes and eligibility", "Deterministic action selection",
    "Recovery scope", "Remediation confidence", "Approval workflow and auth providers",
    "Policy and live re-validation", "Executor: write-ahead and idempotency", "Verification and its limits (state-only)",
    "Re-investigation and cycle limit", "Kill switches and modes", "Security model", "Airflow least-privilege roles",
    "First live test procedure", "Generic platform onboarding", "API", "UI", "Demos", "Hero demo, step by step",
    "Evaluation", "Installation", "Environment variables", "Running locally", "Running tests",
    "Adding a new platform", "Limitations", "Roadmap",
]


def test_every_required_section_is_present():
    headings = {line.lstrip("#").strip() for line in README.splitlines() if line.startswith("#")}
    missing = [s for s in SECTIONS if s not in headings]
    assert not missing, missing


def test_mermaid_diagrams_positioning_and_caveats():
    assert README.count("```mermaid") >= 4
    assert "It does not blindly retry pipelines" in README
    assert "not diagnostic accuracy" in README and "state-only" in README.lower()
    for rule in [f"| R{n} |" for n in range(1, 14)]:
        assert rule in README, rule
    for env in ("HEALING_ENABLED", "HEALING_EXECUTION_MODE", "AUTH_PROVIDER", "WEBHOOK_SECRET", "AIRFLOW_WRITE_"):
        assert env in README
