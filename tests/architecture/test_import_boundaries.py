"""Platform independence and import boundaries (spec B2, invariant I3).

Each rule is checked against the real codebase, and each checker is also proven to detect
a synthetic violation (so a rule cannot silently pass because a directory is still empty).
"""

import pytest

from tests.architecture import scanner as sc

INVESTIGATION_SIDE = ("core", "agent", "tools", "security")


def _scan(dirs, check):
    problems = []
    for path in sc.python_files(*dirs):
        result = check(path)
        problems.extend(f"{path.relative_to(sc.REPO_ROOT)}: {p}" for p in result)
    return problems


def test_scanner_sees_the_codebase():
    files = sc.python_files(*INVESTIGATION_SIDE)
    assert len(files) > 20
    assert any(p.name == "selector.py" for p in files)


# ---------------------------------------------------------------- rule 1


def test_investigation_side_never_imports_actions_adapters_or_platform_sdks():
    def check(path):
        refs = sc.imports_of(path)
        return (
            sc.forbidden_import_violations(refs, ("actions", *sc.PLATFORM_SDKS))
            + sc.adapter_platform_violations(refs)
        )

    assert _scan(INVESTIGATION_SIDE, check) == []


def test_agent_and_tools_never_import_actions():
    assert _scan(("agent", "tools"), lambda p: sc.forbidden_import_violations(sc.imports_of(p), ("actions",))) == []


# ---------------------------------------------------------------- rule 2


def test_actions_never_import_platform_sdks():
    assert _scan(("actions",), lambda p: sc.forbidden_import_violations(sc.imports_of(p), sc.PLATFORM_SDKS)) == []


def test_only_airflow_actions_module_speaks_http_inside_actions():
    def check(path):
        if path.relative_to(sc.REPO_ROOT).as_posix() == "actions/airflow_actions.py":
            return []
        return sc.forbidden_import_violations(sc.imports_of(path), ("httpx", "requests", "aiohttp", "urllib3"))

    assert _scan(("actions",), check) == []


# ---------------------------------------------------------------- rule 3


def test_core_remediation_has_no_execution_capability():
    def check(path):
        source = path.read_text(encoding="utf-8")
        refs = sc.imports_of(path)
        problems = sc.forbidden_import_violations(refs, (*sc.HTTP_AND_PROCESS_MODULES, "actions", "adapters"))
        problems += [f"line {n}: dangerous call" for n in sc.dangerous_call_lines(source)]
        return problems

    assert _scan(("core/remediation",), check) == []


# ---------------------------------------------------------------- rule 4


def test_airflow_action_client_constructed_only_inside_actions():
    problems = []
    for path in sc.all_source_files():
        rel = path.relative_to(sc.REPO_ROOT).as_posix()
        if rel.startswith("actions/"):
            continue
        for line in sc.constructs(path.read_text(encoding="utf-8"), "AirflowActionClient"):
            problems.append(f"{rel}:{line}")
    assert problems == []


def test_only_api_imports_the_executor():
    problems = []
    for path in sc.all_source_files():
        rel = path.relative_to(sc.REPO_ROOT).as_posix()
        if rel.startswith(("api/", "actions/executor/")):
            continue
        problems += [f"{rel}: {p}" for p in sc.forbidden_import_violations(sc.imports_of(path), ("actions.executor",))]
    assert problems == []


# ---------------------------------------------------------------- rule 5


def test_no_platform_branching_in_core():
    problems = []
    for path in sc.python_files("core"):
        for line in sc.platform_branch_lines(path.read_text(encoding="utf-8")):
            problems.append(f"{path.relative_to(sc.REPO_ROOT)}:{line}")
    assert problems == []


# ---------------------------------------------------------------- the checkers themselves catch violations


@pytest.mark.parametrize(
    "source,module,is_pkg,forbidden",
    [
        ("import actions.executor", "core.x", False, ("actions",)),
        ("from actions import registry", "agent.x", False, ("actions",)),
        ("from ...actions.executor import run", "core.remediation.x", False, ("actions",)),
        ("from ...actions import policy", "tools.sub", True, ("actions",)),
        ("import importlib\nimportlib.import_module('actions.executor')", "tools.x", False, ("actions",)),
        ("__import__('airflow.models')", "core.x", False, ("airflow",)),
        ("from airflow.models import DagRun", "core.x", False, ("airflow",)),
        ("import httpx", "core.remediation.x", False, ("httpx",)),
        ("from subprocess import run", "core.remediation.x", False, ("subprocess",)),
    ],
)
def test_import_checker_detects_violations(source, module, is_pkg, forbidden):
    refs = sc.collect_imports(source, module, is_pkg)
    assert sc.forbidden_import_violations(refs, forbidden)


def test_import_checker_ignores_similarly_named_modules():
    refs = sc.collect_imports("import actionsx\nfrom core.actions_view import y", "core.x")
    assert sc.forbidden_import_violations(refs, ("actions",)) == []


def test_adapter_checker():
    assert sc.adapter_platform_violations(sc.collect_imports("from adapters.airflow import client"))
    assert sc.adapter_platform_violations(sc.collect_imports("import adapters.generic.adapter"))
    assert not sc.adapter_platform_violations(sc.collect_imports("from adapters.base import PipelineAdapter"))


def test_platform_branch_checker():
    assert sc.platform_branch_lines("if platform == 'airflow':\n    pass")
    assert sc.platform_branch_lines("if event.platform in ('Airflow', 'x'):\n    pass")
    assert sc.platform_branch_lines("match p:\n    case 'airflow':\n        pass")
    assert not sc.platform_branch_lines("x = 'airflow'\nif p == 'generic':\n    pass")


def test_construction_checker():
    assert sc.constructs("c = AirflowActionClient(url)", "AirflowActionClient") == [1]
    assert sc.constructs("c = mod.AirflowActionClient()", "AirflowActionClient") == [1]
    assert sc.constructs("from actions import AirflowActionClient", "AirflowActionClient") == []


def test_dangerous_call_checker():
    assert sc.dangerous_call_lines("import os\nos.system('ls')")
    assert sc.dangerous_call_lines("eval('1')")
    assert not sc.dangerous_call_lines("os.path.join('a')")


# ---------------------------------------------------------------- Phase 2: read side


def test_adapters_never_import_actions():
    assert _scan(("adapters",), lambda p: sc.forbidden_import_violations(sc.imports_of(p), ("actions",))) == []


def test_application_code_never_imports_demo_fakes():
    dirs = ("core", "agent", "tools", "security", "adapters", "actions")
    assert _scan(dirs, lambda p: sc.forbidden_import_violations(sc.imports_of(p), ("demo", "tests"))) == []


def test_only_airflow_adapter_speaks_http_on_the_read_side():
    def check(path):
        if path.relative_to(sc.REPO_ROOT).as_posix().startswith("adapters/airflow/"):
            return []
        return sc.forbidden_import_violations(sc.imports_of(path), ("httpx", "requests", "aiohttp", "urllib3"))

    assert _scan(("adapters", "core", "tools", "agent", "security"), check) == []


# ---------------------------------------------------------------- Phase 5: persistence, API, UI, notifications


def test_frontend_is_a_pure_http_client():
    server_side = ("api", "actions", "core", "database", "agent", "adapters", "security", "tools", "demo",
                   "notifications")
    assert sc.python_files("frontend"), "frontend not found"
    assert _scan(("frontend",), lambda p: sc.forbidden_import_violations(sc.imports_of(p), server_side)) == []


def test_investigation_side_never_imports_api_database_or_notifications():
    forbidden = ("api", "database", "notifications")
    assert _scan(INVESTIGATION_SIDE, lambda p: sc.forbidden_import_violations(sc.imports_of(p), forbidden)) == []


def test_persistence_and_notifications_cannot_reach_the_executor_or_platform_http():
    assert _scan(("database",), lambda p: sc.forbidden_import_violations(
        sc.imports_of(p), ("httpx", "requests", "actions.executor", "actions.airflow_actions"))) == []
    assert _scan(("notifications",), lambda p: sc.forbidden_import_violations(sc.imports_of(p), ("actions",))) == []
