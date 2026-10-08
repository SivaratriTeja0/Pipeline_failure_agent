"""Read-only tool registry (Part K): import-time enforcement, allowlist, invoker."""

import importlib
import sys
import textwrap

import pytest

from core.models import ActionCapability, ActionType, ReadCapability
from core.models.reads import ReadRequest, ReadResult, ReadStatus
from tools.catalog import READ_ONLY_TOOLS
from tools.invoker import ToolInputError, ToolInvoker, ToolNotAllowedError, llm_allowlist, tool_availability
from tools.registry import MUTATION_VERBS, ToolRegistrationError, ToolRegistry, ToolSpec, first_token

SPEC_TOOLS = {
    "get_run_output", "get_run_history", "get_task_state", "get_pipeline_state", "get_schema", "compare_schema",
    "get_row_counts", "get_data_quality_results", "get_transaction_history", "get_state", "get_code_changes",
    "get_lineage", "get_upstream_status", "get_downstream_status", "get_infrastructure_events",
    "get_configuration", "get_permissions",
}


def spec(name="get_thing", read_only=True, method="get_schema"):
    return ToolSpec(name=name, description="d", read_only=read_only,
                    required_capability=ReadCapability.SCHEMA, adapter_method=method)


def test_catalog_is_exactly_the_spec_tool_set_and_all_read_only():
    assert set(READ_ONLY_TOOLS.names()) == SPEC_TOOLS
    assert all(t.read_only for t in READ_ONLY_TOOLS)


@pytest.mark.parametrize("verb", sorted(MUTATION_VERBS))
def test_mutation_verb_names_rejected(verb):
    with pytest.raises(ToolRegistrationError, match="mutation verb"):
        ToolRegistry().register(spec(name=f"{verb}_dag_run"))


@pytest.mark.parametrize("name", ["clearTaskInstances", "RetryFailedTask", "trigger-dag", "Set.Variable", "DELETE_RUN"])
def test_mutation_verbs_rejected_in_any_naming_style(name):
    with pytest.raises(ToolRegistrationError):
        ToolRegistry().register(spec(name=name))


def test_read_only_false_rejected():
    with pytest.raises(ToolRegistrationError, match="not read_only"):
        ToolRegistry().register(spec(read_only=False))


def test_tool_must_bind_to_adapter_read_method():
    with pytest.raises(ToolRegistrationError, match="not an adapter read method"):
        ToolRegistry().register(spec(method="dispatch"))
    with pytest.raises(ToolRegistrationError):
        ToolRegistry().register(spec(method="normalize_failure"))


def test_duplicate_rejected():
    reg = ToolRegistry()
    reg.register(spec())
    with pytest.raises(ToolRegistrationError):
        reg.register(spec())


def test_first_token():
    assert first_token("get_run_output") == "get"
    assert first_token("clearTaskInstances") == "clear"
    assert first_token("health_check") == "health"


def test_bad_registration_fails_at_import_time(tmp_path, monkeypatch):
    module = tmp_path / "rogue_tools.py"
    module.write_text(textwrap.dedent("""
        from core.models.enums import ReadCapability
        from tools.registry import ToolRegistry, ToolSpec
        REG = ToolRegistry()
        REG.register(ToolSpec(name="rerun_dag", description="x", read_only=True,
                               required_capability=ReadCapability.RUN_LOGS, adapter_method="get_run_output"))
    """), encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    with pytest.raises(ToolRegistrationError):
        importlib.import_module("rogue_tools")
    sys.modules.pop("rogue_tools", None)


def test_llm_facing_registry_contains_zero_action_names():
    action_names = {a.value.lower() for a in ActionType} | {c.value for c in ActionCapability}
    for tool in llm_allowlist(frozenset(ReadCapability)):
        assert tool.name.lower() not in action_names
        assert first_token(tool.name) not in MUTATION_VERBS
        view = tool.llm_view()
        assert set(view) == {"name", "description", "input_schema"}


# ---------------------------------------------------------------- allowlist and invoker


class SpyAdapter:
    """Minimal adapter double that records calls (PipelineAdapter duck type)."""

    platform = "spy"
    demo = False

    def __init__(self, caps):
        self.caps = caps
        self.calls = []

    def read_capabilities(self):
        return self.caps

    def __getattr__(self, name):
        if name.startswith("get_") or name == "compare_schema":
            def method(req):
                self.calls.append((name, req))
                if name == "get_lineage":
                    raise RuntimeError("adapter bug")
                return ReadResult(tool=name, status=ReadStatus.AVAILABLE)
            return method
        raise AttributeError(name)


INCIDENT = ReadRequest(pipeline_id="sales_etl", execution_id="run-1", task_id="load")


def test_allowlist_is_registry_intersect_capabilities():
    caps = frozenset({ReadCapability.RUN_LOGS, ReadCapability.RUN_HISTORY})
    names = {t.name for t in llm_allowlist(caps)}
    assert names == {"get_run_output", "get_run_history", "get_task_state", "get_pipeline_state"}
    availability = tool_availability(caps)
    assert availability["get_schema"] is ReadStatus.UNAVAILABLE
    assert availability["get_run_output"] is ReadStatus.AVAILABLE


def test_unsupported_tool_yields_unavailable_and_is_never_called():
    adapter = SpyAdapter(frozenset({ReadCapability.RUN_LOGS}))
    invoker = ToolInvoker(adapter)
    result = invoker.invoke("get_schema", INCIDENT)
    assert result.status is ReadStatus.UNAVAILABLE and result.evidence == []
    assert adapter.calls == []
    assert "get_schema" not in invoker.allowlist()


def test_unknown_or_action_tool_names_rejected():
    invoker = ToolInvoker(SpyAdapter(frozenset(ReadCapability)))
    for name in ("clear_task_instances", "RETRY_FAILED_TASK", "dispatch", "shell"):
        with pytest.raises(ToolNotAllowedError):
            invoker.invoke(name, INCIDENT)


def test_identifiers_are_bound_to_the_incident():
    adapter = SpyAdapter(frozenset(ReadCapability))
    invoker = ToolInvoker(adapter)
    for args in ({"pipeline_id": "other_dag"}, {"execution_id": "x"}, {"investigation_cycle": 9}, {"sql": "DROP"}):
        with pytest.raises(ToolInputError):
            invoker.invoke("get_run_output", INCIDENT, args)
    with pytest.raises(ToolInputError):
        invoker.invoke("get_run_output", INCIDENT, {"task_id": "../../x"})
    with pytest.raises(ToolInputError):
        invoker.invoke("get_run_output", INCIDENT, {"limit": 10_000})
    invoker.invoke("get_run_output", INCIDENT, {"task_id": "publish", "limit": 3})
    _, req = adapter.calls[-1]
    assert (req.pipeline_id, req.execution_id, req.task_id, req.limit) == ("sales_etl", "run-1", "publish", 3)


def test_adapter_exception_becomes_error_result():
    invoker = ToolInvoker(SpyAdapter(frozenset(ReadCapability)))
    result = invoker.invoke("get_lineage", INCIDENT)
    assert result.status is ReadStatus.ERROR and result.evidence == []
