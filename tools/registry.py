"""Read-only investigation tool registry (spec Part K).

Registration enforces, at import time of whichever module registers the tool:
- ``read_only`` must be True;
- the name must not begin with a mutation verb;
- the tool must map to a read method of PipelineAdapter (never anything else).
"""

import re
from collections.abc import Iterator

from pydantic import BaseModel, ConfigDict

from adapters.base.interfaces import PipelineAdapter
from core.models.enums import ReadCapability
from core.models.reads import ReadRequest, ReadResult

MUTATION_VERBS = frozenset(
    {
        "create", "insert", "update", "delete", "merge", "drop", "alter", "truncate", "run", "rerun",
        "retry", "trigger", "restart", "clear", "set", "write", "grant", "revoke", "pause", "unpause",
        "approve", "execute", "heal", "remediate",
    }
)

# Read methods an investigation tool may bind to: the 17 read methods of PipelineAdapter.
ADAPTER_READ_METHODS = frozenset(
    {
        "get_run_output", "get_run_history", "get_task_state", "get_pipeline_state", "get_schema",
        "compare_schema", "get_row_counts", "get_data_quality_results", "get_transaction_history",
        "get_state", "get_code_changes", "get_lineage", "get_upstream_status", "get_downstream_status",
        "get_infrastructure_events", "get_configuration", "get_permissions",
    }
)
if not ADAPTER_READ_METHODS <= set(dir(PipelineAdapter)):
    raise ImportError("ADAPTER_READ_METHODS is out of sync with PipelineAdapter")

_TOKEN = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


class ToolRegistrationError(ValueError):
    """Raised when a tool violates the read-only contract."""


class ToolSpec(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str
    description: str
    input_schema: type[BaseModel] = ReadRequest
    output_schema: type[BaseModel] = ReadResult
    read_only: bool
    required_capability: ReadCapability
    adapter_method: str

    def llm_view(self) -> dict[str, object]:
        """What the LLM sees: name, description and input schema. Nothing executable."""
        return {"name": self.name, "description": self.description,
                "input_schema": self.input_schema.model_json_schema()}


def first_token(name: str) -> str:
    tokens = [t.lower() for part in re.split(r"[_\-\s.]+", name) for t in _TOKEN.findall(part)]
    return tokens[0] if tokens else ""


def validate_spec(spec: ToolSpec) -> None:
    if spec.read_only is not True:
        raise ToolRegistrationError(f"tool {spec.name!r} is not read_only; mutation tools are forbidden")
    verb = first_token(spec.name)
    if verb in MUTATION_VERBS:
        raise ToolRegistrationError(f"tool {spec.name!r} begins with mutation verb {verb!r}")
    if spec.adapter_method not in ADAPTER_READ_METHODS:
        raise ToolRegistrationError(
            f"tool {spec.name!r} binds to {spec.adapter_method!r}, which is not an adapter read method"
        )


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> ToolSpec:
        validate_spec(spec)
        if spec.name in self._tools:
            raise ToolRegistrationError(f"tool {spec.name!r} already registered")
        self._tools[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def __iter__(self) -> Iterator[ToolSpec]:
        return iter(sorted(self._tools.values(), key=lambda s: s.name))

    def __len__(self) -> int:
        return len(self._tools)
