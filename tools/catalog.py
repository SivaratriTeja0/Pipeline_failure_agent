"""The 17 read-only investigation tools, registered at import time (a bad spec fails the import)."""

from core.models.enums import ReadCapability as RC
from tools.registry import ToolRegistry, ToolSpec

READ_ONLY_TOOLS = ToolRegistry()

_CATALOG: tuple[tuple[str, str, RC], ...] = (
    ("get_run_output", "Bounded log excerpt and stack trace for the failed task attempt(s).", RC.RUN_LOGS),
    ("get_run_history", "Recent runs of the pipeline and later activity on shared resources.", RC.RUN_HISTORY),
    ("get_task_state", "Current orchestrator state of a task's instances in this run.", RC.RUN_HISTORY),
    ("get_pipeline_state", "Current state of this run and counts of task states.", RC.RUN_HISTORY),
    ("get_schema", "Current schema of the source/target datasets.", RC.SCHEMA),
    ("compare_schema", "Differences between current and previous schema.", RC.SCHEMA),
    ("get_row_counts", "Row counts for the affected datasets.", RC.ROW_COUNTS),
    ("get_data_quality_results", "Data-quality rule results, severities and rejected records.", RC.DATA_QUALITY),
    ("get_transaction_history", "Commits / transactions written by this run.", RC.TRANSACTION_HISTORY),
    ("get_state", "Pipeline state mechanism (watermark, checkpoint, offset, ...) before and after.", RC.STATE_TRACKING),
    ("get_code_changes", "Recent code changes affecting this pipeline.", RC.CODE_CHANGES),
    ("get_lineage", "Upstream and downstream datasets of this pipeline.", RC.LINEAGE),
    ("get_upstream_status", "Status of upstream tasks in this run.", RC.UPSTREAM_STATUS),
    ("get_downstream_status", "Status of downstream tasks in this run.", RC.DOWNSTREAM_STATUS),
    ("get_infrastructure_events", "Infrastructure events around the failure time.", RC.INFRASTRUCTURE_EVENTS),
    ("get_configuration", "Pipeline and task configuration (secret values withheld).", RC.CONFIGURATION),
    ("get_permissions", "Permissions of the pipeline's identity on affected objects.", RC.PERMISSIONS),
)

for _name, _description, _capability in _CATALOG:
    READ_ONLY_TOOLS.register(
        ToolSpec(name=_name, description=_description, read_only=True,
                 required_capability=_capability, adapter_method=_name)
    )
