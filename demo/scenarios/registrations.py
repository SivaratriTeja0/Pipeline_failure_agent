"""DEMO pipeline registrations used with FAKE AIRFLOW (DEMO) scenarios."""

from core.models.enums import ActionType, StateMechanism, TaskType, WriteMode
from core.models.pipeline import PipelineRegistration
from core.models.policy import TaskExecutionPolicy

SALES_ETL = PipelineRegistration(
    pipeline_id="sales_etl",
    pipeline_name="Sales ETL (DEMO)",
    platform="airflow",
    environment="production",
    healing_enabled=False,
    allowed_actions=[ActionType.RETRY_FAILED_TASK, ActionType.RETRY_FAILED_DAG_RUN],
    approver_ids=["demo-engineer", "demo-approver-2"],
    task_policies={
        "extract": TaskExecutionPolicy(task_type=TaskType.SNAPSHOT, write_mode=WriteMode.OVERWRITE, idempotent=True,
                                       state_mechanism=StateMechanism.NONE, concurrency_behavior="forbid_overlap"),
        "load": TaskExecutionPolicy(task_type=TaskType.UPSERT, write_mode=WriteMode.MERGE, idempotent=True,
                                    state_mechanism=StateMechanism.NONE, retry_behavior="clear_and_rerun",
                                    concurrency_behavior="forbid_overlap"),
        "publish": TaskExecutionPolicy(task_type=TaskType.OVERWRITE, write_mode=WriteMode.OVERWRITE, idempotent=True,
                                       state_mechanism=StateMechanism.NONE, concurrency_behavior="forbid_overlap"),
    },
)

_IDEMPOTENT = TaskExecutionPolicy(task_type=TaskType.OVERWRITE, write_mode=WriteMode.OVERWRITE, idempotent=True,
                                  state_mechanism=StateMechanism.NONE, concurrency_behavior="forbid_overlap")

ORDERS_ETL = PipelineRegistration(
    pipeline_id="orders_etl",
    pipeline_name="Orders ETL (DEMO)",
    platform="airflow",
    environment="production",
    healing_enabled=False,
    allowed_actions=[ActionType.RETRY_FAILED_TASK, ActionType.RETRY_FAILED_DAG_RUN],
    approver_ids=["demo-engineer", "demo-approver-2"],
    task_policies={t: _IDEMPOTENT for t in ("extract_orders", "extract_customers", "merge", "publish")},
)
