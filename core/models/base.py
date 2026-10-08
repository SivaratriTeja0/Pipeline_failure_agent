"""Shared base model and identifier patterns."""

import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

# Strict identifier patterns (spec M: IDs used in platform URLs must match strict patterns).
# dag_run_id permits ':' and '+' because Airflow run ids embed ISO timestamps.
PIPELINE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,249}$"
TASK_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,249}$"
RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:+\-]{0,249}$"

PIPELINE_ID_RE = re.compile(PIPELINE_ID_PATTERN)
TASK_ID_RE = re.compile(TASK_ID_PATTERN)
RUN_ID_RE = re.compile(RUN_ID_PATTERN)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Base for all domain models: unknown fields are rejected (LLM output included)."""

    model_config = ConfigDict(extra="forbid", validate_default=True)
