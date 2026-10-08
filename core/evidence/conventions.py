"""Platform-neutral evidence conventions that deterministic code may rely on.

Adapters describe observed facts in ``EvidenceItem.metadata`` using these keys, so core logic
never parses platform-specific payloads:

- ``observed_task_states``: list of {task_id, map_index, attempt, state} for the incident's task.
- ``concurrency``: "NONE_CONFIRMED" | "OVERLAP_CONFIRMED" (other active runs of the pipeline).
- ``cause_cleared_candidate``: bool - the item may show that the failure cause has changed.
- ``dq_result``: {gate_failed, target_corrupted, bad_records_quarantined} from a DQ system.
- ``cause_cleared_for``: optional list of failure-category values the cause-cleared candidate
  speaks to (e.g. an overlapping run that finished only shows a CONCURRENCY cause cleared).
- ``fix_attestation``: bool - a human attested a manual fix (MEDIUM reliability; not proof).

Pipelines may also emit instrumentation markers in their own task logs, one per line:

    [triage] target_write=none_confirmed failure_stage=pre_write

Markers are accepted only from CURRENT, HIGH-reliability LOG evidence of the failed attempt
(the platform's own log), are parsed by a strict pattern, and are never taken from LLM output.
They are an opt-in convention: a pipeline that does not emit them yields UNKNOWN facts.
"""

import re

OBSERVED_TASK_STATES = "observed_task_states"
CONCURRENCY = "concurrency"
CAUSE_CLEARED_CANDIDATE = "cause_cleared_candidate"
DQ_RESULT = "dq_result"
CAUSE_CLEARED_FOR = "cause_cleared_for"
FIX_ATTESTATION = "fix_attestation"

MARKER_RE = re.compile(r"^(?:\[[^\]]*\]\s*)*(?:[A-Z]+\s+-\s+)?\[triage\]((?:\s+[a-z_]+=[a-z_]+)+)\s*$", re.MULTILINE)
_PAIR_RE = re.compile(r"([a-z_]+)=([a-z_]+)")

MARKER_VALUES: dict[str, frozenset[str]] = {
    "target_write": frozenset({"none_confirmed", "committed", "partial_confirmed", "partial_possible", "unknown"}),
    "failure_stage": frozenset({"pre_write", "mid_write", "post_write", "unknown"}),
}


def parse_markers(text: str) -> dict[str, str]:
    """Return the last valid value for each known marker key. Unknown keys/values are ignored."""
    found: dict[str, str] = {}
    for match in MARKER_RE.finditer(text):
        for key, value in _PAIR_RE.findall(match.group(1)):
            if key in MARKER_VALUES and value in MARKER_VALUES[key]:
                found[key] = value
    return found
