"""Normalizer and deterministic pre-classifier (Part E)."""

import pytest

from core.evidence.normalizer import NormalizedSignal as N
from core.models import ReadCapability
from core.taxonomy import FailureCategory as FC
from core.taxonomy.preclassifier import preclassify


@pytest.mark.parametrize(
    "text,signal,candidates",
    [
        ("AnalysisException: Column 'amount' not found", N.SCHEMA_COLUMN_MISMATCH,
         [FC.SOURCE_SCHEMA_DRIFT, FC.CODE_LOGIC_BUG, FC.CONFIGURATION]),
        ("cannot resolve column foo", N.SCHEMA_COLUMN_MISMATCH, None),
        ("unresolved column bar", N.SCHEMA_COLUMN_MISMATCH, None),
        ("invalid column reference x", N.SCHEMA_COLUMN_MISMATCH, None),
        ("ERROR: permission denied for table orders", N.AUTHORIZATION_FAILURE, [FC.SECURITY_AUTHORIZATION]),
        ("Access Denied (Service: S3)", N.AUTHORIZATION_FAILURE, None),
        ("HTTP 403 Forbidden", N.AUTHORIZATION_FAILURE, None),
        ("java.lang.OutOfMemoryError: out of memory", N.RESOURCE_MEMORY_FAILURE,
         [FC.RESOURCE_QUOTA, FC.VOLUME_ANOMALY, FC.CODE_LOGIC_BUG]),
        ("container OOMKilled", N.RESOURCE_MEMORY_FAILURE, None),
        ("memory limit exceeded", N.RESOURCE_MEMORY_FAILURE, None),
        ("psycopg2.OperationalError: connection refused", N.NETWORK_CONNECTIVITY_FAILURE,
         [FC.NETWORK_CONNECTIVITY, FC.INFRASTRUCTURE]),
        ("ConnectionResetError: Connection reset by peer", N.NETWORK_CONNECTIVITY_FAILURE, None),
        ("unable to connect to host", N.NETWORK_CONNECTIVITY_FAILURE, None),
        ("Read timed out", N.TIMEOUT, [FC.NETWORK_CONNECTIVITY, FC.RESOURCE_QUOTA, FC.UPSTREAM_DEPENDENCY]),
        ("Timeout waiting for lock", N.TIMEOUT, None),
        ("Table or view not found: sales.orders", N.MISSING_OBJECT,
         [FC.CONFIGURATION, FC.SOURCE_SCHEMA_DRIFT, FC.UPSTREAM_DEPENDENCY]),
        ("object dbo.x does not exist", N.MISSING_OBJECT, None),
        ("Quota exceeded for project", N.QUOTA_EXCEEDED, [FC.RESOURCE_QUOTA]),
        ("429 rate limit", N.QUOTA_EXCEEDED, None),
        ("request throttled", N.QUOTA_EXCEEDED, None),
        ("DQ gate failed: null_rate > 5%", N.DQ_GATE_FAILURE, [FC.DATA_QUALITY]),
        ("Expectation failed: expect_column_values_to_not_be_null", N.DQ_GATE_FAILURE, None),
        ("task state: upstream_failed", N.UPSTREAM_FAILED, [FC.UPSTREAM_DEPENDENCY]),
        ("duplicate key value violates unique constraint", N.DUPLICATE_KEY,
         [FC.DATA_QUALITY, FC.CODE_LOGIC_BUG, FC.CONCURRENCY, FC.ORCHESTRATION_STATE]),
    ],
)
def test_signal_table(text, signal, candidates):
    results = preclassify(text)
    match = next(r for r in results if r.normalized_signal is signal)
    if candidates is not None:
        assert match.candidate_categories == candidates


def test_raw_signal_preserved():
    text = "line one\n2026-10-08 ERROR Connection reset by peer while reading\nline three"
    (r,) = preclassify(text)
    assert r.raw_signal == "2026-10-08 ERROR Connection reset by peer while reading"
    assert r.normalized_signal is N.NETWORK_CONNECTIVITY_FAILURE


def test_ambiguous_signals_populate_needs_evidence():
    (r,) = preclassify("Column 'x' not found")
    assert r.ambiguous and ReadCapability.SCHEMA in r.needs_evidence


def test_unambiguous_signals_need_no_extra_evidence():
    (r,) = preclassify("permission denied")
    assert not r.ambiguous and r.needs_evidence == []


def test_unrecognized_text_is_other_unknown_never_a_root_cause():
    (r,) = preclassify("something odd happened")
    assert r.normalized_signal is N.UNRECOGNIZED
    assert r.candidate_categories == [FC.OTHER_UNKNOWN]
    assert r.needs_evidence


def test_multiple_signals_in_one_text():
    signals = {r.normalized_signal for r in preclassify("connection reset ... then timed out")}
    assert {N.NETWORK_CONNECTIVITY_FAILURE, N.TIMEOUT} <= signals
