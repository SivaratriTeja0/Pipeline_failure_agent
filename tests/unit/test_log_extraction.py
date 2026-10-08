"""Bounded log extraction (Part H)."""

import pytest

from core.evidence.log_extraction import extract_log_excerpt

TRACEBACK_LOG = "\n".join(
    [f"INFO step {i}" for i in range(200)]
    + [
        "Traceback (most recent call last):",
        '  File "/opt/dags/load.py", line 10, in run',
        "    conn.execute(sql)",
        "ConnectionResetError: [Errno 104] Connection reset by peer",
    ]
    + [f"INFO cleanup {i}" for i in range(200)]
)


def test_extracts_error_region_stack_trace_and_signatures():
    ex = extract_log_excerpt(TRACEBACK_LOG, max_bytes=10_000, context_lines=3, original_reference="s3://logs/x")
    assert "Connection reset by peer" in ex.excerpt
    assert ex.stack_trace.startswith("Traceback (most recent call last):")
    assert ex.stack_trace.endswith("Connection reset by peer")
    assert any("Connection reset" in s for s in ex.matched_signatures)
    assert "INFO step 0" not in ex.excerpt  # far-away lines are dropped
    assert ex.original_reference == "s3://logs/x"
    assert ex.truncated


def test_respects_max_bytes_utf8_safe():
    log = ("ERROR ünïcødé failure " * 2000)
    ex = extract_log_excerpt(log, max_bytes=500)
    assert ex.excerpt_size_bytes <= 500
    ex.excerpt.encode("utf-8")
    assert ex.truncated


def test_no_errors_falls_back_to_tail():
    log = "\n".join(f"line {i}" for i in range(100))
    ex = extract_log_excerpt(log, max_bytes=10_000, context_lines=2)
    assert ex.excerpt.splitlines() == [f"line {i}" for i in range(95, 100)]


def test_java_stack_trace():
    log = "\n".join([
        "ERROR Job failed",
        "java.sql.SQLException: Connection refused",
        "    at org.postgresql.Driver.connect(Driver.java:1)",
        "    at com.x.Loader.run(Loader.java:42)",
        "INFO done",
    ])
    ex = extract_log_excerpt(log, max_bytes=10_000)
    assert "Loader.java:42" in ex.stack_trace and "SQLException" in ex.stack_trace


def test_invalid_budget_rejected():
    with pytest.raises(ValueError):
        extract_log_excerpt("x", max_bytes=0)
