"""SQL allow/deny matrix (Part M)."""

import pytest

from security.sql_policy import SQLPolicyViolation, enforce_sql_policy, validate_sql

ALLOW = [
    "SELECT 1",
    "select count(*) from orders",
    "SELECT * FROM orders WHERE status = 'delete me'",          # keyword in string literal
    "SELECT update_time, deleted_flag FROM t",                    # keyword-like identifiers
    "SELECT a FROM t;",                                           # trailing semicolon
    "WITH x AS (SELECT id FROM t) SELECT * FROM x",
    "WITH a AS (SELECT 1 AS v), b AS (SELECT v FROM a) SELECT v FROM b",
    "SELECT o.id, c.name FROM orders o JOIN customers c ON o.cid = c.id GROUP BY 1, 2 ORDER BY 1 LIMIT 10",
    "SELECT * FROM t WHERE id IN (SELECT id FROM u)",
    "SELECT '-- not a comment', '/* nor this */' FROM t",       # markers inside literals
]

DENY = [
    ("INSERT INTO t VALUES (1)", "start"),
    ("UPDATE t SET a = 1", "start"),
    ("DELETE FROM t", "start"),
    ("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", "start"),
    ("CREATE TABLE x (a int)", "start"),
    ("ALTER TABLE t ADD COLUMN b int", "start"),
    ("DROP TABLE t", "start"),
    ("TRUNCATE TABLE t", "start"),
    ("GRANT SELECT ON t TO bob", "start"),
    ("REVOKE SELECT ON t FROM bob", "start"),
    ("CALL do_things()", "start"),
    ("SELECT 1; DROP TABLE t", "statement"),
    ("SELECT 1; SELECT 2", "statement"),
    ("SELECT 1 -- ; DROP TABLE t", "comment"),
    ("SELECT /* sneaky */ 1", "comment"),
    ("SELECT 1 /*", "comment"),
    ("SELECT a FROM t # mysql comment", "comment"),
    ("SELECT a FROM t */", "comment"),
    ("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", "DELETE"),
    ("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", "INSERT"),
    ("SELECT * INTO new_table FROM t", "INTO"),
    ("SELECT * FROM t FOR UPDATE", "UPDATE"),
    ("", "empty"),
    ("   ", "empty"),
    ("EXPLAIN ANALYZE SELECT 1", "start"),
    ("SELECT 1\x00; DROP TABLE t", "null"),
    ("WITH x AS (SELECT 1) UPDATE t SET a = 1", "UPDATE"),
    ("SET search_path = evil", "start"),
]


@pytest.mark.parametrize("sql", ALLOW)
def test_allowed(sql):
    result = validate_sql(sql)
    assert result.allowed, result.reason
    assert enforce_sql_policy(sql) == sql


@pytest.mark.parametrize("sql,why", DENY)
def test_denied(sql, why):
    result = validate_sql(sql)
    assert not result.allowed
    assert why.lower() in result.reason.lower(), result.reason
    with pytest.raises(SQLPolicyViolation):
        enforce_sql_policy(sql)
