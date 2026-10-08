"""SQL policy for any SQL-capable tool (spec Part M).

Allowed: exactly one SELECT, or WITH ... SELECT. Rejected: any DML/DDL/DCL/procedural
keyword anywhere (including inside CTEs), multiple statements, any comment (comment-based
bypass), SELECT INTO, locking reads. Validation is token-based (sqlparse) so keywords inside
string literals or identifiers do not cause false rejections, and runs before any DB call.
"""

import sqlparse
from pydantic import BaseModel
from sqlparse import tokens as T

FORBIDDEN_KEYWORDS = frozenset(
    {
        "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "REPLACE",
        "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "COMMENT",
        "GRANT", "REVOKE",
        "CALL", "EXEC", "EXECUTE", "DO",
        "INTO", "COPY", "LOAD", "UNLOAD", "EXPORT", "IMPORT",
        "LOCK", "UNLOCK", "VACUUM", "ANALYZE", "OPTIMIZE", "REINDEX", "CLUSTER",
        "ATTACH", "DETACH", "PRAGMA", "SET", "RESET", "USE",
        "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "START", "TRANSACTION",
        "SHUTDOWN", "KILL",
    }
)
ALLOWED_LEADING = frozenset({"SELECT", "WITH"})
_COMMENT_MARKERS = ("--", "/*", "*/", "#")


class SQLPolicyViolation(ValueError):
    """Raised by ``enforce_sql_policy`` when a statement is not allowed."""


class SQLValidationResult(BaseModel):
    allowed: bool
    reason: str


def _deny(reason: str) -> SQLValidationResult:
    return SQLValidationResult(allowed=False, reason=reason)


def validate_sql(sql: str) -> SQLValidationResult:
    if not isinstance(sql, str) or not sql.strip():
        return _deny("empty statement")
    if "\x00" in sql:
        return _deny("null byte in statement")

    statements = [s for s in sqlparse.parse(sql) if s.value.strip() and s.value.strip() != ";"]
    if len(statements) != 1:
        return _deny(f"exactly one statement allowed, found {len(statements)}")
    statement = statements[0]

    tokens = list(statement.flatten())

    # Comment markers outside string literals are rejected even when the tokenizer does not
    # recognise them as a comment (e.g. an unterminated "/*").
    outside_literals = "".join(" " if tok.ttype in T.String else tok.value for tok in tokens)
    if any(marker in outside_literals for marker in _COMMENT_MARKERS):
        return _deny("comments are not allowed")

    meaningful = []
    for tok in tokens:
        if tok.ttype in T.Comment or tok.ttype in (T.Comment.Single, T.Comment.Multiline):
            return _deny("comments are not allowed")
        if tok.ttype in T.Whitespace or tok.ttype is T.Newline:
            continue
        meaningful.append(tok)

    # A trailing semicolon is tolerated; any other semicolon is a second statement.
    semicolons = [i for i, tok in enumerate(meaningful) if tok.ttype is T.Punctuation and tok.value == ";"]
    if semicolons and semicolons != [len(meaningful) - 1]:
        return _deny("multiple statements")

    if not meaningful:
        return _deny("empty statement")
    first = meaningful[0]
    if first.ttype not in T.Keyword or first.normalized.upper() not in ALLOWED_LEADING:
        return _deny(f"statement must start with SELECT or WITH, found {first.value!r}")

    saw_select = False
    for tok in meaningful:
        if tok.ttype in T.Keyword or tok.ttype in T.Name.Builtin:
            words = tok.normalized.upper().split()
            for word in words:
                if word in FORBIDDEN_KEYWORDS:
                    return _deny(f"forbidden keyword {word}")
                if word == "SELECT":
                    saw_select = True
        elif tok.ttype is None and tok.value.upper() in FORBIDDEN_KEYWORDS:
            return _deny(f"forbidden keyword {tok.value.upper()}")
    if not saw_select:
        return _deny("no SELECT found")
    return SQLValidationResult(allowed=True, reason="single read-only SELECT")


def enforce_sql_policy(sql: str) -> str:
    """Return ``sql`` if allowed; raise SQLPolicyViolation otherwise. Call before any DB access."""
    result = validate_sql(sql)
    if not result.allowed:
        raise SQLPolicyViolation(result.reason)
    return sql
