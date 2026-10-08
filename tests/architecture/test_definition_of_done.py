"""Definition of done (Part T): no TODO, bare pass, or NotImplementedError in required code
(abstract base methods excepted); and forbidden V1 operations do not exist anywhere."""

import ast
import re

from tests.architecture import scanner as sc


def _is_abstract(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        name = dec.attr if isinstance(dec, ast.Attribute) else getattr(dec, "id", "")
        if name == "abstractmethod":
            return True
    return False


def _body_without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        return body[1:]
    return body


def test_no_todo_markers():
    pattern = re.compile(r"\b(TODO|FIXME|XXX)\b")
    hits = []
    for path in sc.all_source_files():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                hits.append(f"{path.relative_to(sc.REPO_ROOT)}:{n}")
    assert hits == []


def test_no_bare_pass_or_not_implemented_outside_abstract_methods():
    hits = []
    for path in sc.all_source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not _is_abstract(node):
                body = _body_without_docstring(node.body)
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    hits.append(f"{path.relative_to(sc.REPO_ROOT)}:{node.lineno} bare pass")
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Raise) and sub.exc is not None:
                        exc = sub.exc.func if isinstance(sub.exc, ast.Call) else sub.exc
                        if getattr(exc, "id", None) == "NotImplementedError":
                            hits.append(f"{path.relative_to(sc.REPO_ROOT)}:{sub.lineno} NotImplementedError")
    assert hits == []


FORBIDDEN_OPERATION_PATTERNS = [
    r"dagRuns\b.*\bpost\b",               # trigger new DAG run
    r"\b(un)?pause_dag\b|\.(patch|post|put)\([^)]*is_paused",   # pause / unpause (reading is_paused is fine)
    r"\bset_state\b|\bmark_success\b|\bmark_failed\b",
    r"/variables\b|/connections\b",
    r"/xcomEntries\b.*\b(post|patch)\b",
    r"\bgit\s+(push|commit|reset)\b",
]


def test_forbidden_operations_do_not_exist():
    hits = []
    for path in sc.all_source_files():
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_OPERATION_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                hits.append(f"{path.relative_to(sc.REPO_ROOT)}: {m.group(0)}")
    assert hits == []
