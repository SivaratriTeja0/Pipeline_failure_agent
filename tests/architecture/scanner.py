"""AST-based import / call scanner used by the architecture tests (spec B2)."""

import ast
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXCLUDED_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", ".git", "tests"}

PLATFORM_SDKS = (
    "airflow", "apache_airflow", "databricks", "boto3", "botocore", "azure", "google.cloud",
    "dagster", "prefect", "kubernetes",
)
HTTP_AND_PROCESS_MODULES = (
    "httpx", "requests", "urllib.request", "urllib3", "aiohttp", "http.client", "socket",
    "subprocess", "pycurl",
)


@dataclass(frozen=True)
class ImportRef:
    module: str
    line: int


def module_name(path: Path, root: Path = REPO_ROOT) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_relative(current_module: str, is_package: bool, level: int, module: str | None) -> str:
    base = current_module.split(".")
    if not is_package:
        base = base[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join([*base, module] if module else base)


def collect_imports(source: str, current_module: str = "", is_package: bool = False) -> list[ImportRef]:
    """All imported modules, including relative imports, ``from x import y`` submodules,
    and string arguments to ``importlib.import_module`` / ``__import__``."""
    tree = ast.parse(source)
    refs: list[ImportRef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            refs.extend(ImportRef(alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = (
                _resolve_relative(current_module, is_package, node.level, node.module)
                if node.level
                else (node.module or "")
            )
            refs.append(ImportRef(base, node.lineno))
            refs.extend(ImportRef(f"{base}.{alias.name}", node.lineno) for alias in node.names)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in {"import_module", "__import__"} and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    refs.append(ImportRef(arg.value, node.lineno))
    return refs


def matches(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def python_files(*top_dirs: str, root: Path = REPO_ROOT) -> list[Path]:
    files: list[Path] = []
    for top in top_dirs:
        base = root / top
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            if not EXCLUDED_DIRS & set(path.relative_to(root).parts):
                files.append(path)
    return sorted(files)


def all_source_files(root: Path = REPO_ROOT) -> list[Path]:
    return sorted(
        p for p in root.rglob("*.py") if not EXCLUDED_DIRS & set(p.relative_to(root).parts)
    )


def imports_of(path: Path) -> list[ImportRef]:
    source = path.read_text(encoding="utf-8")
    return collect_imports(source, module_name(path), path.name == "__init__.py")


# ---------------------------------------------------------------- rule checks (pure functions)


def forbidden_import_violations(
    refs: list[ImportRef], forbidden_prefixes: tuple[str, ...], allowed_prefixes: tuple[str, ...] = ()
) -> list[str]:
    out = []
    for ref in refs:
        if any(matches(ref.module, a) for a in allowed_prefixes):
            continue
        for prefix in forbidden_prefixes:
            if matches(ref.module, prefix):
                out.append(f"line {ref.line}: imports {ref.module} (forbidden: {prefix})")
    return out


def adapter_platform_violations(refs: list[ImportRef]) -> list[str]:
    """Importing adapters.<platform> (anything but adapters.base) is forbidden."""
    out = []
    for ref in refs:
        parts = ref.module.split(".")
        if parts[0] == "adapters" and len(parts) > 1 and parts[1] != "base":
            out.append(f"line {ref.line}: imports platform adapter {ref.module}")
    return out


def constructs(source: str, class_name: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == class_name:
                lines.append(node.lineno)
    return lines


def platform_branch_lines(source: str) -> list[int]:
    """Comparisons against a string literal naming a platform (e.g. ``platform == "airflow"``)."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for operand in operands:
                values = []
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    values.append(operand.value)
                elif isinstance(operand, (ast.Tuple, ast.List, ast.Set)):
                    values.extend(
                        e.value for e in operand.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    )
                if any("airflow" in v.lower() for v in values):
                    lines.append(node.lineno)
        elif isinstance(node, ast.MatchValue):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and "airflow" in value.value.lower():
                lines.append(node.lineno)
    return lines


def dangerous_call_lines(source: str) -> list[int]:
    """os.system / os.popen / os.exec* / eval / exec calls."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "os":
                if func.attr in {"system", "popen"} or func.attr.startswith(("exec", "spawn")):
                    lines.append(node.lineno)
            elif isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
                lines.append(node.lineno)
    return lines
