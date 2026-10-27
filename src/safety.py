import ast
import builtins
import re

ALLOWED_IMPORTS = {"pandas", "numpy", "matplotlib", "matplotlib.pyplot", "math", "statistics", "datetime"}

FORBIDDEN_NAMES = {
    "open", "exec", "eval", "compile", "__import__", "globals", "locals", "vars", "getattr", "setattr",
    "delattr", "input", "breakpoint", "exit", "quit", "help", "memoryview", "os", "sys", "subprocess",
    "shutil", "pathlib", "socket", "builtins", "importlib", "pickle", "requests", "urllib", "http",
    "ctypes", "multiprocessing", "threading", "asyncio", "signal", "duckdb", "sqlite3", "io", "tempfile",
}

FORBIDDEN_ATTRS = {
    "to_csv", "to_excel", "to_parquet", "to_pickle", "to_json", "to_sql", "to_feather", "to_hdf", "to_html",
    "to_xml", "to_stata", "to_orc", "to_clipboard", "to_latex", "to_markdown", "read_csv", "read_excel",
    "read_parquet", "read_json", "read_pickle", "read_sql", "read_sql_query", "read_sql_table", "read_html",
    "read_table", "read_fwf", "read_clipboard", "read_xml", "read_feather", "read_hdf", "read_orc",
    "read_sas", "read_spss", "read_stata", "eval", "system", "popen", "load", "loadtxt", "fromfile",
    "tofile", "save", "savez", "savez_compressed", "savetxt", "genfromtxt", "memmap", "fromregex",
    "DataSource", "imread", "imsave",
}

SAFE_BUILTINS = {
    name: getattr(builtins, name) for name in [
        "abs", "all", "any", "bool", "dict", "enumerate", "filter", "float", "format", "frozenset", "int",
        "isinstance", "len", "list", "map", "max", "min", "print", "range", "repr", "reversed", "round",
        "set", "slice", "sorted", "str", "sum", "tuple", "zip", "Exception", "ValueError", "KeyError",
        "TypeError", "IndexError", "ZeroDivisionError", "True", "False", "None",
    ] if hasattr(builtins, name)
}


class UnsafeCodeError(ValueError):
    pass


def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0]
    if name not in ALLOWED_IMPORTS and root not in {"pandas", "numpy", "matplotlib"}:
        raise UnsafeCodeError(f"Import of '{name}' is not allowed")
    return __import__(name, globals, locals, fromlist, level)


def restricted_builtins() -> dict:
    out = dict(SAFE_BUILTINS)
    out["__import__"] = _safe_import
    return out


def _check_chart_path(node: ast.Call) -> None:
    if not node.args:
        return
    arg = node.args[0]
    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
        raise UnsafeCodeError("savefig must use a literal relative file name")
    path = arg.value.replace("\\", "/")
    if path.startswith("/") or ":" in path or ".." in path or not path.lower().endswith(".png"):
        raise UnsafeCodeError("savefig path must be a relative .png path inside the workspace")


def validate_code(code: str) -> None:
    if len(code) > 20_000:
        raise UnsafeCodeError("Generated code is too long")
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise UnsafeCodeError(f"Generated code is not valid Python: {exc.msg}") from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_IMPORTS:
                    raise UnsafeCodeError(f"Import of '{alias.name}' is not allowed")
        elif isinstance(node, ast.ImportFrom):
            if node.level or (node.module or "") not in ALLOWED_IMPORTS:
                raise UnsafeCodeError(f"Import from '{node.module}' is not allowed")
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_NAMES or node.id.startswith("__"):
                raise UnsafeCodeError(f"Use of '{node.id}' is not allowed")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise UnsafeCodeError("Access to private or dunder attributes is not allowed")
            if node.attr in FORBIDDEN_ATTRS:
                raise UnsafeCodeError(f"Use of '.{node.attr}' is not allowed")
        elif isinstance(node, (ast.Global, ast.Nonlocal, ast.AsyncFunctionDef, ast.Await, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                raise UnsafeCodeError("Unsupported statement in generated code")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "savefig":
            _check_chart_path(node)


SQL_FORBIDDEN = re.compile(
    r"\b(copy|attach|detach|install|load|pragma|export|import|call|create|insert|update|delete|drop|alter|"
    r"set|reset|checkpoint|vacuum|getenv|glob|sniff_csv|read_\w+|\w+_scan|httpfs|current_setting|"
    r"duckdb_\w+|pg_\w+|information_schema|sqlite_\w+|query_table|query)\b",
    re.IGNORECASE,
)


class UnsafeSQLError(ValueError):
    pass


def validate_sql(query: str) -> str:
    if not isinstance(query, str):
        raise UnsafeSQLError("SQL query must be a string")
    q = query.strip().rstrip(";").strip()
    if len(q) > 5000:
        raise UnsafeSQLError("SQL query is too long")
    if ";" in q:
        raise UnsafeSQLError("Only a single SQL statement is allowed")
    if "--" in q or "/*" in q:
        raise UnsafeSQLError("SQL comments are not allowed")
    if not re.match(r"^(select|with)\b", q, re.IGNORECASE):
        raise UnsafeSQLError("Only SELECT queries are allowed")
    stripped = re.sub(r"'(?:[^']|'')*'", "''", q)
    if SQL_FORBIDDEN.search(stripped):
        raise UnsafeSQLError("The SQL query uses a statement or function that is not allowed")
    if re.search(r"'[^']*(\.csv|\.parquet|\.json|\.txt|://|[\\/])[^']*'", q, re.IGNORECASE):
        raise UnsafeSQLError("File paths and URLs are not allowed in SQL queries")
    return q
