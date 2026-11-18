"""No function in server.py may locally import a module the file already
imports at module level and read that name before the local import.

This exists because of a real crash, not as a style rule. `start_server()`
ended up with an `import os` roughly forty lines below an `os.environ.get(...)`
call in the same function. A local import binds the name for the *whole*
function, so that earlier read raised

    UnboundLocalError: cannot access local variable 'os'
    where it is not associated with a value

even though `os` is imported at module level (server.py line 17). The only path
that reached it was `SERVER_ACCESS_PROTECTED=true` with an empty
`server_access_codes` table -- i.e. the first start of a deployment that wants
the access allowlist. The server refused to start, and the traceback pointed at
`os` rather than at the access-code code it was actually in.

Deliberately an AST check over the source text: it imports neither `server` nor
anything it depends on, so it runs in milliseconds, needs no DB_PATH and no
event loop, and cannot be made to pass by a monkeypatch. It flags only the
ordering that is always a bug -- a local import that shadows a module-level one
without any earlier read is left alone, since there are legitimate reasons to
re-import inside a function (lazy, optional or expensive imports).
"""
import ast
import io
import os

SERVER_PY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server.py"
)


def _module_level_plain_imports(tree):
    """Names bound by a top-level `import x` (no alias, no dotted path)."""
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is None and "." not in alias.name:
                    names.add(alias.name)
    return names


def _shadowing_local_imports(tree, module_names):
    """(function, name, import line, first read line) for every local import
    of a module-level name, whether or not it is read earlier."""
    found = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        local_imports = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if (
                        alias.asname is None
                        and "." not in alias.name
                        and alias.name in module_names
                        and alias.name not in local_imports
                    ):
                        local_imports[alias.name] = node.lineno
        for name, import_line in local_imports.items():
            first_read = None
            for node in ast.walk(func):
                if (
                    isinstance(node, ast.Name)
                    and node.id == name
                    and isinstance(node.ctx, ast.Load)
                    and (first_read is None or node.lineno < first_read)
                ):
                    first_read = node.lineno
            found.append((func.name, name, import_line, first_read))
    return found


def test_no_local_import_is_read_before_it_happens():
    source = io.open(SERVER_PY, encoding="utf-8").read()
    tree = ast.parse(source, filename=SERVER_PY)
    module_names = _module_level_plain_imports(tree)
    assert "os" in module_names, (
        "server.py no longer imports os at module level -- this test's premise "
        "changed, re-read it before editing the assertion away"
    )

    offenders = [
        (func, name, import_line, first_read)
        for func, name, import_line, first_read in _shadowing_local_imports(
            tree, module_names
        )
        if first_read is not None and first_read < import_line
    ]

    assert not offenders, "\n".join(
        f"{func}(): `import {name}` on line {import_line} makes {name} local to "
        f"the whole function, but {name} is read on line {first_read} -- that "
        f"read raises UnboundLocalError. {name} is already imported at module "
        f"level; delete the local import."
        for func, name, import_line, first_read in offenders
    )
