"""Typing contracts from source syntax, without changing the analysis AST."""

import ast
import io
import re
import textwrap
import tokenize
from pathlib import PurePosixPath

from skylos.core.test_paths import is_test_code_path
from skylos.rules.quality._pytest_collection import is_collected_pytest_file


FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def parameters(function):
    args = function.args
    return [
        *args.posonlyargs,
        *args.args,
        *([args.vararg] if args.vararg else []),
        *args.kwonlyargs,
        *([args.kwarg] if args.kwarg else []),
    ]


def _valid_type(text):
    if not text or text == "ignore" or text.startswith("ignore["):
        return False
    try:
        value = ast.parse(text, mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        return False
    return not (isinstance(value, ast.Constant) and value.value is Ellipsis)


def _commented_header(function, lines):
    if not lines or not function.body:
        return function
    first_body = function.body[0].lineno
    if first_body <= function.lineno:
        return function
    header = "".join(lines[function.lineno - 1 : first_body - 1])
    if not re.search(r"#\s*type:", header):
        return function
    indent = re.match(r"[ \t]*", header).group()
    try:
        parsed = ast.parse(
            textwrap.dedent(header + indent + "    pass\n"), type_comments=True
        )
    except (SyntaxError, ValueError, RecursionError):
        return function
    return parsed.body[0]


def _argument_stars(comment):
    """The FunctionType AST discards the * and ** parameter markers."""
    depth = 0
    at_start = False
    stars = []
    for token in tokenize.generate_tokens(io.StringIO(comment).readline):
        text = token.string
        if (
            token.type != tokenize.OP
            and token.type != tokenize.NAME
            and token.type != tokenize.STRING
            and token.type != tokenize.NUMBER
        ):
            continue
        if not depth:
            if text == "(":
                depth, at_start = 1, True
            continue
        if depth == 1 and text == ")":
            break
        if depth == 1 and text == ",":
            at_start = True
            continue
        if at_start:
            stars.append(text if text in {"*", "**"} else "")
            at_start = False
        if text in {"(", "[", "{"}:
            depth += 1
        elif text in {")", "]", "}"}:
            depth -= 1
    return stars


def comment_contract(function, source_lines, receiver=None):
    """Return typed argument names and whether a valid return comment exists.

    Inspect only the header of this function. A misplaced comment elsewhere
    must neither invalidate runnable source nor erase another valid contract.
    """
    commented = _commented_header(function, source_lines)
    args = parameters(commented)
    typed = {
        arg.arg
        for arg in args
        if arg.annotation is None and _valid_type(getattr(arg, "type_comment", None))
    }
    comment = getattr(commented, "type_comment", None)
    if not comment or function.returns is not None:
        return typed, False
    try:
        signature = ast.parse(comment, mode="func_type")
        stars = _argument_stars(comment)
    except (SyntaxError, ValueError, RecursionError, tokenize.TokenError):
        return typed, False
    if (
        isinstance(signature.returns, ast.Constant)
        and signature.returns.value is Ellipsis
    ):
        return typed, False
    if (
        len(signature.argtypes) == 1
        and isinstance(signature.argtypes[0], ast.Constant)
        and signature.argtypes[0].value is Ellipsis
    ):
        return typed, stars == [""]
    # The short form must account for every argument, with only an implicit
    # method receiver optionally omitted. Duplicate inline/comment contracts
    # are invalid, so they cannot establish additional parameter coverage.
    if any(
        arg.annotation is not None or getattr(arg, "type_comment", None) for arg in args
    ):
        return typed, False
    shapes = [
        (
            arg,
            "**"
            if arg is commented.args.kwarg
            else "*"
            if arg is commented.args.vararg
            else "",
        )
        for arg in args
    ]
    if (
        receiver
        and shapes
        and shapes[0][0].arg == receiver
        and len(signature.argtypes) == len(shapes) - 1
    ):
        shapes = shapes[1:]
    if len(signature.argtypes) != len(shapes) or stars != [star for _, star in shapes]:
        return typed, False
    if any(
        isinstance(value, ast.Constant) and value.value is Ellipsis
        for value in signature.argtypes
    ):
        return typed, False
    return {arg.arg for arg, _ in shapes}, True


def is_typing_test_path(filename, project_root=None, *, source=None):
    """Test modules by convention or guarded configured collection evidence.

    Folders follow ``is_test_code_path`` relative to the project root: a
    top-level ``test``/``tests``, ``<pkg>/tests`` or ``src/<pkg>/tests``. A
    deeper ``test`` package (``django/test/client.py``) is shipped API, and
    without a root an absolute path's ancestors are not evidence.
    Custom pytest file patterns additionally require statically collectable
    items; a configured testpaths directory alone does not exempt its helpers.
    """
    text = str(filename or "").replace("\\", "/")
    name = PurePosixPath(text).name.lower()
    if name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
        return True
    return is_test_code_path(filename, project_root) or is_collected_pytest_file(
        filename, project_root, source=source
    )


def pytest_fixture_ids(module):
    """Resolve fixture decorators at their definition, including import aliases."""
    result = set()
    mutated_attributes = set()

    def qualified(node, bindings):
        if isinstance(node, ast.Call):
            return qualified(node.func, bindings)
        if isinstance(node, ast.Name):
            return bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            base = qualified(node.value, bindings)
            name = f"{base}.{node.attr}" if base else None
            return name if name not in mutated_attributes else None
        return None

    def statements(body, bindings):
        for stmt in body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    bindings[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    if alias.name == "*":
                        bindings.clear()
                    else:
                        bindings[alias.asname or alias.name] = (
                            f"{stmt.module}.{alias.name}"
                            if stmt.module and not stmt.level
                            else None
                        )
                        if bindings[alias.asname or alias.name] in mutated_attributes:
                            bindings[alias.asname or alias.name] = None
            elif isinstance(stmt, FUNCTIONS):
                if any(
                    qualified(decorator, bindings)
                    in {"pytest.fixture", "pytest.yield_fixture"}
                    for decorator in stmt.decorator_list
                ):
                    result.add(id(stmt))
                bindings.pop(stmt.name, None)
            elif isinstance(stmt, ast.ClassDef):
                statements(stmt.body, dict(bindings))
                bindings.pop(stmt.name, None)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = (
                    stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                )
                value = (
                    qualified(stmt.value, bindings) if stmt.value is not None else None
                )
                for target in targets:
                    if isinstance(target, ast.Attribute):
                        owner = qualified(target.value, bindings)
                        if owner:
                            mutated_attributes.add(f"{owner}.{target.attr}")
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and isinstance(
                            name.ctx, ast.Store
                        ):
                            bindings[name.id] = (
                                value if isinstance(target, ast.Name) else None
                            )
            else:
                # Unknown control flow cannot establish a decorator binding.
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Name) and isinstance(
                        child.ctx, (ast.Store, ast.Del)
                    ):
                        bindings.pop(child.id, None)
                    elif isinstance(
                        child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    ):
                        bindings.pop(child.name, None)
                    elif isinstance(child, (ast.Import, ast.ImportFrom)):
                        for alias in child.names:
                            bindings.pop(alias.asname or alias.name.split(".")[0], None)

    statements(module.body, {})
    return result
