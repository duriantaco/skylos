"""Static evidence for the ROS 2 Python launch-file loader contract."""

from __future__ import annotations

import ast
import os
from pathlib import Path


def _qualified(node, imports):
    if isinstance(node, ast.Name):
        return imports.get(node.id)
    if isinstance(node, ast.Attribute):
        owner = _qualified(node.value, imports)
        return f"{owner}.{node.attr}" if owner else None
    return None


def find_ros_launch_targets(index, parsed, root: Path):
    """Require a launch-file role and an unshadowed LaunchDescription return.

    A bare function name is not an entrypoint. Local launch modules, replaced
    imports, decorators, reflection and competing definitions retain the
    ordinary dead-code result rather than manufacturing framework evidence.
    """
    for module in parsed:
        if not module.path.name.endswith(".launch.py"):
            continue
        directories = {
            root,
            module.path.parent,
            *(root / name for name in ("src", "lib", "python")),
        }
        shadowed = False
        for directory in directories:
            for name in ("launch.py", "launch"):
                try:
                    os.lstat(directory / name)
                except FileNotFoundError:
                    continue
                except OSError:
                    shadowed = True
                else:
                    shadowed = True
        if shadowed:
            continue
        imports = {}
        for statement in module.tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if alias.name == "launch":
                        imports[alias.asname or "launch"] = "launch"
            elif (
                isinstance(statement, ast.ImportFrom)
                and not statement.level
                and statement.module == "launch"
            ):
                for alias in statement.names:
                    if alias.name == "LaunchDescription":
                        imports[alias.asname or alias.name] = "launch.LaunchDescription"
        candidates = [
            statement
            for statement in module.tree.body
            if isinstance(statement, ast.FunctionDef)
            and statement.name == "generate_launch_description"
        ]
        if not imports or len(candidates) != 1:
            continue
        function = candidates[0]
        if function.decorator_list or any(
            (
                function.args.posonlyargs,
                function.args.args,
                function.args.kwonlyargs,
                function.args.vararg,
                function.args.kwarg,
            )
        ):
            continue
        final = function.body[-1] if function.body else None
        if not (
            isinstance(final, ast.Return)
            and isinstance(final.value, ast.Call)
            and _qualified(final.value.func, imports) == "launch.LaunchDescription"
        ):
            continue
        parents = {
            child: parent
            for parent in ast.walk(module.tree)
            for child in ast.iter_child_nodes(parent)
        }
        invalid = False
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Attribute) and (
                node.attr in {"__dict__", "modules"}
                or node.attr == "LaunchDescription"
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                invalid = True
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ) and (
                node.name in imports
                or node.name == function.name and node is not function
            ):
                invalid = True
            elif isinstance(node, ast.arg) and node.arg in imports:
                invalid = True
            elif isinstance(node, ast.Name):
                if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in {
                    *imports, function.name,
                }:
                    invalid = True
                if isinstance(node.ctx, ast.Load) and node.id in {
                    "eval", "exec", "globals", "locals", "vars", "setattr",
                    "delattr", "getattr", "__import__",
                }:
                    invalid = True
                if isinstance(node.ctx, ast.Load) and node.id in imports:
                    parent = parents.get(node)
                    if imports[node.id] == "launch":
                        if not (
                            isinstance(parent, ast.Attribute)
                            and parent.value is node
                            and isinstance(parent.ctx, ast.Load)
                            and not parent.attr.startswith("__")
                        ):
                            invalid = True
                    elif not (isinstance(parent, ast.Call) and parent.func is node):
                        invalid = True
            elif (
                isinstance(node, ast.Attribute)
                and _qualified(node, imports) == "launch.LaunchDescription"
            ):
                parent = parents.get(node)
                if not (isinstance(parent, ast.Call) and parent.func is node):
                    invalid = True
            elif isinstance(node, ast.ExceptHandler) and node.name in {
                *imports, function.name,
            }:
                invalid = True
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in {
                *imports, function.name,
            }:
                invalid = True
            elif isinstance(node, (ast.Global, ast.Nonlocal)) and set(node.names) & {
                *imports, function.name,
            }:
                invalid = True
            elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                base = node.value
                while isinstance(base, (ast.Attribute, ast.Subscript)):
                    base = base.value
                if isinstance(base, ast.Name) and base.id in imports:
                    invalid = True
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    expected = (
                        node.module + "." + alias.name
                        if isinstance(node, ast.ImportFrom) and not node.level
                        else alias.name
                    )
                    if alias.name == "*" or (
                        bound in imports and imports[bound] != expected
                    ):
                        invalid = True
        if invalid:
            continue
        definition = index.by_location.get(
            (index._resolve_path(module.path), function.lineno)
        )
        if definition is not None:
            yield definition, "ros_launch_description"
