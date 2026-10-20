"""Bounded source-only resolution of call receivers.

This module never imports the project being inspected. A resolved method is
not automatically harmless: consumers must inspect its separate effects.
Annotations, naming conventions and an unavailable provider are not proof.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.security.receiver_bindings import _Reference, _Module, _FUNCTIONS
from skylos.security.receiver_values import resolve_attribute, resolve_expression
from skylos.security.receiver_effects import (
    _VALUE_TYPES,
    _VALUE_CALLS,
    callable_effects,
)

_STDLIB_MODULES = {"pathlib", "io", "builtins", "sqlite3"}


class ReceiverResolver:
    """Resolve bindings conservatively and report independently proved effects."""

    MAX_FILES = 32
    MAX_FILE_BYTES = 2_000_000
    MAX_DEPTH = 16

    def __init__(self, module, file_path, project_root=None):
        self.path = Path(file_path).absolute()
        if project_root is None:
            project_root = self.path.parent
            for candidate in [self.path.parent, *self.path.parents]:
                found = False
                for name in ("pyproject.toml", "setup.cfg", "setup.py", ".git"):
                    if (candidate / name).exists():
                        found = True
                        break
                if found:
                    project_root = candidate
                    break
        self.root = Path(project_root).absolute()
        self.search_roots = [self.root]
        if (self.root / "src").is_dir():
            self.search_roots.append(self.root / "src")
        self.modules = {}
        self._unavailable_modules = set()
        self.main = _Module(module, self.path, self._module_name(self.path))
        self.modules[str(self.path)] = self.main
        self._effect_cache = {}
        self._bound_receiver_context = {}

    def _module_name(self, path):
        for root in reversed(self.search_roots):
            try:
                rel = path.relative_to(root)
            except ValueError:
                continue
            parts = list(rel.with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            return ".".join(parts)
        return path.stem

    def _load(self, name):
        parts = name.split(".")
        if not parts:
            return None
        for part in parts:
            if not part.isidentifier():
                return None
        candidates = []
        for root in self.search_roots:
            base = root.joinpath(*parts)
            for path in [base.with_suffix(".py"), base / "__init__.py"]:
                try:
                    if path.exists() or path.is_symlink():
                        self._unavailable_modules.add(name)
                    if path.is_symlink() or not path.is_file():
                        continue
                    if not path.resolve().is_relative_to(self.root.resolve()):
                        continue
                    if path.stat().st_size > self.MAX_FILE_BYTES:
                        continue
                except (OSError, ValueError):
                    continue
                candidates.append(path.absolute())
        if len(set(candidates)) != 1:
            return None
        path = candidates[0]
        key = str(path)
        if key in self.modules:
            return self.modules[key]
        if len(self.modules) >= self.MAX_FILES:
            return None
        try:
            text = read_project_text_no_symlink(
                self.root, path, max_bytes=self.MAX_FILE_BYTES, newline=""
            )
            if text is None:
                return None
            tree = ast.parse(text, filename=key)
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            return None
        module = _Module(tree, path, name)
        self.modules[key] = module
        self._unavailable_modules.discard(name)
        return module

    def _relative_import(self, module, node):
        if not node.level:
            return node.module or ""
        package = module.name.split(".")
        if module.path.name != "__init__.py":
            package = package[:-1]
        if node.level > len(package) + 1:
            return ""
        keep = len(package) - node.level + 1
        parts = package[:keep]
        if node.module:
            parts.append(node.module)
        return ".".join(parts)

    def _class_safe(self, ref):
        node = ref.node
        if not isinstance(node, ast.ClassDef) or node.decorator_list or node.keywords:
            return False
        for base in node.bases:
            if not isinstance(base, ast.Name) or base.id != "object":
                return False
            resolved = self._name(ref.module, base, "object", 0, frozenset())
            if (
                resolved is None
                or resolved.kind != "builtin"
                or resolved.model != "object"
            ):
                return False
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and child.attr in {
                "__class__",
                "__dict__",
            }:
                return False
            if isinstance(child, _FUNCTIONS) and child.name in {
                "__new__",
                "__getattribute__",
                "__getattr__",
                "__setattr__",
            }:
                return False
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in {"setattr", "delattr", "exec", "eval"}
            ):
                return False
            if isinstance(child, ast.Call):
                arguments = list(child.args)
                for keyword in child.keywords:
                    arguments.append(keyword.value)
                for arg in arguments:
                    if isinstance(arg, ast.Name) and arg.id in {"self", "cls"}:
                        return False
        return True

    def _name(self, module, node, name, depth, active):
        if module.dynamic_namespace or name in module.mutated:
            return None
        scope = module.scope(node)
        while True:
            bindings = module.bindings(scope).get(name, [])
            if bindings:
                if len(bindings) != 1 or bindings[0][2]:
                    return None
                binding, value, _ = bindings[0]
                if isinstance(binding, ast.arg):
                    if name in {"self", "cls"} and isinstance(scope, _FUNCTIONS):
                        key = (str(module.path), id(scope), name)
                        receiver = self._bound_receiver_context.get(key)
                        if receiver is not None:
                            return receiver
                    return None
                if isinstance(binding, ast.ClassDef):
                    return _Reference("class", f"{module.name}.{name}", module, binding)
                if isinstance(binding, _FUNCTIONS):
                    if binding.decorator_list:
                        return None
                    return _Reference(
                        "function", f"{module.name}.{name}", module, binding
                    )
                if isinstance(binding, ast.Import):
                    qualified = value.name
                    if not value.asname:
                        qualified = value.name.split(".")[0]
                    imported = self._load(qualified)
                    model = None
                    if (
                        qualified in _STDLIB_MODULES
                        and imported is None
                        and qualified not in self._unavailable_modules
                    ):
                        model = qualified
                    return _Reference("module", qualified, imported, model=model)
                if isinstance(binding, ast.ImportFrom):
                    qualified = self._relative_import(module, binding)
                    imported = self._load(qualified)
                    model = None
                    if (
                        qualified in _STDLIB_MODULES
                        and imported is None
                        and qualified not in self._unavailable_modules
                    ):
                        model = qualified
                    base = _Reference("module", qualified, imported, model=model)
                    return self._attribute(base, value.name, depth + 1, active)
                if value is not None:
                    marker = (str(module.path), id(binding))
                    if marker in active:
                        return None
                    return self._expr(module, value, depth + 1, active | {marker})
                return None
            if scope is module.tree:
                break
            scope = module.scope(scope)
            # A method's bare names do not close over its class namespace.
            if isinstance(scope, ast.ClassDef):
                scope = module.scope(scope)
        if name in _VALUE_TYPES:
            return _Reference("class", f"builtins.{name}", model=name)
        if name in _VALUE_CALLS or name in {"open", "object"}:
            return _Reference("builtin", f"builtins.{name}", model=name)
        return None

    def _attribute(self, base, name, depth, active):
        return resolve_attribute(self, base, name, depth, active)

    def _expr(self, module, node, depth=0, active=frozenset()):
        return resolve_expression(self, module, node, depth, active)

    def _effects(self, ref, active=frozenset()):
        key = None
        previous = None
        if (
            ref.kind == "method"
            and ref.receiver is not None
            and isinstance(ref.node, _FUNCTIONS)
        ):
            args = [*ref.node.args.posonlyargs, *ref.node.args.args]
            if args:
                key = (str(ref.module.path), id(ref.node), args[0].arg)
                previous = self._bound_receiver_context.get(key)
                self._bound_receiver_context[key] = ref.receiver
        try:
            return callable_effects(self, ref, active)
        finally:
            if key is not None:
                if previous is None:
                    self._bound_receiver_context.pop(key, None)
                else:
                    self._bound_receiver_context[key] = previous

    def resolve_call(self, node):
        result = {
            "status": "unknown",
            "qualified_name": None,
            "kind": "unknown",
            "file": None,
            "line": None,
            "steps": [],
            "limitations": [],
            "effects": {"filesystem": "unknown", "database": "unknown"},
            "receiver_is_path": None,
            "receiver_is_non_path": None,
            "path_argument_index": None,
            "bound_method": None,
            "path_argument_name": None,
        }
        if not isinstance(node, ast.Call):
            result["limitations"].append("The supplied node is not a call.")
            return result
        ref = self._expr(self.main, node.func)
        if ref is None:
            result["limitations"].append(
                "Receiver or binding is unavailable, reassigned, conditional, dynamically modified, inherited, or supported only by an annotation."
            )
            return result
        if ref.kind not in {"method", "function", "builtin", "class"}:
            result["limitations"].append(
                "The callee does not resolve to an owned callable."
            )
            return result
        effects, index = self._effects(ref)
        result.update(
            status="resolved",
            qualified_name=ref.name,
            kind="function",
            effects=effects,
            path_argument_index=index,
        )
        if ref.kind == "method":
            result["bound_method"] = True
            if ref.model == "path":
                result["kind"] = "path_method"
            else:
                result["kind"] = "local_method"
            if ref.module is not None and ref.module is not self.main:
                result["kind"] = "imported_method"
            result["receiver_is_path"] = ref.model == "path"
            result["receiver_is_non_path"] = ref.model != "path"
        if index is not None and isinstance(ref.node, _FUNCTIONS):
            args = [*ref.node.args.posonlyargs, *ref.node.args.args]
            if ref.kind == "method" and args:
                args = args[1:]
            if index < len(args):
                result["path_argument_name"] = args[index].arg
        if ref.module is not None:
            result["file"] = str(ref.module.path)
        if ref.node is not None:
            result["line"] = getattr(ref.node, "lineno", None)
        result["steps"].append(
            {
                "kind": "source_binding",
                "file": result["file"] or str(self.path),
                "line": result["line"] or getattr(node, "lineno", None),
                "description": f"Callee resolves statically to {ref.name}.",
            }
        )
        if ref.model == "database":
            result["kind"] = "database_method"
            result["steps"].append(
                {
                    "kind": "standard_library_contract",
                    "file": str(self.path),
                    "line": getattr(node, "lineno", None),
                    "description": "An unshadowed sqlite3 import and its connect/cursor factory establish a DB-API receiver; SQL execution remains a sink.",
                }
            )
        if effects["filesystem"] == "unknown" or effects["database"] == "unknown":
            result["limitations"].append(
                "Resolving a callable does not prove the effects of its unresolved delegates."
            )
        return result
