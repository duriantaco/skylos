"""Bounded source proofs that a method repeats a project base signature.

This is presentation evidence, not a reason to discard an argument finding.
Unresolved imports, dynamic class construction and changed interfaces have no
contract evidence. Target modules are parsed as text and are never imported.
"""

import ast
import os
from dataclasses import dataclass
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality._overload_groups import _mutated_names, overload_groups
from skylos.rules.quality._receivers import _scope_bindings


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_TYPING = {"typing", "typing_extensions"}
_MAX_BYTES = 1_000_000
_MAX_MODULES = 16
_MAX_READS = 48
_MAX_DEPTH = 16


@dataclass(eq=False)
class _Source:
    tree: ast.Module
    filename: str
    methods: dict

    def __post_init__(self):
        self.bindings = _scope_bindings(self.tree)
        self.mutated = _mutated_names(self.tree)
        self.classes = {
            node.name: node for node in self.tree.body if isinstance(node, ast.ClassDef)
        }
        self.imports = {}
        for statement in self.tree.body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                for alias in statement.names:
                    name = alias.asname or (
                        alias.name.split(".")[0]
                        if isinstance(statement, ast.Import)
                        else alias.name
                    )
                    self.imports[name] = (statement, alias)
        self.groups = {
            member: group
            for group in overload_groups(self.tree, filename=self.filename)
            for member in group.members
        }

    def stable(self, name):
        return (
            self.bindings.counts[name] == 1
            and name not in self.mutated
            and "*" not in self.bindings.names
            and "*" not in self.mutated
        )


class ArgumentContracts:
    """Resolve only direct declarations, with bounded imports and C3 ancestry."""

    def __init__(self, tree, context, methods):
        self.context = context
        self.complete_module = isinstance(tree, ast.Module)
        if not self.complete_module:
            tree = ast.Module(body=[], type_ignores=[])
        try:
            self.root = (
                Path(os.path.abspath(context["project_root"]))
                if context.get("project_root")
                else None
            )
        except (TypeError, ValueError, OSError):
            self.root = None
        self.reader = context.get("receiver_source_reader")
        filename = str(context.get("filename") or "")
        if filename and self.root is not None and not Path(filename).is_absolute():
            filename = str(self.root / filename)
        self.main = _Source(tree, filename, methods)
        self.sources = {self.main.filename: self.main}
        self.blocked_sources = set()
        self.reads = 0
        self.class_sources = {node: self.main for node in self.main.classes.values()}
        self.owners = {
            method: node
            for node in self.main.classes.values()
            for method in node.body
            if isinstance(method, _FUNCTIONS)
        }
        self.mros = {}
        self.marker_shadow = {}
        self.class_bindings = {}

    def _bindings(self, owner):
        if owner not in self.class_bindings:
            self.class_bindings[owner] = _scope_bindings(owner)
        return self.class_bindings[owner]

    def _read(self, path):
        if self.root is None or self.reads >= _MAX_READS:
            return None
        try:
            path = Path(os.path.abspath(path))
            relative = path.relative_to(self.root)
        except (TypeError, ValueError):
            return None
        self.reads += 1
        if self.reader is None:
            return read_project_text_no_symlink(self.root, path, max_bytes=_MAX_BYTES)
        try:
            source = self.reader(relative)
        except (OSError, ValueError, UnicodeError):
            return None
        try:
            if isinstance(source, str) and len(source.encode("utf-8")) <= _MAX_BYTES:
                return source
        except UnicodeError:
            pass
        return None

    def _source(self, base):
        if self.root is None:
            return None
        candidates = (base.with_suffix(".py"), base / "__init__.py")
        found = []
        for path in candidates:
            key = str(path)
            if key not in self.sources:
                if self.reads >= _MAX_READS or (
                    sum(value is not None for value in self.sources.values())
                    >= _MAX_MODULES
                ):
                    return None
                source = self._read(path)
                self.sources[key] = None
                if source is not None:
                    try:
                        tree = ast.parse(source)
                    except (SyntaxError, ValueError, RecursionError):
                        self.blocked_sources.add(key)
                        return None
                    parsed = _Source(tree, key, {})
                    self.sources[key] = parsed
                    self.class_sources.update(
                        (node, parsed) for node in parsed.classes.values()
                    )
                elif self.reader is None:
                    try:
                        path.lstat()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        self.blocked_sources.add(key)
                    else:
                        self.blocked_sources.add(key)
            if key in self.blocked_sources:
                return None
            if self.sources[key] is not None:
                found.append(self.sources[key])
        return found[0] if len(found) == 1 else None

    def _module(self, source, statement, extra=()):
        if self.root is None or not source.filename:
            return None
        parts = (
            tuple((statement.module or "").split("."))
            if isinstance(statement, ast.ImportFrom)
            else ()
        )
        parts = tuple(part for part in parts if part) + tuple(extra)
        if not parts or not all(part.isidentifier() for part in parts):
            return None
        if isinstance(statement, ast.ImportFrom) and statement.level:
            base = Path(source.filename).parent
            for _ in range(statement.level - 1):
                base = base.parent
            return self._source(base.joinpath(*parts))
        # These are source layouts, not a search of the environment or sys.path.
        # More than one matching layout leaves import identity unresolved.
        found = []
        for base in (self.root, self.root / "src", self.root / "lib"):
            if self.reads >= _MAX_READS:
                return None
            candidate = base.joinpath(*parts)
            parsed = self._source(candidate)
            if any(
                str(path) in self.blocked_sources
                for path in (candidate.with_suffix(".py"), candidate / "__init__.py")
            ):
                return None
            if parsed is not None and parsed not in found:
                found.append(parsed)
        return found[0] if len(found) == 1 else None

    def _class(self, expression, source):
        if isinstance(expression, ast.Name):
            name = expression.id
            if not source.stable(name):
                return None
            if name in source.classes:
                node = source.classes[name]
                return node if node.lineno < expression.lineno else None
            imported = source.imports.get(name)
            if imported and isinstance(imported[0], ast.ImportFrom):
                statement, alias = imported
                if statement.lineno >= expression.lineno:
                    return None
                module = self._module(source, statement)
                if module is not None and module.stable(alias.name):
                    return module.classes.get(alias.name)
            return None
        if not isinstance(expression, ast.Attribute):
            return None
        attributes = []
        while isinstance(expression, ast.Attribute):
            attributes.insert(0, expression.attr)
            expression = expression.value
        if not isinstance(expression, ast.Name) or not source.stable(expression.id):
            return None
        imported = source.imports.get(expression.id)
        if imported is None:
            return None
        statement, alias = imported
        if statement.lineno >= expression.lineno:
            return None
        if isinstance(statement, ast.ImportFrom):
            module = self._module(source, statement, (alias.name, *attributes[:-1]))
        else:
            parts = alias.name.split(".")
            if not alias.asname:
                # ``import package.base`` binds ``package``, not ``base``.
                parts = [parts[0]]
            module = self._module(source, statement, (*parts, *attributes[:-1]))
        name = attributes[-1]
        return module.classes.get(name) if module and module.stable(name) else None

    def _stdlib_marker(self, expression, source, owner, marker):
        """Prove the decorator import and reject local module/name shadows."""
        if isinstance(expression, ast.Name):
            local = expression.id
            imported = source.imports.get(local)
            if imported is None or not isinstance(imported[0], ast.ImportFrom):
                return False
            statement, alias = imported
            module = statement.module
            if statement.level or alias.name != marker:
                return False
        elif (
            isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
            and expression.attr == marker
        ):
            local = expression.value.id
            imported = source.imports.get(local)
            if imported is None or not isinstance(imported[0], ast.Import):
                return False
            statement, alias = imported
            module = alias.name
        else:
            return False
        modules = _TYPING if marker in {"override", "overload"} else {"abc"}
        if (
            module not in modules
            or not source.stable(local)
            or (owner is not None and local in self._bindings(owner).names)
            or statement.lineno >= expression.lineno
        ):
            return False
        if module not in self.marker_shadow:
            shadowed = False
            if self.root is not None:
                for base in (self.root, self.root / "src", self.root / "lib"):
                    for path in (base / f"{module}.py", base / module / "__init__.py"):
                        if self.reads >= _MAX_READS:
                            shadowed = True
                            break
                        if self._read(path) is not None:
                            shadowed = True
                        elif self.reader is None:
                            try:
                                path.lstat()
                            except FileNotFoundError:
                                pass
                            except OSError:
                                shadowed = True
                            else:
                                # Unsafe/oversized potential shadows also count.
                                shadowed = True
            self.marker_shadow[module] = shadowed
        return not self.marker_shadow[module]

    def _kind(self, method, owner, source):
        kind = "instance"
        bindings = self._bindings(owner)
        for decorator in method.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in {
                "staticmethod",
                "classmethod",
            }:
                if (
                    decorator.id in bindings.names
                    or decorator.id in source.bindings.names
                    or decorator.id in source.mutated
                ):
                    return None
                next_kind = "static" if decorator.id == "staticmethod" else "class"
                if kind != "instance":
                    return None
                kind = next_kind
            elif not any(
                self._stdlib_marker(decorator, source, owner, marker)
                for marker in ("override", "overload", "abstractmethod")
            ):
                return None
        return kind

    def _linearize(self, node, active=()):
        if node in self.mros:
            return self.mros[node]
        if len(active) >= _MAX_DEPTH or node in active:
            return None
        source = self.class_sources[node]
        if (
            not source.stable(node.name)
            or node.decorator_list
            or node.keywords
            or "*" in self._bindings(node).names
            or any(
                name in self._bindings(node).names
                for name in ("__init_subclass__", "__getattribute__", "__getattr__")
            )
        ):
            return None
        bases = []
        for expression in node.bases:
            if (
                isinstance(expression, ast.Name)
                and expression.id == "object"
                and "object" not in source.bindings.names
                and "object" not in source.mutated
            ):
                if len(node.bases) != 1:
                    return None
                continue
            base = self._class(expression, source)
            if base is None or base in bases:
                return None
            bases.append(base)
        sequences = []
        for base in bases:
            linear = self._linearize(base, (*active, node))
            if linear is None:
                return None
            sequences.append(list(linear))
        sequences.append(list(bases))
        result = [node]
        while any(sequences):
            sequences = [seq for seq in sequences if seq]
            head = next(
                (
                    seq[0]
                    for seq in sequences
                    if not any(seq[0] in other[1:] for other in sequences)
                ),
                None,
            )
            if head is None or len(result) >= 64:
                return None
            result.append(head)
            for seq in sequences:
                if seq[0] is head:
                    seq.pop(0)
        self.mros[node] = tuple(result)
        return self.mros[node]

    def binding_for(self, method):
        if not self.complete_module:
            return None
        owner = self.owners.get(method)
        if owner is not None:
            members = self._members(owner, method.name)
            if (
                self._linearize(owner) is None
                or members is None
                or method not in members
            ):
                return None
            return self._kind(method, owner, self.main)
        if method in self.main.methods:
            # Nested/dynamic classes are outside the bounded class index.
            return None
        if (
            method in self.main.tree.body
            and method not in self.main.groups
            and self.main.bindings.counts[method.name] != 1
        ):
            return None
        if all(
            self._stdlib_marker(d, self.main, None, "overload")
            for d in method.decorator_list
        ):
            return "function"
        return None

    def _members(self, owner, name):
        source = self.class_sources[owner]
        members = [
            node
            for node in owner.body
            if isinstance(node, _FUNCTIONS) and node.name == name
        ]
        if not members:
            return None
        group = source.groups.get(members[0])
        expected = tuple(group.members) if group else tuple(members)
        if (
            (group is None and len(members) != 1)
            or set(expected) != set(members)
            or self._bindings(owner).counts[name] != len(members)
        ):
            return None
        return members

    def _shape(self, method, owner, source):
        kind = self._kind(method, owner, source)
        if kind is None:
            return None
        args = method.args
        positional = [*args.posonlyargs, *args.args]
        required = len(positional) - len(args.defaults)
        items = [
            (
                "positional_only"
                if index < len(args.posonlyargs)
                else "positional_or_keyword",
                arg.arg,
                index < required,
            )
            for index, arg in enumerate(positional)
        ]
        if kind in {"instance", "class"}:
            if not items:
                return None
            items = items[1:]
        return (
            kind,
            isinstance(method, ast.AsyncFunctionDef),
            tuple(items),
            tuple(
                (arg.arg, default is None)
                for arg, default in zip(args.kwonlyargs, args.kw_defaults)
            ),
            args.vararg.arg if args.vararg else None,
            args.kwarg.arg if args.kwarg else None,
        )

    def contract_for(self, method):
        owner = self.owners.get(method)
        if owner is None:
            return None
        linear = self._linearize(owner)
        source = self.class_sources[owner]
        child_shape = self._shape(method, owner, source)
        members = self._members(owner, method.name)
        if (
            linear is None
            or child_shape is None
            or members is None
            or method not in members
        ):
            return None
        for base in linear[1:]:
            base_source = self.class_sources[base]
            if method.name not in self._bindings(base).names:
                continue
            members = self._members(base, method.name)
            if members is None:
                return None
            for candidate in members:
                if self._shape(candidate, base, base_source) == child_shape:
                    return {
                        "kind": "project_base_signature",
                        "base_class": base.name,
                        "base_file": base_source.filename,
                        "base_line": base.lineno,
                        "method_line": candidate.lineno,
                        "receiver_binding": child_shape[0],
                        "required_positional": sum(item[2] for item in child_shape[2]),
                        "total_parameters": len(child_shape[2]) + len(child_shape[3]),
                        "parameter_shape": "identical",
                        **(
                            {"marker": "typing.override"}
                            if any(
                                self._stdlib_marker(d, source, owner, "override")
                                for d in method.decorator_list
                            )
                            else {}
                        ),
                    }
            # The first declaration in C3 order supplies this interface.
            return None
        return None
