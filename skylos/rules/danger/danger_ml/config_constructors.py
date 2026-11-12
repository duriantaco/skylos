"""Optional, source-only proof that a call only records configuration values.

Unknown bindings keep the remote-code finding.  This deliberately supports
direct imports and field-only frozen dataclasses, rather than arbitrary local
constructors, factories, inheritance, or constructor assignment aliases.
"""

from __future__ import annotations

import ast

from ..builtin_bindings import builtin_references
from ..import_proof import (
    _Effects,
    import_environment_is_stable,
    provider_binding_is_stable,
    provider_is_unshadowed,
)
from ..module_namespace import module_name_for, module_rebinding
from ..project_imports import project_import_context


_MAX_FILES = 128
_MAX_NODES = 50_000
_MAX_DEPTH = 32
_SCALAR_TYPES = frozenset({"str", "bool", "int", "float", "bytes"})
_GENERIC_TYPES = frozenset({"tuple", "list", "dict", "set", "frozenset", "type"})
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_NATIVE_CALLS = frozenset({"argparse.Namespace", "dataclasses.dataclass"})


def _literal_default(node, depth=0):
    if depth > _MAX_DEPTH:
        return False
    if isinstance(node, ast.Constant):
        return type(node.value) in {str, bytes, int, float, complex, bool, type(None)}
    if isinstance(node, ast.Tuple):
        return all(_literal_default(item, depth + 1) for item in node.elts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return isinstance(node.operand, ast.Constant) and type(node.operand.value) in {
            int,
            float,
            complex,
        }
    return False


def _keyword_values(node):
    """Literal, ordinary attribute names; values are still visited by the rule."""
    values = {}
    for keyword in node.keywords:
        if keyword.arg is not None:
            entries = [(keyword.arg, keyword.value)]
        elif isinstance(keyword.value, ast.Dict):
            entries = []
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if not isinstance(key, ast.Constant) or type(key.value) is not str:
                    return None
                entries.append((key.value, value))
        else:
            return None
        for name, value in entries:
            if (
                not name.isidentifier()
                or name.startswith("__")
                or name.endswith("__")
                or name in values
                or len(values) >= 128
            ):
                return None
            values[name] = value
    return values


def _literal_argument(node, depth=0):
    if depth > _MAX_DEPTH:
        return False
    if _literal_default(node):
        return True
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return all(_literal_argument(value, depth + 1) for value in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None
            and _literal_argument(key, depth + 1)
            and _literal_argument(value, depth + 1)
            for key, value in zip(node.keys, node.values)
        )
    return False


def _matches_fields(node, layout, keywords):
    if layout is None or keywords is None:
        return False
    fields, optional = layout
    positional = set(fields[: len(node.args)])
    return not (
        any(isinstance(argument, ast.Starred) for argument in node.args)
        or len(node.args) > len(fields)
        or set(keywords) - set(fields)
        or positional & set(keywords)
        or set(fields) - positional - set(keywords) - optional
    )


class _ConstructorEffects(_Effects):
    """An annotation-aware view owned by this proof, never cached on the AST."""

    def __init__(self, tree):
        super().__init__(tree)
        self.inert_annotations = set()

    def implicit_use_is_safe(self, node, sensitive, immutable_values=None):
        if id(node) in self.inert_annotations:
            return True
        return super().implicit_use_is_safe(node, sensitive, immutable_values)


class DataConstructorProof:
    def __init__(self, tree, filename, project_root=None):
        self.tree = tree
        self.filename = filename
        self.project_root = project_root
        self.effects = _ConstructorEffects(tree)
        self._units = None
        self._prepared = False
        self._guard_result = None
        self._providers = {}
        self._project_modules = set()
        self._project_callables = set()
        self._data_calls = {"argparse.Namespace"}
        self._data_layouts = {}
        self._project_root = None

    @staticmethod
    def _root(node):
        while isinstance(node, ast.Attribute):
            node = node.value
        return node if isinstance(node, ast.Name) else None

    @staticmethod
    def _direct_origin(effects, expression):
        root = DataConstructorProof._root(expression)
        if root is None or not effects.canonical_reference(expression):
            return None
        key = effects.lookup_key(root)
        if key is None or key in effects.parameter_bindings:
            return None
        origins = []
        for node in effects.nodes:
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                candidate = (
                    effects.binding_scope(effects.scope(node), node.id),
                    node.id,
                )
                if candidate == key:
                    return None
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local = alias.asname or (
                        alias.name.split(".", 1)[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    candidate = (
                        effects.binding_scope(effects.scope(node), local),
                        local,
                    )
                    if candidate == key:
                        if isinstance(node, ast.ImportFrom) and (
                            node.level or not node.module
                        ):
                            return None
                        origins.append(node)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                candidate = (
                    effects.binding_scope(effects.scope(node), node.name),
                    node.name,
                )
                if candidate == key:
                    origins.append(node)
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                if node.name == root.id:
                    return None
            elif isinstance(node, ast.MatchMapping) and node.rest == root.id:
                return None
            elif (
                isinstance(node, ast.NamedExpr)
                and isinstance(node.target, ast.Name)
                and node.target.id == root.id
            ):
                # A comprehension walrus binds outside the comprehension;
                # decline instead of relying on its simplified scope index.
                return None
        return origins[0] if len(origins) == 1 else None

    @staticmethod
    def _field_layout(effects, klass):
        if (
            not isinstance(klass, ast.ClassDef)
            or effects.scope(klass) is not None
            or klass.bases
            or klass.keywords
            or getattr(klass, "type_params", ())
            or len(klass.decorator_list) != 1
        ):
            return None
        decorator = klass.decorator_list[0]
        if (
            not isinstance(decorator, ast.Call)
            or decorator.args
            or len(decorator.keywords) != 1
            or decorator.keywords[0].arg != "frozen"
            or not isinstance(decorator.keywords[0].value, ast.Constant)
            or decorator.keywords[0].value.value is not True
            or effects.refs(decorator.func) != {"dataclasses.dataclass"}
            or DataConstructorProof._direct_origin(effects, decorator.func) is None
        ):
            return None
        scalar_annotations = getattr(effects, "_config_scalar_annotations", None)
        if scalar_annotations is None:
            scalar_annotations = builtin_references(effects.nodes[0], _SCALAR_TYPES)
            effects._config_scalar_annotations = scalar_annotations
        fields = []
        optional = set()
        for member in klass.body:
            if isinstance(member, ast.Pass) or (
                isinstance(member, ast.Expr)
                and isinstance(member.value, ast.Constant)
                and isinstance(member.value.value, str)
            ):
                continue
            if (
                not isinstance(member, ast.AnnAssign)
                or not member.simple
                or not isinstance(member.target, ast.Name)
                or not isinstance(member.annotation, ast.Name)
                or member.annotation.id not in _SCALAR_TYPES
                or id(member.annotation) not in scalar_annotations
                or member.target.id.startswith("__")
                or member.target.id.endswith("__")
                or member.target.id in fields
                or member.value is not None
                and not _literal_default(member.value)
                or optional
                and member.value is None
            ):
                return None
            fields.append(member.target.id)
            if member.value is not None:
                optional.add(member.target.id)
        return (tuple(fields), frozenset(optional)) if fields else None

    @staticmethod
    def _annotation_nodes(effects, tree):
        builtins = builtin_references(tree, _SCALAR_TYPES | _GENERIC_TYPES)

        def inert(node, depth=0):
            if depth > _MAX_DEPTH:
                return False
            if isinstance(node, ast.Constant):
                return node.value is None or isinstance(node.value, str)
            if isinstance(node, ast.Name) and id(node) in builtins:
                return True
            if isinstance(node, (ast.Name, ast.Attribute)):
                origins = effects.refs(node)
                return (
                    len(origins) == 1
                    and (
                        origins == {"argparse.Namespace"}
                        or next(iter(origins)) in effects.class_nodes
                    )
                    and DataConstructorProof._direct_origin(effects, node) is not None
                )
            if isinstance(node, ast.Subscript):
                return (
                    isinstance(node.value, ast.Name)
                    and node.value.id in _GENERIC_TYPES
                    and id(node.value) in builtins
                    and all(
                        inert(part, depth + 1)
                        for part in (
                            node.slice.elts
                            if isinstance(node.slice, ast.Tuple)
                            else [node.slice]
                        )
                    )
                )
            return False

        allowed = set()
        for node in effects.nodes:
            annotations = []
            if isinstance(node, ast.AnnAssign):
                annotations.append(node.annotation)
            elif isinstance(node, ast.arg) and node.annotation is not None:
                annotations.append(node.annotation)
            elif (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.returns
            ):
                annotations.append(node.returns)
            for annotation in annotations:
                if inert(annotation):
                    allowed.update(id(part) for part in ast.walk(annotation))
        return allowed

    def _prepare(self):
        if self._prepared:
            return self._units
        self._prepared = True
        if not isinstance(self.tree, ast.Module) or not self.effects.complete:
            return None
        context = project_import_context(self.tree, self.filename, self.project_root)
        if context is None or len(context.snapshot) > _MAX_FILES:
            return None
        self._project_root = context.root
        units = []
        count = 0
        for path, parsed in context.snapshot.items():
            parsed = self.tree if path == context.source else parsed
            effects = (
                self.effects if parsed is self.tree else _ConstructorEffects(parsed)
            )
            count += len(effects.nodes)
            if not effects.complete or count > _MAX_NODES:
                return None
            # Relative imports need a separate qualified-binding proof.  Do
            # not let their missing _Effects alias silently hide a capability.
            if any(
                isinstance(node, ast.ImportFrom) and node.level
                for node in effects.nodes
            ):
                return None
            effects.inert_annotations = self._annotation_nodes(effects, parsed)
            units.append((path, parsed, effects))
            modules = {name for name in context.names.get(path, ()) if name}
            self._project_modules.update(modules)
            self._project_callables.update(
                f"{module}.{node.name}"
                for module in modules
                for node in parsed.body
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
            )
            for node in parsed.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                layout = self._field_layout(effects, node)
                if layout is not None:
                    names = {f"@class:{id(node)}"}
                    names.update(f"{module}.{node.name}" for module in modules)
                    self._data_calls.update(names)
                    self._data_layouts.update((name, layout) for name in names)
        self._units = units
        return units

    def _provider(self, qualified):
        if qualified in self._providers:
            return self._providers[qualified]
        units = self._prepare()
        if units is None:
            return False
        # The normal proof is reused when it can finish.  A sensitive type
        # annotation can make it abstain; the fallback below keeps original
        # source attestation and performs private annotation-aware effects.
        ordinary = provider_binding_is_stable(
            qualified, self.tree, self.filename, self.project_root
        )
        result = ordinary or all(
            provider_is_unshadowed(qualified, path, self._project_root)
            and import_environment_is_stable(parsed)
            for path, parsed, _effects in units
        )
        self._providers[qualified] = result
        return result

    def _guard(self):
        if self._guard_result is not None:
            return self._guard_result
        self._guard_result = False
        units = self._prepare()
        if units is None:
            return False
        for path, parsed, effects in units:
            dynamic, rebound = module_rebinding(parsed, module_name_for(path))
            if dynamic or rebound or not import_environment_is_stable(parsed):
                return False
            for node in effects.nodes:
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.decorator_list
                ):
                    return False
                if (
                    isinstance(node, ast.ClassDef)
                    and node.decorator_list
                    and self._field_layout(effects, node) is None
                ):
                    return False
                # A stored instance still exposes its mutable type.  Avoid a
                # heap evaluator: visible attribute/item writes and nonliteral
                # arguments to other calls make this optional proof abstain.
                if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    return False
                if isinstance(node, ast.Call):
                    functions = effects.refs(node.func)
                    keywords = _keyword_values(node)
                    call_origin = self._direct_origin(effects, node.func)
                    recording = (
                        len(functions) == 1
                        and functions <= self._data_calls
                        and keywords is not None
                        and not any(
                            isinstance(argument, ast.Starred) for argument in node.args
                        )
                        and effects.canonical_reference(node.func)
                        and call_origin is not None
                    )
                    if recording:
                        if functions == {"argparse.Namespace"}:
                            recording = (
                                not node.args
                                and self._provider("argparse.Namespace")
                                and self._provider("builtins.setattr")
                            )
                        else:
                            recording = (
                                isinstance(call_origin, ast.ClassDef)
                                and _matches_fields(
                                    node,
                                    self._data_layouts.get(next(iter(functions))),
                                    keywords,
                                )
                                and self._provider("dataclasses.dataclass")
                                and self._provider("builtins.object")
                            )
                    if not recording and any(
                        not _literal_argument(value)
                        for value in [
                            *node.args,
                            *(keyword.value for keyword in node.keywords),
                        ]
                    ):
                        return False

            def sensitive(name):
                return name.startswith(("@function:", "@class:")) or any(
                    name == root or name.startswith(root + ".")
                    for root in (
                        "argparse",
                        "dataclasses",
                        "builtins",
                        *self._project_modules,
                    )
                )

            callables = set(_NATIVE_CALLS) | self._project_callables
            callables.update(
                origin
                for origins in effects.aliases.values()
                for origin in origins
                if origin.startswith(("@function:", "@class:")) and "." not in origin
            )
            if not effects.stable(sensitive, callable_names=callables):
                return False
        self._guard_result = True
        return True

    def is_data_call(self, node):
        if not isinstance(node, ast.Call) or id(node) not in self.effects.parents:
            return False
        current = node
        while current is not None:
            if isinstance(current, (ast.Lambda, *_COMPREHENSIONS)):
                return False
            current = self.effects.parents.get(id(current))
        if isinstance(self.effects.scope(node), ast.ClassDef):
            return False
        keywords = _keyword_values(node)
        if keywords is None:
            return False
        origin = self._direct_origin(self.effects, node.func)
        if origin is None:
            return False
        names = self.effects.refs(node.func)
        if names == {"argparse.Namespace"}:
            return (
                not node.args
                and self._provider("argparse.Namespace")
                and self._provider("builtins.setattr")
                and self._guard()
            )
        if not isinstance(origin, ast.ClassDef) or origin not in self.tree.body:
            return False
        if names != {f"@class:{id(origin)}"}:
            return False
        layout = self._field_layout(self.effects, origin)
        if not _matches_fields(node, layout, keywords):
            return False
        return (
            self._provider("dataclasses.dataclass")
            and self._provider("builtins.object")
            and self._guard()
        )
