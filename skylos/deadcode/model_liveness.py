"""Prove declarative model fields and hooks from Python source bindings."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from functools import cache, partial
from pathlib import Path

from skylos.analysis.known_patterns import (
    PYDANTIC_MODEL_METHODS,
    PYDANTIC_VALIDATOR_DECORATORS,
)
from skylos.deadcode._reachability_bindings import (
    FUNCTION_NODES,
    ModuleInfo,
    argument_nodes,
    bound_names,
    import_bindings,
)
from skylos.deadcode.framework_liveness import _module_name
from skylos.deadcode.python_import_roots import ModuleAliases
from skylos.deadcode.python_proofs import qualified_name

_FRAMEWORKS = {
    "pydantic",
    "pydantic_settings",
    "sqlmodel",
    "sqlalchemy",
    "flask_sqlalchemy",
}
_SETTINGS_V1 = {
    "pydantic.BaseSettings",
    "pydantic.env_settings.BaseSettings",
    "pydantic.v1.BaseSettings",
    "pydantic.v1.env_settings.BaseSettings",
}
_SETTINGS_V2 = {"pydantic_settings.BaseSettings", "pydantic_settings.main.BaseSettings"}
_PYDANTIC = (
    _SETTINGS_V1
    | _SETTINGS_V2
    | {
        "pydantic.BaseModel",
        "pydantic.main.BaseModel",
        "pydantic.RootModel",
        "pydantic.root_model.RootModel",
        "pydantic.generics.GenericModel",
        "pydantic.v1.BaseModel",
        "pydantic.v1.main.BaseModel",
        "pydantic.v1.generics.GenericModel",
        "sqlmodel.SQLModel",
        "sqlmodel.main.SQLModel",
    }
)
_PYDANTIC_FIELDS = {
    "pydantic.Field",
    "pydantic.fields.Field",
    "pydantic.PrivateAttr",
    "pydantic.fields.PrivateAttr",
    "pydantic.v1.Field",
    "pydantic.v1.fields.Field",
    "pydantic.v1.PrivateAttr",
    "pydantic.v1.fields.PrivateAttr",
    "sqlmodel.Field",
    "sqlmodel.Relationship",
    "sqlmodel.main.Field",
    "sqlmodel.main.Relationship",
}
_PYDANTIC_DECORATORS = {
    f"{provider}.{name}"
    for provider in (
        "pydantic",
        "pydantic.v1",
        "pydantic.class_validators",
        "pydantic.v1.class_validators",
        "pydantic.functional_validators",
        "pydantic.functional_serializers",
        "pydantic.fields",
        "pydantic.deprecated.class_validators",
    )
    for name in PYDANTIC_VALIDATOR_DECORATORS
}
_DECLARATIVE_BASE = "@sqlalchemy_base"
_REGISTRY = "@sqlalchemy_registry"
_FLASK_EXTENSION = "@flask_sqlalchemy"
_BASE_FACTORIES = {
    "sqlalchemy.orm.declarative_base",
    "sqlalchemy.orm.decl_api.declarative_base",
    "sqlalchemy.ext.declarative.declarative_base",
    f"{_REGISTRY}.generate_base",
}
_FACTORIES = {
    **dict.fromkeys(_BASE_FACTORIES, _DECLARATIVE_BASE),
    "sqlalchemy.orm.registry": _REGISTRY,
    "sqlalchemy.orm.decl_api.registry": _REGISTRY,
    "flask_sqlalchemy.SQLAlchemy": _FLASK_EXTENSION,
    "flask_sqlalchemy.extension.SQLAlchemy": _FLASK_EXTENSION,
}
_SQLALCHEMY_BASES = {
    _DECLARATIVE_BASE,
    "sqlalchemy.orm.DeclarativeBase",
    "sqlalchemy.orm.DeclarativeBaseNoMeta",
    "sqlalchemy.orm.decl_api.DeclarativeBase",
    "sqlalchemy.orm.decl_api.DeclarativeBaseNoMeta",
}
_SQLALCHEMY_MAPPED = {
    f"{provider}.{name}"
    for provider in ("sqlalchemy.orm", "sqlalchemy.orm.base")
    for name in ("Mapped", "DynamicMapped", "WriteOnlyMapped")
}
_SQLALCHEMY_FIELDS = {
    f"sqlalchemy.orm.{name}"
    for name in (
        "RelationshipProperty",
        "column_property",
        "composite",
        "deferred",
        "dynamic_loader",
        "mapped_column",
        "query_expression",
        "relationship",
        "synonym",
    )
} | {
    "sqlalchemy.Column",
    "sqlalchemy.sql.schema.Column",
    "sqlalchemy.ext.associationproxy.association_proxy",
}
_DECLARED_ATTR = {
    provider + variant
    for provider in (
        "sqlalchemy.orm.declared_attr",
        "sqlalchemy.orm.decl_api.declared_attr",
        "sqlalchemy.ext.declarative.declared_attr",
    )
    for variant in ("", ".cascading", ".directive")
}
_ORM_CONFIGURATION = {
    "__abstract__",
    "__allow_unmapped__",
    "__mapper_args__",
    "__table__",
    "__table_args__",
    "__tablename__",
}
_CLASSVAR = {"typing.ClassVar", "typing_extensions.ClassVar"}
_ANNOTATED = {"typing.Annotated", "typing_extensions.Annotated"}


@dataclass
class _Member:
    node: ast.stmt
    name: str
    annotation: tuple[str | None, ...] = ()
    value_provider: str | None = None
    decorators: tuple[str | None, ...] = ()


@dataclass
class _Model:
    path: Path
    bases: tuple[str | None, ...]
    decorators: tuple[str | None, ...]
    members: list[_Member] = field(default_factory=list)


def _qualified_head(node, bindings):
    if isinstance(node, (ast.Subscript, ast.Call)):
        node = node.value if isinstance(node, ast.Subscript) else node.func
    name = qualified_name(node, bindings)
    return bindings.get(name, name)


def _annotation_heads(annotation, bindings):
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        if len(annotation.value) > 512:
            return ()
        try:
            annotation = ast.parse(annotation.value, mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            return ()
    heads = []
    for _ in range(8):
        heads.append(_qualified_head(annotation, bindings))
        if not isinstance(annotation, ast.Subscript):
            break
        annotation = annotation.slice
        if isinstance(annotation, ast.Tuple) and annotation.elts:
            annotation = annotation.elts[0]
    return tuple(heads)


class _ModelBindings:
    def __init__(self, root, parsed_files):
        self.modules = {
            _module_name(parsed.path, root): parsed
            for parsed in parsed_files
            if parsed.path.is_relative_to(root)
        }
        self.module_aliases = ModuleAliases(root, self.modules)
        self.modules_by_path = {module.path: module for module in self.modules.values()}
        self.module_bindings = {}
        self.models = {}
        self.constructors = {}
        self.shadowed = {name.partition(".")[0] for name in self.modules}
        for name, parsed in self.modules.items():
            info = ModuleInfo(parsed.path, parsed.tree, {name})
            bindings = {}
            self._scan_scope(parsed.tree.body, bindings, info)
            self.module_bindings[parsed.path] = bindings

    def _scan_scope(self, body, bindings, info, members=None, enclosing=None):
        pending = list(reversed(body))
        while pending:
            node = pending.pop()
            if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
                pending.extend(reversed(node.body if node.test.value else node.orelse))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if any(item.name == "*" for item in node.names):
                    bindings.clear()
                else:
                    bindings.update(
                        (name, value[1] if value else None)
                        for name, value in import_bindings(node, info).items()
                    )
            elif isinstance(node, ast.ClassDef):
                key = f"@class:{len(self.models)}"
                model = _Model(
                    info.path,
                    tuple(_qualified_head(base, bindings) for base in node.bases),
                    tuple(
                        _qualified_head(decorator, bindings)
                        for decorator in node.decorator_list
                    ),
                )
                self.models[key] = model
                parent = bindings if enclosing is None else enclosing
                self._scan_scope(node.body, parent.copy(), info, model.members, parent)
                bindings[node.name] = key
                if members is not None:
                    members.append(_Member(node, node.name))
            elif isinstance(node, FUNCTION_NODES):
                if members is not None:
                    members.append(
                        _Member(
                            node,
                            node.name,
                            decorators=tuple(
                                _qualified_head(decorator, bindings)
                                for decorator in node.decorator_list
                            ),
                        )
                    )
                local = (bindings if enclosing is None else enclosing).copy()
                local.update(dict.fromkeys(bound_names(node.body).counts))
                local.update(
                    dict.fromkeys(arg.arg for arg in argument_nodes(node.args))
                )
                self._scan_scope(node.body, local, info)
                bindings[node.name] = None
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._assignment(node, bindings, info.path, members)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    name = _qualified_head(target, bindings)
                    if isinstance(target, ast.Attribute) and name:
                        bindings[name] = None
                bindings.update(dict.fromkeys(bound_names([node]).counts))
            else:
                bindings.update(dict.fromkeys(bound_names([node]).counts))

    def _assignment(self, node, bindings, path, members):
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        annotation = (
            _annotation_heads(node.annotation, bindings)
            if isinstance(node, ast.AnnAssign)
            else ()
        )
        provider = _qualified_head(value, bindings)
        binding = provider
        if isinstance(value, ast.Call) and provider:
            binding = f"@constructor:{len(self.constructors)}"
            self.constructors[binding] = (provider, path)
        for target in targets:
            if isinstance(target, ast.Name):
                if members is not None:
                    members.append(_Member(node, target.id, annotation, provider))
                if value is not None:
                    bindings[target.id] = binding
            elif isinstance(target, ast.Attribute):
                name = _qualified_head(target, bindings)
                if name:
                    bindings[name] = None
            else:
                bindings.update(dict.fromkeys(bound_names([target]).counts))

    def expand(self, name, importer, seen=()):
        """Follow project exports in the defining module's import scope."""
        state = name, importer
        if not name or state in seen or len(seen) >= 24:
            return None
        active = (*seen, state)
        if name.startswith("@constructor:"):
            key, _, attribute = name.partition(".")
            provider, origin = self.constructors[key]
            target = _FACTORIES.get(self.expand(provider, origin, active))
            return (
                self.expand(f"{target}.{attribute}", importer, active)
                if target and attribute
                else target
            )
        if name == f"{_FLASK_EXTENSION}.Model":
            return _DECLARATIVE_BASE
        parts = name.split(".")
        shadowed = parts[0] in self.shadowed
        for end in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:end])
            module, blocked = self.module_aliases.scoped(
                prefix, self.modules_by_path[importer]
            )
            if blocked:
                shadowed = True
                continue
            if module is None:
                module = self.modules.get(prefix)
            if module is None:
                continue
            target = self.module_bindings[module.path].get(parts[end])
            if target:
                name = ".".join([target, *parts[end + 1 :]])
                return self.expand(name, module.path, active)
            return None
        return None if shadowed else name

    def descendants_of_mappers(self, mapped, bases):
        """Include mixins only when a proven mapping inherits from them."""
        result = set(mapped)
        pending = list(mapped)
        while pending:
            for base in bases[pending.pop()]:
                if base in self.models and base not in result:
                    result.add(base)
                    pending.append(base)
        return result


def _annotation_provider(member, expand):
    for head in member.annotation:
        provider = expand(head)
        if provider not in _ANNOTATED:
            return provider
    return None


def _pydantic_member(member, ancestors, expand):
    name = member.name
    node = member.node
    if isinstance(node, FUNCTION_NODES):
        if name in PYDANTIC_MODEL_METHODS:
            return True
        if name == "settings_customise_sources" and ancestors & _SETTINGS_V2:
            return True
        return any(
            expand(decorator) in _PYDANTIC_DECORATORS for decorator in member.decorators
        )
    if isinstance(node, ast.ClassDef):
        return name == "Config"
    if name == "model_config":
        return True
    if member.annotation:
        return _annotation_provider(member, expand) not in _CLASSVAR
    if (
        isinstance(node.value, ast.Call)
        and expand(member.value_provider) in _PYDANTIC_FIELDS
    ):
        return True
    # Pydantic 1 accepted inferred field types from a plain default value.
    return not name.startswith("_") and (
        bool(ancestors & _SETTINGS_V1)
        or any(base.startswith("pydantic.v1.") for base in ancestors)
        or (
            bool(ancestors & {"pydantic.BaseModel", "pydantic.main.BaseModel"})
            and isinstance(
                node.value, (ast.Constant, ast.List, ast.Dict, ast.Tuple, ast.Set)
            )
        )
    )


def _sqlalchemy_member(member, expand):
    if isinstance(member.node, FUNCTION_NODES):
        return any(
            expand(decorator) in _DECLARED_ATTR for decorator in member.decorators
        )
    if isinstance(member.node, ast.ClassDef):
        return False
    if (
        member.name in _ORM_CONFIGURATION
        or _annotation_provider(member, expand) in _SQLALCHEMY_MAPPED
    ):
        return True
    return (
        isinstance(member.node.value, ast.Call)
        and expand(member.value_provider) in _SQLALCHEMY_FIELDS
    )


def _imports_model_framework(parsed_files):
    for parsed in parsed_files:
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Import):
                if any(alias.name.partition(".")[0] in _FRAMEWORKS for alias in node.names):
                    return True
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.partition(".")[0] in _FRAMEWORKS:
                    return True
    return False


def find_model_members(definitions, parsed_files, root):
    """Return source-owned definitions consumed by a model constructor or mapper."""
    if not _imports_model_framework(parsed_files):
        return
    if root.is_file():
        root = root.parent
    index = _ModelBindings(root, parsed_files)
    expand = cache(index.expand)
    bases = {
        key: tuple(expand(base, model.path) for base in model.bases)
        for key, model in index.models.items()
    }

    @cache
    def ancestors(key):
        found = set()
        pending = [key]
        while pending:
            for base in bases.get(pending.pop(), ()):
                if base and base not in found:
                    found.add(base)
                    pending.append(base)
        return found

    mapped = {
        key
        for key, model in index.models.items()
        if ancestors(key) & _SQLALCHEMY_BASES
        or any(
            expand(decorator, model.path)
            in {f"{_REGISTRY}.mapped", f"{_REGISTRY}.mapped_as_dataclass"}
            for decorator in model.decorators
        )
    }
    mapper_members = index.descendants_of_mappers(mapped, bases)

    @cache
    def resolved_path(filename):
        return Path(filename).resolve()

    definitions_at = {
        (resolved_path(item.filename), item.line, item.simple_name): item
        for item in definitions.values()
        if item.type in {"class", "variable", "method", "function"}
    }
    for key, model in index.models.items():
        resolve = partial(expand, importer=model.path)
        model_ancestors = ancestors(key)
        if key not in mapper_members and not model_ancestors & _PYDANTIC:
            continue
        for member in model.members:
            if model_ancestors & _PYDANTIC and _pydantic_member(
                member, model_ancestors, resolve
            ):
                reason = "pydantic_model_member"
            elif key in mapper_members and _sqlalchemy_member(member, resolve):
                reason = "sqlalchemy_mapped_member"
            else:
                continue
            target = definitions_at.get((model.path, member.node.lineno, member.name))
            if target is not None:
                yield target, reason
            if (
                member.name == "Config"
                and isinstance(member.node, ast.ClassDef)
                and model_ancestors & _SETTINGS_V1
            ):
                for hook in member.node.body:
                    if (
                        isinstance(hook, FUNCTION_NODES)
                        and hook.name == "customise_sources"
                    ):
                        target = definitions_at.get(
                            (model.path, hook.lineno, hook.name)
                        )
                        if target is not None:
                            yield target, reason
