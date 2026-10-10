"""Bounded Django template evidence from configured, contained source paths."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
import re

from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.deadcode.framework_liveness import _qualified
from skylos.deadcode.web_framework_ast import _dict_values, _literal

_STRINGS = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1", re.DOTALL)
_TEMPLATE_COMMENTS = re.compile(
    r"{#.*?#}|{%\s*comment\b.*?%}.*?{%\s*endcomment\s*%}",
    re.DOTALL,
)
_TEMPLATE_TAGS = re.compile(r"{{(.*?)}}|{%(.*?)%}", re.DOTALL)
_TEMPLATE_DEPENDENCY = re.compile(
    r"\s*(?:extends|include)\s+(['\"])(.*?)\1\s*",
    re.DOTALL,
)


@dataclass
class _PathEvaluator:
    bindings: dict
    filename: Path
    values: dict

    def expression(self, node):
        if isinstance(_literal(node), str):
            return Path(_literal(node)), False
        if isinstance(node, ast.Name):
            return self._name(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._join(node)
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            base, is_path = self.expression(node.value)
            return (
                (base.parent, True) if base is not None and is_path else (None, False)
            )
        if isinstance(node, ast.Call) and not node.keywords:
            return self._call(node)
        return None, False

    def _name(self, node):
        if node.id == "__file__" and node.id not in self.bindings:
            return self.filename, False
        return self.values.get(node.id, (None, False))

    def _join(self, node):
        base, is_path = self.expression(node.left)
        part = _literal(node.right)
        if is_path and base is not None and isinstance(part, str):
            return base / part, True
        return None, False

    def _call(self, node):
        if (
            _qualified(node.func, self.bindings) == "pathlib.Path"
            and len(node.args) == 1
        ):
            return self.expression(node.args[0])[0], True
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "resolve":
            return None, False
        if node.args:
            return None, False
        base, is_path = self.expression(node.func.value)
        return _resolve_path(base) if is_path else (None, False)


def _resolve_path(base):
    if base is None or not base.is_absolute():
        return None, False
    try:
        return base.resolve(), True
    except (OSError, ValueError, RuntimeError):
        return None, False


def _path_expression(node, bindings, filename, values):
    """Resolve literals or genuine pathlib expressions, never project calls."""
    return _PathEvaluator(bindings, filename, values).expression(node)


def _engine_options(engines):
    if not isinstance(engines, (ast.List, ast.Tuple)) or len(engines.elts) != 1:
        return None
    options = _dict_values(engines.elts[0])
    if options is None:
        return None
    if (
        _literal(options.get("BACKEND"))
        != "django.template.backends.django.DjangoTemplates"
    ):
        return None
    custom = _dict_values(options.get("OPTIONS"))
    if "OPTIONS" in options and (custom is None or "loaders" in custom):
        return None
    return options


def _explicit_directories(options, scanner):
    explicit = options.get("DIRS")
    if explicit is None:
        return set()
    if not isinstance(explicit, (ast.List, ast.Tuple)):
        return None
    bindings, paths = scanner.value_contexts["TEMPLATES"]
    resolved = {
        _path_expression(node, bindings, scanner.path, paths)[0]
        for node in explicit.elts
    }
    if any(path is None or not path.is_absolute() for path in resolved):
        return None
    return resolved


def _app_directories(app, scanners):
    package = scanners.get(app)
    if package is not None and package.path.name == "__init__.py":
        return {package.path.parent / "templates"}
    # Namespace packages may omit __init__.py.
    return {
        module.path.parent / "templates"
        for module in scanners.values()
        if module.module.rpartition(".")[0] == app
    }


def _configured_template_directories(scanner, active_apps, scanners):
    options = _engine_options(scanner.values.get("TEMPLATES"))
    if options is None:
        return set()
    directories = _explicit_directories(options, scanner)
    if directories is None:
        return set()
    if _literal(options.get("APP_DIRS")) is True:
        for app in active_apps:
            directories.update(_app_directories(app, scanners))
    return directories


@dataclass
class _TemplateScope:
    aliases: frozenset
    scopes: list = field(default_factory=list)
    assigned: set = field(default_factory=set)

    def active(self, tag):
        if self.scopes:
            kind = self.scopes[-1][0]
            if tag == "end" + kind:
                self.scopes.pop()
            elif tag == "empty" and kind == "for":
                self.scopes[-1] = ("for", set())
        masked = self.assigned | set().union(*(names for _, names in self.scopes))
        return self.aliases - masked

    def bind(self, tag, clean):
        rebound = set(re.findall(r"\bas\s+([A-Za-z]\w*)\b", clean))
        if tag == "with":
            rebound.update(re.findall(r"(?<!\S)([A-Za-z]\w*)\s*=", clean))
            self.scopes.append((tag, rebound))
        elif tag == "for":
            variables = clean.partition(" in ")[0].removeprefix("for ")
            self.scopes.append((tag, set(re.findall(r"[A-Za-z]\w*", variables))))
        elif tag != "include":
            self.assigned.update(rebound)


def _expression_members(expression, aliases):
    return {
        name
        for alias in aliases
        for name in re.findall(
            r"(?<![\w.])" + re.escape(alias) + r"\.([A-Za-z]\w*)\b",
            expression,
        )
    }


def _template_dependency(expression, tag, overrides_blocks):
    if tag not in {"extends", "include"} or tag == "extends" and overrides_blocks:
        return None
    match = _TEMPLATE_DEPENDENCY.fullmatch(expression)
    return match.group(2) if match else None


def _template_tokens(match):
    expression = match.group(1) if match.group(1) is not None else match.group(2)
    clean = _STRINGS.sub("", expression)
    words = clean.split()
    tag = words[0] if match.group(2) is not None and words else None
    return expression, clean, tag


def _template_references(source, aliases):
    scope = _TemplateScope(aliases)
    found = set()
    dependencies = []
    overrides_blocks = bool(re.search(r"{%\s*block\b", source))
    for match in _TEMPLATE_TAGS.finditer(source):
        expression, clean, tag = _template_tokens(match)
        active = scope.active(tag)
        found.update(_expression_members(clean, active))
        scope.bind(tag, clean)
        dependency = _template_dependency(expression, tag, overrides_blocks)
        if dependency:
            dependencies.append((dependency, frozenset(active)))
    return found, dependencies


@dataclass
class _TemplateResolver:
    root: Path
    directories: set
    exclude_folders: object

    def _candidate(self, directory, name):
        path = directory / name
        if should_exclude_path(path, self.root, self.exclude_folders):
            return None
        try:
            resolved = path.resolve()
            resolved.relative_to(self.root)
            if path.is_file() and not path.is_symlink():
                return resolved
        except (OSError, ValueError):
            pass
        return None

    def _read(self, name):
        candidates = {
            path
            for directory in self.directories
            if (path := self._candidate(directory, name)) is not None
        }
        # Do not guess loader ordering when template names collide.
        if len(candidates) != 1:
            return None
        source = read_text_no_symlink(next(iter(candidates)), max_bytes=65536)
        return _TEMPLATE_COMMENTS.sub("", source) if source is not None else None

    def members(self, template, aliases):
        pending = [(template, frozenset(aliases))]
        visited = set()
        found = set()
        while pending and len(visited) < 32:
            name, context = pending.pop()
            key = (name, context)
            if key in visited or not isinstance(name, str):
                continue
            visited.add(key)
            source = self._read(name)
            if source is not None:
                members, dependencies = _template_references(source, context)
                found.update(members)
                pending.extend(dependencies)
        return found


def _template_members(root, directories, template, aliases, exclude_folders):
    return _TemplateResolver(root, directories, exclude_folders).members(
        template, aliases
    )
