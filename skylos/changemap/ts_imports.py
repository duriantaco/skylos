from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.changemap.ts_nodes import IDENTIFIER, NAME, STRING, VALUE
from skylos.visitors.languages.typescript.resolve import MonorepoResolver

TS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_PROBE = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_JS_TO_TS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}


def is_ts_path(path: str) -> bool:
    return path.endswith(TS_SUFFIXES) and not path.endswith(".d.ts")


def ts_module_name(path: str) -> str:
    stem = PurePosixPath(path)
    for suffix in TS_SUFFIXES:
        if path.endswith(suffix):
            stem = PurePosixPath(path[: -len(suffix)])
            break
    return ".".join(part.replace(".", "_") for part in stem.parts)


@dataclass
class Bindings:
    names: dict[str, str] = field(default_factory=dict)
    namespaces: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    star_from: list[str] = field(default_factory=list)


class Resolver:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.monorepo = MonorepoResolver(str(self.root))
        self.cache: dict[tuple[str, str], str | None] = {}

    def _existing(self, candidate: Path) -> str | None:
        if candidate.is_file() and is_ts_path(candidate.name):
            return candidate.resolve().relative_to(self.root.resolve()).as_posix()
        return None

    def _probe(self, base: Path) -> str | None:
        found = self._existing(base)
        if found:
            return found
        for suffix in _PROBE:
            found = self._existing(base.with_name(base.name + suffix))
            if found:
                return found
        for replacement in _JS_TO_TS.get(base.suffix, ()):
            found = self._existing(base.with_suffix(replacement))
            if found:
                return found
        for suffix in _PROBE:
            found = self._existing(base / f"index{suffix}")
            if found:
                return found
        return None

    def _absolute(self, target: str) -> str | None:
        try:
            Path(target).resolve().relative_to(self.root.resolve())
        except ValueError:
            return None
        return self._probe(Path(target))

    def resolve(self, source: str, importer: str) -> str | None:
        key = (source, importer)
        if key not in self.cache:
            self.cache[key] = self._resolve(source, importer)
        return self.cache[key]

    def _resolve(self, source: str, importer: str) -> str | None:
        importer_path = self.root / importer
        if source.startswith("."):
            return self._probe(importer_path.parent / source)
        try:
            target = self.monorepo.resolve(source, str(importer_path))
        except (OSError, ValueError):
            return None
        if target:
            return self._absolute(target)
        return None

    def target(self, source: str, importer: str) -> str:
        found = self.resolve(source, importer)
        if found:
            return ts_module_name(found)
        return source.removeprefix("node:")


def _string_value(node, text) -> str | None:
    if node is None or node.type != STRING:
        return None
    return text(node).strip("'\"`")


def _named_specifiers(node, text) -> list[tuple[str, str]]:
    pairs = []
    for spec in node.children:
        if spec.type not in ("import_specifier", "export_specifier"):
            continue
        name = spec.child_by_field_name(NAME)
        alias = spec.child_by_field_name("alias")
        if name is not None:
            local = alias or name
            pairs.append((text(name), text(local)))
    return pairs


def _import_clause(clause, module: str, text, bindings: Bindings) -> None:
    for part in clause.children:
        if part.type == IDENTIFIER:
            bindings.names[text(part)] = f"{module}.default"
        elif part.type == "namespace_import":
            ids = [c for c in part.children if c.type == IDENTIFIER]
            if ids:
                bindings.namespaces[text(ids[-1])] = module
        elif part.type == "named_imports":
            for name, local in _named_specifiers(part, text):
                bindings.names[local] = f"{module}.{name}"


def _import_statement(node, importer: str, text, resolver: Resolver, bindings: Bindings) -> None:
    source = _string_value(node.child_by_field_name("source"), text)
    if source is None:
        return
    module = resolver.target(source, importer)
    for child in node.children:
        if child.type == "import_clause":
            _import_clause(child, module, text, bindings)


def _export_statement(node, own_module: str, context: tuple) -> None:
    importer, text, resolver, bindings = context
    source = _string_value(node.child_by_field_name("source"), text)
    if source is None:
        return
    module = resolver.target(source, importer)
    clauses = [c for c in node.children if c.type == "export_clause"]
    if not clauses:
        bindings.star_from.append(module)
        return
    for name, local in _named_specifiers(clauses[0], text):
        bindings.aliases[f"{own_module}.{local}"] = f"{module}.{name}"


def _require_source(value, text) -> str | None:
    if value is None or value.type != "call_expression":
        return None
    func = value.child_by_field_name("function")
    if func is None or text(func) != "require":
        return None
    args = [a for a in value.child_by_field_name("arguments").children if a.type == STRING]
    if not args:
        return None
    return _string_value(args[0], text)


def _pattern_binding(prop, module: str, text, bindings: Bindings) -> None:
    if prop.type == "shorthand_property_identifier_pattern":
        bindings.names[text(prop)] = f"{module}.{text(prop)}"
        return
    if prop.type != "pair_pattern":
        return
    key, value = prop.child_by_field_name("key"), prop.child_by_field_name(VALUE)
    if key is not None and value is not None:
        bindings.names[text(value)] = f"{module}.{text(key)}"


def _require_declarator(declarator, context: tuple) -> None:
    importer, text, resolver, bindings = context
    source = _require_source(declarator.child_by_field_name(VALUE), text)
    target = declarator.child_by_field_name(NAME)
    if source is None or target is None:
        return
    module = resolver.target(source, importer)
    if target.type == IDENTIFIER:
        bindings.namespaces[text(target)] = module
        return
    for prop in target.children:
        _pattern_binding(prop, module, text, bindings)


def collect_bindings(root_node, own_module: str, importer: str, text, resolver: Resolver) -> Bindings:
    bindings = Bindings()
    context = (importer, text, resolver, bindings)
    for node in root_node.children:
        if node.type == "import_statement":
            _import_statement(node, importer, text, resolver, bindings)
        elif node.type == "export_statement":
            _export_statement(node, own_module, context)
        elif node.type in ("lexical_declaration", "variable_declaration"):
            for declarator in (d for d in node.children if d.type == "variable_declarator"):
                _require_declarator(declarator, context)
    return bindings
