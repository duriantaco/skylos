from __future__ import annotations

import logging

from skylos.changemap.symbols import KIND_FUNCTION, ParsedFile
from skylos.changemap.ts_classes import parse_class
from skylos.changemap.ts_core import FUNCTION_VALUES, Decl, TsFile, make_scope, make_symbol
from skylos.changemap.ts_imports import Resolver
from skylos.changemap.ts_nodes import DECLARATOR, DEFAULT, IDENTIFIER, NAME, VALUE

logger = logging.getLogger(__name__)

_FUNCTION_DECLS = frozenset({"function_declaration", "generator_function_declaration"})
_CLASS_DECLS = frozenset({"class_declaration", "abstract_class_declaration", "class"})
_VARIABLE_DECLS = frozenset({"lexical_declaration", "variable_declaration"})


def _unwrap(node):
    if node.type != "export_statement":
        return node, False
    default = any(c.type == DEFAULT for c in node.children)
    return node.child_by_field_name("declaration") or node.child_by_field_name(VALUE), default


def _wrapped_function(value):
    if value is None or value.type != "call_expression" or value.child_by_field_name("arguments") is None:
        return None, None
    for argument in value.child_by_field_name("arguments").named_children:
        if argument.type in FUNCTION_VALUES:
            return argument, value.child_by_field_name("function")
    return None, None


def _variable(file: TsFile, declarator, statement) -> None:
    name_node = declarator.child_by_field_name(NAME)
    value = declarator.child_by_field_name(VALUE)
    if name_node is None or name_node.type != IDENTIFIER or value is None:
        return
    name = file.text(name_node)
    if value.type in FUNCTION_VALUES:
        make_symbol(file, Decl(name, KIND_FUNCTION, statement, statement, value), make_scope(file))
        return
    wrapped, wrapper = _wrapped_function(value)
    if wrapped is not None:
        make_symbol(file, Decl(name, KIND_FUNCTION, statement, statement, wrapped, [file.text(wrapper)]), make_scope(file))
        return
    file.assignments[name] = (statement.start_point[0] + 1, statement.end_point[0] + 1, file.tokens(value))


def _declared_names(target, file: TsFile) -> set[str]:
    if target.type in _FUNCTION_DECLS | _CLASS_DECLS:
        name = target.child_by_field_name(NAME)
        if name is None:
            return set()
        return {file.text(name)}
    if target.type not in _VARIABLE_DECLS:
        return set()
    found = set()
    for declarator in (d for d in target.named_children if d.type == DECLARATOR):
        name = declarator.child_by_field_name(NAME)
        if name is not None and name.type == IDENTIFIER:
            found.add(file.text(name))
    return found


def _top_names(root, file: TsFile) -> set[str]:
    names = set()
    for node in root.children:
        target, _ = _unwrap(node)
        if target is not None:
            names |= _declared_names(target, file)
    return names


def _function_declaration(file: TsFile, node, target, is_default: bool) -> str:
    name_node = target.child_by_field_name(NAME)
    named = DEFAULT
    if name_node is not None:
        named = file.text(name_node)
    make_symbol(file, Decl(named, KIND_FUNCTION, node, node, target), make_scope(file))
    return named


def _variable_declaration(file: TsFile, node, target, is_default: bool) -> None:
    for declarator in (d for d in target.named_children if d.type == DECLARATOR):
        _variable(file, declarator, node)


def _default_value(file: TsFile, node, target, is_default: bool) -> str | None:
    if not is_default:
        return None
    if target.type == IDENTIFIER:
        return file.text(target)
    if target.type in FUNCTION_VALUES:
        make_symbol(file, Decl(DEFAULT, KIND_FUNCTION, node, node, target), make_scope(file))
        return DEFAULT
    return None


def _handler(target_type: str):
    if target_type in _FUNCTION_DECLS:
        return _function_declaration
    if target_type in _CLASS_DECLS:
        return lambda file, node, target, is_default: parse_class(file, target, node)
    if target_type in _VARIABLE_DECLS:
        return _variable_declaration
    return _default_value


def _declaration(file: TsFile, node, target, is_default: bool) -> None:
    named = _handler(target.type)(file, node, target, is_default)
    if is_default and named:
        file.bindings.aliases[f"{file.module}.default"] = f"{file.module}.{named}"


def _graph_parts(file: TsFile):
    graph, sites, shapes, unresolved = {}, {}, {}, {}
    for symbol in file.symbols.values():
        facts = file.facts.get(symbol.full_name)
        graph[symbol.full_name] = set(symbol.calls)
        if facts is not None:
            sites[symbol.full_name] = dict(facts.sites)
            shapes[symbol.full_name] = dict(facts.shapes)
            unresolved[symbol.full_name] = list(facts.unresolved)
    return graph, sites, shapes, unresolved


def _parse_tree(path: str, data: bytes):
    from skylos.visitors.languages.typescript.core import TS_LANG, TSX_LANG, _get_parser, parse_typescript_source

    jsx = not path.endswith((".ts", ".mts", ".cts"))
    lang = TS_LANG
    if jsx:
        lang = TSX_LANG
    if lang is None:
        return None
    try:
        return parse_typescript_source(_get_parser(lang), data, file_path=path, jsx=jsx)
    except (ValueError, RuntimeError, UnicodeError):
        logger.debug("change map could not parse %s", path, exc_info=True)
        return None


def parse_ts_source(module: str, path: str, source: str, resolver: Resolver) -> ParsedFile | None:
    from skylos.changemap.risk import is_security_call

    data = source.encode("utf-8")
    tree = _parse_tree(path, data)
    if tree is None:
        return None
    file = TsFile(module=module, path=path, source=data, root=tree.root_node, resolver=resolver, security_named=is_security_call)
    file.local_tops = _top_names(tree.root_node, file)
    for node in tree.root_node.children:
        target, is_default = _unwrap(node)
        if target is not None:
            _declaration(file, node, target, is_default)
    graph, sites, shapes, unresolved = _graph_parts(file)
    return ParsedFile(
        module=module, symbols=file.symbols, graph=graph, nodes={}, assignments=file.assignments,
        imported=set(file.bindings.names) | set(file.bindings.namespaces), language="ts",
        call_sites=sites, call_shapes=shapes, unresolved=unresolved,
        aliases=dict(file.bindings.aliases), star_from=list(file.bindings.star_from),
    )
