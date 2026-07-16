from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from skylos.core.js_api_surface_utils import MAX_JS_API_SURFACE_SOURCE_BYTES
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.ai_defect.js_api_namespace_references import (
    collect_namespace_member_references as _collect_namespace_member_references,
)
from skylos.rules.ai_defect.js_api_reference_model import (
    ImportContext as _ImportContext,
    JsApiReference,
    NamespaceBinding as _NamespaceBinding,
    first_named_child as _first_named_child,
    make_reference as _reference,
    named_child as _named_child,
    node_line as _line,
    property_name as _property_name,
    source_string_node as _source_string_node,
    string_value as _string_value,
)
from skylos.visitors.languages.typescript import is_minified_js_source
from skylos.visitors.languages.typescript.core import TypeScriptCore


def extract_js_api_references(
    path: Path,
) -> tuple[list[JsApiReference], Counter[str]]:
    source_text = read_text_no_symlink(
        path,
        max_bytes=MAX_JS_API_SURFACE_SOURCE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if source_text is None:
        return [], Counter({"source_unreadable": 1})
    source = source_text.encode("utf-8", "ignore")
    if is_minified_js_source(str(path), source):
        return [], Counter({"minified_source": 1})

    core = TypeScriptCore(str(path), source)
    core.scan()
    if core.root_node is None or core.root_node.has_error:
        return [], Counter({"parse_error": 1})
    return _collect_references(core)


def _collect_references(
    core: TypeScriptCore,
) -> tuple[list[JsApiReference], Counter[str]]:
    references: list[JsApiReference] = []
    namespaces: dict[str, _NamespaceBinding] = {}
    reasons: Counter[str] = Counter()
    for node in core.root_node.named_children:
        if node.type == "import_statement":
            _collect_import_references(core, node, references, namespaces)
        elif node.type == "export_statement":
            _collect_reexport_references(core, node, references)

    for node in core._iter_nodes(core.root_node):
        if node.type == "call_expression":
            _collect_require_reference(core, node, references, namespaces, reasons)

    _collect_namespace_member_references(core, namespaces, references)
    return references, reasons


def _collect_import_references(
    core: TypeScriptCore,
    node: Any,
    references: list[JsApiReference],
    namespaces: dict[str, _NamespaceBinding],
) -> None:
    if _collect_import_equals(core, node, references):
        return
    context = _import_context(core, node)
    if context is None:
        return
    for child in context.clause.named_children:
        _collect_import_clause_child(core, child, context, references, namespaces)


def _collect_import_equals(
    core: TypeScriptCore,
    node: Any,
    references: list[JsApiReference],
) -> bool:
    require_clause = _named_child(node, "import_require_clause")
    if require_clause is None:
        return False
    source_node = _source_string_node(require_clause)
    source = _string_value(core, source_node)
    if source is not None and source_node is not None:
        alias_node = _first_named_child(require_clause, "identifier")
        references.append(
            _reference(
                source,
                None,
                "typescript_import_equals",
                alias_node or require_clause,
                _line(source_node),
                skip_reason="unsupported_typescript_import_equals",
            )
        )
    return True


def _import_context(core: TypeScriptCore, node: Any) -> _ImportContext | None:
    source_node = _source_string_node(node)
    source = _string_value(core, source_node)
    clause = _named_child(node, "import_clause")
    if source is None or source_node is None or clause is None:
        return None
    return _ImportContext(
        source=source,
        source_line=_line(source_node),
        clause=clause,
        type_only=core._get_text(node).lstrip().startswith("import type "),
    )


def _collect_import_clause_child(
    core: TypeScriptCore,
    child: Any,
    context: _ImportContext,
    references: list[JsApiReference],
    namespaces: dict[str, _NamespaceBinding],
) -> None:
    if child.type == "identifier":
        references.append(
            _reference(
                context.source,
                "default",
                "default_import",
                child,
                context.source_line,
                type_only=context.type_only,
            )
        )
        return
    if child.type == "namespace_import":
        _collect_namespace_import(core, child, context, namespaces)
        return
    if child.type == "named_imports":
        _collect_named_imports(core, child, context, references)


def _collect_namespace_import(
    core: TypeScriptCore,
    child: Any,
    context: _ImportContext,
    namespaces: dict[str, _NamespaceBinding],
) -> None:
    alias_node = _first_named_child(child, "identifier")
    if alias_node is None:
        return
    namespaces[core._get_text(alias_node)] = _NamespaceBinding(
        source=context.source,
        source_line=context.source_line,
        kind="namespace_member",
        type_only=context.type_only,
    )


def _collect_named_imports(
    core: TypeScriptCore,
    clause: Any,
    context: _ImportContext,
    references: list[JsApiReference],
) -> None:
    for specifier in clause.named_children:
        if specifier.type != "import_specifier":
            continue
        name_node = specifier.child_by_field_name("name")
        if name_node is None:
            continue
        specifier_type_only = core._get_text(specifier).lstrip().startswith("type ")
        references.append(
            _reference(
                context.source,
                core._get_text(name_node),
                "named_import",
                name_node,
                context.source_line,
                type_only=context.type_only or specifier_type_only,
            )
        )


def _collect_reexport_references(
    core: TypeScriptCore,
    node: Any,
    references: list[JsApiReference],
) -> None:
    source_node = _source_string_node(node)
    source = _string_value(core, source_node)
    if source is None or source_node is None:
        return
    context = _ImportContext(
        source=source,
        source_line=_line(source_node),
        clause=_named_child(node, "export_clause"),
        type_only=core._get_text(node).lstrip().startswith("export type "),
    )
    if context.clause is None:
        return
    for specifier in context.clause.named_children:
        _collect_reexport_specifier(core, specifier, context, references)


def _collect_reexport_specifier(
    core: TypeScriptCore,
    specifier: Any,
    context: _ImportContext,
    references: list[JsApiReference],
) -> None:
    if specifier.type != "export_specifier":
        return
    name_node = specifier.child_by_field_name("name")
    if name_node is None:
        return
    specifier_type_only = core._get_text(specifier).lstrip().startswith("type ")
    references.append(
        _reference(
            context.source,
            core._get_text(name_node),
            "named_reexport",
            name_node,
            context.source_line,
            type_only=context.type_only or specifier_type_only,
        )
    )


def _collect_require_reference(
    core: TypeScriptCore,
    node: Any,
    references: list[JsApiReference],
    namespaces: dict[str, _NamespaceBinding],
    reasons: Counter[str],
) -> None:
    loader = _module_loader(core, node)
    if loader is None:
        return
    argument = _first_call_argument(node)
    source = _string_value(core, argument)
    if source is None:
        reasons["dynamic_module_specifier"] += 1
        return
    if loader == "import":
        reasons["unsupported_dynamic_import"] += 1
        return
    parent = node.parent
    if parent is None:
        return
    source_line = _line(argument)
    if _collect_require_binding(
        core, node, parent, source, source_line, references, namespaces
    ):
        return
    _collect_require_access(core, node, parent, source, source_line, references)


def _module_loader(core: TypeScriptCore, node: Any) -> str | None:
    function = node.child_by_field_name("function")
    if function is None or function.type not in {"identifier", "import"}:
        return None
    function_name = core._get_text(function)
    if function.type == "identifier" and function_name != "require":
        return None
    return function.type


def _first_call_argument(node: Any) -> Any | None:
    arguments = node.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return None
    return arguments.named_children[0]


def _collect_require_binding(
    core: TypeScriptCore,
    node: Any,
    parent: Any,
    source: str,
    source_line: int,
    references: list[JsApiReference],
    namespaces: dict[str, _NamespaceBinding],
) -> bool:
    if parent.type != "variable_declarator":
        return False
    if parent.child_by_field_name("value") != node:
        return False
    name_node = parent.child_by_field_name("name")
    if name_node is None:
        return True
    if name_node.type == "identifier":
        namespaces[core._get_text(name_node)] = _NamespaceBinding(
            source=source,
            source_line=source_line,
            kind="commonjs_namespace_member",
        )
    elif name_node.type == "object_pattern":
        _collect_commonjs_destructure(core, source, source_line, name_node, references)
    return True


def _collect_require_access(
    core: TypeScriptCore,
    node: Any,
    parent: Any,
    source: str,
    source_line: int,
    references: list[JsApiReference],
) -> None:
    if parent.child_by_field_name("object") != node:
        return
    if parent.type == "member_expression":
        property_node = parent.child_by_field_name("property")
        if property_node is not None:
            references.append(
                _reference(
                    source,
                    core._get_text(property_node),
                    "commonjs_member",
                    property_node,
                    source_line,
                )
            )
        return
    if parent.type == "subscript_expression":
        references.append(
            _reference(
                source,
                None,
                "commonjs_computed_member",
                parent,
                source_line,
                skip_reason="computed_namespace_member",
            )
        )


def _collect_commonjs_destructure(
    core: TypeScriptCore,
    source: str,
    source_line: int,
    pattern: Any,
    references: list[JsApiReference],
) -> None:
    for child in pattern.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            references.append(
                _reference(
                    source,
                    core._get_text(child),
                    "commonjs_destructure",
                    child,
                    source_line,
                )
            )
            continue
        symbol_node = _destructure_symbol_node(child)
        symbol = _property_name(core, symbol_node) if symbol_node is not None else None
        if symbol is not None:
            references.append(
                _reference(
                    source,
                    symbol,
                    "commonjs_destructure",
                    symbol_node,
                    source_line,
                )
            )
            continue
        references.append(
            _reference(
                source,
                None,
                "commonjs_destructure",
                child,
                source_line,
                skip_reason="dynamic_commonjs_destructure",
            )
        )


def _destructure_symbol_node(node: Any) -> Any | None:
    if node.type != "pair_pattern":
        return None
    key_node = node.child_by_field_name("key")
    if key_node is None:
        named = list(node.named_children)
        key_node = named[0] if named else None
    if key_node is None:
        return None
    if key_node.type not in {"identifier", "property_identifier", "string"}:
        return None
    return key_node
