"""Dart value reads and directive facts, without inventing module-name bindings."""

from __future__ import annotations


_OBJECT_METHODS = {"toString", "noSuchMethod"}
_ITERABLE_METHODS = set(
    "any cast contains elementAt every expand firstWhere fold followedBy forEach join lastWhere map reduce singleWhere skip skipWhile take takeWhile toList toSet where whereType".split()
)
# Only known instance methods exclude an extension-call possibility. An unlisted
# method is still unresolved; this is not an exhaustive Core API model.
_CORE_METHODS = {
    "Object": _OBJECT_METHODS,
    "String": set(
        "codeUnitAt compareTo contains endsWith indexOf lastIndexOf padLeft padRight replaceAll replaceAllMapped replaceFirst replaceFirstMapped replaceRange split splitMapJoin startsWith substring toLowerCase toUpperCase trim trimLeft trimRight".split()
    ),
    "Iterable": _ITERABLE_METHODS,
    "List": _ITERABLE_METHODS
    | set(
        "add addAll asMap clear fillRange getRange indexOf indexWhere insert insertAll lastIndexOf lastIndexWhere remove removeAt removeLast removeRange removeWhere replaceRange retainWhere setAll setRange shuffle sort sublist".split()
    ),
    "Set": _ITERABLE_METHODS
    | set(
        "add addAll clear containsAll difference intersection lookup remove removeAll removeWhere retainAll retainWhere union".split()
    ),
    "Map": set(
        "addAll addEntries cast clear containsKey containsValue forEach map putIfAbsent remove removeWhere update updateAll".split()
    ),
    "num": set(
        "abs ceil ceilToDouble clamp compareTo floor floorToDouble remainder round roundToDouble sign toDouble toInt toStringAsExponential toStringAsFixed toStringAsPrecision truncate truncateToDouble".split()
    ),
    "bool": set(),
}
_CORE_METHODS["int"] = _CORE_METHODS["num"] | {
    "gcd",
    "modInverse",
    "modPow",
    "toRadixString",
    "toSigned",
    "toUnsigned",
}
_CORE_METHODS["double"] = _CORE_METHODS["num"]
_LITERAL_TYPES = {
    "string_literal": "String",
    "list_literal": "List",
    "decimal_integer_literal": "int",
    "decimal_floating_point_literal": "double",
    "true": "bool",
    "false": "bool",
}


def directive_metadata(core, node):
    text = core._get_text(node).strip()
    sources = [
        core._get_text(uri).strip("\"'")
        for uri in core._descendants_of_type(node, "uri")
    ]
    shown, hidden = [], []
    for combinator in core._descendants_of_type(node, "combinator"):
        destination = (
            shown if core._get_text(combinator).split()[0] == "show" else hidden
        )
        destination.extend(
            core._get_text(item)
            for item in core._descendants_of_type(combinator, "identifier")
        )
    prefix = None
    specification = core._first_descendant_of_type(node, "import_specification")
    if specification is not None:
        identifiers = [
            item for item in specification.named_children if item.type == "identifier"
        ]
        if identifiers:
            prefix = core._get_text(identifiers[-1])
    return {
        "sources": sources,
        "prefix": prefix,
        "show": shown,
        "hide": hidden,
        "line": node.start_point[0] + 1,
        "kind": "export" if text.startswith("export ") else "import",
    }


def _context(core, node):
    matches = [
        context
        for context in core._body_contexts
        if context[0] <= node.start_byte and node.end_byte <= context[1]
    ]
    return (
        min(matches, key=lambda item: item[1] - item[0])[2:]
        if matches
        else (None, None)
    )


def _parameter_names(core, parameters):
    for parameter in core._descendants_of_type(parameters, "formal_parameter"):
        for child in parameter.named_children:
            if child.type == "identifier":
                yield core._get_text(child)
            elif child.type in {
                "function_signature",
                "function_typed_formal_parameter",
            }:
                name = core._function_signature_name_node(child)
                if name is not None:
                    yield core._get_text(name)


def _shadowed(core, name, node, caller, classes):
    found, _ = core._local_receiver_class(name, node, caller, classes)
    if found:
        return True
    signature = core._callable_signatures.get(caller)
    if signature is not None:
        parameters = core._first_descendant_of_type(signature, "formal_parameter_list")
        if parameters is not None and name in set(_parameter_names(core, parameters)):
            return True
    parent = node.parent
    while parent is not None:
        if parent.type in {"function_expression", "lambda_expression"}:
            parameters = core._child_by_type(parent, "formal_parameter_list")
            if parameters is not None and name in set(
                _parameter_names(core, parameters)
            ):
                return True
        parent = parent.parent
    return False


def _selector_receiver(node):
    parent = node.parent
    if parent is None or parent.type != "unconditional_assignable_selector":
        return None
    direct = list(parent.named_children)
    if len(direct) > 1:
        return direct[0] if node == direct[-1] else None
    selector = (
        parent.parent
        if parent.parent is not None and parent.parent.type == "selector"
        else parent
    )
    host = selector.parent
    if host is None:
        return None
    children = list(host.named_children)
    try:
        index = children.index(selector)
    except ValueError:
        return None
    return children[index - 1] if index else None


def _known_receiver_methods(core, classes):
    known = {
        name: methods for name, methods in _CORE_METHODS.items() if name not in classes
    }
    for directive in core.binding_metadata["imports"]:
        if directive.get("prefix") or "dart:math" not in directive["sources"]:
            continue
        shown, hidden = set(directive["show"]), set(directive["hide"])
        if "Random" not in classes and (not shown or "Random" in shown):
            if "Random" not in hidden:
                known["Random"] = {"nextBool", "nextDouble", "nextInt"}
    return known


def _possible_extension_calls(core, classes, definitions, known_methods):
    receiver_types = {**dict.fromkeys(known_methods), **classes}
    prefixes = {
        directive["prefix"]
        for directive in core.binding_metadata["imports"]
        if directive.get("prefix")
    }
    found = {}
    for called, node, receiver, caller in core._call_sites.values():
        if receiver is None:
            continue
        name = core._get_text(called)
        if name in _OBJECT_METHODS:
            continue
        receiver_text = core._get_text(receiver).strip()
        if receiver_text in prefixes and not _shadowed(
            core, receiver_text, node, caller, classes
        ):
            continue
        owner = core._receiver_class(receiver, node, caller, classes)
        if owner is not None:
            target = core._member_target(owner, name, classes, definitions)
            if target in definitions:
                continue
        declared = core._receiver_class(receiver, node, caller, receiver_types)
        declared = declared or _LITERAL_TYPES.get(receiver.type)
        if name in known_methods.get(declared, set()):
            continue
        found[called.start_byte] = {
            "member": name,
            "receiver": receiver_text,
            "line": called.start_point[0] + 1,
        }
    return list(found.values())


def collect_value_references(core):
    definitions = {
        definition.name: definition
        for definition in core.defs
        if definition.type != "import"
    }
    classes = {
        name: definition
        for name, definition in definitions.items()
        if definition.type == "class"
    }
    known_methods = _known_receiver_methods(core, classes)
    receiver_types = {**dict.fromkeys(known_methods), **classes}
    declaration_positions = set()
    called_positions = {called.start_byte for called, *_ in core._call_sites.values()}

    def declarations(node):
        if node.type in {
            "class_definition",
            "mixin_declaration",
            "extension_declaration",
            "enum_declaration",
        }:
            name = core._name_node(node)
            if name is not None:
                declaration_positions.add(name.start_byte)
        elif node.type in {
            "function_signature",
            "getter_signature",
            "setter_signature",
        }:
            name = core._function_signature_name_node(node)
            if name is not None:
                declaration_positions.add(name.start_byte)
        elif node.type in {"constructor_signature", "constant_constructor_signature"}:
            declaration_positions.update(
                child.start_byte
                for child in node.children
                if child.type == "identifier"
            )
        elif node.type in {
            "initialized_identifier",
            "initialized_variable_definition",
            "static_final_declaration",
            "formal_parameter",
        }:
            name = core._child_by_type(node, "identifier")
            if name is not None:
                declaration_positions.add(name.start_byte)
        for child in node.named_children:
            declarations(child)

    declarations(core.root_node)
    seen_uses = set()

    def visit(node):
        if node.type in {
            "comment",
            "documentation_comment",
            "import_or_export",
            "library_name",
        }:
            return
        if node.type == "string_literal":
            for child in node.named_children:
                if child.type == "template_substitution":
                    visit(child)
            return
        if node.type in {"part_directive", "part_of_directive"}:
            literal = core._first_descendant_of_type(node, "string_literal")
            source = (
                core._get_text(literal).strip("\"'") if literal is not None else None
            )
            if node.type == "part_directive" and source:
                core.binding_metadata["parts"].append(source)
            elif source:
                core.binding_metadata["part_of"] = source
            return
        if (
            node.type in {"identifier", "type_identifier", "identifier_dollar_escaped"}
            and node.start_byte not in declaration_positions
        ):
            name = core._get_text(node)
            current_class, caller = _context(core, node)
            receiver = _selector_receiver(node)
            receiver_text = (
                core._get_text(receiver).strip() if receiver is not None else None
            )
            is_type = node.type == "type_identifier"
            local = not is_type and _shadowed(core, name, node, caller, classes)
            receiver_local = (
                receiver is not None
                and receiver.type == "identifier"
                and _shadowed(core, receiver_text, node, caller, classes)
            )
            receiver_type = (
                core._receiver_class(receiver, receiver.parent, caller, receiver_types)
                or _LITERAL_TYPES.get(receiver.type)
                if receiver is not None
                else None
            )
            target = name
            if receiver is not None:
                owner = core._receiver_class(receiver, receiver.parent, caller, classes)
                if owner is not None:
                    target = f"{owner}.{name}"
                elif receiver_text and not receiver_local:
                    target = f"{receiver_text}.{name}"
                else:
                    target = None
            elif (
                not local
                and not is_type
                and current_class
                and f"{current_class}.{name}" in definitions
            ):
                target = f"{current_class}.{name}"
            elif local:
                target = None
            if node.start_byte in core._resolved_calls and not local:
                target = core._resolved_calls[node.start_byte]

            # Call extraction already resolves receiver identities; a value pass must
            # not turn a failed qualified call into an unrelated free function.
            if target and node.start_byte not in called_positions:
                core._add_ref(target, node.start_byte, current_callable=None)
                if (
                    caller
                    and target != caller
                    and target in definitions
                    and definitions[target].type in {"method", "function"}
                ):
                    core.call_pairs.append((caller, target))
            use_name = f"{receiver_text}.{name}" if receiver_text else name
            if (
                not local
                and (not receiver_local or receiver is not None)
                and (node.start_byte, use_name) not in seen_uses
            ):
                seen_uses.add((node.start_byte, use_name))
                core.binding_metadata["uses"].append(
                    {
                        "name": use_name,
                        "line": node.start_point[0] + 1,
                        "target": target,
                        "caller": caller,
                        "owner": current_class,
                        "member": name if receiver is not None else None,
                        "receiver_type": receiver_type,
                        "known_receiver_member": name in _OBJECT_METHODS
                        or name in known_methods.get(receiver_type, set()),
                        "unknown_receiver": receiver is not None
                        and core._receiver_class(
                            receiver, receiver.parent, caller, classes
                        )
                        is None
                        and receiver_local
                        and core._receiver_class(
                            receiver, receiver.parent, caller, receiver_types
                        )
                        not in known_methods,
                        "import_eligible": not receiver_local,
                        "kind": "type" if is_type else "value",
                    }
                )
        for child in node.named_children:
            visit(child)

    visit(core.root_node)
    core.binding_metadata["possible_extension_calls"] = _possible_extension_calls(
        core, classes, definitions, known_methods
    )
