"""Per-module facts for the TS/JS export hygiene checks.

One pass over a module's top-level statements records what the module-wide
checks need: exported type declarations, names each statement reads, the
names in each statement's type shape, duplicate export names and exported
namespaces with their members. Facts are plain data; no tree is retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from skylos.core.js_ast import iter_import_clause_bindings

from .jsdoc_tags import has_public_api_tag, leading_comment_tags
from .namespace_references import namespace_member_reads

_REF_TYPES = frozenset(
    {"identifier", "type_identifier", "shorthand_property_identifier"}
)
_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "generator_function",
        "arrow_function",
        "method_definition",
        "function_signature",
        "method_signature",
    }
)
_TYPE_KINDS = {"type_alias_declaration": "type", "interface_declaration": "interface"}
_VALUE_KINDS = {
    "function_declaration": "function",
    "generator_function_declaration": "function",
    "function_signature": "function",
    "class_declaration": "class",
    "abstract_class_declaration": "class",
    "enum_declaration": "enum",
    "internal_module": "namespace",
}
_REPORTED_MEMBER_KINDS = frozenset({"variable", "type", "interface"})
_ASSIGNMENTS = frozenset({"assignment_expression", "augmented_assignment_expression"})


@dataclass(frozen=True)
class TypeExport:
    name: str
    local: str
    line: int
    kind: str
    tagged: bool


@dataclass
class NamespaceFacts:
    name: str
    line: int
    tagged: bool
    leaves: dict = field(default_factory=dict)
    containers: set = field(default_factory=set)
    body_names: set = field(default_factory=set)
    unsupported: str | None = None


@dataclass
class ModuleFacts:
    statement_refs: list = field(default_factory=list)
    statement_shape_refs: list = field(default_factory=list)
    clause_statements: set = field(default_factory=set)
    augmentation_statements: set = field(default_factory=set)
    declarations: dict = field(default_factory=dict)
    exported_statements: dict = field(default_factory=dict)
    type_exports: list = field(default_factory=list)
    tagged_exports: set = field(default_factory=set)
    duplicates: list = field(default_factory=list)
    namespaces: list = field(default_factory=list)
    namespace_reads: dict = field(default_factory=dict)
    exported_enums: set = field(default_factory=set)


def _text(source, node):
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


_JSX_ELEMENT_TYPES = frozenset({"jsx_element", "jsx_self_closing_element", "jsx_fragment"})


def _shape_skipped_child(node):
    """The part of ``node`` that cannot change a declaration's emitted type.

    A function body is skipped only behind an explicit return type, and a
    variable initializer only behind an explicit type annotation.
    """
    if node.type in _FUNCTION_TYPES and node.child_by_field_name("return_type"):
        return node.child_by_field_name("body")
    if node.type in {"variable_declarator", "public_field_definition"} and (
        node.child_by_field_name("type") is not None
    ):
        return node.child_by_field_name("value")
    return None


def _statement_names(source, node):
    """``(names, shape names)`` a top-level statement reads, in one walk."""
    found, shape = set(), set()
    stack = [(node, True)]
    while stack:
        current, in_shape = stack.pop()
        if current.type in _REF_TYPES:
            text = _text(source, current)
            found.add(text)
            if in_shape:
                shape.add(text)
            continue
        if in_shape and current.type in _JSX_ELEMENT_TYPES:
            # A JSX element is a ``JSX.Element`` whatever it renders, so the
            # components and props inside it cannot change an inferred type.
            in_shape = False
        skipped = _shape_skipped_child(current) if in_shape else None
        stack.extend(
            (child, in_shape and (skipped is None or child.id != skipped.id))
            for child in current.named_children
        )
    return frozenset(found), frozenset(shape)


def _pattern_names(source, node):
    if node is None:
        return []
    if node.type == "identifier":
        return [_text(source, node)]
    names = []
    for child in node.named_children:
        if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.append(_text(source, child))
        elif child.type not in {"property_identifier", "string", "number"}:
            names.extend(_pattern_names(source, child))
    return names


def _unwrap_ambient(node):
    if node is not None and node.type == "ambient_declaration":
        return next(
            (
                child
                for child in node.named_children
                if child.type in _TYPE_KINDS
                or child.type in _VALUE_KINDS
                or child.type in {"lexical_declaration", "variable_declaration"}
            ),
            None,
        )
    return node


def _declared(source, node):
    """``[(name, kind)]`` that a declaration node introduces."""
    if node is None:
        return []
    if node.type in _TYPE_KINDS or node.type in _VALUE_KINDS:
        name = node.child_by_field_name("name")
        if name is None or name.type not in {"identifier", "type_identifier"}:
            return []
        kind = _TYPE_KINDS.get(node.type) or _VALUE_KINDS[node.type]
        return [(_text(source, name), kind)]
    if node.type in {"lexical_declaration", "variable_declaration"}:
        return [
            (name, "variable")
            for declarator in node.named_children
            if declarator.type == "variable_declarator"
            for name in _pattern_names(source, declarator.child_by_field_name("name"))
        ]
    return []


def _reassigned_names(source, root):
    names = set()
    stack = [root]
    while stack:
        node = stack.pop()
        target = None
        if node.type in _ASSIGNMENTS:
            target = node.child_by_field_name("left")
        elif node.type == "update_expression":
            target = node.child_by_field_name("argument")
        if target is not None and target.type == "identifier":
            names.add(_text(source, target))
        stack.extend(node.named_children)
    return names


def _is_default(statement):
    return any(child.type == "default" for child in statement.children)


def _specifier_pairs(source, statement):
    for clause in statement.named_children:
        if clause.type != "export_clause":
            continue
        for specifier in clause.named_children:
            if specifier.type != "export_specifier":
                continue
            name = specifier.child_by_field_name("name")
            alias = specifier.child_by_field_name("alias")
            if name is None or name.type != "identifier":
                continue
            exported = alias or name
            if exported.type != "identifier":
                continue
            yield _text(source, name), _text(source, exported), specifier


@dataclass
class _Pending:
    """Module facts resolved after every top-level statement is read."""

    specifier_exports: dict = field(default_factory=dict)
    declaration_exports: set = field(default_factory=set)
    constant_names: set = field(default_factory=set)


def collect_module_facts(source: bytes, root) -> ModuleFacts:
    facts = ModuleFacts()
    statements = [node for node in root.named_children if node.type != "comment"]
    imports = _import_locals(source, statements)
    pending = _Pending()
    for index, statement in enumerate(statements):
        _record_statement(source, facts, pending, index, statement)
    _record_specifier_exports(facts, pending, imports)
    stable_locals = {
        name
        for name, entries in facts.declarations.items()
        if entries and all(kind in {"function", "class"} for _i, kind in entries)
    } | pending.constant_names
    facts.duplicates = _DuplicateScanner(source, root, imports, stable_locals).scan(
        statements
    )
    if facts.namespaces:
        reads = namespace_member_reads(
            root, source, include_local_namespaces=True, member_paths=True
        )
        facts.namespace_reads = {
            namespace.name: reads.get(namespace.name, None)
            for namespace in facts.namespaces
        }
    return facts


def _import_locals(source, statements):
    imports = set()
    for statement in statements:
        if statement.type != "import_statement":
            continue
        for clause in statement.named_children:
            if clause.type == "import_clause":
                imports.update(
                    binding.local
                    for binding in iter_import_clause_bindings(source, clause)
                )
    return imports


def _is_const(node):
    return (
        node is not None
        and node.type == "lexical_declaration"
        and any(child.type == "const" for child in node.children)
    )


def _is_augmentation(statement):
    return statement.type == "ambient_declaration" and any(
        child.type in {"statement_block", "module"}
        for child in statement.named_children
    )


def _declare(facts, index, declared):
    for name, kind in declared:
        facts.declarations.setdefault(name, []).append((index, kind))


def _record_statement(source, facts, pending, index, statement):
    lexical = statement
    if statement.type == "export_statement":
        lexical = statement.child_by_field_name("declaration")
    if _is_const(lexical):
        pending.constant_names.update(
            name for name, _kind in _declared(source, lexical)
        )
    refs, shape_refs = _statement_names(source, statement)
    facts.statement_refs.append(refs)
    facts.statement_shape_refs.append(shape_refs)
    if _is_augmentation(statement):
        facts.augmentation_statements.add(index)
    if statement.type != "export_statement":
        _declare(facts, index, _declared(source, _unwrap_ambient(statement)))
        return
    if statement.child_by_field_name("source") is not None:
        return
    tagged = has_public_api_tag(leading_comment_tags(source, statement))
    declaration = _unwrap_ambient(statement.child_by_field_name("declaration"))
    if _is_default(statement):
        facts.exported_statements.setdefault("default", set()).add(index)
        if tagged:
            facts.tagged_exports.add("default")
        _declare(facts, index, _declared(source, declaration))
    elif declaration is None:
        facts.clause_statements.add(index)
        for local, exported, specifier in _specifier_pairs(source, statement):
            pending.specifier_exports.setdefault(local, []).append(
                (exported, specifier.start_point[0] + 1, tagged)
            )
    else:
        _record_declaration_export(
            source, facts, pending, index, statement, declaration, tagged
        )


def _record_declaration_export(
    source, facts, pending, index, statement, declaration, tagged
):
    for name, kind in _declared(source, declaration):
        facts.declarations.setdefault(name, []).append((index, kind))
        facts.exported_statements.setdefault(name, set()).add(index)
        pending.declaration_exports.add(name)
        if kind == "enum":
            facts.exported_enums.add(name)
        if tagged:
            facts.tagged_exports.add(name)
        if kind in {"type", "interface"}:
            line = statement.start_point[0] + 1
            facts.type_exports.append(TypeExport(name, name, line, kind, tagged))
    if declaration.type == "internal_module":
        namespace = _namespace_facts(source, statement, declaration)
        if declaration.parent is not None and (
            declaration.parent.type == "ambient_declaration"
        ):
            namespace.unsupported = "ambient_namespace"
        facts.namespaces.append(namespace)


def _record_specifier_exports(facts, pending, imports):
    for local, exports in pending.specifier_exports.items():
        for exported, _line, tagged in exports:
            for index, _kind in facts.declarations.get(local, ()):
                facts.exported_statements.setdefault(exported, set()).add(index)
            if tagged:
                facts.tagged_exports.add(exported)
        kinds = {kind for _index, kind in facts.declarations.get(local, ())}
        if local in imports or not kinds or not kinds <= {"type", "interface"}:
            continue
        names = {exported for exported, _line, _tagged in exports}
        # Two names for one local are alias entries of the re-export check.
        if len(names) != 1 or local in pending.declaration_exports:
            continue
        kind = "interface" if kinds == {"interface"} else "type"
        exported, line, tagged = exports[0]
        facts.type_exports.append(TypeExport(exported, local, line, kind, tagged))


class _DuplicateScanner:
    """Duplicate exports (SKY-E005), narrowed to bindings that cannot change.

    ``export const B = A`` with ``A`` exported earlier, and ``export default
    A`` with ``A`` exported by its declaration, export one binding twice. An
    `@alias` tag marks a deliberate alias. Mutable or reassigned bindings,
    imported bindings and specifier lists (``export { a, a as b }``) are not
    grouped here.
    """

    def __init__(self, source, root, imports, stable_locals):
        self.source = source
        self.root = root
        self.imports = imports
        self.stable_locals = stable_locals
        self.reassigned = None
        # name -> (origin, unchanging, line); origin is declaration,
        # specifier or import.
        self.exported = {}
        self.specifier_names = set()
        self.groups = {}

    def scan(self, statements):
        for statement in statements:
            if statement.type != "export_statement":
                continue
            if statement.child_by_field_name("source") is not None:
                continue
            aliased = "@alias" in leading_comment_tags(self.source, statement)
            declaration = statement.child_by_field_name("declaration")
            if _is_default(statement):
                if declaration is None and not aliased:
                    self._default(statement)
            elif declaration is None:
                self._clause(statement)
            elif declaration.type == "lexical_declaration":
                self._lexical(declaration, aliased)
            else:
                line = statement.start_point[0] + 1
                for name, kind in _declared(self.source, declaration):
                    unchanging = kind in {"function", "class"}
                    self.exported.setdefault(name, ("declaration", unchanging, line))
        return [group for group in self.groups.values() if len(group) > 1]

    def _stable(self, name):
        if self.reassigned is None:
            self.reassigned = _reassigned_names(self.source, self.root)
        return name not in self.reassigned

    def _group(self, original, alias, line):
        group = self.groups.setdefault(
            original, [(original, self.exported[original][2])]
        )
        group.append((alias, line))

    def _default(self, statement):
        value = statement.child_by_field_name("value")
        if value is None or value.type != "identifier":
            return
        name = _text(self.source, value)
        info = self.exported.get(name)
        if (
            info is not None
            and info[0] == "declaration"
            and info[1]
            and name not in self.specifier_names
            and self._stable(name)
        ):
            self._group(name, "default", statement.start_point[0] + 1)

    def _clause(self, statement):
        for local, name, specifier in _specifier_pairs(self.source, statement):
            self.specifier_names.add(name)
            self.exported.setdefault(
                name,
                (
                    "import" if local in self.imports else "specifier",
                    local == name and local in self.stable_locals,
                    specifier.start_point[0] + 1,
                ),
            )

    def _lexical(self, declaration, aliased):
        constant = _is_const(declaration)
        for declarator in declaration.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            if name_node is None or name_node.type != "identifier":
                continue
            name = _text(self.source, name_node)
            line = name_node.start_point[0] + 1
            value = declarator.child_by_field_name("value")
            if (
                constant
                and not aliased
                and value is not None
                and value.type == "identifier"
            ):
                self._alias(_text(self.source, value), name, line)
            self.exported.setdefault(name, ("declaration", constant, line))

    def _alias(self, original, name, line):
        info = self.exported.get(original)
        if (
            info is not None
            and info[0] in {"declaration", "specifier"}
            and info[1]
            and original not in self.imports
            and self._stable(original)
        ):
            self._group(original, name, line)


def _namespace_facts(source, statement, module_node):
    name_node = module_node.child_by_field_name("name")
    facts = NamespaceFacts(
        _text(source, name_node) if name_node is not None else "",
        statement.start_point[0] + 1,
        has_public_api_tag(leading_comment_tags(source, statement)),
    )
    if name_node is None or name_node.type != "identifier":
        facts.unsupported = "dotted_or_unnamed_namespace"
        return facts
    body = module_node.child_by_field_name("body")
    if body is None:
        facts.unsupported = "namespace_without_body"
        return facts
    declared_ids = set()
    _namespace_members(source, body, "", facts, declared_ids, facts.tagged)
    stack = [body]
    while stack:
        node = stack.pop()
        if node.id in declared_ids:
            continue
        if node.type in _REF_TYPES or node.type == "property_identifier":
            facts.body_names.add(_text(source, node))
            continue
        stack.extend(node.named_children)
    return facts


def _namespace_members(source, body, prefix, facts, declared_ids, tagged_scope):
    for statement in body.named_children:
        if statement.type == "comment" or statement.type != "export_statement":
            continue
        declaration = statement.child_by_field_name("declaration")
        tagged = tagged_scope or has_public_api_tag(
            leading_comment_tags(source, statement)
        )
        line = statement.start_point[0] + 1
        if declaration is None:
            facts.unsupported = "export_clause_in_namespace"
            return
        if declaration.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in declaration.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                if name is None or name.type != "identifier":
                    facts.unsupported = "destructured_namespace_member"
                    return
                declared_ids.add(name.id)
                key = prefix + _text(source, name)
                facts.leaves.setdefault(
                    key, (name.start_point[0] + 1, "variable", tagged)
                )
            continue
        if declaration.type == "internal_module":
            name = declaration.child_by_field_name("name")
            inner = declaration.child_by_field_name("body")
            if name is None or name.type != "identifier" or inner is None:
                facts.unsupported = "dotted_or_unnamed_namespace"
                return
            declared_ids.add(name.id)
            key = prefix + _text(source, name)
            facts.containers.add(key)
            _namespace_members(source, inner, key + ".", facts, declared_ids, tagged)
            if facts.unsupported:
                return
            continue
        kind = _TYPE_KINDS.get(declaration.type) or _VALUE_KINDS.get(declaration.type)
        name = declaration.child_by_field_name("name")
        if kind is None or name is None:
            facts.unsupported = "unsupported_namespace_member"
            return
        declared_ids.add(name.id)
        facts.leaves.setdefault(prefix + _text(source, name), (line, kind, tagged))


def is_reported_member_kind(kind: str) -> bool:
    """Functions, classes and enums keep their existing per-symbol findings."""
    return kind in _REPORTED_MEMBER_KINDS
