"""Source-visible C library calls and straight-line C allocation lifetimes."""

from .core import _has_local_binding, _text

_HEADERS = {
    "gets": {"<cstdio>", "<stdio.h>"},
    "sprintf": {"<cstdio>", "<stdio.h>"},
    "vsprintf": {"<cstdio>", "<stdio.h>"},
    "strcpy": {"<cstring>", "<string.h>"},
    "strcat": {"<cstring>", "<string.h>"},
    "malloc": {"<cstdlib>", "<stdlib.h>"},
    "calloc": {"<cstdlib>", "<stdlib.h>"},
    "free": {"<cstdlib>", "<stdlib.h>"},
}
_UNBOUNDED = {"gets", "sprintf", "vsprintf", "strcpy", "strcat"}
_ALLOCATION_CALLS = {"malloc", "calloc"}
_POINTER_CASTS = {"static_cast", "reinterpret_cast", "const_cast"}
_UNEVALUATED = {
    "alignof_expression",
    "decltype",
    "noexcept_expression",
    "requires_expression",
    "sizeof_expression",
}
_DECLARATOR_CONTAINERS = {
    "array_declarator",
    "function_declarator",
    "init_declarator",
    "parenthesized_declarator",
    "pointer_declarator",
    "reference_declarator",
}
_COMMENT = "comment"


def _children(node):
    return [child for child in node.named_children if child.type != _COMMENT]


def _unwrap(node):
    while node is not None and node.type == "parenthesized_expression":
        values = _children(node)
        node = values[0] if len(values) == 1 else None
    return node


def _declarator_name(node):
    reference = False
    while node is not None and node.type in _DECLARATOR_CONTAINERS:
        reference |= node.type == "reference_declarator"
        child = node.child_by_field_name("declarator")
        if child is None and node.type in {
            "parenthesized_declarator",
            "reference_declarator",
        }:
            children = _children(node)
            child = children[0] if len(children) == 1 else None
        node = child
    return node, reference


def _enclosing_namespace(node):
    current = node.parent
    while current is not None:
        if current.type == "namespace_definition":
            return current
        current = current.parent
    return None


def _global_declaration(node):
    current = node.parent
    while current is not None:
        if current.type == "translation_unit":
            return True
        if current.type in {
            "namespace_definition",
            "field_declaration",
            "field_declaration_list",
            "compound_statement",
        }:
            return False
        current = current.parent
    return False


def _evaluated(node):
    current = node.parent
    while current is not None:
        if current.type in _UNEVALUATED:
            return False
        current = current.parent
    return True


def _lifetime_nodes(root):
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type in _UNEVALUATED or node.type == "lambda_expression":
            continue
        yield node
        if node.type == "conditional_expression":
            condition = node.child_by_field_name("condition")
            if condition is not None:
                pending.append(condition)
        elif (
            node.type == "binary_expression"
            and (operator := node.child_by_field_name("operator")) is not None
            and operator.type in {"&&", "||"}
        ):
            left = node.child_by_field_name("left")
            if left is not None:
                pending.append(left)
        else:
            pending.extend(reversed(_children(node)))


class _MemoryChecks:
    def __init__(self, nodes, source, file_path, locals_):
        self.source = source
        self.file_path = file_path
        self.locals = locals_
        self.headers = {}
        self.macros = set()
        self.global_names = set()
        self.source_names = set()
        self.standard_names = set()
        self.local_std = False
        self.imported_namespace = False
        for node in nodes:
            if (
                node.type == "preproc_include"
                and node.parent.type == "translation_unit"
            ):
                header = node.child_by_field_name("path")
                if header is not None and header.type == "system_lib_string":
                    self.headers.setdefault(self.text(header), node.start_byte)
            elif node.type in {"preproc_def", "preproc_function_def"}:
                name = node.child_by_field_name("name")
                if name is not None:
                    self.macros.add(self.text(name))
            elif node.type in {
                "namespace_definition",
                "namespace_alias_definition",
                "class_specifier",
                "struct_specifier",
                "alias_declaration",
            }:
                name = node.child_by_field_name("name")
                if (
                    name is not None
                    and self.text(name) == "std"
                    and (
                        node.type != "namespace_definition"
                        or not _global_declaration(node)
                    )
                ):
                    self.local_std = True
            elif node.type in {
                "declaration",
                "field_declaration",
                "function_definition",
                "parameter_declaration",
            }:
                self.record_source_names(node)
            elif node.type == "using_declaration":
                imported = _children(node)
                if any(child.type == "namespace" for child in node.children):
                    if not imported or self.text(imported[0]) not in {"std", "::std"}:
                        self.imported_namespace = True
                elif imported and imported[0].type == "qualified_identifier":
                    scope = imported[0].child_by_field_name("scope")
                    name = self.text(imported[0].child_by_field_name("name"))
                    if self.text(scope) != "std":
                        if name in _HEADERS:
                            self.source_names.add(name)
                        elif name == "std":
                            self.local_std = True

    def text(self, node):
        return _text(node, self.source) if node is not None else ""

    def record_source_names(self, node):
        for declaration in node.children_by_field_name("declarator"):
            target, _ = _declarator_name(declaration)
            if target is None:
                continue
            name = self.text(target)
            if name not in _HEADERS:
                continue
            self.source_names.add(name)
            if node.type != "parameter_declaration" and _global_declaration(node):
                self.global_names.add(name)
            namespace = _enclosing_namespace(node)
            if (
                namespace is not None
                and _global_declaration(namespace)
                and self.text(namespace.child_by_field_name("name")) == "std"
            ):
                self.standard_names.add(name)

    def emit(self, rule, node, message):
        row, col = node.start_point
        return {
            "rule_id": rule,
            "severity": "HIGH" if rule != "SKY-D435" else "MEDIUM",
            "message": message,
            "file": self.file_path,
            "line": row + 1,
            "col": col,
            "category": "danger",
        }

    def native_call(self, node):
        if node is None or node.type != "call_expression":
            return None
        callee = node.child_by_field_name("function")
        if callee is None:
            return None
        if callee.type == "identifier":
            name = self.text(callee)
            if (
                name not in _HEADERS
                or name in self.source_names
                or self.imported_namespace
                or _has_local_binding(callee, self.source, self.locals)
            ):
                return None
        elif callee.type == "qualified_identifier":
            scope = callee.child_by_field_name("scope")
            target = callee.child_by_field_name("name")
            absolute = scope is None
            if (
                absolute
                and target is not None
                and target.type == "qualified_identifier"
            ):
                scope = target.child_by_field_name("scope")
                target = target.child_by_field_name("name")
            if target is None or target.type != "identifier":
                return None
            name = self.text(target)
            if scope is None:
                if name in self.global_names:
                    return None
            elif (
                self.text(scope) != "std"
                or "std" in self.macros
                or name in self.standard_names
                or (
                    not absolute
                    and (
                        self.local_std
                        or _has_local_binding(scope, self.source, self.locals)
                    )
                )
            ):
                return None
        else:
            return None
        if name in self.macros or not any(
            self.headers.get(header, node.start_byte) < node.start_byte
            for header in _HEADERS.get(name, ())
        ):
            return None
        return name

    def pointer_cast_operand(self, value):
        if value.type == "cast_expression":
            cast_type = value.child_by_field_name("type")
            if cast_type is not None and "*" in self.text(cast_type):
                return value.child_by_field_name("value")
        if value.type != "call_expression":
            return None
        callee = value.child_by_field_name("function")
        if callee is None or callee.type != "template_function":
            return None
        name = self.text(callee.child_by_field_name("name"))
        cast_type = callee.child_by_field_name("arguments")
        if name not in _POINTER_CASTS or "*" not in self.text(cast_type):
            return None
        arguments = value.child_by_field_name("arguments")
        args = _children(arguments) if arguments is not None else []
        return args[0] if len(args) == 1 else None

    def allocation(self, initializer, pointers):
        value = _unwrap(initializer)
        while value is not None:
            if value.type == "identifier":
                return pointers.get(self.text(value))
            if self.native_call(value) in _ALLOCATION_CALLS:
                return value.start_byte
            value = _unwrap(self.pointer_cast_operand(value))
        return None

    def free_target(self, expression, pointers):
        if self.native_call(expression) != "free":
            return None
        args = expression.child_by_field_name("arguments")
        values = _children(args) if args is not None else []
        arg = _unwrap(values[0]) if len(values) == 1 else None
        return (
            pointers.get(self.text(arg))
            if arg is not None and arg.type == "identifier"
            else None
        )

    def dereference(self, node, pointers, released):
        operator = node.child_by_field_name("operator")
        if not (
            node.type == "subscript_expression"
            or (
                node.type == "pointer_expression"
                and operator is not None
                and operator.type == "*"
            )
            or (
                node.type == "field_expression"
                and operator is not None
                and operator.type == "->"
            )
        ):
            return False
        parent = node.parent
        while parent is not None and parent.type == "parenthesized_expression":
            parent = parent.parent
        if parent is not None and parent.type == "pointer_expression":
            parent_operator = parent.child_by_field_name("operator")
            if parent_operator is not None and parent_operator.type == "&":
                return False
        target = _unwrap(node.child_by_field_name("argument"))
        return (
            target is not None
            and target.type == "identifier"
            and pointers.get(self.text(target)) in released
        )

    def lifetime_issues(self, block):
        pointers = {}
        locals_ = set()
        released = set()
        for statement in _children(block):
            if statement.type in {
                "throw_statement",
                "break_statement",
                "continue_statement",
                "goto_statement",
            }:
                break
            if statement.type not in {
                "declaration",
                "expression_statement",
                "return_statement",
            }:
                pointers.clear()
                released.clear()
                continue
            values = _children(statement)
            expression = (
                _unwrap(values[0])
                if values
                and statement.type in {"expression_statement", "return_statement"}
                else None
            )
            allocation = self.free_target(expression, pointers)
            if allocation is not None:
                if allocation in released:
                    yield self.emit(
                        "SKY-D436",
                        expression,
                        "This call can free the same allocation a second time.",
                    )
                released.add(allocation)
                if statement.type == "return_statement":
                    break
                continue

            opaque = False
            escaped = set()
            for node in _lifetime_nodes(statement):
                if self.dereference(node, pointers, released):
                    yield self.emit(
                        "SKY-D437",
                        node,
                        "This expression dereferences a pointer after the same block freed it.",
                    )
                if node.type == "call_expression" and (
                    self.native_call(node) not in _ALLOCATION_CALLS
                    and self.pointer_cast_operand(node) is None
                ):
                    opaque = True
                if node.type == "pointer_expression":
                    operator = node.child_by_field_name("operator")
                    target = _unwrap(node.child_by_field_name("argument"))
                    if (
                        operator is not None
                        and operator.type == "&"
                        and target is not None
                        and target.type == "identifier"
                    ):
                        escaped.add(self.text(target))
                if node.type == "update_expression" or (
                    node.type == "assignment_expression" and node != expression
                ):
                    opaque = True
            for name in escaped:
                pointers.pop(name, None)
            locals_.difference_update(escaped)
            if opaque:
                pointers.clear()
                released.clear()
            if statement.type == "return_statement":
                break
            if statement.type == "declaration":
                for declaration in statement.children_by_field_name("declarator"):
                    identifier, reference = _declarator_name(declaration)
                    value = declaration.child_by_field_name("value")
                    if reference:
                        target = _unwrap(value)
                        if target is not None and target.type == "identifier":
                            target_name = self.text(target)
                            pointers.pop(target_name, None)
                            locals_.discard(target_name)
                        continue
                    if identifier is None or identifier.type != "identifier":
                        continue
                    name = self.text(identifier)
                    locals_.add(name)
                    pointers[name] = self.allocation(value, pointers)
            elif expression is not None and expression.type == "assignment_expression":
                left = expression.child_by_field_name("left")
                right = expression.child_by_field_name("right")
                operator = expression.child_by_field_name("operator")
                if (
                    left is not None
                    and left.type == "identifier"
                    and self.text(left) in locals_
                ):
                    pointers[self.text(left)] = (
                        self.allocation(right, pointers)
                        if operator is not None and operator.type == "="
                        else None
                    )


def scan_memory_calls(nodes, source, file_path, locals_):
    checker = _MemoryChecks(nodes, source, file_path, locals_)
    findings = []
    for node in nodes:
        name = checker.native_call(node)
        if name in _UNBOUNDED and _evaluated(node):
            findings.append(
                checker.emit(
                    "SKY-D435",
                    node,
                    f"{name} writes text without checking destination capacity. Use a size-bounded API.",
                )
            )
        if node.type == "compound_statement":
            findings.extend(checker.lifetime_issues(node))
    return sorted(findings, key=lambda row: (row["line"], row["col"], row["rule_id"]))
