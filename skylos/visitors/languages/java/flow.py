from __future__ import annotations

from dataclasses import dataclass, field


REQUEST_SOURCE_METHODS = {
    "getParameter",
    "getPathInfo",
    "getHeader",
    "getHeaders",
    "getHeaderNames",
    "getParameterMap",
    "getParameterValues",
    "getParameterNames",
    "getCookies",
    "getQueryString",
}

REQUEST_PARAM_ANNOTATIONS = {
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
}

REQUEST_TYPES = {
    "HttpServletRequest",
    "ServletRequest",
}

PATH_NORMALIZER_METHODS = {
    "normalize",
    "toRealPath",
    "getCanonicalPath",
    "getCanonicalFile",
}

CONTROL_FLOW_STMTS = {
    "throw_statement",
    "return_statement",
    "break_statement",
    "continue_statement",
}

SQL_SINKS = {
    "prepareCall": (0,),
    "prepareStatement": (0,),
    "executeQuery": (0,),
    "executeUpdate": (0,),
    "execute": (0,),
    "queryForObject": (0,),
    "queryForRowSet": (0,),
    "query": (0,),
}

LDAP_SINKS = {"search": (1,)}
XPATH_SINKS = {"evaluate": (0,), "compile": (0,)}
XSS_WRITER_METHODS = {"print", "println", "printf", "format", "write"}
XSS_SANITIZER_METHODS = {
    "encodeForHTML",
    "encodeForHtml",
    "forHtml",
    "escapeHtml",
    "htmlEscape",
}

FILES_PATH_METHODS = {
    "readAllBytes": (0,),
    "readString": (0,),
    "newInputStream": (0,),
    "newOutputStream": (0,),
    "write": (0,),
    "writeString": (0,),
    "copy": (0, 1),
}

PATH_CONSTRUCTOR_TYPES = {
    "FileInputStream": (0,),
    "FileReader": (0,),
    "FileOutputStream": (0,),
}


@dataclass(frozen=True)
class JavaTaint:
    tainted: bool = False
    xss_safe: bool = False

    @staticmethod
    def combine(values: list["JavaTaint"]) -> "JavaTaint":
        tainted = any(value.tainted for value in values)
        if not tainted:
            return JavaTaint()
        return JavaTaint(
            tainted=True,
            xss_safe=all(value.xss_safe for value in values if value.tainted),
        )


@dataclass
class JavaFlowState:
    request_vars: set[str] = field(default_factory=set)
    tainted_vars: set[str] = field(default_factory=set)
    xss_safe_vars: set[str] = field(default_factory=set)
    constants: dict[str, int | bool | str] = field(default_factory=dict)
    object_types: dict[str, str] = field(default_factory=dict)
    map_entries: dict[tuple[str, str], JavaTaint] = field(default_factory=dict)
    list_entries: dict[str, list[JavaTaint]] = field(default_factory=dict)
    tainted_collections: set[str] = field(default_factory=set)
    tainted_process_builders: set[str] = field(default_factory=set)
    cookie_vars: set[str] = field(default_factory=set)
    insecure_cookie_vars: set[str] = field(default_factory=set)
    normalized_path_vars: set[str] = field(default_factory=set)
    guarded_path_vars: set[str] = field(default_factory=set)
    canonical_string_vars: set[str] = field(default_factory=set)
    slash_terminated_vars: set[str] = field(default_factory=set)
    canonical_path_sources: dict[str, set[str]] = field(default_factory=dict)
    pending_path_objects: dict[str, int] = field(default_factory=dict)

    def copy(self) -> "JavaFlowState":
        return JavaFlowState(
            request_vars=set(self.request_vars),
            tainted_vars=set(self.tainted_vars),
            xss_safe_vars=set(self.xss_safe_vars),
            constants=dict(self.constants),
            object_types=dict(self.object_types),
            map_entries=dict(self.map_entries),
            list_entries={key: list(value) for key, value in self.list_entries.items()},
            tainted_collections=set(self.tainted_collections),
            tainted_process_builders=set(self.tainted_process_builders),
            cookie_vars=set(self.cookie_vars),
            insecure_cookie_vars=set(self.insecure_cookie_vars),
            normalized_path_vars=set(self.normalized_path_vars),
            guarded_path_vars=set(self.guarded_path_vars),
            canonical_string_vars=set(self.canonical_string_vars),
            slash_terminated_vars=set(self.slash_terminated_vars),
            canonical_path_sources={
                key: set(value) for key, value in self.canonical_path_sources.items()
            },
            pending_path_objects=dict(self.pending_path_objects),
        )

    def merge_from(self, left: "JavaFlowState", right: "JavaFlowState") -> None:
        self.tainted_vars = left.tainted_vars | right.tainted_vars
        self.xss_safe_vars = left.xss_safe_vars & right.xss_safe_vars
        self.constants = {
            name: value
            for name, value in left.constants.items()
            if right.constants.get(name) == value
        }
        self.object_types = {
            name: value
            for name, value in left.object_types.items()
            if right.object_types.get(name) == value
        }
        self.map_entries = self._merge_map_entries(left.map_entries, right.map_entries)
        self.list_entries = self._merge_list_entries(left.list_entries, right.list_entries)
        self.tainted_collections = left.tainted_collections | right.tainted_collections
        self.tainted_process_builders = (
            left.tainted_process_builders | right.tainted_process_builders
        )
        self.cookie_vars = left.cookie_vars | right.cookie_vars
        self.insecure_cookie_vars = left.insecure_cookie_vars | right.insecure_cookie_vars
        self.normalized_path_vars = left.normalized_path_vars | right.normalized_path_vars
        self.guarded_path_vars = left.guarded_path_vars & right.guarded_path_vars
        self.canonical_string_vars = left.canonical_string_vars | right.canonical_string_vars
        self.slash_terminated_vars = left.slash_terminated_vars | right.slash_terminated_vars
        self.canonical_path_sources = {
            **left.canonical_path_sources,
            **right.canonical_path_sources,
        }
        self.pending_path_objects = {
            name: min(
                left.pending_path_objects.get(name, right.pending_path_objects.get(name, 0)),
                right.pending_path_objects.get(name, left.pending_path_objects.get(name, 0)),
            )
            for name in set(left.pending_path_objects) | set(right.pending_path_objects)
        }

    def _merge_map_entries(
        self,
        left: dict[tuple[str, str], JavaTaint],
        right: dict[tuple[str, str], JavaTaint],
    ) -> dict[tuple[str, str], JavaTaint]:
        merged = {}
        for key in set(left) | set(right):
            values = [value for value in (left.get(key), right.get(key)) if value is not None]
            merged[key] = JavaTaint.combine(values)
        return merged

    def _merge_list_entries(
        self,
        left: dict[str, list[JavaTaint]],
        right: dict[str, list[JavaTaint]],
    ) -> dict[str, list[JavaTaint]]:
        merged = {}
        for key in set(left) | set(right):
            left_items = left.get(key, [])
            right_items = right.get(key, [])
            size = max(len(left_items), len(right_items))
            merged[key] = [
                JavaTaint.combine(
                    [
                        value
                        for value in (
                            left_items[index] if index < len(left_items) else None,
                            right_items[index] if index < len(right_items) else None,
                        )
                        if value is not None
                    ]
                )
                for index in range(size)
            ]
        return merged


@dataclass(frozen=True)
class JavaHelperSummary:
    returns_request_source: bool = False
    returns_arg_taint: bool = False


class JavaSecurityFlowAnalyzer:
    def __init__(self, root_node, file_path: str, source_bytes: bytes) -> None:
        self.root_node = root_node
        self.file_path = file_path
        self.source = source_bytes
        self.findings: list[dict] = []
        self.seen: set[tuple[str, int, str]] = set()
        self.helper_summaries: dict[
            tuple[str | None, str, int], JavaHelperSummary
        ] = {}

    def scan(self) -> list[dict]:
        self.helper_summaries = self._collect_helper_summaries()
        for method in self._method_nodes():
            self._scan_method(method)
        return self.findings

    def _scan_method(self, method_node) -> None:
        state = self._initial_state(method_node)
        body = method_node.child_by_field_name("body")
        if body is None:
            return
        for statement in self._block_statements(body):
            self._process_statement(statement, state)
        self._flush_pending_path_objects(state)

    def _initial_state(self, method_node) -> JavaFlowState:
        state = JavaFlowState()
        for param in self._formal_parameters(method_node):
            name = self._param_name(param)
            if not name:
                continue
            type_name = self._simple_name(self._param_type(param))
            annotations = self._annotation_names(param)
            if type_name in REQUEST_TYPES or name in {"request", "req"}:
                state.request_vars.add(name)
            if annotations & REQUEST_PARAM_ANNOTATIONS:
                state.tainted_vars.add(name)
        return state

    def _collect_helper_summaries(
        self,
    ) -> dict[tuple[str | None, str, int], JavaHelperSummary]:
        summaries: dict[tuple[str | None, str, int], JavaHelperSummary] = {}
        request_fields = self._collect_request_fields()
        for method in self._method_nodes():
            if method.type != "method_declaration":
                continue
            name = self._method_name(method)
            if not name:
                continue
            params = [self._param_name(param) for param in self._formal_parameters(method)]
            param_names = [param for param in params if param]
            class_name = self._class_name_for_node(method)
            class_request_fields = request_fields.get(class_name, set())
            returns_request_source = self._method_returns_taint(
                method, [], class_request_fields
            )
            returns_arg_taint = self._method_returns_taint(method, param_names)
            summaries[(class_name, name, len(param_names))] = JavaHelperSummary(
                returns_request_source=returns_request_source,
                returns_arg_taint=returns_arg_taint,
            )
        return summaries

    def _collect_request_fields(self) -> dict[str | None, set[str]]:
        fields: dict[str | None, set[str]] = {}
        for declaration in self._iter_nodes(self.root_node):
            if declaration.type != "field_declaration":
                continue
            type_node = declaration.child_by_field_name("type")
            if self._simple_name(self._text(type_node)) not in REQUEST_TYPES:
                continue
            class_name = self._class_name_for_node(declaration)
            for declarator in self._children_of_type(declaration, "variable_declarator"):
                name_node = declarator.child_by_field_name("name")
                if name_node is not None:
                    fields.setdefault(class_name, set()).add(self._text(name_node))
        return fields

    def _method_returns_taint(
        self,
        method_node,
        seed_params: list[str],
        request_fields: set[str] | None = None,
    ) -> bool:
        state = self._initial_state(method_node)
        if request_fields:
            state.request_vars.update(request_fields)
        state.tainted_vars.update(seed_params)
        body = method_node.child_by_field_name("body")
        if body is None:
            return False
        return self._block_returns_taint(body, state)

    def _block_returns_taint(self, block_node, state: JavaFlowState) -> bool:
        for statement in self._block_statements(block_node):
            if statement.type == "return_statement":
                expr = self._first_expression_child(statement)
                if expr is not None and self._expr_facts(expr, state).tainted:
                    return True
                continue
            if statement.type == "if_statement":
                condition = statement.child_by_field_name("condition")
                selected = self._eval_condition(condition, state)
                consequence = statement.child_by_field_name("consequence")
                alternative = statement.child_by_field_name("alternative")
                if selected is True:
                    if consequence is not None and self._statement_returns_taint(
                        consequence, state.copy()
                    ):
                        return True
                elif selected is False:
                    if alternative is not None and self._statement_returns_taint(
                        alternative, state.copy()
                    ):
                        return True
                else:
                    if consequence is not None and self._statement_returns_taint(
                        consequence, state.copy()
                    ):
                        return True
                    if alternative is not None and self._statement_returns_taint(
                        alternative, state.copy()
                    ):
                        return True
                continue
            self._process_statement(statement, state, collect_findings=False)
        return False

    def _statement_returns_taint(self, statement, state: JavaFlowState) -> bool:
        if statement.type == "return_statement":
            expr = self._first_expression_child(statement)
            return expr is not None and self._expr_facts(expr, state).tainted
        if statement.type == "block":
            return self._block_returns_taint(statement, state)
        self._process_statement(statement, state, collect_findings=False)
        return False

    def _process_statement(
        self, statement, state: JavaFlowState, *, collect_findings: bool = True
    ) -> None:
        if statement.type == "block":
            for child in self._block_statements(statement):
                self._process_statement(child, state, collect_findings=collect_findings)
            return

        if statement.type == "local_variable_declaration":
            for declarator in self._children_of_type(statement, "variable_declarator"):
                self._process_variable_declarator(
                    declarator, state, collect_findings=collect_findings
                )
            return

        if statement.type == "expression_statement":
            expr = self._first_expression_child(statement)
            if expr is not None:
                self._process_expression_statement(
                    expr, state, collect_findings=collect_findings
                )
            return

        if statement.type == "return_statement":
            if collect_findings:
                self._scan_expression_effects(statement, state)
            return

        if statement.type == "if_statement":
            self._process_if_statement(
                statement, state, collect_findings=collect_findings
            )
            return

        if statement.type in {"switch_expression", "switch_statement"}:
            self._process_switch(
                statement, state, collect_findings=collect_findings
            )
            return

        if statement.type == "enhanced_for_statement":
            self._process_enhanced_for(
                statement, state, collect_findings=collect_findings
            )
            return

        if collect_findings:
            self._scan_expression_effects(statement, state)
        for child in statement.children:
            if child.type.endswith("_statement") or child.type in {
                "block",
                "local_variable_declaration",
            }:
                self._process_statement(child, state, collect_findings=collect_findings)

    def _process_expression_statement(
        self, expr, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        if expr.type == "assignment_expression":
            self._process_assignment(expr, state, collect_findings=collect_findings)
            return
        if collect_findings:
            self._scan_expression_effects(expr, state)

    def _process_variable_declarator(
        self, declarator, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        name_node = declarator.child_by_field_name("name")
        value_node = declarator.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        name = self._text(name_node)
        if collect_findings:
            self._scan_expression_effects(value_node, state)
        self._assign_var(name, value_node, state)

    def _process_assignment(
        self, assignment, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        left = assignment.child_by_field_name("left")
        right = assignment.child_by_field_name("right")
        if right is None:
            return
        if collect_findings:
            self._scan_expression_effects(right, state)
        name = self._assignment_target_name(left)
        if name:
            self._assign_var(name, right, state)

    def _assign_var(self, name: str, value_node, state: JavaFlowState) -> None:
        state.guarded_path_vars.discard(name)
        state.pending_path_objects.pop(name, None)

        const_value = self._eval_constant(value_node, state)
        if const_value is not None:
            state.constants[name] = const_value
        else:
            state.constants.pop(name, None)

        object_type = self._object_creation_type(value_node)
        if object_type:
            state.object_types[name] = object_type
            if object_type == "Cookie":
                state.cookie_vars.add(name)
            object_args = self._object_creation_args(value_node)
            if object_type == "ProcessBuilder" and (
                self._args_tainted(object_args, state)
                or self._args_mention_names(object_args, state.tainted_collections)
            ):
                state.tainted_process_builders.add(name)
            if object_type == "File":
                facts = self._expr_facts(value_node, state)
                if facts.tainted:
                    state.pending_path_objects[name] = self._line(value_node)
        else:
            state.object_types.pop(name, None)

        facts = self._expr_facts(value_node, state)
        if facts.tainted:
            state.tainted_vars.add(name)
            if facts.xss_safe:
                state.xss_safe_vars.add(name)
            else:
                state.xss_safe_vars.discard(name)
        else:
            state.tainted_vars.discard(name)
            state.xss_safe_vars.discard(name)
            state.tainted_collections.discard(name)
            state.tainted_process_builders.discard(name)

        if self._expr_has_normalizer(value_node):
            state.normalized_path_vars.add(name)
            if self._expr_has_canonical_path(value_node):
                state.canonical_string_vars.add(name)
                source_name = self._first_receiver_for_call(value_node, "getCanonicalPath")
                if source_name:
                    state.canonical_path_sources[name] = {source_name}
                if self._expr_is_slash_terminated_base(value_node):
                    state.slash_terminated_vars.add(name)
                else:
                    state.slash_terminated_vars.discard(name)
        else:
            state.normalized_path_vars.discard(name)
            state.canonical_string_vars.discard(name)
            state.slash_terminated_vars.discard(name)
            state.canonical_path_sources.pop(name, None)

    def _process_if_statement(
        self, node, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        guarded_after = self._path_guards_from_if(node, state)
        condition = node.child_by_field_name("condition")
        selected = self._eval_condition(condition, state)
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")

        if selected is True:
            if consequence is not None:
                self._process_statement(
                    consequence, state, collect_findings=collect_findings
                )
        elif selected is False:
            if alternative is not None:
                self._process_statement(
                    alternative, state, collect_findings=collect_findings
                )
        else:
            left = state.copy()
            right = state.copy()
            if consequence is not None:
                self._process_statement(
                    consequence, left, collect_findings=collect_findings
                )
            if alternative is not None:
                self._process_statement(
                    alternative, right, collect_findings=collect_findings
                )
            state.merge_from(left, right)

        state.guarded_path_vars.update(guarded_after)
        for name in guarded_after:
            state.pending_path_objects.pop(name, None)

    def _process_enhanced_for(
        self, node, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        name = None
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is not None:
            name = self._text(name_node)
        if name and value is not None and self._expr_facts(value, state).tainted:
            state.tainted_vars.add(name)
        body = node.child_by_field_name("body")
        if body is not None:
            self._process_statement(body, state, collect_findings=collect_findings)

    def _process_switch(
        self, node, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        body = node.child_by_field_name("body")
        if body is None:
            if collect_findings:
                self._scan_expression_effects(node, state)
            return

        groups = [
            child for child in body.children if child.type == "switch_block_statement_group"
        ]
        if not groups:
            return

        condition_value = self._eval_constant(node.child_by_field_name("condition"), state)
        if condition_value is not None:
            selected_index = self._select_switch_group_index(
                groups, condition_value, state
            )
            if selected_index is not None:
                for group in groups[selected_index:]:
                    stop = False
                    for child in group.children:
                        if child.type == "switch_label":
                            continue
                        self._process_statement(
                            child, state, collect_findings=collect_findings
                        )
                        if child.type in {"break_statement", "return_statement", "throw_statement"}:
                            stop = True
                            break
                    if stop:
                        break
                return

        merged_state: JavaFlowState | None = None
        for group in groups:
            branch_state = state.copy()
            for child in group.children:
                if child.type == "switch_label":
                    continue
                self._process_statement(
                    child, branch_state, collect_findings=collect_findings
                )
            if merged_state is None:
                merged_state = branch_state
            else:
                next_state = state.copy()
                next_state.merge_from(merged_state, branch_state)
                merged_state = next_state

        if merged_state is not None:
            state.merge_from(merged_state, merged_state)

    def _select_switch_group_index(
        self, groups: list, condition_value: int | bool | str, state: JavaFlowState
    ) -> int | None:
        default_index = None
        for index, group in enumerate(groups):
            for label in [child for child in group.children if child.type == "switch_label"]:
                if self._text(label).lstrip().startswith("default"):
                    default_index = index
                    continue
                label_expr = self._first_expression_child(label)
                label_value = self._eval_constant(label_expr, state)
                if label_value == condition_value:
                    return index
        return default_index

    def _scan_expression_effects(self, node, state: JavaFlowState) -> None:
        for child in self._iter_nodes(node):
            if child.type == "method_invocation":
                self._process_method_effects(child, state)
                self._process_method_sinks(child, state)
            elif child.type == "object_creation_expression":
                self._process_constructor_sinks(child, state)
                self._process_weak_random(child, state)

    def _process_method_effects(self, call, state: JavaFlowState) -> None:
        method = self._call_name(call)
        receiver = self._receiver_name(call)
        args = self._call_args(call)

        if method == "add" and receiver and args:
            value = self._expr_facts(args[0], state)
            state.list_entries.setdefault(receiver, []).append(value)
            if value.tainted:
                state.tainted_collections.add(receiver)
            return

        if method == "remove" and receiver and args:
            index = self._eval_constant(args[0], state)
            if isinstance(index, int):
                entries = state.list_entries.get(receiver)
                if entries and 0 <= index < len(entries):
                    entries.pop(index)
                    if not any(entry.tainted for entry in entries):
                        state.tainted_collections.discard(receiver)
            return

        if method == "put" and receiver and len(args) >= 2:
            key = self._string_literal_value(args[0])
            if key is not None:
                state.map_entries[(receiver, key)] = self._expr_facts(args[1], state)
            return

        if method == "setSecure" and receiver in state.cookie_vars and args:
            value = self._eval_constant(args[0], state)
            if value is False:
                state.insecure_cookie_vars.add(receiver)
            elif value is True:
                state.insecure_cookie_vars.discard(receiver)
            return

        if (
            method == "command"
            and receiver
            and (
                self._args_tainted(args, state)
                or self._args_mention_names(args, state.tainted_collections)
            )
        ):
            state.tainted_process_builders.add(receiver)
            return

    def _process_method_sinks(self, call, state: JavaFlowState) -> None:
        method = self._call_name(call)
        args = self._call_args(call)
        line = self._line(call)

        if method == "addCookie" and self._args_mention_names(
            args, state.insecure_cookie_vars
        ):
            self._add_finding(
                "SKY-D252",
                "HIGH",
                "Cookie is added with Secure disabled. Set Secure before sending sensitive cookies.",
                line,
                category="cookie_security",
                cwe="CWE-614",
            )

        if method == "start":
            receiver = self._receiver_name(call)
            if receiver in state.tainted_process_builders:
                self._add_finding(
                    "SKY-D212",
                    "CRITICAL",
                    "ProcessBuilder starts a shell command built from servlet-controlled data. Use fixed argv elements and validate inputs.",
                    line,
                    cwe="CWE-78",
                )

        if method == "exec" and (
            self._args_tainted(args, state)
            or self._args_mention_names(args, state.tainted_collections)
        ):
            self._add_finding(
                "SKY-D212",
                "CRITICAL",
                "Process execution uses servlet-controlled data. Use fixed argv elements and validate inputs.",
                line,
                cwe="CWE-78",
            )

        if method in SQL_SINKS and self._sink_args_tainted(args, SQL_SINKS[method], state):
            self._add_finding(
                "SKY-D211",
                "CRITICAL",
                "SQL query uses servlet-controlled data. Use parameterized queries with fixed SQL.",
                line,
                cwe="CWE-89",
            )

        if method in LDAP_SINKS and self._sink_args_tainted(
            args, LDAP_SINKS[method], state
        ):
            self._add_finding(
                "SKY-D240",
                "CRITICAL",
                "LDAP search filter uses servlet-controlled data. Escape LDAP filter values or use safe APIs.",
                line,
                category="ldap_injection",
                cwe="CWE-90",
            )

        if method in XPATH_SINKS and self._sink_args_tainted(
            args, XPATH_SINKS[method], state
        ):
            self._add_finding(
                "SKY-D241",
                "CRITICAL",
                "XPath expression uses servlet-controlled data. Use fixed expressions or strict allowlists.",
                line,
                category="xpath_injection",
                cwe="CWE-643",
            )

        if (
            method in XSS_WRITER_METHODS
            and self._receiver_chain_has_call(call, "getWriter")
            and any(self._expr_facts(arg, state).tainted and not self._expr_facts(arg, state).xss_safe for arg in args)
        ):
            self._add_finding(
                "SKY-D226",
                "HIGH",
                "Servlet response writes untrusted data without HTML encoding.",
                line,
                cwe="CWE-79",
            )

        if (
            method in {"setAttribute", "putValue"}
            and self._receiver_chain_has_call(call, "getSession")
            and self._args_tainted(args, state)
        ):
            self._add_finding(
                "SKY-D253",
                "HIGH",
                "Servlet-controlled data crosses into HTTP session state.",
                line,
                category="trust_boundary",
                cwe="CWE-501",
            )

        if self._is_files_path_sink(call):
            positions = FILES_PATH_METHODS.get(method, ())
            if self._path_sink_tainted(call, args, positions, state):
                self._add_finding(
                    "SKY-D215",
                    "HIGH",
                    "Servlet-controlled path reaches a filesystem sink without canonical path validation.",
                    line,
                    cwe="CWE-22",
                )

        self._process_weak_random(call, state)

    def _process_constructor_sinks(self, node, state: JavaFlowState) -> None:
        class_name = self._object_creation_type(node)
        args = self._object_creation_args(node)
        if class_name in PATH_CONSTRUCTOR_TYPES and self._path_sink_tainted(
            node, args, PATH_CONSTRUCTOR_TYPES[class_name], state
        ):
            self._add_finding(
                "SKY-D215",
                "HIGH",
                "Servlet-controlled path reaches a filesystem sink without canonical path validation.",
                self._line(node),
                cwe="CWE-22",
            )

    def _process_weak_random(self, node, state: JavaFlowState) -> None:
        if not self._is_weak_random_call(node):
            return
        method = self._enclosing_method(node)
        if method is None:
            return
        if not self._method_has_security_token_context(method):
            return
        self._add_finding(
            "SKY-D250",
            "HIGH",
            "Weak random value is used in security-sensitive token or session material. Use SecureRandom.",
            self._line(node),
            category="weak_random",
            cwe="CWE-330",
        )

    def _expr_facts(self, node, state: JavaFlowState) -> JavaTaint:
        if node is None:
            return JavaTaint()

        if node.type == "identifier":
            name = self._text(node)
            return JavaTaint(
                tainted=name in state.tainted_vars,
                xss_safe=name in state.xss_safe_vars,
            )

        if node.type in {
            "string_literal",
            "decimal_integer_literal",
            "hex_integer_literal",
            "octal_integer_literal",
            "binary_integer_literal",
            "true",
            "false",
            "null_literal",
        }:
            return JavaTaint()

        if node.type == "parenthesized_expression":
            child = self._first_expression_child(node)
            return self._expr_facts(child, state) if child is not None else JavaTaint()

        if node.type == "cast_expression":
            return JavaTaint.combine(
                [self._expr_facts(child, state) for child in node.children[-1:]]
            )

        if node.type == "assignment_expression":
            right = node.child_by_field_name("right")
            return self._expr_facts(right, state) if right is not None else JavaTaint()

        if node.type == "ternary_expression":
            condition = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            selected = self._eval_condition(condition, state)
            if selected is True and consequence is not None:
                return self._expr_facts(consequence, state)
            if selected is False and alternative is not None:
                return self._expr_facts(alternative, state)
            values = []
            if consequence is not None:
                values.append(self._expr_facts(consequence, state))
            if alternative is not None:
                values.append(self._expr_facts(alternative, state))
            return JavaTaint.combine(values)

        if node.type == "method_invocation":
            return self._method_call_facts(node, state)

        if node.type == "object_creation_expression":
            args = self._object_creation_args(node)
            if self._args_mention_names(args, state.tainted_collections):
                return JavaTaint(tainted=True)
            return JavaTaint.combine(
                [self._expr_facts(arg, state) for arg in args]
            )

        if node.type == "array_access":
            values = [self._expr_facts(child, state) for child in node.children]
            return JavaTaint.combine(values)

        values = []
        for child in node.children:
            if child.is_named:
                values.append(self._expr_facts(child, state))
        return JavaTaint.combine(values)

    def _method_call_facts(self, call, state: JavaFlowState) -> JavaTaint:
        method = self._call_name(call)
        args = self._call_args(call)

        if self._is_request_source_call(call, state):
            return JavaTaint(tainted=True)

        if method in XSS_SANITIZER_METHODS:
            facts = JavaTaint.combine([self._expr_facts(arg, state) for arg in args])
            return JavaTaint(tainted=facts.tainted, xss_safe=facts.tainted)

        receiver = self._receiver_name(call)
        if method == "get" and receiver and args:
            key = self._string_literal_value(args[0])
            if key is not None and (receiver, key) in state.map_entries:
                return state.map_entries[(receiver, key)]
            index = self._eval_constant(args[0], state)
            if isinstance(index, int):
                entries = state.list_entries.get(receiver, [])
                if 0 <= index < len(entries):
                    return entries[index]

        summary = self._helper_summary_for_call(call, state)
        if summary is not None:
            if summary.returns_request_source:
                return JavaTaint(tainted=True)
            if summary.returns_arg_taint:
                return JavaTaint.combine([self._expr_facts(arg, state) for arg in args])
            return JavaTaint()

        values = [self._expr_facts(arg, state) for arg in args]
        receiver_node = call.child_by_field_name("object")
        if receiver_node is not None:
            values.append(self._expr_facts(receiver_node, state))
        return JavaTaint.combine(values)

    def _helper_summary_for_call(
        self, call, state: JavaFlowState
    ) -> JavaHelperSummary | None:
        method = self._call_name(call)
        args = self._call_args(call)
        receiver = self._receiver_name(call)
        receiver_class = None
        if receiver:
            receiver_class = state.object_types.get(receiver)
        if receiver_class is None:
            object_node = call.child_by_field_name("object")
            if object_node is not None and object_node.type == "object_creation_expression":
                receiver_class = self._object_creation_type(object_node)
        if receiver_class is None and call.child_by_field_name("object") is None:
            receiver_class = self._class_name_for_node(call)
        return self.helper_summaries.get((receiver_class, method, len(args)))

    def _is_request_source_call(self, call, state: JavaFlowState) -> bool:
        method = self._call_name(call)
        if method not in REQUEST_SOURCE_METHODS:
            return False
        receiver = self._receiver_name(call)
        if receiver in state.request_vars:
            return True
        return receiver in {"request", "req"}

    def _path_sink_tainted(
        self, sink_node, args: list, positions: tuple[int, ...], state: JavaFlowState
    ) -> bool:
        for pos in positions:
            if pos >= len(args):
                continue
            arg = args[pos]
            facts = self._expr_facts(arg, state)
            if not facts.tainted:
                continue
            names = self._tainted_identifiers(arg, state)
            if names and self._path_arg_guarded(sink_node, names, state):
                continue
            return True
        return False

    def _path_arg_guarded(
        self, sink_node, names: set[str], state: JavaFlowState
    ) -> bool:
        if names and names <= state.guarded_path_vars:
            return True
        current = sink_node.parent
        while current is not None:
            if current.type == "if_statement":
                guarded = self._positive_path_guard_names(current, state)
                if names and names <= guarded and self._is_in_consequence(sink_node, current):
                    return True
            current = current.parent
        return False

    def _path_guards_from_if(self, node, state: JavaFlowState) -> set[str]:
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            return set()
        if not self._statement_always_exits(consequence, state):
            return set()
        guards = set()
        for call in self._calls_named(condition, "startsWith"):
            receiver = self._receiver_name(call)
            if not receiver:
                continue
            if not self._is_negative_guard_condition(condition):
                continue
            if not self._is_simple_startswith_guard_condition(condition):
                continue
            if self._is_safe_path_guard_call(call, state):
                guards.add(receiver)
                guards.update(state.canonical_path_sources.get(receiver, set()))
        return guards

    def _positive_path_guard_names(self, node, state: JavaFlowState) -> set[str]:
        condition = node.child_by_field_name("condition")
        if (
            condition is None
            or self._is_negative_guard_condition(condition)
            or not self._is_simple_startswith_guard_condition(condition)
        ):
            return set()
        guards = set()
        for call in self._calls_named(condition, "startsWith"):
            receiver = self._receiver_name(call)
            if receiver and self._is_safe_path_guard_call(call, state):
                guards.add(receiver)
                guards.update(state.canonical_path_sources.get(receiver, set()))
        return guards

    def _is_safe_path_guard_call(self, call, state: JavaFlowState) -> bool:
        receiver = self._receiver_name(call)
        if not receiver:
            return False
        args = self._call_args(call)
        arg = self._text(args[0]).strip() if args else ""
        receiver_safe = (
            receiver in state.normalized_path_vars
            or receiver in state.canonical_string_vars
            or self._expr_has_normalizer(call.child_by_field_name("object"))
        )
        if not receiver_safe:
            return False
        if receiver in state.canonical_string_vars:
            arg_name = arg if arg.isidentifier() else ""
            if arg_name in state.canonical_string_vars:
                return arg_name in state.slash_terminated_vars
        return True

    def _flush_pending_path_objects(self, state: JavaFlowState) -> None:
        for name, line in sorted(state.pending_path_objects.items(), key=lambda item: item[1]):
            if name in state.guarded_path_vars:
                continue
            self._add_finding(
                "SKY-D215",
                "HIGH",
                "Servlet-controlled path reaches a filesystem sink without canonical path validation.",
                line,
                cwe="CWE-22",
            )

    def _is_files_path_sink(self, call) -> bool:
        method = self._call_name(call)
        if method not in FILES_PATH_METHODS:
            return False
        receiver = self._receiver_text(call)
        base = self._simple_name(receiver)
        return base in {"Files", "java.nio.file.Files"} or receiver.endswith(".Files")

    def _args_tainted(self, args: list, state: JavaFlowState) -> bool:
        return any(self._expr_facts(arg, state).tainted for arg in args)

    def _sink_args_tainted(
        self, args: list, positions: tuple[int, ...], state: JavaFlowState
    ) -> bool:
        return any(
            pos < len(args) and self._expr_facts(args[pos], state).tainted
            for pos in positions
        )

    def _args_mention_names(self, args: list, names: set[str]) -> bool:
        return any(self._identifier_names(arg) & names for arg in args)

    def _tainted_identifiers(self, node, state: JavaFlowState) -> set[str]:
        return self._identifier_names(node) & state.tainted_vars

    def _expr_has_normalizer(self, node) -> bool:
        if node is None:
            return False
        return any(
            self._call_name(call) in PATH_NORMALIZER_METHODS
            for call in self._method_calls(node)
        )

    def _expr_has_canonical_path(self, node) -> bool:
        if node is None:
            return False
        return any(self._call_name(call) == "getCanonicalPath" for call in self._method_calls(node))

    def _expr_is_slash_terminated_base(self, node) -> bool:
        text = self._text(node)
        return (
            "File.separator" in text
            or "java.io.File.separator" in text
            or '"/"' in text
            or '"\\\\"' in text
            or "separatorChar" in text
        )

    def _is_weak_random_call(self, node) -> bool:
        if node.type == "method_invocation":
            method = self._call_name(node)
            receiver = self._receiver_text(node)
            if receiver in {"Math", "java.lang.Math"} and method == "random":
                return True
            if method.startswith("next") and "SecureRandom" not in self._text(node):
                object_node = node.child_by_field_name("object")
                if object_node is not None and "Random" in self._text(object_node):
                    return True
        if node.type == "object_creation_expression":
            return self._object_creation_type(node) == "Random"
        return False

    def _method_has_security_token_context(self, method_node) -> bool:
        for node in self._iter_nodes(method_node):
            if node.type == "identifier":
                name = self._text(node)
                if any(token in name.lower() for token in ("token", "session", "remember")):
                    return True
            elif node.type == "string_literal":
                value = self._text(node).lower()
                if any(token in value for token in ("token", "session", "rememberme")):
                    return True
            elif node.type == "method_invocation" and self._call_name(node) == "getSession":
                return True
        return False

    def _eval_condition(self, node, state: JavaFlowState) -> bool | None:
        value = self._eval_constant(node, state)
        return value if isinstance(value, bool) else None

    def _eval_constant(self, node, state: JavaFlowState) -> int | bool | str | None:
        if node is None:
            return None
        if node.type == "parenthesized_expression":
            child = self._first_expression_child(node)
            return self._eval_constant(child, state)
        if node.type == "string_literal":
            return self._string_literal_value(node)
        if node.type == "character_literal":
            text = self._text(node)
            if len(text) >= 3 and text[0] == "'" and text[-1] == "'":
                return text[1:-1]
            return None
        if node.type == "decimal_integer_literal":
            try:
                return int(self._text(node).replace("_", ""))
            except ValueError:
                return None
        if node.type == "true":
            return True
        if node.type == "false":
            return False
        if node.type == "identifier":
            return state.constants.get(self._text(node))
        if node.type == "unary_expression":
            child = self._first_expression_child(node)
            text = self._text(node).strip()
            value = self._eval_constant(child, state)
            if text.startswith("!") and isinstance(value, bool):
                return not value
            if text.startswith("-") and isinstance(value, int):
                return -value
            return None
        if node.type == "binary_expression":
            left = self._eval_constant(node.child_by_field_name("left"), state)
            right = self._eval_constant(node.child_by_field_name("right"), state)
            op = self._text(node.child_by_field_name("operator"))
            return self._eval_binary(left, op, right)
        if node.type == "method_invocation" and self._call_name(node) == "charAt":
            receiver = self._receiver_name(node)
            args = self._call_args(node)
            if receiver and args:
                receiver_value = state.constants.get(receiver)
                index = self._eval_constant(args[0], state)
                if isinstance(receiver_value, str) and isinstance(index, int):
                    if 0 <= index < len(receiver_value):
                        return receiver_value[index]
        return None

    def _eval_binary(
        self, left: int | bool | str | None, op: str, right: int | bool | str | None
    ) -> int | bool | str | None:
        if left is None or right is None:
            return None
        try:
            if op == "+" and (isinstance(left, str) or isinstance(right, str)):
                return str(left) + str(right)
            if op == "+" and isinstance(left, int) and isinstance(right, int):
                return left + right
            if op == "-" and isinstance(left, int) and isinstance(right, int):
                return left - right
            if op == "*" and isinstance(left, int) and isinstance(right, int):
                return left * right
            if op == "/" and isinstance(left, int) and isinstance(right, int) and right:
                return left // right
            if op == "%" and isinstance(left, int) and isinstance(right, int) and right:
                return left % right
            if op == ">":
                return left > right
            if op == ">=":
                return left >= right
            if op == "<":
                return left < right
            if op == "<=":
                return left <= right
            if op == "==":
                return left == right
            if op == "!=":
                return left != right
            if op == "&&" and isinstance(left, bool) and isinstance(right, bool):
                return left and right
            if op == "||" and isinstance(left, bool) and isinstance(right, bool):
                return left or right
        except Exception:
            return None
        return None

    def _is_negative_guard_condition(self, node) -> bool:
        text = self._text(node)
        return (
            text.strip().startswith("(!")
            or "== false" in text
            or "false ==" in text
            or text.strip().startswith("!")
        )

    def _is_simple_startswith_guard_condition(self, node) -> bool:
        text = self._text(node)
        return "&&" not in text and "||" not in text and len(self._calls_named(node, "startsWith")) == 1

    def _statement_always_exits(self, node, state: JavaFlowState) -> bool:
        if node.type in CONTROL_FLOW_STMTS:
            return True
        if node.type == "block":
            for statement in self._block_statements(node):
                if self._statement_always_exits(statement, state):
                    return True
            return False
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            selected = self._eval_condition(condition, state)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            if selected is True:
                return consequence is not None and self._statement_always_exits(
                    consequence, state
                )
            if selected is False:
                return alternative is not None and self._statement_always_exits(
                    alternative, state
                )
            return (
                consequence is not None
                and alternative is not None
                and self._statement_always_exits(consequence, state)
                and self._statement_always_exits(alternative, state)
            )
        return False

    def _is_in_consequence(self, node, if_node) -> bool:
        consequence = if_node.child_by_field_name("consequence")
        current = node
        while current is not None:
            if self._same_node(current, consequence):
                return True
            if self._same_node(current, if_node):
                return False
            current = current.parent
        return False

    def _receiver_chain_has_call(self, call, method_name: str) -> bool:
        receiver = call.child_by_field_name("object")
        if receiver is None:
            return False
        return any(
            node.type == "method_invocation" and self._call_name(node) == method_name
            for node in self._iter_nodes(receiver)
        )

    def _calls_named(self, node, method_name: str) -> list:
        return [
            call
            for call in self._method_calls(node)
            if self._call_name(call) == method_name
        ]

    def _first_receiver_for_call(self, node, method_name: str) -> str | None:
        for call in self._calls_named(node, method_name):
            receiver = self._receiver_name(call)
            if receiver:
                return receiver
        return None

    def _method_calls(self, node) -> list:
        if node is None:
            return []
        return [child for child in self._iter_nodes(node) if child.type == "method_invocation"]

    def _identifier_names(self, node) -> set[str]:
        if node is None:
            return set()
        return {
            self._text(child)
            for child in self._iter_nodes(node)
            if child.type == "identifier"
        }

    def _same_node(self, left, right) -> bool:
        if left is None or right is None:
            return False
        return (
            left.type == right.type
            and left.start_byte == right.start_byte
            and left.end_byte == right.end_byte
        )

    def _method_nodes(self) -> list:
        return [
            node
            for node in self._iter_nodes(self.root_node)
            if node.type in {"method_declaration", "constructor_declaration"}
        ]

    def _iter_nodes(self, node):
        stack = [node]
        while stack:
            current = stack.pop()
            yield current
            stack.extend(reversed(current.children))

    def _block_statements(self, block_node) -> list:
        return [child for child in block_node.children if child.is_named]

    def _children_of_type(self, node, type_name: str) -> list:
        return [child for child in self._iter_nodes(node) if child.type == type_name]

    def _formal_parameters(self, method_node) -> list:
        params = method_node.child_by_field_name("parameters")
        if params is None:
            return []
        return [child for child in params.children if child.type == "formal_parameter"]

    def _param_name(self, param) -> str | None:
        name = param.child_by_field_name("name")
        return self._text(name) if name is not None else None

    def _param_type(self, param) -> str:
        type_node = param.child_by_field_name("type")
        return self._text(type_node) if type_node is not None else ""

    def _annotation_names(self, node) -> set[str]:
        names = set()
        for child in node.children:
            if child.type != "modifiers":
                continue
            for modifier in child.children:
                if modifier.type not in {"marker_annotation", "annotation"}:
                    continue
                name = modifier.child_by_field_name("name")
                if name is not None:
                    names.add(self._simple_name(self._text(name)))
        return names

    def _method_name(self, method_node) -> str | None:
        name = method_node.child_by_field_name("name")
        return self._text(name) if name is not None else None

    def _class_name_for_node(self, node) -> str | None:
        current = node.parent
        while current is not None:
            if current.type in {
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
            }:
                name = current.child_by_field_name("name")
                return self._text(name) if name is not None else None
            current = current.parent
        return None

    def _enclosing_method(self, node):
        current = node.parent
        while current is not None:
            if current.type in {"method_declaration", "constructor_declaration"}:
                return current
            current = current.parent
        return None

    def _call_name(self, call) -> str:
        name = call.child_by_field_name("name")
        return self._text(name) if name is not None else ""

    def _receiver_text(self, call) -> str:
        receiver = call.child_by_field_name("object")
        return self._text(receiver) if receiver is not None else ""

    def _receiver_name(self, call) -> str | None:
        receiver = call.child_by_field_name("object")
        if receiver is not None and receiver.type == "identifier":
            return self._text(receiver)
        return None

    def _call_args(self, call) -> list:
        args = call.child_by_field_name("arguments")
        return self._argument_children(args)

    def _object_creation_type(self, node) -> str | None:
        if node is None or node.type != "object_creation_expression":
            return None
        type_node = node.child_by_field_name("type")
        if type_node is None:
            return None
        return self._simple_name(self._text(type_node))

    def _object_creation_args(self, node) -> list:
        args = node.child_by_field_name("arguments")
        return self._argument_children(args)

    def _argument_children(self, args_node) -> list:
        if args_node is None:
            return []
        return [
            child
            for child in args_node.children
            if child.is_named and child.type not in {"line_comment", "block_comment"}
        ]

    def _first_expression_child(self, node):
        for child in node.children:
            if child.is_named:
                return child
        return None

    def _assignment_target_name(self, node) -> str | None:
        if node is None:
            return None
        if node.type == "identifier":
            return self._text(node)
        if node.type == "field_access":
            field = node.child_by_field_name("field")
            return self._text(field) if field is not None else None
        return None

    def _string_literal_value(self, node) -> str | None:
        if node is None or node.type != "string_literal":
            return None
        text = self._text(node)
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            return text[1:-1]
        return None

    def _simple_name(self, name: str) -> str:
        if not name:
            return ""
        return name.replace("[]", "").split("<", 1)[0].rsplit(".", 1)[-1]

    def _text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _line(self, node) -> int:
        return node.start_point[0] + 1

    def _add_finding(
        self,
        rule_id: str,
        severity: str,
        message: str,
        line: int,
        *,
        category: str | None = None,
        cwe: str | None = None,
    ) -> None:
        key = (rule_id, line, category or "")
        if key in self.seen:
            return
        self.seen.add(key)
        finding = {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "file": str(self.file_path),
            "line": line,
            "col": 0,
        }
        if category:
            finding["category"] = category
        if cwe:
            finding["cwe"] = cwe
        self.findings.append(finding)


def scan_java_security_flows(root_node, file_path: str, source_bytes: bytes) -> list[dict]:
    if root_node is None:
        return []
    return JavaSecurityFlowAnalyzer(root_node, file_path, source_bytes).scan()
