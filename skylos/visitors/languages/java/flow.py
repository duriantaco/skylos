from __future__ import annotations

from dataclasses import dataclass, field

from . import models
from .properties import JavaPropertyResources
from .source_helpers import JavaSourceHelpers


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
    "getInputStream",
    "getReader",
    "getPart",
    "getParts",
}

REQUEST_PARAM_ANNOTATIONS = {
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestBody",
    "RequestPart",
    "ModelAttribute",
    "MatrixVariable",
    "QueryParam",
    "PathParam",
    "FormParam",
    "HeaderParam",
    "CookieParam",
    "MatrixParam",
    "BeanParam",
}

IMPORT_EVIDENCE = {
    "Context": ("javax.naming",),
    "Template": ("freemarker.template",),
    "Eval": ("groovy.util",),
    "Velocity": ("org.apache.velocity.app",),
    "MVEL": ("org.mvel2",),
    "Ognl": ("ognl", "org.apache.commons.ognl"),
    "TemplateEngine": ("groovy.text",),
}

REQUEST_TYPES = {
    "HttpServletRequest",
    "ServletRequest",
}

RESPONSE_TYPES = {
    "HttpServletResponse",
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

XSS_WRITER_METHODS = {"print", "println", "printf", "format", "write"}
XSS_SANITIZER_METHODS = {
    "encodeForHTML",
    "encodeForHtml",
    "forHtml",
    "escapeHtml",
    "htmlEscape",
}

URL_NETWORK_METHODS = {
    "connect",
    "openConnection",
    "openStream",
    "getContent",
    "getInputStream",
    "getOutputStream",
}

HTTP_REQUEST_BUILDER_METHODS = {
    "newBuilder": (0,),
    "uri": (0,),
}

REST_TEMPLATE_URL_METHODS = {
    "delete": (0,),
    "exchange": (0,),
    "execute": (0,),
    "getForEntity": (0,),
    "getForObject": (0,),
    "headForHeaders": (0,),
    "optionsForAllow": (0,),
    "patchForObject": (0,),
    "postForEntity": (0,),
    "postForLocation": (0,),
    "postForObject": (0,),
    "put": (0,),
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

XSTREAM_PERMISSION_METHODS = frozenset(
    {
        "addPermission",
        "allowTypes",
        "allowTypesByRegExp",
        "allowTypesByWildcard",
        "allowTypeHierarchy",
        "setupDefaultSecurity",
    }
)

SCRIPT_RECEIVER_TYPES = frozenset(
    {"ScriptEngine", "Compilable", "GroovyShell", "GroovyClassLoader", "Eval"}
)

CLASSPATH_RESOURCE_METHODS = frozenset(
    {
        "getResourceAsStream",
        "getResource",
        "getSystemResourceAsStream",
        "getSystemResource",
    }
)

REQUEST_HELPER_METHODS = frozenset(
    {
        "getCookie",
        "getCookieValue",
        "getStringParameter",
        "getStringParameters",
        "getRequiredStringParameter",
        "getRequiredStringParameters",
        "findParameterValue",
        "getParametersStartingWith",
    }
)

SPEL_EVALUATION_METHODS = frozenset(
    {"getValue", "setValue", "getValueType", "getValueTypeDescriptor"}
)

LDAP_ENCODER_METHODS = frozenset(
    {
        "filterEncode",
        "nameEncode",
        "escapeValue",
        "encodeValue",
        "encodeForLDAP",
        "encodeForDN",
        "createEqualityFilter",
        "createSubstringFilter",
        "createPresenceFilter",
    }
)

DESER_STATUS_RANK = {"allowed": 0, "safe": 0, "open": 1, "any": 2}

_UNKNOWN_VALUE = object()

MAX_CONSTANT_STRING_CHARS = 4096
MAX_CONSTANT_STORE_CHARS = 16384
MAX_CONSTANT_ENTRIES = 256
MAX_CONSTANT_ABS_INT = (1 << 63) - 1


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
    # Preserve package identity for source-backed helper resolution. The older
    # object_types map intentionally uses simple names for JDK sink matching.
    source_types: dict[str, str] = field(default_factory=dict)
    # Property-backed constants are crypto evidence only, never branch/safety
    # proofs. Object IDs preserve aliases without sharing mutable branch state.
    crypto_constants: dict[str, str] = field(default_factory=dict)
    property_objects: dict[str, int] = field(default_factory=dict)
    property_values: dict[int, dict[str, str]] = field(default_factory=dict)
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
    guarded_url_vars: set[str] = field(default_factory=set)
    guarded_redirect_vars: set[str] = field(default_factory=set)
    fixed_host_vars: set[str] = field(default_factory=set)
    redirect_view_vars: set[str] = field(default_factory=set)
    ldap_safe_vars: set[str] = field(default_factory=set)
    xml_objects: dict[str, tuple[str, tuple]] = field(default_factory=dict)
    deser_objects: dict[str, str] = field(default_factory=dict)

    def copy(self) -> "JavaFlowState":
        return JavaFlowState(
            request_vars=set(self.request_vars),
            tainted_vars=set(self.tainted_vars),
            xss_safe_vars=set(self.xss_safe_vars),
            constants=dict(self.constants),
            object_types=dict(self.object_types),
            source_types=dict(self.source_types),
            crypto_constants=dict(self.crypto_constants),
            property_objects=dict(self.property_objects),
            property_values={
                key: dict(value) for key, value in self.property_values.items()
            },
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
            guarded_url_vars=set(self.guarded_url_vars),
            guarded_redirect_vars=set(self.guarded_redirect_vars),
            fixed_host_vars=set(self.fixed_host_vars),
            redirect_view_vars=set(self.redirect_view_vars),
            ldap_safe_vars=set(self.ldap_safe_vars),
            xml_objects=dict(self.xml_objects),
            deser_objects=dict(self.deser_objects),
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
        self.source_types = {
            name: value
            for name, value in left.source_types.items()
            if right.source_types.get(name) == value
        }
        self.crypto_constants = {
            name: value
            for name, value in left.crypto_constants.items()
            if right.crypto_constants.get(name) == value
        }
        self.property_objects = {
            name: value
            for name, value in left.property_objects.items()
            if right.property_objects.get(name) == value
        }
        self.property_values = {
            key: dict(value)
            for key, value in left.property_values.items()
            if right.property_values.get(key) == value
        }
        self.map_entries = self._merge_map_entries(left.map_entries, right.map_entries)
        self.list_entries = self._merge_list_entries(
            left.list_entries, right.list_entries
        )
        self.tainted_collections = left.tainted_collections | right.tainted_collections
        self.tainted_process_builders = (
            left.tainted_process_builders | right.tainted_process_builders
        )
        self.cookie_vars = left.cookie_vars | right.cookie_vars
        self.insecure_cookie_vars = (
            left.insecure_cookie_vars | right.insecure_cookie_vars
        )
        self.normalized_path_vars = (
            left.normalized_path_vars | right.normalized_path_vars
        )
        self.guarded_path_vars = left.guarded_path_vars & right.guarded_path_vars
        self.canonical_string_vars = (
            left.canonical_string_vars | right.canonical_string_vars
        )
        self.slash_terminated_vars = (
            left.slash_terminated_vars | right.slash_terminated_vars
        )
        self.canonical_path_sources = {
            **left.canonical_path_sources,
            **right.canonical_path_sources,
        }
        self.pending_path_objects = {
            name: min(
                left.pending_path_objects.get(
                    name, right.pending_path_objects.get(name, 0)
                ),
                right.pending_path_objects.get(
                    name, left.pending_path_objects.get(name, 0)
                ),
            )
            for name in set(left.pending_path_objects) | set(right.pending_path_objects)
        }
        self.guarded_url_vars = left.guarded_url_vars & right.guarded_url_vars
        self.guarded_redirect_vars = (
            left.guarded_redirect_vars & right.guarded_redirect_vars
        )
        self.fixed_host_vars = left.fixed_host_vars & right.fixed_host_vars
        self.redirect_view_vars = left.redirect_view_vars | right.redirect_view_vars
        self.ldap_safe_vars = left.ldap_safe_vars & right.ldap_safe_vars
        self.xml_objects = self._merge_xml_objects(left.xml_objects, right.xml_objects)
        self.deser_objects = self._merge_deser_objects(
            left.deser_objects, right.deser_objects
        )

    def _merge_xml_objects(
        self,
        left: dict[str, tuple[str, tuple]],
        right: dict[str, tuple[str, tuple]],
    ) -> dict[str, tuple[str, tuple]]:
        merged = {}
        for name in set(left) & set(right):
            left_kind, left_settings = left[name]
            right_kind, right_settings = right[name]
            if left_kind != right_kind:
                continue
            common = set(left_settings) & set(right_settings)
            merged[name] = (left_kind, tuple(sorted(common, key=repr)))
        return merged

    def _merge_deser_objects(
        self, left: dict[str, str], right: dict[str, str]
    ) -> dict[str, str]:
        merged = {}
        for name in set(left) & set(right):
            left_kind, _, left_status = left[name].partition(":")
            right_kind, _, right_status = right[name].partition(":")
            if left_kind != right_kind:
                continue
            if DESER_STATUS_RANK.get(left_status, 0) >= DESER_STATUS_RANK.get(
                right_status, 0
            ):
                merged[name] = left[name]
            else:
                merged[name] = right[name]
        return merged

    def _merge_map_entries(
        self,
        left: dict[tuple[str, str], JavaTaint],
        right: dict[tuple[str, str], JavaTaint],
    ) -> dict[tuple[str, str], JavaTaint]:
        merged = {}
        for key in set(left) | set(right):
            values = [
                value for value in (left.get(key), right.get(key)) if value is not None
            ]
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
    def __init__(
        self,
        root_node,
        file_path: str,
        source_bytes: bytes,
        *,
        enable_source_helpers: bool = True,
    ) -> None:
        self.root_node = root_node
        self.file_path = file_path
        self.source = source_bytes
        self.findings: list[dict] = []
        self.seen: set[tuple[str, int, str]] = set()
        self.helper_summaries: dict[tuple[str | None, str, int], JavaHelperSummary] = {}
        self.source_helpers = (
            JavaSourceHelpers(root_node, file_path, source_bytes)
            if enable_source_helpers and root_node is not None
            else None
        )
        self.property_resources: JavaPropertyResources | None = None
        self._crypto_receiver_names: set[str] | None = None
        self._class_fields: dict[str | None, dict[str, str]] | None = None
        self._class_string_constants: dict[str | None, dict[str, str]] | None = None
        self._imports: tuple[set[str], set[str], set[str]] | None = None
        self._field_deser_cache: dict[tuple[int, str], str | None] = {}
        self._local_type_names: set[str] | None = None
        self._method_locals: dict[tuple[int, int], set[str]] = {}
        self._methods_by_name: dict[tuple[str | None, str, int], list] | None = None

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
        binds_request = self._method_binds_request(method_node)
        for param in self._formal_parameters(method_node):
            name = self._param_name(param)
            if not name:
                continue
            type_name = self._simple_name(self._param_type(param))
            annotations = self._annotation_names(param)
            if type_name in REQUEST_TYPES or name in {"request", "req"}:
                state.request_vars.add(name)
            if self._param_is_request_input(type_name, annotations, binds_request):
                state.tainted_vars.add(name)
            if type_name:
                state.object_types[name] = type_name
                state.source_types[name] = self._param_type(param)
        return state

    def _method_binds_request(self, method_node) -> bool:
        """Spring controller handlers and JAX-RS resource methods bind every
        parameter that is not a framework object from the request (CodeQL
        SpringRequestMappingParameter and JaxRsResourceMethod)."""
        annotations = self._annotation_names(method_node)
        if annotations & models.JAXRS_HANDLER_ANNOTATIONS:
            return True
        if not annotations & models.SPRING_HANDLER_ANNOTATIONS:
            return False
        current = method_node.parent
        while current is not None:
            if current.type == "class_declaration":
                return bool(
                    self._annotation_names(current) & {"Controller", "RestController"}
                )
            current = current.parent
        return False

    def _param_is_request_input(
        self, type_name: str, annotations: set[str], binds_request: bool
    ) -> bool:
        if type_name in models.SCALAR_PARAM_TYPES:
            return False
        if annotations & REQUEST_PARAM_ANNOTATIONS:
            return True
        if type_name in models.UPLOAD_PARAM_TYPES:
            return True
        if not binds_request or annotations & models.NON_INPUT_PARAM_ANNOTATIONS:
            return False
        return type_name not in models.NON_INPUT_PARAM_TYPES

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
            params = [
                self._param_name(param) for param in self._formal_parameters(method)
            ]
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
            for declarator in self._children_of_type(
                declaration, "variable_declarator"
            ):
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
        returns_taint, _ = self._summary_block_flow(body, state)
        return returns_taint

    def _summary_block_flow(
        self, block_node, state: JavaFlowState
    ) -> tuple[bool, bool]:
        """Return (tainted return seen, execution can reach the next statement)."""
        for statement in self._block_statements(block_node):
            returns_taint, continues = self._summary_statement_flow(statement, state)
            if returns_taint or not continues:
                return returns_taint, continues
        return False, True

    def _summary_statement_flow(
        self, statement, state: JavaFlowState
    ) -> tuple[bool, bool]:
        if statement is None:
            return False, True
        if statement.type == "return_statement":
            expr = self._first_expression_child(statement)
            return expr is not None and self._expr_facts(expr, state).tainted, False
        if statement.type == "throw_statement":
            return False, False
        if statement.type == "block":
            return self._summary_block_flow(statement, state)
        if statement.type == "if_statement":
            self._forget_property_effects(
                statement.child_by_field_name("condition"), state
            )
            selected = self._eval_condition(
                statement.child_by_field_name("condition"), state
            )
            consequence = statement.child_by_field_name("consequence")
            alternative = statement.child_by_field_name("alternative")
            if selected is not None:
                return self._summary_statement_flow(
                    consequence if selected else alternative, state
                )
            left, right = state.copy(), state.copy()
            left_taint, left_continues = self._summary_statement_flow(consequence, left)
            right_taint, right_continues = self._summary_statement_flow(
                alternative, right
            )
            # A returning/throwing branch cannot contribute its assignments to
            # a later return. Only merge states that actually fall through.
            if left_continues and right_continues:
                state.merge_from(left, right)
            elif left_continues:
                state.merge_from(left, left)
            elif right_continues:
                state.merge_from(right, right)
            return left_taint or right_taint, left_continues or right_continues
        self._process_statement(statement, state, collect_findings=False)
        return False, True

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
                self._process_return_redirect(statement, state)
            return

        if statement.type == "if_statement":
            self._process_if_statement(
                statement, state, collect_findings=collect_findings
            )
            return

        if statement.type in {"switch_expression", "switch_statement"}:
            self._process_switch(statement, state, collect_findings=collect_findings)
            return

        if statement.type == "enhanced_for_statement":
            self._process_enhanced_for(
                statement, state, collect_findings=collect_findings
            )
            return

        for child in statement.children:
            if not child.is_named:
                continue
            if child.type.endswith("_statement") or child.type in {
                "block",
                "local_variable_declaration",
            }:
                self._process_statement(child, state, collect_findings=collect_findings)
            elif child.type in {"catch_clause", "finally_clause"}:
                for part in child.named_children:
                    if part.type == "block":
                        self._process_statement(
                            part, state, collect_findings=collect_findings
                        )
            elif child.type == "resource_specification":
                for resource in child.named_children:
                    self._process_resource(
                        resource, state, collect_findings=collect_findings
                    )
            elif child.type not in {"line_comment", "block_comment"}:
                self._scan_expression_effects(
                    child, state, collect_findings=collect_findings
                )
                if child.type == "parenthesized_expression":
                    self._apply_embedded_assignments(child, state)

    def _string_builder_root(self, call, state: JavaFlowState) -> str | None:
        """``sql.append(" WHERE n = '").append(name)`` taints ``sql``: walk the
        append chain down to a StringBuilder/StringBuffer/StringJoiner local."""
        node = call
        while node is not None and node.type == "method_invocation":
            if self._call_name(node) not in {"append", "insert", "add"}:
                return None
            if not self._call_args(node):
                return None
            node = self._strip_parentheses(node.child_by_field_name("object"))
        if node is None or node.type != "identifier":
            return None
        name = self._text(node)
        if state.object_types.get(name) in {
            "StringBuilder",
            "StringBuffer",
            "StringJoiner",
        }:
            return name
        return None

    def _apply_embedded_assignments(self, node, state: JavaFlowState) -> None:
        """``if ((cmd = request.getParameter("c")) != null)`` and
        ``while ((line = reader.readLine()) != null)`` assign in a condition."""
        if node is None:
            return
        stack = [node]
        assignments = []
        while stack:
            current = stack.pop()
            if current.type == "lambda_expression":
                continue
            if current.type == "assignment_expression":
                assignments.append(current)
            stack.extend(reversed(current.children))
        for assignment in assignments:
            self._process_assignment(assignment, state, collect_findings=False)

    def _process_resource(
        self, resource, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        if resource.type != "resource":
            return
        name_node = resource.child_by_field_name("name")
        value_node = resource.child_by_field_name("value")
        if value_node is None:
            self._scan_expression_effects(
                resource, state, collect_findings=collect_findings
            )
            return
        self._scan_expression_effects(
            value_node, state, collect_findings=collect_findings
        )
        if name_node is None:
            return
        type_node = resource.child_by_field_name("type")
        raw_type = self._text(type_node)
        self._assign_var(
            self._text(name_node),
            value_node,
            state,
            declared_type=self._simple_name(raw_type) or None,
            source_type=raw_type or None,
        )

    def _process_expression_statement(
        self, expr, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        if expr.type == "assignment_expression":
            self._process_assignment(expr, state, collect_findings=collect_findings)
            return
        self._scan_expression_effects(expr, state, collect_findings=collect_findings)

    def _process_variable_declarator(
        self, declarator, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        name_node = declarator.child_by_field_name("name")
        value_node = declarator.child_by_field_name("value")
        if name_node is None:
            return
        name = self._text(name_node)
        declared_type = self._declared_type_for_declarator(declarator)
        declaration_type = declarator.parent.child_by_field_name("type")
        source_type = self._text(declaration_type) or None
        if value_node is None:
            if declared_type:
                state.object_types[name] = declared_type
            if source_type:
                state.source_types[name] = source_type
            return
        self._scan_expression_effects(
            value_node, state, collect_findings=collect_findings
        )
        self._assign_var(
            name,
            value_node,
            state,
            declared_type=declared_type,
            source_type=source_type,
        )

    def _process_assignment(
        self, assignment, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        left = assignment.child_by_field_name("left")
        right = assignment.child_by_field_name("right")
        if right is None:
            return
        self._scan_expression_effects(right, state, collect_findings=collect_findings)
        if left is not None and left.type != "identifier":
            self._invalidate_property_references(right, state)
        name = self._assignment_target_name(left)
        if name:
            self._assign_var(name, right, state)
            if self._text(assignment.child_by_field_name("operator")) != "=":
                # Compound assignments are not plain RHS replacement. Until
                # their full value is modeled, do not use it as crypto proof.
                state.constants.pop(name, None)
                state.crypto_constants.pop(name, None)

    def _assign_var(
        self,
        name: str,
        value_node,
        state: JavaFlowState,
        *,
        declared_type: str | None = None,
        source_type: str | None = None,
    ) -> None:
        state.guarded_path_vars.discard(name)
        state.guarded_url_vars.discard(name)
        state.guarded_redirect_vars.discard(name)
        state.pending_path_objects.pop(name, None)

        crypto_value = self._crypto_algorithm(value_node, state)
        state.crypto_constants.pop(name, None)
        if isinstance(crypto_value, str) and (
            len(state.crypto_constants) < MAX_CONSTANT_ENTRIES
            and len(crypto_value) <= MAX_CONSTANT_STRING_CHARS
            and sum(map(len, state.crypto_constants.values())) + len(crypto_value)
            <= MAX_CONSTANT_STORE_CHARS
        ):
            state.crypto_constants[name] = crypto_value

        self._assign_properties(name, value_node, state)
        const_value = self._eval_constant(value_node, state)
        self._store_constant(name, const_value, state)

        object_type = self._object_creation_type(value_node)
        if object_type:
            source_type = self._text(value_node.child_by_field_name("type"))
        elif value_node.type == "identifier":
            source_type = state.source_types.get(self._text(value_node), source_type)
        if source_type:
            state.source_types[name] = source_type
        else:
            state.source_types.pop(name, None)
        builder_type = self._http_request_builder_type(value_node)
        if declared_type == "var":
            declared_type = self._expr_type(value_node, state)
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
        elif builder_type:
            state.object_types[name] = builder_type
        elif declared_type:
            state.object_types[name] = declared_type
        else:
            state.object_types.pop(name, None)

        if self._process_builder_chain_tainted(value_node, state):
            state.tainted_process_builders.add(name)
        elif not object_type:
            state.tainted_process_builders.discard(name)
        self._assign_xml_object(name, value_node, state)
        self._assign_deser_object(name, value_node, state)
        if self._url_value_fixes_host(value_node, state):
            state.fixed_host_vars.add(name)
        else:
            state.fixed_host_vars.discard(name)
        if self._redirect_view_tainted(value_node, state):
            state.redirect_view_vars.add(name)
        else:
            state.redirect_view_vars.discard(name)
        if self._expr_facts(value_node, state).tainted and not self._ldap_value_tainted(
            value_node, state
        ):
            state.ldap_safe_vars.add(name)
        else:
            state.ldap_safe_vars.discard(name)

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
                source_name = self._first_receiver_for_call(
                    value_node, "getCanonicalPath"
                )
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
        self._forget_property_effects(node.child_by_field_name("condition"), state)
        guarded_after = self._path_guards_from_if(node, state)
        guarded_urls_after = self._url_guards_from_if(node, state)
        guarded_redirects_after = self._redirect_guards_from_if(node, state)
        condition = node.child_by_field_name("condition")
        if collect_findings and condition is not None:
            self._scan_condition_sinks(condition, state)
        self._apply_embedded_assignments(condition, state)
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
        state.guarded_url_vars.update(guarded_urls_after)
        state.guarded_redirect_vars.update(guarded_redirects_after)

    def _process_enhanced_for(
        self, node, state: JavaFlowState, *, collect_findings: bool
    ) -> None:
        name = None
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is not None:
            name = self._text(name_node)
        if collect_findings and value is not None:
            self._scan_condition_sinks(value, state)
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
            child
            for child in body.children
            if child.type == "switch_block_statement_group"
        ]
        if not groups:
            return

        condition_value = self._eval_constant(
            node.child_by_field_name("condition"), state
        )
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
                        if child.type in {
                            "break_statement",
                            "return_statement",
                            "throw_statement",
                        }:
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
            for label in [
                child for child in group.children if child.type == "switch_label"
            ]:
                if self._text(label).lstrip().startswith("default"):
                    default_index = index
                    continue
                label_expr = self._first_expression_child(label)
                label_value = self._eval_constant(label_expr, state)
                if label_value == condition_value:
                    return index
        return default_index

    def _scan_expression_effects(
        self, node, state: JavaFlowState, *, collect_findings: bool = True
    ) -> None:
        # Do not claim constants across nested mutations: Java evaluates
        # arguments before their enclosing call, whereas this shared walker is
        # sink-oriented. Keep this slice conservative rather than simulating
        # argument snapshots or changing all existing taint evaluation order.
        uncertain_properties = self._forget_property_effects(
            node, state, skip_root=True
        )
        for child in self._iter_nodes(node):
            if child.type == "method_invocation":
                self._process_method_effects(child, state)
                if collect_findings:
                    self._process_method_sinks(child, state)
            elif child.type == "object_creation_expression":
                for arg in self._object_creation_args(child):
                    self._invalidate_property_references(arg, state)
                if collect_findings:
                    self._process_constructor_sinks(child, state)
                    self._process_weak_random(child, state)
        for object_id in uncertain_properties:
            state.property_values.pop(object_id, None)

    def _process_method_effects(self, call, state: JavaFlowState) -> None:
        method = self._call_name(call)
        receiver = self._receiver_name(call)
        args = self._call_args(call)

        self._process_property_effects(call, state)
        self._process_xml_effects(call, state)
        self._process_deser_effects(call, state)

        builder = self._string_builder_root(call, state)
        if builder is not None:
            if self._args_tainted(args, state):
                state.tainted_vars.add(builder)
                state.xss_safe_vars.discard(builder)
                if method == "insert":
                    state.fixed_host_vars.discard(builder)
            return

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

        if (
            method == "getInstance"
            and args
            and args[0].type != "string_literal"
            and self._matches_java_type(
                self._receiver_text(call), "java.security.MessageDigest"
            )
            and not self._crypto_receiver_shadowed(call)
        ):
            algorithm = self._crypto_algorithm(args[0], state)
            normalized = algorithm.upper() if isinstance(algorithm, str) else None
            if normalized in {"MD5", "SHA1", "SHA-1"}:
                md5 = normalized == "MD5"
                self._add_finding(
                    "SKY-D207" if md5 else "SKY-D208",
                    "MEDIUM",
                    f"Weak hash algorithm {'MD5' if md5 else 'SHA-1'}. Use SHA-256 or better.",
                    line,
                    category="weak_hash",
                    cwe="CWE-328",
                )

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

        if method == "start" and self._process_builder_chain_tainted(
            call.child_by_field_name("object"), state
        ):
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

        receiver_type = self._call_receiver_type(call, state)
        if self._is_sql_sink(call, receiver_type) and self._sink_args_tainted(
            args, self._sql_sink_positions(method), state
        ):
            self._add_finding(
                "SKY-D211",
                "CRITICAL",
                "SQL query uses servlet-controlled data. Use parameterized queries with fixed SQL.",
                line,
                cwe="CWE-89",
            )

        ldap_positions = self._typed_sink_positions(
            models.LDAP_SEARCH_SINKS, receiver_type, method
        )
        if ldap_positions and any(
            position < len(args) and self._ldap_value_tainted(args[position], state)
            for position in ldap_positions
        ):
            self._add_finding(
                "SKY-D239",
                "CRITICAL",
                "LDAP query uses servlet-controlled data. Escape LDAP filter and DN values or use a fixed filter with encoded arguments.",
                line,
                category="ldap_injection",
                cwe="CWE-90",
            )

        xpath_positions = self._typed_sink_positions(
            models.XPATH_SINKS, receiver_type, method
        )
        if (
            not xpath_positions
            and method == "createXPath"
            and receiver_type == "DocumentHelper"
        ):
            xpath_positions = (0,)
        if xpath_positions and self._sink_args_tainted(args, xpath_positions, state):
            self._add_finding(
                "SKY-D229",
                "CRITICAL",
                "XPath expression uses servlet-controlled data. Use fixed expressions with XPath variables or strict allowlists.",
                line,
                category="xpath_injection",
                cwe="CWE-643",
            )

        self._process_expression_sinks(call, receiver_type, state)
        self._process_template_sinks(call, receiver_type, state)
        self._process_xml_sinks(call, state)
        self._process_deser_sinks(call, receiver_type, state)
        self._process_redirect_call_sinks(call, receiver_type, state)
        self._process_ssrf_call_sinks(call, receiver_type, state)

        if (
            method == "transferTo"
            and receiver_type in models.UPLOAD_PARAM_TYPES
            and self._path_sink_tainted(call, args, (0,), state)
        ):
            self._add_finding(
                "SKY-D215",
                "HIGH",
                "Servlet-controlled path reaches a filesystem sink without canonical path validation.",
                line,
                cwe="CWE-22",
            )

        if (
            method in XSS_WRITER_METHODS
            and self._receiver_chain_has_call(call, "getWriter")
            and any(
                self._expr_facts(arg, state).tainted
                and not self._expr_facts(arg, state).xss_safe
                for arg in args
            )
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
                "SKY-D254",
                "HIGH",
                "Servlet-controlled data crosses into HTTP session state.",
                line,
                category="trust_boundary",
                cwe="CWE-501",
            )

        if self._is_send_redirect_sink(call, state) and self._redirect_sink_tainted(
            args, state
        ):
            self._add_finding(
                "SKY-D230",
                "HIGH",
                "Servlet redirect uses request-controlled data. Validate redirect targets against a relative-path or host allowlist.",
                line,
                cwe="CWE-601",
            )

        if self._is_url_network_sink(call, state):
            self._add_finding(
                "SKY-D216",
                "CRITICAL",
                "Request-controlled URL reaches a network client. Validate scheme and host against an allowlist.",
                line,
                cwe="CWE-918",
            )

        builder_url_arg_positions = (
            HTTP_REQUEST_BUILDER_METHODS[method]
            if method in HTTP_REQUEST_BUILDER_METHODS
            else ()
        )
        if self._is_http_request_builder_sink(
            call, state
        ) and self._url_sink_args_tainted(args, builder_url_arg_positions, state):
            self._add_finding(
                "SKY-D216",
                "CRITICAL",
                "Request-controlled URL reaches Java HTTP request construction. Validate scheme and host against an allowlist.",
                line,
                cwe="CWE-918",
            )

        if self._is_rest_template_sink(call, state) and self._url_sink_args_tainted(
            args, REST_TEMPLATE_URL_METHODS.get(method, ()), state
        ):
            self._add_finding(
                "SKY-D216",
                "CRITICAL",
                "Request-controlled URL reaches RestTemplate. Validate scheme and host against an allowlist.",
                line,
                cwe="CWE-918",
            )

        if self._is_files_path_sink(call):
            positions = FILES_PATH_METHODS.get(method, ())
            if method == "copy" and args and self._is_stream_value(args[0], state):
                positions = (1,)
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
        line = self._line(node)
        if class_name in models.SSRF_CONSTRUCTORS and self._url_sink_args_tainted(
            args, models.SSRF_CONSTRUCTORS[class_name], state
        ):
            self._add_finding(
                "SKY-D216",
                "CRITICAL",
                "Request-controlled URL reaches an HTTP client request. Validate scheme and host against an allowlist.",
                line,
                cwe="CWE-918",
            )
        if (
            class_name == "RedirectView"
            and args
            and self._redirect_target_tainted(args[0], state)
        ) or (
            class_name == "ModelAndView"
            and args
            and self._redirect_view_tainted(args[0], state)
        ):
            self._report_spring_redirect(line)
        if (
            class_name in models.TEMPLATE_CONSTRUCTORS
            and self._has_import_evidence(class_name)
            and self._sink_args_tainted(
                args, models.TEMPLATE_CONSTRUCTORS[class_name], state
            )
        ):
            self._report_template_injection(line)
        if class_name == "ObjectInputStream":
            self._report_object_input_stream(node, args, state)
        if class_name == "XMLDecoder" and args and args[0].type != "string_literal":
            severity = "HIGH"
            if self._args_tainted(args, state) or any(
                self._is_network_stream(arg, state) for arg in args
            ):
                severity = "CRITICAL"
            self._add_finding(
                "SKY-D233",
                severity,
                "XMLDecoder can call arbitrary methods while reading XML. Do not decode untrusted input; use a data-only format.",
                line,
                cwe="CWE-502",
            )

    def _scan_condition_sinks(self, node, state: JavaFlowState) -> None:
        for child in self._iter_nodes(node):
            if child.type == "method_invocation":
                self._process_method_sinks(child, state)
            elif child.type == "object_creation_expression":
                self._process_constructor_sinks(child, state)

    def _process_return_redirect(self, statement, state: JavaFlowState) -> None:
        expr = self._first_expression_child(statement)
        if expr is not None and self._redirect_view_tainted(expr, state):
            self._report_spring_redirect(self._line(statement))

    def _report_spring_redirect(self, line: int) -> None:
        self._add_finding(
            "SKY-D230",
            "HIGH",
            "Redirect target uses request-controlled data. Validate redirect targets against a relative-path or host allowlist.",
            line,
            cwe="CWE-601",
        )

    def _report_template_injection(self, line: int) -> None:
        self._add_finding(
            "SKY-D349",
            "CRITICAL",
            "Template source is built from request-controlled data. Render fixed templates and pass input only as model values.",
            line,
            category="template_injection",
            cwe="CWE-1336",
        )

    def _process_builder_chain_tainted(self, node, state: JavaFlowState) -> bool:
        node = self._strip_parentheses(node)
        while node is not None:
            if node.type == "identifier":
                return self._text(node) in state.tainted_process_builders
            if node.type == "object_creation_expression":
                if self._object_creation_type(node) != "ProcessBuilder":
                    return False
                args = self._object_creation_args(node)
                return self._args_tainted(args, state) or self._args_mention_names(
                    args, state.tainted_collections
                )
            if node.type != "method_invocation":
                return False
            if self._call_name(node) == "command":
                args = self._call_args(node)
                if self._args_tainted(args, state) or self._args_mention_names(
                    args, state.tainted_collections
                ):
                    return True
            node = self._strip_parentheses(node.child_by_field_name("object"))
        return False

    def _call_receiver_type(self, call, state: JavaFlowState) -> str | None:
        receiver = call.child_by_field_name("object")
        if receiver is None:
            return None
        return self._expr_type(receiver, state)

    def _expr_type(self, node, state: JavaFlowState) -> str | None:
        node = self._strip_parentheses(node)
        if node is None:
            return None
        if node.type == "identifier":
            name = self._text(node)
            if name in state.object_types:
                return state.object_types[name]
            if self._is_local_name(node, name):
                return None
            field_type = self._field_type(node, name)
            if field_type is not None:
                return field_type
            if name[:1].isupper():
                return name
            return None
        if node.type == "field_access":
            owner = node.child_by_field_name("object")
            field_node = node.child_by_field_name("field")
            if owner is not None and owner.type == "this" and field_node is not None:
                return self._field_type(node, self._text(field_node))
            last = self._text(node).rsplit(".", 1)[-1]
            if last[:1].isupper() and self._text(owner)[:1].islower():
                return last
            return None
        if node.type == "object_creation_expression":
            return self._object_creation_type(node)
        if node.type == "cast_expression":
            return (
                self._simple_name(self._text(node.child_by_field_name("type"))) or None
            )
        if node.type == "method_invocation":
            method = self._call_name(node)
            args = self._call_args(node)
            if method == "unwrap" and args and args[0].type == "class_literal":
                return self._simple_name(self._text(args[0]).rsplit(".class", 1)[0])
            return models.CALL_RESULT_TYPES.get(method)
        return None

    def _chain_root(self, node):
        node = self._strip_parentheses(node)
        while node is not None and node.type == "method_invocation":
            receiver = node.child_by_field_name("object")
            if receiver is None:
                return node
            node = self._strip_parentheses(receiver)
        return node

    def _ldap_value_tainted(self, node, state: JavaFlowState, depth: int = 0) -> bool:
        """Request data that reaches an LDAP query unencoded. Encoders
        (``LdapEncoder.filterEncode``, ``Rdn.escapeValue``, UnboundID
        ``Filter.encodeValue``/``createEqualityFilter``), Spring LDAP filter
        objects other than ``HardcodedFilter``, and ``LdapQueryBuilder``
        ``where(...).is(...)`` chains escape the value."""
        node = self._strip_parentheses(node)
        if node is None or depth > 16 or not self._expr_facts(node, state).tainted:
            return False
        if node.type == "identifier":
            return self._text(node) not in state.ldap_safe_vars
        if node.type == "binary_expression" and self._binary_operator(node) == "+":
            return any(
                self._ldap_value_tainted(operand, state, depth + 1)
                for operand in self._concat_operands(node)
            )
        if node.type != "method_invocation":
            return True
        if self._call_name(node) in LDAP_ENCODER_METHODS:
            return False
        if any(
            child.type == "object_creation_expression"
            and self._object_creation_type(child) == "HardcodedFilter"
            and self._args_tainted(self._object_creation_args(child), state)
            for child in self._iter_nodes(node)
        ):
            return True
        root = self._chain_root(node)
        if (
            root is not None
            and root.type == "object_creation_expression"
            and (self._object_creation_type(root) or "").endswith("Filter")
            and self._call_name(node) in {"encode", "toString"}
        ):
            return False
        query_builder = (
            root is not None
            and root.type == "method_invocation"
            and self._call_name(root) == "query"
        ) or (root is not None and self._text(root) == "LdapQueryBuilder")
        if query_builder:
            if not any(
                self._call_name(call) == "filter"
                and self._args_tainted(self._call_args(call), state)
                for call in self._method_calls(node)
            ):
                return False
        return True

    def _typed_sink_positions(
        self, table: dict, receiver_type: str | None, method: str
    ) -> tuple[int, ...]:
        if receiver_type is None:
            return ()
        positions = table.get(receiver_type, {}).get(method, ())
        if positions and not self._has_import_evidence(receiver_type):
            return ()
        return positions

    def _is_sql_sink(self, call, receiver_type: str | None) -> bool:
        method = self._call_name(call)
        if method in models.SQL_DISTINCT_SINKS:
            return True
        if method not in models.SQL_TYPED_SINKS:
            return False
        if receiver_type in models.SQL_RECEIVER_TYPES:
            return True
        if receiver_type is not None:
            return False
        receiver = self._receiver_name(call)
        return receiver is not None and receiver.lower() in models.SQL_RECEIVER_NAMES

    def _sql_sink_positions(self, method: str) -> tuple[int, ...]:
        if method in models.SQL_DISTINCT_SINKS:
            return models.SQL_DISTINCT_SINKS[method]
        return models.SQL_TYPED_SINKS.get(method, ())

    def _process_expression_sinks(
        self, call, receiver_type: str | None, state: JavaFlowState
    ) -> None:
        method = self._call_name(call)
        positions = self._typed_sink_positions(
            models.EXPRESSION_SINKS, receiver_type, method
        )
        args = self._call_args(call)
        if not positions or not self._sink_args_tainted(args, positions, state):
            return
        if method in {"parseExpression", "parseRaw"} and self._spel_evaluated_safely(
            call
        ):
            return
        if receiver_type in SCRIPT_RECEIVER_TYPES:
            message = "Script source is built from request-controlled data. Never evaluate input as code."
            cwe = "CWE-94"
        elif method in {
            "lookup",
            "lookupLink",
            "doLookup",
            "lookupContext",
            "findByDn",
        }:
            message = "JNDI lookup name uses request-controlled data, which can load remote classes. Look up only fixed names."
            cwe = "CWE-74"
        else:
            message = "Expression language input is request-controlled. Evaluate only fixed expressions; pass input as variables."
            cwe = "CWE-917"
        self._add_finding(
            "SKY-D237",
            "CRITICAL",
            message,
            self._line(call),
            category="expression_injection",
            cwe=cwe,
        )

    def _spel_evaluated_safely(self, call) -> bool:
        """CodeQL's SpEL barrier: the parsed expression is only evaluated with
        a SimpleEvaluationContext, which has no type references or
        constructors. A no-argument getValue() uses the standard context."""
        parent = call.parent
        if (
            parent is not None
            and parent.type == "method_invocation"
            and self._same_node(parent.child_by_field_name("object"), call)
        ):
            return self._call_name(
                parent
            ) in SPEL_EVALUATION_METHODS and self._is_simple_evaluation_context(parent)
        name = None
        if parent is not None and parent.type == "variable_declarator":
            name_node = parent.child_by_field_name("name")
            if name_node is not None:
                name = self._text(name_node)
        if name is None:
            return False
        method = self._enclosing_method(call)
        if method is None:
            return False
        uses = [
            node
            for node in self._iter_nodes(method)
            if node.type == "identifier" and self._text(node) == name
        ]
        evaluations = []
        for use in uses:
            if self._same_node(use, parent.child_by_field_name("name")):
                continue
            owner = use.parent
            if (
                owner is None
                or owner.type != "method_invocation"
                or not self._same_node(owner.child_by_field_name("object"), use)
                or self._call_name(owner) not in SPEL_EVALUATION_METHODS
            ):
                return False
            evaluations.append(owner)
        return bool(evaluations) and all(
            self._is_simple_evaluation_context(evaluation) for evaluation in evaluations
        )

    def _is_simple_evaluation_context(self, evaluation) -> bool:
        args = self._call_args(evaluation)
        if not args:
            return False
        context = self._strip_parentheses(args[0])
        if context is None:
            return False
        if context.type != "identifier":
            return self._text(context).startswith("SimpleEvaluationContext.")
        name = self._text(context)
        method = self._enclosing_method(evaluation)
        if method is None:
            return False
        declared = False
        for node in self._iter_nodes(method):
            if node.type == "assignment_expression":
                if (
                    self._assignment_target_name(node.child_by_field_name("left"))
                    == name
                ):
                    return False
            if node.type != "variable_declarator":
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None or self._text(name_node) != name:
                continue
            declaration = node.parent
            type_text = ""
            if declaration is not None:
                type_text = self._text(declaration.child_by_field_name("type"))
            value_text = self._text(node.child_by_field_name("value"))
            if self._simple_name(
                type_text
            ) != "SimpleEvaluationContext" and not value_text.startswith(
                "SimpleEvaluationContext."
            ):
                return False
            declared = True
        return declared

    def _process_template_sinks(
        self, call, receiver_type: str | None, state: JavaFlowState
    ) -> None:
        positions = self._typed_sink_positions(
            models.TEMPLATE_SINKS, receiver_type, self._call_name(call)
        )
        if positions and self._sink_args_tainted(
            self._call_args(call), positions, state
        ):
            self._report_template_injection(self._line(call))

    def _process_redirect_call_sinks(
        self, call, receiver_type: str | None, state: JavaFlowState
    ) -> None:
        method = self._call_name(call)
        args = self._call_args(call)
        target = None
        view = None
        if method in {"setHeader", "addHeader"} and len(args) >= 2:
            header = self._string_literal_value(args[0])
            if (
                header is not None
                and header.lower() == "location"
                and (
                    receiver_type in RESPONSE_TYPES
                    or self._receiver_name(call) in {"response", "resp", "res"}
                )
            ):
                target = args[1]
        elif method == "location" and args and self._is_response_builder_chain(call):
            target = args[0]
        elif method == "setLocation" and args and receiver_type == "HttpHeaders":
            target = args[0]
        elif method in {"seeOther", "temporaryRedirect"} and args:
            if receiver_type == "Response":
                target = args[0]
        elif method == "setUrl" and args and receiver_type == "RedirectView":
            target = args[0]
        elif method == "setViewName" and args and receiver_type == "ModelAndView":
            view = args[0]
        if (target is not None and self._redirect_target_tainted(target, state)) or (
            view is not None and self._redirect_view_tainted(view, state)
        ):
            self._report_spring_redirect(self._line(call))

    def _is_response_builder_chain(self, call) -> bool:
        root = self._chain_root(call.child_by_field_name("object"))
        if root is None or root.type not in {"identifier", "field_access"}:
            return False
        return self._simple_name(self._text(root)) in {"ResponseEntity", "Response"}

    def _redirect_target_tainted(self, node, state: JavaFlowState) -> bool:
        node = self._strip_parentheses(node)
        if node is None or not self._expr_facts(node, state).tainted:
            return False
        if self._url_value_fixes_host(node, state):
            return False
        names = self._tainted_identifiers(node, state)
        return not (names and names <= state.guarded_redirect_vars)

    def _redirect_view_tainted(self, node, state: JavaFlowState) -> bool:
        node = self._strip_parentheses(node)
        if node is None:
            return False
        if node.type == "identifier":
            return self._text(node) in state.redirect_view_vars
        operands = self._concat_operands(node)
        if len(operands) < 2:
            return False
        head = self._eval_constant(operands[0], state)
        if not isinstance(head, str):
            return False
        head = head.lstrip()
        prefix = next(
            (item for item in models.REDIRECT_PREFIXES if head.startswith(item)), None
        )
        if prefix is None:
            return False
        fixed = head[len(prefix) :]
        for operand in operands[1:]:
            if self._expr_facts(operand, state).tainted:
                if models.url_prefix_fixes_host(fixed):
                    return False
                if self._url_value_fixes_host(operand, state):
                    return False
                names = self._tainted_identifiers(operand, state)
                return not (names and names <= state.guarded_redirect_vars)
            constant = self._eval_constant(operand, state)
            if isinstance(constant, str):
                fixed += constant
            else:
                fixed += "x"
        return False

    def _concat_operands(self, node) -> list:
        node = self._strip_parentheses(node)
        if (
            node is not None
            and node.type == "binary_expression"
            and self._binary_operator(node) == "+"
        ):
            return self._concat_operands(
                node.child_by_field_name("left")
            ) + self._concat_operands(node.child_by_field_name("right"))
        return [node]

    def _url_value_fixes_host(self, node, state: JavaFlowState, depth: int = 0) -> bool:
        node = self._strip_parentheses(node)
        if node is None or depth > 16:
            return False
        if node.type == "string_literal":
            value = self._string_literal_value(node)
            return value is not None and models.url_prefix_fixes_host(value)
        if node.type == "identifier":
            if self._text(node) in state.fixed_host_vars:
                return True
            value = state.constants.get(self._text(node))
            return isinstance(value, str) and models.url_prefix_fixes_host(value)
        if node.type == "binary_expression" and self._binary_operator(node) == "+":
            prefix = ""
            for operand in self._concat_operands(node):
                if self._expr_facts(operand, state).tainted:
                    return models.url_prefix_fixes_host(
                        prefix
                    ) or self._url_value_fixes_host(operand, state, depth + 1)
                constant = self._eval_constant(operand, state)
                if isinstance(constant, str):
                    prefix += constant
                else:
                    prefix += "x"
                if models.url_prefix_fixes_host(prefix):
                    return True
            return False
        if node.type == "object_creation_expression":
            args = self._object_creation_args(node)
            if (
                self._object_creation_type(node)
                in {"URI", "URL", "StringBuilder", "StringBuffer"}
                and len(args) == 1
            ):
                return self._url_value_fixes_host(args[0], state, depth + 1)
            return False
        if node.type == "method_invocation":
            method = self._call_name(node)
            args = self._call_args(node)
            if method == "format" and args:
                pattern = self._string_literal_value(args[0])
                return pattern is not None and models.url_prefix_fixes_host(
                    pattern.split("%", 1)[0]
                )
            if method in {"create", "fromHttpUrl", "fromUriString", "parse"} and args:
                return self._url_value_fixes_host(args[0], state, depth + 1)
            if method in {
                "toString",
                "trim",
                "strip",
                "toURI",
                "toUri",
                "toURL",
                "toUriString",
                "build",
                "encode",
                "append",
            }:
                return self._url_value_fixes_host(
                    node.child_by_field_name("object"), state, depth + 1
                )
        return False

    def _process_ssrf_call_sinks(
        self, call, receiver_type: str | None, state: JavaFlowState
    ) -> None:
        method = self._call_name(call)
        args = self._call_args(call)
        positions: tuple[int, ...] = ()
        if method == "url" and self._is_okhttp_builder_chain(call, state):
            positions = (0,)
        elif method in {"uri", "baseUrl"}:
            root_type = self._expr_type(
                self._chain_root(call.child_by_field_name("object")), state
            )
            if root_type in models.WEB_CLIENT_TYPES:
                positions = (0,)
        else:
            positions = self._typed_sink_positions(
                models.SSRF_STATIC_SINKS, receiver_type, method
            )
        if (
            positions
            and args
            and args[0].type not in {"lambda_expression", "method_reference"}
            and self._url_sink_args_tainted(args, positions, state)
        ):
            self._add_finding(
                "SKY-D216",
                "CRITICAL",
                "Request-controlled URL reaches an HTTP client request. Validate scheme and host against an allowlist.",
                self._line(call),
                cwe="CWE-918",
            )

    def _is_okhttp_builder_chain(self, call, state: JavaFlowState) -> bool:
        root = self._chain_root(call.child_by_field_name("object"))
        if root is None:
            return False
        if root.type == "object_creation_expression":
            raw = self._text(root.child_by_field_name("type"))
        elif root.type == "identifier":
            raw = state.source_types.get(self._text(root), "")
        else:
            return False
        return raw == "Request.Builder" or raw.endswith(".Request.Builder")

    def _report_object_input_stream(self, node, args: list, state) -> None:
        line = self._line(node)
        if self._object_stream_filtered(node):
            self._add_finding(
                "SKY-D204",
                "MEDIUM",
                "ObjectInputStream deserializes with a class filter. Confirm the filter allows only expected classes.",
                line,
                cwe="CWE-502",
            )
            return
        if self._args_tainted(args, state) or any(
            self._is_network_stream(arg, state) for arg in args
        ):
            self._add_finding(
                "SKY-D204",
                "CRITICAL",
                "ObjectInputStream deserializes request or network data, which can run code. Use a data-only format or an ObjectInputFilter allowlist.",
                line,
                cwe="CWE-502",
            )
            return
        self._add_finding(
            "SKY-D204",
            "HIGH",
            "ObjectInputStream deserializes data without a class filter. Use a data-only format or set an ObjectInputFilter allowlist.",
            line,
            cwe="CWE-502",
        )

    def _object_stream_filtered(self, node) -> bool:
        for child in node.children:
            if child.type == "class_body" and any(
                member.type == "method_declaration"
                and self._method_name(member) == "resolveClass"
                for member in child.named_children
            ):
                return True
        for call in self._method_calls(self.root_node):
            if self._call_name(call) in {"setSerialFilter", "setSerialFilterFactory"}:
                return True
        parent = node.parent
        if parent is None or parent.type not in {"variable_declarator", "resource"}:
            return False
        name_node = parent.child_by_field_name("name")
        method = self._enclosing_method(node)
        if name_node is None or method is None:
            return False
        name = self._text(name_node)
        return any(
            self._call_name(call) == "setObjectInputFilter"
            and self._receiver_name(call) == name
            for call in self._method_calls(method)
        )

    def _is_network_stream(self, node, state: JavaFlowState) -> bool:
        for call in self._method_calls(node):
            if self._call_name(call) != "getInputStream":
                continue
            receiver = self._strip_parentheses(call.child_by_field_name("object"))
            if receiver is None:
                continue
            if (
                receiver.type == "method_invocation"
                and self._call_name(receiver) == "accept"
            ):
                return True
            if self._expr_type(receiver, state) in models.SOCKET_TYPES:
                return True
        return False

    def _assign_deser_object(self, name: str, value_node, state: JavaFlowState) -> None:
        status = self._deser_status(value_node, state)
        if status is None:
            state.deser_objects.pop(name, None)
        else:
            state.deser_objects[name] = status

    def _deser_status(self, node, state: JavaFlowState) -> str | None:
        node = self._strip_parentheses(node)
        if node is None:
            return None
        if node.type == "identifier":
            name = self._text(node)
            if name in state.deser_objects:
                return state.deser_objects[name]
            if self._is_local_name(node, name) or self._field_type(node, name) not in {
                "XStream",
                "Yaml",
            }:
                return None
            return self._field_deser_status(node, name)
        if node.type == "field_access":
            owner = node.child_by_field_name("object")
            field_node = node.child_by_field_name("field")
            if owner is None or owner.type != "this" or field_node is None:
                return None
            name = self._text(field_node)
            if self._field_type(node, name) not in {"XStream", "Yaml"}:
                return None
            return self._field_deser_status(node, name)
        if node.type != "object_creation_expression":
            return None
        class_name = self._object_creation_type(node)
        if class_name == "XStream":
            return "xstream:open"
        if class_name == "Yaml":
            if self._yaml_constructor_safe(node, state):
                return "yaml:safe"
            return "yaml:open"
        return None

    def _yaml_constructor_safe(self, node, state: JavaFlowState) -> bool:
        for arg in self._object_creation_args(node):
            arg = self._strip_parentheses(arg)
            raw = None
            if arg is not None and arg.type == "object_creation_expression":
                raw = self._text(arg.child_by_field_name("type"))
            elif arg is not None and arg.type == "identifier":
                raw = state.source_types.get(self._text(arg))
            if raw and self._resolves_to(
                raw, "org.yaml.snakeyaml.constructor.SafeConstructor"
            ):
                return True
        return False

    def _field_deser_status(self, node, name: str) -> str | None:
        class_node = self._enclosing_class(node)
        if class_node is None:
            return None
        key = (class_node.start_byte, name)
        if key not in self._field_deser_cache:
            self._field_deser_cache[key] = self._class_field_deser_status(
                class_node, name
            )
        return self._field_deser_cache[key]

    def _class_field_deser_status(self, class_node, name: str) -> str | None:
        creations = []
        permitted = False
        any_type = False
        for child in self._iter_nodes(class_node):
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value = child.child_by_field_name("value")
                if (
                    name_node is not None
                    and self._text(name_node) == name
                    and value is not None
                    and child.parent is not None
                    and child.parent.type == "field_declaration"
                ):
                    creations.append(value)
            elif child.type == "assignment_expression":
                target = child.child_by_field_name("left")
                if self._assignment_target_name(target) == name:
                    creations.append(child.child_by_field_name("right"))
            elif child.type == "method_invocation":
                receiver = self._strip_parentheses(child.child_by_field_name("object"))
                receiver_name = self._assignment_target_name(receiver)
                if (
                    receiver_name == name
                    and self._call_name(child) in XSTREAM_PERMISSION_METHODS
                ):
                    if "AnyTypePermission" in self._text(child):
                        any_type = True
                    else:
                        permitted = True
        statuses = set()
        empty = JavaFlowState()
        for creation in creations:
            creation = self._strip_parentheses(creation)
            if creation is None or creation.type != "object_creation_expression":
                continue
            status = self._deser_status(creation, empty)
            if status is not None:
                statuses.add(status)
        if not statuses:
            return None
        if "xstream:open" in statuses:
            if any_type:
                return "xstream:any"
            if permitted:
                return "xstream:allowed"
            return "xstream:open"
        if "yaml:open" in statuses:
            return "yaml:open"
        return statuses.pop()

    def _process_deser_effects(self, call, state: JavaFlowState) -> None:
        method = self._call_name(call)
        if method not in XSTREAM_PERMISSION_METHODS:
            return
        receiver = self._receiver_name(call)
        if method == "setupDefaultSecurity":
            args = self._call_args(call)
            if args and args[0].type == "identifier":
                receiver = self._text(args[0])
        status = state.deser_objects.get(receiver or "")
        if status is None or not status.startswith("xstream:"):
            return
        if "AnyTypePermission" in self._text(call):
            state.deser_objects[receiver] = "xstream:any"
        elif status != "xstream:any":
            state.deser_objects[receiver] = "xstream:allowed"

    def _process_deser_sinks(
        self, call, receiver_type: str | None, state: JavaFlowState
    ) -> None:
        method = self._call_name(call)
        args = self._call_args(call)
        line = self._line(call)
        if method in {"enableDefaultTyping", "enableDefaultTypingAsProperty"}:
            self._add_finding(
                "SKY-D233",
                "HIGH",
                "Jackson default typing lets JSON choose the class to create. Use activateDefaultTyping with an allowlisting PolymorphicTypeValidator.",
                line,
                cwe="CWE-502",
            )
            return
        if (
            method in {"activateDefaultTyping", "activateDefaultTypingAsProperty"}
            and args
            and "LaissezFaireSubTypeValidator" in self._text(args[0])
        ):
            self._add_finding(
                "SKY-D233",
                "HIGH",
                "Jackson default typing with LaissezFaireSubTypeValidator accepts any class. Use a validator that allowlists your own types.",
                line,
                cwe="CWE-502",
            )
            return
        if (
            method == "setRegistrationRequired"
            and args
            and self._eval_constant(args[0], state) is False
        ):
            self._add_finding(
                "SKY-D233",
                "HIGH",
                "Kryo with registration turned off deserializes any class named in the input. Keep registration required and register expected classes.",
                line,
                cwe="CWE-502",
            )
            return
        receiver = call.child_by_field_name("object")
        if receiver is None:
            return
        if method == "fromXML":
            status = self._deser_status(receiver, state)
            tainted = self._args_tainted(args, state)
            if status == "xstream:any":
                severity = "HIGH"
                if tainted:
                    severity = "CRITICAL"
                message = "XStream allows any type (AnyTypePermission), so input XML can create any class. Allow only expected types."
            elif status == "xstream:open":
                severity = "MEDIUM"
                if tainted:
                    severity = "HIGH"
                message = "XStream has no explicit type permissions; before 1.4.18 it deserializes any class. Call addPermission(NoTypePermission.NONE) and allow only expected types."
            else:
                return
            self._add_finding(
                "SKY-D233",
                severity,
                message,
                line,
                cwe="CWE-502",
            )
            return
        if method in {"load", "loadAll", "loadAs"}:
            if self._deser_status(receiver, state) != "yaml:open":
                return
            severity = "MEDIUM"
            if self._args_tainted(args, state):
                severity = "HIGH"
            self._add_finding(
                "SKY-D233",
                severity,
                "SnakeYAML without SafeConstructor builds any class named by a YAML tag before version 2.0. Use new Yaml(new SafeConstructor(new LoaderOptions())).",
                line,
                cwe="CWE-502",
            )

    def _assign_xml_object(self, name: str, value_node, state: JavaFlowState) -> None:
        obj = self._xml_object(value_node, state)
        if obj is None:
            state.xml_objects.pop(name, None)
            return
        kind, settings = obj
        state.xml_objects[name] = (kind, tuple(sorted(settings.items(), key=repr)))

    def _xml_object(self, node, state: JavaFlowState, depth: int = 0):
        node = self._strip_parentheses(node)
        if node is None or depth > 16:
            return None
        if node.type == "identifier":
            entry = state.xml_objects.get(self._text(node))
            if entry is None:
                return None
            return entry[0], dict(entry[1])
        if node.type == "object_creation_expression":
            kind = models.XML_PARSER_CONSTRUCTORS.get(self._object_creation_type(node))
            if kind is None or any(
                child.type == "class_body" for child in node.children
            ):
                return None
            return kind, {}
        if node.type != "method_invocation":
            return None
        method = self._call_name(node)
        receiver = node.child_by_field_name("object")
        if receiver is None:
            return None
        receiver_name = self._simple_name(self._text(receiver))
        if method in models.XML_FACTORY_METHODS:
            kind = models.XML_FACTORY_TYPES.get(receiver_name)
            if kind is None:
                return None
            return kind, {}
        if method == "createXMLReader" and receiver_name == "XMLReaderFactory":
            return "XMLReader", {}
        if method == "createDefault" and receiver_name == "SAXReader":
            return "SAXReader", {
                models.EXTERNAL_GENERAL: False,
                models.EXTERNAL_PARAMETER: False,
                models.LOAD_EXTERNAL_DTD: False,
            }
        base = self._xml_object(receiver, state, depth + 1)
        if base is None:
            return None
        derived = models.XML_DERIVED_OBJECTS.get((base[0], method))
        if derived is None:
            return None
        return derived, base[1]

    def _process_xml_effects(self, call, state: JavaFlowState) -> None:
        if not state.xml_objects:
            return
        method = self._call_name(call)
        receiver = self._receiver_name(call)
        args = self._call_args(call)
        if receiver and receiver in state.xml_objects:
            if method in models.XML_SETTING_METHODS and len(args) >= 2:
                kind, settings = state.xml_objects[receiver]
                key = self._xml_setting_key(args[0], state)
                value = self._xml_setting_value(args[1], state)
                if key is None or value is _UNKNOWN_VALUE:
                    state.xml_objects.pop(receiver, None)
                    return
                updated = dict(settings)
                updated[key] = value
                state.xml_objects[receiver] = (
                    kind,
                    tuple(sorted(updated.items(), key=repr)),
                )
                return
            if method in models.XML_UNKNOWN_CONFIG_METHODS:
                state.xml_objects.pop(receiver, None)
                return
        for index, arg in enumerate(args):
            arg = self._strip_parentheses(arg)
            if arg is not None and arg.type == "identifier":
                name = self._text(arg)
                if name in state.xml_objects:
                    self._apply_xml_helper(call, index, name, state)

    def _apply_xml_helper(
        self, call, index: int, name: str, state: JavaFlowState
    ) -> None:
        helper = self._same_file_method(call)
        if helper is None:
            state.xml_objects.pop(name, None)
            return
        params = [self._param_name(param) for param in self._formal_parameters(helper)]
        if index >= len(params) or not params[index]:
            state.xml_objects.pop(name, None)
            return
        param = params[index]
        body = helper.child_by_field_name("body")
        kind, settings = state.xml_objects[name]
        updated = dict(settings)
        empty = JavaFlowState()
        for inner in self._method_calls(body):
            inner_args = self._call_args(inner)
            mentions = any(
                self._strip_parentheses(arg) is not None
                and self._strip_parentheses(arg).type == "identifier"
                and self._text(self._strip_parentheses(arg)) == param
                for arg in inner_args
            )
            if mentions:
                state.xml_objects.pop(name, None)
                return
            if self._receiver_name(inner) != param:
                continue
            inner_method = self._call_name(inner)
            if inner_method in models.XML_UNKNOWN_CONFIG_METHODS:
                state.xml_objects.pop(name, None)
                return
            if inner_method not in models.XML_SETTING_METHODS or len(inner_args) < 2:
                continue
            key = self._xml_setting_key(inner_args[0], empty)
            value = self._xml_setting_value(inner_args[1], empty)
            if key is None or value is _UNKNOWN_VALUE:
                state.xml_objects.pop(name, None)
                return
            updated[key] = value
        state.xml_objects[name] = (kind, tuple(sorted(updated.items(), key=repr)))

    def _same_file_method(self, call):
        receiver = call.child_by_field_name("object")
        class_name = self._class_name_for_node(call)
        if receiver is not None:
            receiver_text = self._text(receiver)
            if receiver_text != "this" and receiver_text != class_name:
                return None
        if self._methods_by_name is None:
            self._methods_by_name = {}
            for method in self._method_nodes():
                if method.type != "method_declaration":
                    continue
                key = (
                    self._class_name_for_node(method),
                    self._method_name(method) or "",
                    len(self._formal_parameters(method)),
                )
                self._methods_by_name.setdefault(key, []).append(method)
        matches = self._methods_by_name.get(
            (class_name, self._call_name(call), len(self._call_args(call))), []
        )
        if len(matches) != 1:
            return None
        return matches[0]

    def _xml_setting_key(self, node, state: JavaFlowState) -> str | None:
        node = self._strip_parentheses(node)
        if node is None:
            return None
        raw = None
        if node.type == "string_literal":
            raw = self._string_literal_value(node)
        elif node.type == "identifier":
            name = self._text(node)
            value = state.constants.get(name)
            if isinstance(value, str):
                raw = value
            else:
                raw = self._class_string_constant(node, name)
            if raw is None and name in models.XML_SETTING_CONSTANTS:
                if self._has_static_import(name):
                    return models.XML_SETTING_CONSTANTS[name]
        elif node.type == "field_access":
            owner, _, field_name = self._text(node).rpartition(".")
            if owner in models.XML_CONSTANT_OWNERS:
                return models.XML_SETTING_CONSTANTS.get(field_name, field_name)
        if not isinstance(raw, str):
            return None
        return models.XML_SETTING_URIS.get(raw, raw)

    def _xml_setting_value(self, node, state: JavaFlowState):
        node = self._strip_parentheses(node)
        if node is not None and node.type == "field_access":
            text = self._text(node)
            if text in {"Boolean.TRUE", "java.lang.Boolean.TRUE"}:
                return True
            if text in {"Boolean.FALSE", "java.lang.Boolean.FALSE"}:
                return False
        value = self._eval_constant(node, state)
        if value is None:
            return _UNKNOWN_VALUE
        return value

    def _process_xml_sinks(self, call, state: JavaFlowState) -> None:
        receiver = call.child_by_field_name("object")
        if receiver is None:
            return
        if (
            self._call_name(call) == "parseText"
            and self._simple_name(self._text(receiver)) == "DocumentHelper"
        ):
            self._report_dom4j_parse_text(call, state)
            return
        obj = self._xml_object(receiver, state)
        if obj is None:
            return
        kind, settings = obj
        method = self._call_name(call)
        if method not in models.XML_PARSE_SINKS.get(kind, ()):
            return
        args = self._call_args(call)
        if not args:
            return
        if kind in {
            "Transformer",
            "TransformerFactory",
        } and not self._source_parses_xml(args[0], state):
            return
        if self._is_bundled_xml_input(args[0], state):
            return
        if models.xml_settings_safe(kind, settings):
            return
        severity = "HIGH"
        if self._args_tainted(args, state):
            severity = "CRITICAL"
        self._add_finding(
            "SKY-D236",
            severity,
            f"{kind} parses XML with DTDs and external entities enabled (XXE). Set disallow-doctype-decl to true, or turn off external entities, before creating the parser.",
            self._line(call),
            category="xxe",
            cwe="CWE-611",
        )

    def _report_dom4j_parse_text(self, call, state: JavaFlowState) -> None:
        args = self._call_args(call)
        if not args or self._is_bundled_xml_input(args[0], state):
            return
        severity = "MEDIUM"
        if self._args_tainted(args, state):
            severity = "HIGH"
        self._add_finding(
            "SKY-D236",
            severity,
            "dom4j DocumentHelper.parseText uses a default SAXReader, which resolves external entities before dom4j 2.1.3. Parse with a SAXReader that sets disallow-doctype-decl.",
            self._line(call),
            category="xxe",
            cwe="CWE-611",
        )

    def _source_parses_xml(self, node, state: JavaFlowState) -> bool:
        node = self._strip_parentheses(node)
        if node is None:
            return False
        if self._expr_facts(node, state).tainted:
            return True
        if node.type == "object_creation_expression":
            return self._object_creation_type(node) in {"StreamSource", "SAXSource"}
        if node.type == "identifier":
            return state.object_types.get(self._text(node)) in {
                "StreamSource",
                "SAXSource",
            }
        return False

    def _is_bundled_xml_input(self, node, state: JavaFlowState, depth: int = 0) -> bool:
        """XML read from the application's own classpath or a literal path."""
        node = self._strip_parentheses(node)
        if node is None or depth > 8:
            return False
        if node.type == "string_literal":
            return True
        if node.type == "identifier":
            name = self._text(node)
            return (
                name not in state.tainted_vars
                and state.object_types.get(name) == "ClassPathResource"
            )
        if node.type == "method_invocation":
            method = self._call_name(node)
            args = self._call_args(node)
            if method in CLASSPATH_RESOURCE_METHODS:
                return bool(args) and not self._args_tainted(args, state)
            if method in {"getInputStream", "openStream"}:
                return self._is_bundled_xml_input(
                    node.child_by_field_name("object"), state, depth + 1
                )
            return False
        if node.type == "object_creation_expression":
            args = self._object_creation_args(node)
            class_name = self._object_creation_type(node)
            if class_name == "ClassPathResource":
                return bool(args) and not self._args_tainted(args, state)
            if (
                class_name
                in {
                    "File",
                    "FileInputStream",
                    "StreamSource",
                    "InputSource",
                    "BufferedInputStream",
                }
                and len(args) == 1
            ):
                return self._is_bundled_xml_input(args[0], state, depth + 1)
        return False

    def _has_import_evidence(self, type_name: str) -> bool:
        prefixes = IMPORT_EVIDENCE.get(type_name)
        if prefixes is None:
            return True
        exact, wildcard, _ = self._file_imports()
        return any(
            f"{prefix}.{type_name}" in exact or prefix in wildcard
            for prefix in prefixes
        )

    def _resolves_to(self, raw_type: str, qualified: str) -> bool:
        raw_type = raw_type.split("<", 1)[0].strip()
        if raw_type == qualified:
            return True
        package, _, simple = qualified.rpartition(".")
        if raw_type != simple or simple in self._file_type_names():
            return False
        exact, wildcard, _ = self._file_imports()
        if qualified in exact:
            return True
        if any(item.rsplit(".", 1)[-1] == simple for item in exact):
            return False
        return package in wildcard

    def _has_static_import(self, name: str) -> bool:
        _, _, static = self._file_imports()
        return any(
            item.endswith("." + name)
            or (
                item.endswith(".*")
                and item[:-2].rsplit(".", 1)[-1] in {"XMLConstants", "XMLInputFactory"}
            )
            for item in static
        )

    def _file_imports(self) -> tuple[set[str], set[str], set[str]]:
        if self._imports is None:
            exact: set[str] = set()
            wildcard: set[str] = set()
            static: set[str] = set()
            if self.root_node is not None:
                for node in self.root_node.named_children:
                    if node.type != "import_declaration":
                        continue
                    names = [
                        child
                        for child in node.named_children
                        if child.type in {"identifier", "scoped_identifier"}
                    ]
                    if not names:
                        continue
                    name = self._text(names[0])
                    is_static = any(child.type == "static" for child in node.children)
                    has_star = any(child.type == "asterisk" for child in node.children)
                    if is_static:
                        if has_star:
                            name += ".*"
                        static.add(name)
                    elif has_star:
                        wildcard.add(name)
                    else:
                        exact.add(name)
            self._imports = (exact, wildcard, static)
        return self._imports

    def _file_type_names(self) -> set[str]:
        if self._local_type_names is None:
            names = set()
            if self.root_node is not None:
                for node in self._iter_nodes(self.root_node):
                    if node.type in {
                        "class_declaration",
                        "interface_declaration",
                        "enum_declaration",
                        "record_declaration",
                    }:
                        name_node = node.child_by_field_name("name")
                        if name_node is not None:
                            names.add(self._text(name_node))
            self._local_type_names = names
        return self._local_type_names

    def _enclosing_class(self, node):
        current = node.parent
        while current is not None:
            if current.type in {
                "class_declaration",
                "enum_declaration",
                "record_declaration",
            }:
                return current
            current = current.parent
        return None

    def _enclosing_class_names(self, node) -> list[str | None]:
        names: list[str | None] = []
        current = node.parent
        while current is not None:
            if current.type in {
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
            }:
                name_node = current.child_by_field_name("name")
                if name_node is not None:
                    names.append(self._text(name_node))
            current = current.parent
        return names

    def _collect_class_fields(self) -> None:
        fields: dict[str | None, dict[str, str]] = {}
        constants: dict[str | None, dict[str, str]] = {}
        if self.root_node is not None:
            for declaration in self._iter_nodes(self.root_node):
                if declaration.type != "field_declaration":
                    continue
                class_name = self._class_name_for_node(declaration)
                type_name = self._simple_name(
                    self._text(declaration.child_by_field_name("type"))
                )
                modifiers = " ".join(
                    self._text(child)
                    for child in declaration.children
                    if child.type == "modifiers"
                ).split()
                is_constant = "static" in modifiers and "final" in modifiers
                for declarator in declaration.children:
                    if declarator.type != "variable_declarator":
                        continue
                    name_node = declarator.child_by_field_name("name")
                    if name_node is None:
                        continue
                    name = self._text(name_node)
                    fields.setdefault(class_name, {})[name] = type_name
                    value = self._string_literal_value(
                        declarator.child_by_field_name("value")
                    )
                    if is_constant and value is not None:
                        constants.setdefault(class_name, {})[name] = value
        self._class_fields = fields
        self._class_string_constants = constants

    def _field_type(self, node, name: str) -> str | None:
        if self._class_fields is None:
            self._collect_class_fields()
        for class_name in self._enclosing_class_names(node):
            field_type = self._class_fields.get(class_name, {}).get(name)
            if field_type:
                return field_type
        return None

    def _class_string_constant(self, node, name: str) -> str | None:
        if self._class_string_constants is None:
            self._collect_class_fields()
        if self._is_local_name(node, name):
            return None
        for class_name in self._enclosing_class_names(node):
            value = self._class_string_constants.get(class_name, {}).get(name)
            if value is not None:
                return value
        return None

    def _is_local_name(self, node, name: str) -> bool:
        method = self._enclosing_method(node)
        if method is None:
            return False
        key = (method.start_byte, method.end_byte)
        names = self._method_locals.get(key)
        if names is None:
            names = set()
            for child in self._iter_nodes(method):
                if child.type in {
                    "variable_declarator",
                    "formal_parameter",
                    "catch_formal_parameter",
                    "enhanced_for_statement",
                    "resource",
                    "spread_parameter",
                }:
                    name_node = child.child_by_field_name("name")
                    if name_node is not None:
                        names.add(self._text(name_node))
                elif child.type == "lambda_expression":
                    params = child.child_by_field_name("parameters")
                    if params is not None and params.type == "identifier":
                        names.add(self._text(params))
                    elif params is not None:
                        for param in params.named_children:
                            if param.type == "identifier":
                                names.add(self._text(param))
            self._method_locals[key] = names
        return name in names

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
            return JavaTaint.combine([self._expr_facts(arg, state) for arg in args])

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

        if self._is_request_source_call(call, state) or self._is_request_helper_call(
            call, state
        ):
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
            receiver_node = call.child_by_field_name("object")
            if receiver_node is not None:
                receiver_facts = self._expr_facts(receiver_node, state)
                if receiver_facts.tainted:
                    return JavaTaint(tainted=True)
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
        source_type = None
        if receiver:
            receiver_class = state.object_types.get(receiver)
            source_type = state.source_types.get(receiver)
            if self._is_static_type_receiver(call, receiver, state):
                receiver_class = receiver
                source_type = receiver
        if receiver_class is None:
            object_node = call.child_by_field_name("object")
            if (
                object_node is not None
                and object_node.type == "object_creation_expression"
            ):
                receiver_class = self._object_creation_type(object_node)
                source_type = self._text(object_node.child_by_field_name("type"))
        if receiver_class is None and call.child_by_field_name("object") is None:
            receiver_class = self._class_name_for_node(call)
        if source_type and "." in source_type:
            # A qualified external type must not borrow the safe/unsafe summary
            # of an unrelated same-named class in this file.
            receiver_class = (
                self.source_helpers.local_type_name(source_type)
                if self.source_helpers is not None
                else None
            )
        if receiver_class is not None:
            summary = self.helper_summaries.get((receiver_class, method, len(args)))
            if summary is not None:
                return summary
        if self.source_helpers is not None and source_type:
            return self.source_helpers.summary(source_type, method, len(args))
        return None

    def _is_static_type_receiver(self, call, receiver: str, state) -> bool:
        """``WebUtils.getRequestBody(request)``: a capitalised name that is not a
        local, parameter or field names the helper's class."""
        return (
            receiver[:1].isupper()
            and receiver not in state.object_types
            and receiver not in state.source_types
            and not self._is_local_name(call, receiver)
            and self._field_type(call, receiver) is None
        )

    def _is_request_helper_call(self, call, state: JavaFlowState) -> bool:
        """Spring WebUtils/ServletRequestUtils accessors read the request they
        are given (``getCookie(request, name)``)."""
        if self._call_name(call) not in REQUEST_HELPER_METHODS:
            return False
        for arg in self._call_args(call):
            arg = self._strip_parentheses(arg)
            if arg is not None and arg.type == "identifier":
                name = self._text(arg)
                if name in state.request_vars or name in {"request", "req"}:
                    return True
        return False

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
                if (
                    names
                    and names <= guarded
                    and self._is_in_consequence(sink_node, current)
                ):
                    return True
            current = current.parent
        return False

    def _url_sink_args_tainted(
        self, args: list, positions: tuple[int, ...], state: JavaFlowState
    ) -> bool:
        for pos in positions:
            if pos >= len(args):
                continue
            arg = args[pos]
            facts = self._expr_facts(arg, state)
            if not facts.tainted:
                continue
            names = self._tainted_identifiers(arg, state)
            if names and names <= state.guarded_url_vars:
                continue
            if self._url_value_fixes_host(arg, state):
                continue
            return True
        return False

    def _redirect_sink_tainted(self, args: list, state: JavaFlowState) -> bool:
        if not args:
            return False
        return self._redirect_target_tainted(args[0], state)

    def _is_url_network_sink(self, call, state: JavaFlowState) -> bool:
        method = self._call_name(call)
        if method not in URL_NETWORK_METHODS:
            return False
        receiver = call.child_by_field_name("object")
        if receiver is None or not self._expr_facts(receiver, state).tainted:
            return False
        names = self._tainted_identifiers(receiver, state)
        if names and names <= state.guarded_url_vars:
            return False
        if self._url_value_fixes_host(receiver, state):
            return False
        receiver_class = self._receiver_class_name(call, state)
        if receiver_class in {"URL", "URLConnection", "HttpURLConnection", "URI"}:
            return True
        if receiver.type == "method_invocation":
            receiver_method = self._call_name(receiver)
            return receiver_method in {"toURL", "openConnection", "create"}
        return False

    def _is_http_request_builder_sink(self, call, state: JavaFlowState) -> bool:
        method = self._call_name(call)
        if method not in HTTP_REQUEST_BUILDER_METHODS:
            return False
        receiver = self._simple_name(self._receiver_text(call))
        if method == "newBuilder":
            return receiver == "HttpRequest"
        if method == "uri":
            receiver_class = self._receiver_class_name(call, state)
            if receiver_class == "HttpRequest.Builder":
                return True
            receiver_text = self._receiver_text(call)
            return receiver_text.startswith(
                "HttpRequest.newBuilder("
            ) or receiver_text.startswith("java.net.http.HttpRequest.newBuilder(")
        return False

    def _is_rest_template_sink(self, call, state: JavaFlowState) -> bool:
        method = self._call_name(call)
        if method not in REST_TEMPLATE_URL_METHODS:
            return False
        receiver_class = self._receiver_class_name(call, state)
        if receiver_class == "RestTemplate":
            return True
        if receiver_class is not None:
            return False
        receiver = self._receiver_name(call)
        return receiver is not None and receiver.lower() in {
            "resttemplate",
            "rest_template",
        }

    def _is_send_redirect_sink(self, call, state: JavaFlowState) -> bool:
        if self._call_name(call) != "sendRedirect":
            return False
        receiver_class = self._receiver_class_name(call, state)
        if receiver_class in RESPONSE_TYPES:
            return True
        receiver = self._receiver_name(call)
        return receiver in {"response", "resp", "res"}

    def _receiver_class_name(self, call, state: JavaFlowState) -> str | None:
        receiver = self._receiver_name(call)
        if receiver:
            if receiver in state.object_types:
                return state.object_types[receiver]
            if self._is_local_name(call, receiver):
                return None
            return self._field_type(call, receiver)
        receiver_node = call.child_by_field_name("object")
        if receiver_node is not None and receiver_node.type == "field_access":
            return self._expr_type(receiver_node, state)
        if (
            receiver_node is not None
            and receiver_node.type == "object_creation_expression"
        ):
            return self._object_creation_type(receiver_node)
        return None

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

    def _url_guards_from_if(self, node, state: JavaFlowState) -> set[str]:
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        if condition is None or consequence is None:
            return set()
        if not self._statement_always_exits(consequence, state):
            return set()
        guards = self._url_host_rejection_guard_names(condition, state)
        if alternative is not None and self._statement_assigns_names(
            alternative, guards
        ):
            return set()
        return guards

    def _redirect_guards_from_if(self, node, state: JavaFlowState) -> set[str]:
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        if condition is None or consequence is None:
            return set()
        if not self._statement_always_exits(consequence, state):
            return set()
        guards = self._relative_redirect_guard_names(condition, state)
        if alternative is not None and self._statement_assigns_names(
            alternative, guards
        ):
            return set()
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

    def _url_host_rejection_guard_names(self, node, state: JavaFlowState) -> set[str]:
        node = self._strip_parentheses(node)
        if node is None or node.type != "unary_expression":
            return set()
        text = self._text(node).strip()
        if not text.startswith("!"):
            return set()
        target = self._strip_parentheses(self._first_expression_child(node))
        if target is None or target.type != "method_invocation":
            return set()
        if self._call_name(target) not in {"equals", "equalsIgnoreCase"}:
            return set()

        args = self._call_args(target)
        receiver = target.child_by_field_name("object")
        if len(args) != 1 or receiver is None:
            return set()

        if receiver.type == "string_literal":
            return self._host_call_tainted_names(args[0], state)
        if args[0].type == "string_literal":
            return self._host_call_tainted_names(receiver, state)
        return set()

    def _host_call_tainted_names(self, node, state: JavaFlowState) -> set[str]:
        node = self._strip_parentheses(node)
        if node is None or node.type != "method_invocation":
            return set()
        if self._call_name(node) != "getHost":
            return set()
        receiver = self._receiver_name(node)
        if receiver and receiver in state.tainted_vars:
            return {receiver}
        receiver_node = node.child_by_field_name("object")
        return self._tainted_identifiers(receiver_node, state)

    def _relative_redirect_guard_names(self, node, state: JavaFlowState) -> set[str]:
        node = self._strip_parentheses(node)
        if node is None or node.type != "binary_expression":
            return set()
        if self._binary_operator(node) != "||":
            return set()
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        left_neg = self._negative_startswith_guard_name(left, "/", state)
        right_pos = self._positive_startswith_guard_name(right, "//", state)
        if left_neg and left_neg == right_pos:
            return {left_neg}

        left_pos = self._positive_startswith_guard_name(left, "//", state)
        right_neg = self._negative_startswith_guard_name(right, "/", state)
        if left_pos and left_pos == right_neg:
            return {left_pos}

        return set()

    def _negative_startswith_guard_name(
        self, node, value: str, state: JavaFlowState
    ) -> str | None:
        node = self._strip_parentheses(node)
        if node is None or node.type != "unary_expression":
            return None
        text = self._text(node).strip()
        if not text.startswith("!"):
            return None
        return self._positive_startswith_guard_name(
            self._first_expression_child(node), value, state
        )

    def _positive_startswith_guard_name(
        self, node, value: str, state: JavaFlowState
    ) -> str | None:
        node = self._strip_parentheses(node)
        if node is None or node.type != "method_invocation":
            return None
        if self._call_name(node) != "startsWith":
            return None
        receiver = self._receiver_name(node)
        if not receiver or receiver not in state.tainted_vars:
            return None
        args = self._call_args(node)
        if not args or self._string_literal_value(args[0]) != value:
            return None
        return receiver

    def _flush_pending_path_objects(self, state: JavaFlowState) -> None:
        for name, line in sorted(
            state.pending_path_objects.items(), key=lambda item: item[1]
        ):
            if name in state.guarded_path_vars:
                continue
            self._add_finding(
                "SKY-D215",
                "HIGH",
                "Servlet-controlled path reaches a filesystem sink without canonical path validation.",
                line,
                cwe="CWE-22",
            )

    def _is_stream_value(self, node, state: JavaFlowState) -> bool:
        """``Files.copy(InputStream, Path)`` copies content: the stream is data,
        only the target is a path."""
        node = self._strip_parentheses(node)
        if node is None:
            return False
        if node.type == "method_invocation":
            return self._call_name(node) in {
                "getInputStream",
                "openStream",
                "newInputStream",
                "getBody",
                "getResourceAsStream",
            }
        type_name = self._expr_type(node, state) or ""
        return type_name.endswith("InputStream") or type_name.endswith("Reader")

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
        return any(
            self._call_name(call) == "getCanonicalPath"
            for call in self._method_calls(node)
        )

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
                if any(
                    token in name.lower() for token in ("token", "session", "remember")
                ):
                    return True
            elif node.type == "string_literal":
                value = self._text(node).lower()
                if any(token in value for token in ("token", "session", "rememberme")):
                    return True
            elif (
                node.type == "method_invocation"
                and self._call_name(node) == "getSession"
            ):
                return True
        return False

    def _matches_java_type(self, raw_type: str, qualified_name: str) -> bool:
        return self.source_helpers is not None and self.source_helpers.matches_type(
            raw_type, qualified_name
        )

    def _crypto_receiver_shadowed(self, call) -> bool:
        first = self._receiver_text(call).split(".", 1)[0]
        # Keep lexical bindings even when reassignment clears inferred types.
        # Fields/parameters in other classes are conservatively ambiguous too.
        if self._crypto_receiver_names is None:
            self._crypto_receiver_names = {
                self._text(node.child_by_field_name("name"))
                for node in self._iter_nodes(self.root_node)
                if node.type
                in {"variable_declarator", "formal_parameter", "enhanced_for_statement"}
            }
        return first in self._crypto_receiver_names

    def _assign_properties(self, name: str, value_node, state: JavaFlowState) -> None:
        value_node = self._strip_parentheses(value_node)
        while value_node is not None and value_node.type == "cast_expression":
            value_node = self._strip_parentheses(
                value_node.child_by_field_name("value")
            )
        alias = (
            state.property_objects.get(self._text(value_node))
            if value_node is not None and value_node.type == "identifier"
            else None
        )
        state.property_objects.pop(name, None)
        if len(state.property_objects) >= MAX_CONSTANT_ENTRIES:
            self._invalidate_property_references(value_node, state)
            return
        if alias is not None:
            state.property_objects[name] = alias
        elif (
            value_node is not None
            and value_node.type == "object_creation_expression"
            and self._matches_java_type(
                self._text(value_node.child_by_field_name("type")),
                "java.util.Properties",
            )
            and not any(child.type == "class_body" for child in value_node.children)
            and not self._object_creation_args(value_node)
        ):
            object_id = value_node.start_byte
            state.property_objects[name] = object_id
            state.property_values[object_id] = {}
        else:
            # Arrays, conditionals and unsupported alias-producing values may
            # expose a tracked object. Do not leave its old values trusted.
            self._invalidate_property_references(value_node, state)
        live_objects = set(state.property_objects.values())
        state.property_values = {
            key: value
            for key, value in state.property_values.items()
            if key in live_objects
        }

    def _invalidate_property_references(self, node, state: JavaFlowState) -> set[int]:
        invalidated: set[int] = set()
        if node is None or not state.property_objects:
            return invalidated
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in {"method_invocation", "object_creation_expression"}:
                # Their arguments are processed separately. Passing a getter's
                # string result is not the same as passing the Properties object.
                continue
            if current.type == "identifier":
                object_id = state.property_objects.get(self._text(current))
                if object_id is not None:
                    state.property_values.pop(object_id, None)
                    invalidated.add(object_id)
            stack.extend(current.named_children)
        return invalidated

    def _forget_property_effects(
        self, node, state: JavaFlowState, *, skip_root: bool = False
    ) -> set[int]:
        invalidated: set[int] = set()
        if node is None or not state.property_objects:
            return invalidated
        for call in self._method_calls(node):
            if skip_root and self._same_node(call, node):
                continue
            for arg in self._call_args(call):
                invalidated.update(self._invalidate_property_references(arg, state))
            object_id = state.property_objects.get(self._receiver_name(call))
            if object_id is not None and self._call_name(call) != "getProperty":
                state.property_values.pop(object_id, None)
                invalidated.add(object_id)
        return invalidated

    def _process_property_effects(self, call, state: JavaFlowState) -> None:
        args = self._call_args(call)
        for arg in args:
            self._invalidate_property_references(arg, state)
        object_id = state.property_objects.get(self._receiver_name(call))
        if object_id is None:
            return
        method = self._call_name(call)
        if method == "getProperty" and len(args) in {1, 2}:
            return
        values = state.property_values.get(object_id)
        if method == "clear" and not args:
            state.property_values[object_id] = {}
            return
        if values is None:
            return
        if method == "load" and len(args) == 1:
            resource_name = self._classpath_resource_name(args[0], state)
            loaded = None
            if resource_name is not None and self.source_helpers is not None:
                if self.property_resources is None:
                    package = self.source_helpers.package_name
                    if package is not None:
                        self.property_resources = JavaPropertyResources(
                            self.file_path, package
                        )
                if self.property_resources is not None:
                    loaded = self.property_resources.load(resource_name)
            if loaded is None:
                state.property_values.pop(object_id, None)
                return
            values.update(loaded)
        elif method in {"setProperty", "put"} and len(args) == 2:
            key = self._eval_constant(args[0], state)
            value = self._crypto_algorithm(args[1], state)
            if not isinstance(key, str) or not isinstance(value, str):
                state.property_values.pop(object_id, None)
                return
            values[key] = value
        elif method == "remove" and len(args) == 1:
            key = self._eval_constant(args[0], state)
            if not isinstance(key, str):
                state.property_values.pop(object_id, None)
                return
            values.pop(key, None)
        else:
            state.property_values.pop(object_id, None)
            return
        if (
            len(values) > MAX_CONSTANT_ENTRIES
            or sum(len(key) + len(value) for key, value in values.items())
            > MAX_CONSTANT_STORE_CHARS
        ):
            state.property_values.pop(object_id, None)

    def _classpath_resource_name(self, node, state: JavaFlowState) -> str | None:
        node = self._strip_parentheses(node)
        if node is None or node.type != "method_invocation":
            return None
        args = self._call_args(node)
        if self._call_name(node) != "getResourceAsStream" or len(args) != 1:
            return None
        loader = node.child_by_field_name("object")
        if (
            loader is None
            or loader.type != "method_invocation"
            or self._call_name(loader) != "getClassLoader"
            or self._call_args(loader)
        ):
            return None
        owner = loader.child_by_field_name("object")
        if (
            owner is None
            or owner.type != "method_invocation"
            or self._call_name(owner) != "getClass"
            or self._call_args(owner)
            or self._receiver_text(owner) not in {"", "this"}
        ):
            return None
        resource_name = self._eval_constant(args[0], state)
        return resource_name if isinstance(resource_name, str) else None

    def _crypto_algorithm(self, node, state: JavaFlowState) -> str | None:
        node = self._strip_parentheses(node)
        if node is None:
            return None
        if node.type == "identifier":
            value = state.crypto_constants.get(self._text(node))
            if value is not None:
                return value
        if node.type == "method_invocation" and self._call_name(node) == "getProperty":
            object_id = state.property_objects.get(self._receiver_name(node))
            values = state.property_values.get(object_id)
            args = self._call_args(node)
            if values is None or len(args) not in {1, 2}:
                return None
            key = self._eval_constant(args[0], state)
            if not isinstance(key, str):
                return None
            if key in values:
                return values[key]
            return self._crypto_algorithm(args[1], state) if len(args) == 2 else None
        value = self._eval_constant(node, state)
        return value if isinstance(value, str) else None

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
            return self._bounded_constant(self._string_literal_value(node))
        if node.type == "character_literal":
            text = self._text(node)
            if len(text) >= 3 and text[0] == "'" and text[-1] == "'":
                return self._bounded_constant(text[1:-1])
            return None
        if node.type == "decimal_integer_literal":
            try:
                return self._bounded_constant(int(self._text(node).replace("_", "")))
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
                return self._bounded_constant(-value)
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
                left_text = str(left)
                right_text = str(right)
                if len(left_text) + len(right_text) > MAX_CONSTANT_STRING_CHARS:
                    return None
                return left_text + right_text
            if op == "+" and isinstance(left, int) and isinstance(right, int):
                return self._bounded_constant(left + right)
            if op == "-" and isinstance(left, int) and isinstance(right, int):
                return self._bounded_constant(left - right)
            if op == "*" and isinstance(left, int) and isinstance(right, int):
                return self._bounded_constant(left * right)
            if op == "/" and isinstance(left, int) and isinstance(right, int) and right:
                return self._bounded_constant(left // right)
            if op == "%" and isinstance(left, int) and isinstance(right, int) and right:
                return self._bounded_constant(left % right)
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

    def _bounded_constant(
        self, value: int | bool | str | None
    ) -> int | bool | str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            if abs(value) > MAX_CONSTANT_ABS_INT:
                return None
            return value
        if isinstance(value, str):
            if len(value) > MAX_CONSTANT_STRING_CHARS:
                return None
            return value
        return None

    def _store_constant(
        self,
        name: str,
        value: int | bool | str | None,
        state: JavaFlowState,
    ) -> None:
        bounded = self._bounded_constant(value)
        if bounded is None:
            state.constants.pop(name, None)
            return

        if name not in state.constants and len(state.constants) >= MAX_CONSTANT_ENTRIES:
            state.constants.pop(name, None)
            return

        retained_chars = sum(
            len(existing)
            for key, existing in state.constants.items()
            if key != name and isinstance(existing, str)
        )
        if isinstance(bounded, str):
            retained_chars += len(bounded)
        if retained_chars > MAX_CONSTANT_STORE_CHARS:
            state.constants.pop(name, None)
            return

        state.constants[name] = bounded

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
        return (
            "&&" not in text
            and "||" not in text
            and len(self._calls_named(node, "startsWith")) == 1
        )

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

    def _statement_assigns_names(self, node, names: set[str]) -> bool:
        if not names:
            return False
        for child in self._iter_nodes(node):
            if child.type == "assignment_expression":
                target = self._assignment_target_name(child.child_by_field_name("left"))
                if target in names:
                    return True
            elif child.type == "variable_declarator":
                name = child.child_by_field_name("name")
                if name is not None and self._text(name) in names:
                    return True
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
        return [
            child
            for child in self._iter_nodes(node)
            if child.type == "method_invocation"
        ]

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

    def _strip_parentheses(self, node):
        while node is not None and node.type == "parenthesized_expression":
            node = self._first_expression_child(node)
        return node

    def _binary_operator(self, node) -> str:
        op_node = node.child_by_field_name("operator")
        return self._text(op_node) if op_node is not None else ""

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

    def _declared_type_for_declarator(self, declarator) -> str | None:
        declaration = declarator.parent
        if declaration is None or declaration.type != "local_variable_declaration":
            return None
        type_node = declaration.child_by_field_name("type")
        if type_node is None:
            return None
        raw = self._text(type_node).replace("[]", "").split("<", 1)[0].strip()
        if raw.endswith("HttpRequest.Builder"):
            return "HttpRequest.Builder"
        return self._simple_name(raw)

    def _http_request_builder_type(self, node) -> str | None:
        if node is None or node.type != "method_invocation":
            return None
        if self._call_name(node) != "newBuilder":
            return None
        if self._simple_name(self._receiver_text(node)) != "HttpRequest":
            return None
        return "HttpRequest.Builder"

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


def scan_java_security_flows(
    root_node, file_path: str, source_bytes: bytes
) -> list[dict]:
    if root_node is None:
        return []
    return JavaSecurityFlowAnalyzer(root_node, file_path, source_bytes).scan()
