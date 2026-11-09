"""Lexical Kotlin security flows.

Kotlin has no parser in Skylos, so this module reads the comment/string-masked
code view from ``_lex``: functions and lambdas are brace ranges, statements are
depth-0 lines, and an expression is tainted when it contains a request source
or a tainted name. Source, sink and XML-hardening tables are the Java ones
(``java/models.py`` and ``java/flow.py``) because Kotlin calls the same JVM APIs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from skylos.rules.danger.danger_web.html_context import (
    ATTR_SAFE,
    TEXT_SAFE,
    hole_requirements,
)
from skylos.visitors.languages.java import models
from skylos.visitors.languages.java.flow import (
    FILES_PATH_METHODS,
    PATH_CONSTRUCTOR_TYPES,
    REQUEST_HELPER_METHODS,
    REQUEST_PARAM_ANNOTATIONS,
    REQUEST_SOURCE_METHODS,
    REQUEST_TYPES,
    RESPONSE_TYPES,
    REST_TEMPLATE_URL_METHODS,
    SCRIPT_RECEIVER_TYPES,
    URL_NETWORK_METHODS,
    XSS_WRITER_METHODS,
)
from skylos.visitors.languages.kotlin._lex import KotlinSource, matching_close

_IDENT = r"(?:`[^`\n]+`|[A-Za-z_]\w*)"
_GENERIC = r"<(?:[^<>\n]|<(?:[^<>\n]|<[^<>\n]*>)*>)*>"
_IDENT_RE = re.compile(_IDENT)
_FUN_RE = re.compile(
    rf"\bfun\s+(?:{_GENERIC}\s*)?"
    rf"(?:{_IDENT}(?:\s*\.\s*{_IDENT})*(?:{_GENERIC})?\??\s*\.\s*)?"
    rf"(?P<name>{_IDENT})\s*\("
)
_CLASS_RE = re.compile(rf"\b(?:class|object|interface)\s+(?P<name>{_IDENT})")
_ANNOTATION_NAME_RE = re.compile(r"@(?:[A-Za-z_]\w*:)?(?P<name>[A-Za-z_][\w.]*)")
_CALL_RE = re.compile(rf"(?P<name>{_IDENT})\s*(?:{_GENERIC})?\s*\(")
_DECL_RE = re.compile(
    rf"^\s*(?:(?:private|public|internal|protected|override|lateinit|const|open)\s+)*"
    rf"(?:val|var)\s+(?P<name>{_IDENT})\s*(?::\s*(?P<type>[^=\n]+?))?\s*(?:=|\bby\b)"
)
_DESTRUCTURE_RE = re.compile(r"^\s*(?:val|var)\s*\((?P<names>[^()]*)\)\s*=")
_REASSIGN_RE = re.compile(
    rf"^\s*(?:this\s*\.\s*)?(?P<name>{_IDENT})\s*(?P<op>\+=|=)(?![=>])"
)
_PARAM_RE = re.compile(
    rf"^\s*(?P<annotations>(?:@[^\s(]+(?:\([^)]*\))?\s*)*)"
    rf"(?:(?:private|public|internal|protected|override|vararg|val|var|crossinline|noinline)\s+)*"
    rf"(?P<name>{_IDENT})\s*:\s*(?P<type>.+?)\s*(?:=.*)?$",
    re.DOTALL,
)
_FIELD_RE = re.compile(
    rf"\b(?:val|var)\s+(?P<name>{_IDENT})\s*(?::\s*(?P<type>[\w.]+))?\s*(?:=\s*(?P<ctor>[A-Z][\w.]*)\s*[(<])?"
)
_CONST_RE = re.compile(rf"\bconst\s+val\s+(?P<name>{_IDENT})")
_LITERAL_VAL_RE = re.compile(rf"\bval\s+(?P<name>{_IDENT})\s*(?::\s*String\s*)?=\s*\"")

_KTOR_SOURCE_RE = re.compile(
    r"\bcall\s*\.\s*(?:"
    r"(?:parameters|pathParameters|queryParameters)\b"
    r"|request\s*\.\s*(?:queryParameters|rawQueryParameters|headers|cookies|uri|"
    r"queryString|document|path|header|local)\b"
    r"|receive(?:Text|Parameters|Multipart|Stream|Channel|Nullable|OrNull)?\b"
    r")"
)
_SERVER_REQUEST_METHODS = (
    "queryParam|queryParams|pathVariable|pathVariables|bodyToMono|bodyToFlux|"
    "awaitBody|awaitBodyOrNull|formData|awaitFormData|multipartData|"
    "awaitMultipartData|headers|cookies"
)
_NUMERIC_CONVERSION_RE = re.compile(
    r"(?:\?\s*)?\.\s*(?:toInt|toLong|toShort|toByte|toDouble|toFloat|toBoolean|"
    r"toBigDecimal|toBigInteger|toUInt|toULong)(?:OrNull)?\s*\(\s*\)"
)
_STATIC_SCALAR_RE = re.compile(
    r"\b(?:java\s*\.\s*lang\s*\.\s*)?(?:Integer|Long|Short|Byte|Double|Float|Boolean|UUID)"
    r"\s*\.\s*(?:parseInt|parseLong|parseShort|parseByte|parseDouble|parseFloat|"
    r"parseBoolean|valueOf|fromString)\s*\("
)
_HTML_ENCODER_OWNERS = {
    "escapeHtml4": frozenset(
        {
            "org.apache.commons.text.StringEscapeUtils",
            "org.apache.commons.lang3.StringEscapeUtils",
        }
    ),
    "escapeHtml": frozenset({"org.apache.commons.lang.StringEscapeUtils"}),
    "escapeXml": frozenset(
        {
            "org.apache.commons.lang3.StringEscapeUtils",
            "org.apache.commons.lang.StringEscapeUtils",
        }
    ),
    "htmlEscape": frozenset({"org.springframework.web.util.HtmlUtils"}),
    "forHtml": frozenset({"org.owasp.encoder.Encode"}),
    "forHtmlAttribute": frozenset({"org.owasp.encoder.Encode"}),
    "forHtmlContent": frozenset({"org.owasp.encoder.Encode"}),
}
_ESAPI_CLASS = "org.owasp.esapi.ESAPI"
_ESAPI_ENCODER_METHODS = frozenset({"encodeForHTML"})
_ESAPI_RECEIVER_RE = re.compile(r"(?P<root>[\w.]+)\.encoder\(\)")
_TEXT_ONLY_ENCODERS = frozenset({"forHtmlContent"})
_IMPORT_BINDING_RE = re.compile(
    r"(?m)^\s*import\s+(?P<path>[\w.`]+)(?:\s+as\s+(?P<alias>[\w`]+))?"
)
_HTML_RAW = "html_raw"
_HTML_JOINERS = " \t\r\n+()"
_KOTLIN_ESCAPE_RE = re.compile(r"\\(u[0-9A-Fa-f]{4}|.)")
_KOTLIN_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "r": "\r"}
_BASENAME_AFTER_RE = re.compile(
    r"^\s*(?:\?|!!)?\s*\.\s*(?:name|nameWithoutExtension|extension|fileName|getName\s*\(\s*\)|getFileName\s*\(\s*\))\b"
)
_PATH_STRING_ONLY_RE = re.compile(
    r"^(?:\s*(?:\?|!!)?\s*\.\s*(?:(?:parent|parentFile|path|absolutePath|invariantSeparatorsPath)\b|"
    r"toString\s*\(\s*\)|toURI\s*\(\s*\)|toUri\s*\(\s*\)))+(?!\s*(?:\?|!!)?\s*\.)"
)
_BASENAME_CALL_RE = re.compile(r"\b(?:FilenameUtils|FileNameUtils)\s*\.\s*getName\s*\(")
_NORMALIZER_RE = re.compile(
    r"\b(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile|canonicalPath|canonicalFile)\b"
)
_PATH_READ_ACCESSORS = re.compile(
    r"^\s*(?:\.\s*(?:canonicalFile|canonicalPath|absoluteFile|absolutePath|normalize\s*\(\s*\)|"
    r"toPath\s*\(\s*\)|toAbsolutePath\s*\(\s*\)|getCanonicalFile\s*\(\s*\)|getCanonicalPath\s*\(\s*\)))*\s*$"
)
_SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.IGNORECASE)
_GUARD_START_RE = re.compile(
    r"^\s*(?:\}\s*)?(?:else\s+)?(?:if|require|check|when|assert|while)\b"
)
_HTML_CONTENT_TYPE_RE = re.compile(r"ContentType\s*\.\s*Text\s*\.\s*Html\b")
_LAMBDA_PARAMS_RE = re.compile(rf"^\s*(?P<params>{_IDENT}(?:\s*,\s*{_IDENT})*)\s*->")
_SCOPE_CALL_RE = re.compile(
    r"(?:\?|!!)?\s*\.\s*(?:let|also|run|apply|use|map|mapNotNull|flatMap|forEach|"
    r"forEachIndexed|filter|filterNot|onEach|takeIf|takeUnless|first|firstOrNull|"
    r"find|any|all|associate|associateWith|associateBy|ifEmpty|ifBlank)\s*$"
)
_JS_ENABLED_RE = re.compile(
    r"\bjavaScriptEnabled\s*=\s*true\b|\bsetJavaScriptEnabled\s*\(\s*true\s*\)"
)
_JS_BRIDGE_RE = re.compile(r"\baddJavascriptInterface\s*\(")
_FILE_URL_ACCESS_RE = re.compile(
    r"\b(?:allowUniversalAccessFromFileURLs|allowFileAccessFromFileURLs)\s*=\s*true\b"
    r"|\b(?:setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs)\s*\(\s*true\s*\)"
)
_KRYO_OPEN_RE = re.compile(
    r"\bisRegistrationRequired\s*=\s*false\b|\bsetRegistrationRequired\s*\(\s*false\s*\)"
)

_KINDS = ("sql", "cmd", "path", "url", "redirect", "xss", "xss_attr", "code")
_SCALAR_TYPES = models.SCALAR_PARAM_TYPES | {
    "Int",
    "Char",
    "UInt",
    "ULong",
    "UShort",
    "UByte",
    "Number",
}
_SERVLET_PROPERTIES = {
    method[3].lower() + method[4:]
    for method in REQUEST_SOURCE_METHODS
    if method.startswith("get") and len(method) > 3
}
_REQUEST_NAMES = {"request", "req"}
_RESPONSE_NAMES = {"response", "resp", "res", "httpResponse", "servletResponse"}
_SPRING_CONTROLLERS = {"Controller", "RestController"}
_HTTP_CLIENT_METHODS = {
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "request",
    "prepareGet",
    "preparePost",
    "preparePut",
    "prepareDelete",
    "prepareRequest",
    "submitForm",
}
_URL_READ_METHODS = URL_NETWORK_METHODS | {"readText", "readBytes"}
_URL_TYPES = {"URL", "URI", "URLConnection", "HttpURLConnection", "HttpsURLConnection"}
_PATH_FACTORY_RECEIVERS = {"Paths", "Path"}
_PATH_CONSTRUCTORS = {
    **PATH_CONSTRUCTOR_TYPES,
    "File": (0, 1),
    "FileWriter": (0,),
    "RandomAccessFile": (0,),
}
_EXPRESSION_TYPES_NEEDING_IMPORT = {"Context": "javax.naming"}
_SQL_CRITICAL = (
    "SQL query uses request-controlled data. Use parameterized queries with fixed SQL."
)
_SQL_BUILT = (
    "SQL query built from a string template or concatenation, risk of SQL injection. "
    "Use parameterized queries."
)
_PATH_MESSAGE = (
    "Request-controlled path reaches a filesystem sink without canonical path validation. "
    "Normalize the path and enforce it stays under the intended root."
)
_SSRF_MESSAGE = "Request-controlled URL reaches a network client. Validate scheme and host against an allowlist."
_REDIRECT_MESSAGE = (
    "Redirect target uses request-controlled data. Validate redirect targets against a "
    "relative-path or host allowlist."
)
_MODIFIER_WORDS = frozenset(
    {
        "private",
        "public",
        "internal",
        "protected",
        "override",
        "open",
        "suspend",
        "inline",
        "final",
        "abstract",
        "operator",
        "infix",
        "tailrec",
    }
)
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_UNKNOWN = object()


@dataclass
class _Param:
    name: str
    type: str
    annotations: set[str]


@dataclass
class _Class:
    name: str
    start: int
    end: int
    annotations: set[str]
    field_types: dict[str, str]


@dataclass
class _Function:
    keyword: int
    start: int
    end: int
    params: list[_Param]
    annotations: set[str]
    owner: _Class | None


@dataclass
class _Xml:
    kind: str
    settings: dict
    root_kind: str


@dataclass
class _Call:
    name: str
    name_start: int
    open_paren: int
    close_paren: int
    receiver: str
    receiver_start: int
    args: list[tuple[int, int]]
    after: str


@dataclass
class _State:
    tainted: dict[str, frozenset[str]] = field(default_factory=dict)
    decl_depth: dict[str, int] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    request_vars: set[str] = field(default_factory=set)
    server_request_vars: set[str] = field(default_factory=set)
    response_vars: set[str] = field(default_factory=set)
    constants: set[str] = field(default_factory=set)
    fixed_host: set[str] = field(default_factory=set)
    pending_paths: dict[str, int] = field(default_factory=dict)
    normalized: set[str] = field(default_factory=set)
    derived: dict[str, set[str]] = field(default_factory=dict)
    guarded_path: set[str] = field(default_factory=set)
    guarded_redirect: set[str] = field(default_factory=set)
    xml: dict[str, _Xml] = field(default_factory=dict)
    xml_unknown: set[str] = field(default_factory=set)


class KotlinSecurityScanner:
    def __init__(self, lexed: KotlinSource, file_path: str) -> None:
        self.lexed = lexed
        self.code = lexed.code
        self.file_path = str(file_path)
        self.findings: dict[tuple[str, int], dict] = {}
        self.classes = self._classes()
        self.file_constants = {
            match.group("name") for match in _CONST_RE.finditer(self.code)
        } | {match.group("name") for match in _LITERAL_VAL_RE.finditer(self.code)}
        self.imports = re.findall(r"(?m)^\s*import\s+([\w.`]+)", self.code)
        self.import_bindings = _import_bindings(self.code)
        self.declared_functions = {
            match.group("name").strip("`") for match in _FUN_RE.finditer(self.code)
        }
        self.declared_types = {
            match.group("name").strip("`") for match in _CLASS_RE.finditer(self.code)
        }
        self.encoder_binding_types: dict[str, list[tuple[int, int, str | None]]] = {}
        self.encoder_bindings = self._encoder_binding_ranges()
        self.encoder_call_re = self._encoder_call_pattern()
        self.encoder_methods: dict[int, str | None] = {}

    def scan(self) -> list[dict]:
        for function in self._functions():
            self._scan_function(function)
        self._scan_android()
        self._scan_file_patterns()
        return sorted(
            self.findings.values(), key=lambda item: (item["line"], item["rule_id"])
        )

    def _add(
        self,
        rule_id: str,
        severity: str,
        message: str,
        offset: int,
        *,
        cwe: str,
        category: str | None = None,
        low_risk_context: dict | None = None,
    ) -> None:
        line = self.lexed.line_for(offset)
        key = (rule_id, line)
        existing = self.findings.get(key)
        if (
            existing
            and _SEVERITY_RANK[existing["severity"]] >= _SEVERITY_RANK[severity]
        ):
            return
        finding = {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "file": self.file_path,
            "line": line,
            "col": 0,
            "cwe": cwe,
        }
        if category:
            finding["category"] = category
        if low_risk_context:
            finding["low_risk_context"] = low_risk_context
        self.findings[key] = finding

    def _classes(self) -> list[_Class]:
        classes = []
        code = self.code
        for match in _CLASS_RE.finditer(code):
            index = match.end()
            constructor = ""
            while index < len(code) and code[index] in " \t":
                index += 1
            if code.startswith("<", index):
                generic = re.match(_GENERIC, code[index:])
                if generic:
                    index += generic.end()
            ctor_match = re.match(
                r"\s*(?:(?:@\w+\s*)*(?:private|internal|protected|public)?\s*constructor\s*)?\(",
                code[index:],
            )
            if ctor_match:
                open_paren = index + ctor_match.end() - 1
                close_paren = self.lexed.close_of(open_paren)
                if close_paren != -1:
                    constructor = code[open_paren + 1 : close_paren]
                    index = close_paren + 1
            brace = _body_brace(code, index)
            if brace == -1:
                start = end = match.start()
            else:
                start = brace
                end = self.lexed.close_of(brace)
                if end == -1:
                    end = len(code)
            field_types = {}
            for param in _split_top_level(constructor):
                parsed = _parse_param(param)
                if parsed:
                    field_types[parsed.name] = parsed.type
            if brace != -1:
                for field_match in _FIELD_RE.finditer(code, start, end):
                    field_type = field_match.group("type") or field_match.group("ctor")
                    if field_type:
                        field_types.setdefault(
                            field_match.group("name"), _simple_type(field_type)
                        )
            classes.append(
                _Class(
                    name=match.group("name"),
                    start=start,
                    end=end,
                    annotations=_annotations_before(code, match.start()),
                    field_types=field_types,
                )
            )
        return classes

    def _owner(self, offset: int) -> _Class | None:
        best = None
        for item in self.classes:
            if item.start < offset < item.end and (
                best is None or item.start > best.start
            ):
                best = item
        return best

    def _functions(self) -> list[_Function]:
        functions = []
        code = self.code
        for match in _FUN_RE.finditer(code):
            open_paren = match.end() - 1
            close_paren = self.lexed.close_of(open_paren)
            if close_paren == -1:
                continue
            params = [
                parsed
                for parsed in (
                    _parse_param(text)
                    for text in _split_top_level(code[open_paren + 1 : close_paren])
                )
                if parsed
            ]
            body = _function_body(self.lexed, close_paren + 1)
            if body is None:
                continue
            functions.append(
                _Function(
                    keyword=match.start(),
                    start=body[0],
                    end=body[1],
                    params=params,
                    annotations=_annotations_before(code, match.start()),
                    owner=self._owner(match.start()),
                )
            )
        return functions

    def _scan_function(self, function: _Function) -> None:
        state = _State()
        state.constants = set(self.file_constants)
        owner = function.owner
        if owner is not None:
            for name, type_name in owner.field_types.items():
                state.types[name] = type_name
        handler = bool(
            function.annotations & models.SPRING_HANDLER_ANNOTATIONS
        ) and bool(owner is not None and owner.annotations & _SPRING_CONTROLLERS)
        jaxrs = bool(function.annotations & models.JAXRS_HANDLER_ANNOTATIONS)
        for param in function.params:
            type_name = _simple_type(param.type)
            state.types[param.name] = type_name
            if type_name in REQUEST_TYPES:
                state.request_vars.add(param.name)
                continue
            if type_name == "ServerRequest":
                state.server_request_vars.add(param.name)
                continue
            if type_name in RESPONSE_TYPES:
                state.response_vars.add(param.name)
                continue
            if type_name in _SCALAR_TYPES:
                state.constants.add(param.name)
                continue
            if param.annotations & models.NON_INPUT_PARAM_ANNOTATIONS:
                continue
            explicit = bool(param.annotations & REQUEST_PARAM_ANNOTATIONS)
            implicit = (
                handler or jaxrs
            ) and type_name not in models.NON_INPUT_PARAM_TYPES
            if explicit or implicit or type_name in models.UPLOAD_PARAM_TYPES:
                state.tainted[param.name] = frozenset()
                state.decl_depth[param.name] = 0
        self._process_block(function.start, function.end, state, 0)
        for name, offset in sorted(
            state.pending_paths.items(), key=lambda item: item[1]
        ):
            self._add("SKY-D215", "HIGH", _PATH_MESSAGE, offset, cwe="CWE-22")

    def _process_block(self, start: int, end: int, state: _State, depth: int) -> None:
        for stmt_start, stmt_end in _statements(self.lexed, start, end):
            self._process_statement(stmt_start, stmt_end, state, depth)

    def _process_statement(
        self, start: int, end: int, state: _State, depth: int
    ) -> None:
        code = self.code
        blocks = _top_blocks(self.lexed, start, end)
        header = list(code[start:end])
        for block_start, block_end in blocks:
            for index in range(block_start + 1, block_end):
                if header[index - start] not in "\n\r":
                    header[index - start] = " "
        header_text = "".join(header)
        if not header_text.strip():
            return
        self._process_guards(header_text, start, state)
        self._process_assignment(header_text, start, end, state, depth)
        for call in self._calls(header_text, start):
            self._process_call(call, start, end, state)
        self._process_redirect_strings(start, end, header_text, state)
        for block_start, block_end in blocks:
            saved = self._bind_lambda(block_start, block_end, state)
            self._process_block(block_start + 1, block_end, state, depth + 1)
            for name, value in saved.items():
                if value is None:
                    state.tainted.pop(name, None)
                else:
                    state.tainted[name] = value

    def _bind_lambda(self, block_start: int, block_end: int, state: _State) -> dict:
        code = self.code
        before = code[max(0, block_start - 200) : block_start].rstrip()
        scope = _SCOPE_CALL_RE.search(before)
        params_match = _LAMBDA_PARAMS_RE.match(code[block_start + 1 : block_end])
        names = ["it"]
        if params_match:
            names = [part.strip() for part in params_match.group("params").split(",")]
        saved = {}
        for name in names:
            saved[name] = state.tainted.get(name)
        if scope is None:
            for name in names:
                if params_match:
                    state.tainted.pop(name, None)
            return saved
        receiver_end = (
            block_start
            - (len(code[max(0, block_start - 200) : block_start]) - len(before))
            - len(scope.group(0))
        )
        receiver_start = _chain_start(code, receiver_end - 1, self.lexed)
        kinds = self._taint_kinds(receiver_start, receiver_end, state)
        for name in names[:1]:
            if kinds is None:
                state.tainted.pop(name, None)
            else:
                state.tainted[name] = kinds
        return saved

    def _process_guards(self, header: str, base: int, state: _State) -> None:
        if not _GUARD_START_RE.match(header) and ".takeIf" not in header:
            return
        prefixes_by_root: dict[str, set[str]] = {}
        for match in re.finditer(r"\.\s*startsWith\s*\(", header):
            receiver_end = base + match.start()
            receiver_start = _chain_start(self.code, receiver_end - 1, self.lexed)
            chain = self.code[receiver_start:receiver_end]
            root = _root_name(chain)
            if not root:
                continue
            if root in state.normalized or _NORMALIZER_RE.search(chain):
                guarded = {root} | state.derived.get(root, set())
                state.guarded_path.update(guarded)
                for name in guarded:
                    state.pending_paths.pop(name, None)
            arg_open = base + match.end() - 1
            literal = self._literal_value(arg_open + 1, self.lexed.close_of(arg_open))
            if literal is not None:
                prefixes_by_root.setdefault(root, set()).add(literal)
        for root, prefixes in prefixes_by_root.items():
            if root in state.tainted and {"/", "//"} <= prefixes:
                state.guarded_redirect.add(root)
        for match in re.finditer(rf"(?P<name>{_IDENT})\s*!?in\b", header):
            if match.group("name") in state.tainted:
                state.guarded_redirect.add(match.group("name"))
        for match in re.finditer(
            rf"\.\s*contains\s*\(\s*(?P<name>{_IDENT})\s*\)", header
        ):
            if match.group("name") in state.tainted:
                state.guarded_redirect.add(match.group("name"))

    def _process_assignment(
        self, header: str, start: int, end: int, state: _State, depth: int
    ) -> None:
        code = self.code
        names: list[str] = []
        declared_type = None
        declaration = False
        match = _DECL_RE.match(header)
        if match:
            names = [match.group("name").strip("`")]
            declared_type = match.group("type")
            declaration = True
        else:
            destructure = _DESTRUCTURE_RE.match(header)
            if destructure:
                names = [
                    part.split(":")[0].strip()
                    for part in destructure.group("names").split(",")
                    if part.strip() and part.strip() != "_"
                ]
                match = destructure
                declaration = True
            else:
                match = _REASSIGN_RE.match(header)
                if match:
                    names = [match.group("name").strip("`")]
        if not match or not names:
            return
        rhs_start = start + match.end()
        rhs_end = end
        kinds = self._taint_kinds(rhs_start, rhs_end, state)
        rhs_text = code[rhs_start:rhs_end]
        for name in names:
            if kinds is not None:
                if (
                    match.re is _REASSIGN_RE
                    and match.group("op") == "+="
                    and name in state.tainted
                ):
                    state.tainted[name] = state.tainted[name] & kinds
                else:
                    state.tainted[name] = kinds
                if declaration:
                    state.decl_depth[name] = depth
            elif declaration or state.decl_depth.get(name, depth) == depth:
                if not (match.re is _REASSIGN_RE and match.group("op") == "+="):
                    state.tainted.pop(name, None)
                if declaration:
                    state.decl_depth[name] = depth
            if declaration:
                self._remember_value(
                    name, declared_type, rhs_start, rhs_end, rhs_text, state
                )

    def _remember_value(
        self,
        name: str,
        declared_type: str | None,
        rhs_start: int,
        rhs_end: int,
        rhs_text: str,
        state: _State,
    ) -> None:
        stripped = rhs_text.strip()
        value_type = None
        if declared_type:
            value_type = _simple_type(declared_type)
        inferred = self._expression_type(rhs_start, rhs_end, state)
        if inferred:
            value_type = inferred
        if value_type:
            state.types[name] = value_type
        else:
            state.types.pop(name, None)
        if value_type in REQUEST_TYPES:
            state.request_vars.add(name)
        if re.fullmatch(r"\"[^\n]*\"", stripped) and not self._string_has_exprs(
            rhs_start, rhs_end
        ):
            state.constants.add(name)
        elif re.fullmatch(r"-?\d[\d_]*[lLuU]?", stripped):
            state.constants.add(name)
        else:
            state.constants.discard(name)
        if self._fixes_host(rhs_start, rhs_end, state):
            state.fixed_host.add(name)
        else:
            state.fixed_host.discard(name)
        if _NORMALIZER_RE.search(rhs_text):
            state.normalized.add(name)
        state.derived[name] = self._tainted_names(rhs_start, rhs_end, state)
        self._remember_xml(name, rhs_start, rhs_end, state)
        path_call = self._pending_path_call(rhs_start, rhs_end, state)
        if path_call is not None:
            state.pending_paths[name] = path_call.name_start

    def _remember_xml(self, name: str, start: int, end: int, state: _State) -> None:
        xml = self._xml_for_chain(start, end, state)
        if xml is None:
            state.xml.pop(name, None)
            return
        state.xml[name] = xml
        state.types[name] = xml.kind

    def _calls(self, header: str, base: int) -> list[_Call]:
        calls = []
        code = self.code
        for match in _CALL_RE.finditer(header):
            name = match.group("name").strip("`")
            if name in {
                "if",
                "when",
                "while",
                "for",
                "catch",
                "fun",
                "return",
                "super",
                "this",
            }:
                continue
            before = header[max(0, match.start() - 40) : match.start()]
            if re.search(r"\bfun\s+(?:\S+\s*\.\s*)?$", before):
                continue
            open_paren = base + match.end() - 1
            close_paren = self.lexed.close_of(open_paren)
            if close_paren == -1:
                continue
            name_start = base + match.start("name")
            receiver_start = name_start
            receiver = ""
            index = name_start - 1
            while index >= 0 and code[index] in " \t\n":
                index -= 1
            if index >= 0 and code[index] == ".":
                dot = index
                if dot > 0 and code[dot - 1] == "?":
                    dot -= 1
                receiver_start = _chain_start(code, dot - 1, self.lexed)
                receiver = code[receiver_start:dot].strip()
            args = []
            for arg_start, arg_end in _split_spans(code, open_paren + 1, close_paren):
                label = re.match(rf"\s*{_IDENT}\s*=(?![=>])", code[arg_start:arg_end])
                if label:
                    arg_start += label.end()
                args.append((arg_start, arg_end))
            after_end = min(len(code), close_paren + 160)
            calls.append(
                _Call(
                    name=name,
                    name_start=name_start,
                    open_paren=open_paren,
                    close_paren=close_paren,
                    receiver=receiver,
                    receiver_start=receiver_start,
                    args=args,
                    after=code[close_paren + 1 : after_end],
                )
            )
        return calls

    def _process_call(
        self, call: _Call, stmt_start: int, stmt_end: int, state: _State
    ) -> None:
        receiver_type = self._receiver_type(call, state)
        self._process_command(call, receiver_type, state)
        self._process_sql(call, receiver_type, state)
        self._process_path(call, receiver_type, stmt_start, state)
        self._process_ssrf(call, receiver_type, state)
        self._process_redirect_call(call, receiver_type, state)
        self._process_xss(call, state)
        self._process_deserialization(call, state)
        self._process_xml(call, receiver_type, state)
        self._process_expression(call, receiver_type, state)

    def _process_command(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        if call.name == "exec" and (
            receiver_type == "Runtime"
            or re.search(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)$", call.receiver)
        ):
            constant = all(self._is_constant_value(s, e) for s, e in call.args)
            if constant:
                self._add(
                    "SKY-D203",
                    "LOW",
                    "Runtime.exec() runs an OS command. Pass a fixed argv array and validate any input.",
                    call.name_start,
                    cwe="CWE-78",
                    low_risk_context={
                        "reason": "constant-shell-command",
                        "detail": "the command is a fixed string with no input",
                    },
                )
            else:
                self._add(
                    "SKY-D203",
                    "HIGH",
                    "Runtime.exec() runs an OS command. Pass a fixed argv array and validate any input.",
                    call.name_start,
                    cwe="CWE-78",
                )
            if self._any_arg_tainted(call.args, "cmd", state):
                self._add(
                    "SKY-D212",
                    "CRITICAL",
                    "Process execution uses request-controlled data. Use fixed argv elements and validate inputs.",
                    call.name_start,
                    cwe="CWE-78",
                )
            return
        builder = call.name == "ProcessBuilder" and _is_constructor(call)
        command = call.name == "command" and (
            receiver_type == "ProcessBuilder"
            or "ProcessBuilder(" in call.receiver.replace(" ", "")
        )
        if (builder or command) and self._any_arg_tainted(call.args, "cmd", state):
            shell = any(
                self._literal_value(s, e)
                in {"sh", "bash", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "-c", "/c"}
                for s, e in self._flatten_args(call.args)
            )
            message = "Process execution uses request-controlled data. Use fixed argv elements and validate inputs."
            if shell:
                message = "ProcessBuilder starts a shell command built from request-controlled data. Use fixed argv elements and validate inputs."
            self._add("SKY-D212", "CRITICAL", message, call.name_start, cwe="CWE-78")

    def _process_sql(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        name = call.name
        if name in models.SQL_DISTINCT_SINKS:
            positions = models.SQL_DISTINCT_SINKS[name]
        elif name in models.SQL_TYPED_SINKS and self._is_sql_receiver(
            call, receiver_type
        ):
            positions = models.SQL_TYPED_SINKS[name]
        else:
            return
        for position in positions:
            if position >= len(call.args):
                continue
            start, end = call.args[position]
            if self._is_tainted(start, end, "sql", state):
                self._add(
                    "SKY-D211", "CRITICAL", _SQL_CRITICAL, call.name_start, cwe="CWE-89"
                )
                return
            if self._is_string_built_sql(start, end, state):
                self._add("SKY-D211", "HIGH", _SQL_BUILT, call.name_start, cwe="CWE-89")
                return

    def _is_sql_receiver(self, call: _Call, receiver_type: str | None) -> bool:
        if receiver_type in models.SQL_RECEIVER_TYPES:
            return True
        if receiver_type is not None:
            return False
        root = _root_name(call.receiver)
        simple = call.receiver.strip()
        return (
            bool(root) and simple == root and root.lower() in models.SQL_RECEIVER_NAMES
        )

    def _process_path(
        self, call: _Call, receiver_type: str | None, stmt_start: int, state: _State
    ) -> None:
        positions: tuple[int, ...] = ()
        creation = False
        if _is_constructor(call) and call.name in _PATH_CONSTRUCTORS:
            positions = _PATH_CONSTRUCTORS[call.name]
            creation = True
        elif (
            call.name in {"get", "of"}
            and _last_segment(call.receiver) in _PATH_FACTORY_RECEIVERS
        ):
            positions = tuple(range(len(call.args)))
            creation = True
        elif (
            call.name in FILES_PATH_METHODS and _last_segment(call.receiver) == "Files"
        ):
            positions = FILES_PATH_METHODS[call.name]
        elif call.name == "resolve" and receiver_type in {"Path", "File"}:
            positions = (0,)
        elif call.name == "transferTo" and receiver_type in models.UPLOAD_PARAM_TYPES:
            positions = (0,)
        if not positions:
            return
        tainted_args = [
            call.args[position]
            for position in positions
            if position < len(call.args)
            and self._is_tainted(
                call.args[position][0], call.args[position][1], "path", state
            )
        ]
        if not tainted_args:
            return
        if creation and (
            _BASENAME_AFTER_RE.match(call.after)
            or _PATH_STRING_ONLY_RE.match(call.after)
        ):
            return
        names = set()
        for start, end in tainted_args:
            names |= self._tainted_names(start, end, state)
        if names and names <= (state.guarded_path | set(state.pending_paths)):
            return
        if creation and self._assigned_root(call, stmt_start):
            return
        self._add("SKY-D215", "HIGH", _PATH_MESSAGE, call.name_start, cwe="CWE-22")

    def _assigned_root(self, call: _Call, stmt_start: int) -> bool:
        call_start = call.name_start
        if call.receiver:
            call_start = call.receiver_start
        prefix = self.code[stmt_start:call_start]
        if not re.search(r"(?:\b(?:val|var)\s+[^=]+|^\s*[\w.]+\s*)=\s*$", prefix):
            return False
        return bool(_PATH_READ_ACCESSORS.match(_statement_rest(call.after)))

    def _pending_path_call(self, start: int, end: int, state: _State) -> _Call | None:
        text = self.code[start:end]
        stripped_offset = len(text) - len(text.lstrip())
        for call in self._calls(text, start):
            if (
                call.receiver_start != start + stripped_offset
                and call.name_start != start + stripped_offset
            ):
                continue
            is_creation = (
                _is_constructor(call) and call.name in _PATH_CONSTRUCTORS
            ) or (
                call.name in {"get", "of"}
                and _last_segment(call.receiver) in _PATH_FACTORY_RECEIVERS
            )
            if not is_creation:
                return None
            if not _PATH_READ_ACCESSORS.match(_statement_rest(call.after)):
                return None
            positions = _PATH_CONSTRUCTORS.get(call.name, tuple(range(len(call.args))))
            if call.name in {"get", "of"}:
                positions = tuple(range(len(call.args)))
            names = set()
            tainted = False
            for position in positions:
                if position < len(call.args):
                    arg = call.args[position]
                    if self._is_tainted(arg[0], arg[1], "path", state):
                        tainted = True
                        names |= self._tainted_names(arg[0], arg[1], state)
            if not tainted or (names and names <= state.guarded_path):
                return None
            return call
        return None

    def _process_ssrf(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        positions: tuple[int, ...] = ()
        if call.name in _URL_READ_METHODS:
            self._process_url_read(call, receiver_type, state)
            return
        if receiver_type == "HttpClient" and call.name in _HTTP_CLIENT_METHODS:
            positions = (0,)
        elif call.name == "url" and (
            re.search(r"\bBuilder\s*\(\s*\)", call.receiver)
            or receiver_type in {"Builder", "Request.Builder"}
        ):
            positions = (0,)
        elif call.name in REST_TEMPLATE_URL_METHODS and (
            receiver_type == "RestTemplate"
            or call.receiver.strip().lower() == "resttemplate"
        ):
            positions = REST_TEMPLATE_URL_METHODS[call.name]
        elif _last_segment(call.receiver) in models.SSRF_STATIC_SINKS:
            positions = models.SSRF_STATIC_SINKS[_last_segment(call.receiver)].get(
                call.name, ()
            )
        elif call.name == "uri" and (
            self._chain_root_type(call.receiver, state) in models.WEB_CLIENT_TYPES
            or "HttpRequest.newBuilder" in call.receiver.replace(" ", "")
        ):
            positions = (0,)
        elif (
            call.name == "newBuilder" and _last_segment(call.receiver) == "HttpRequest"
        ):
            positions = (0,)
        elif _is_constructor(call) and call.name in models.SSRF_CONSTRUCTORS:
            positions = models.SSRF_CONSTRUCTORS[call.name]
        for position in positions:
            if position >= len(call.args):
                continue
            start, end = call.args[position]
            if self._is_tainted(start, end, "url", state) and not self._fixes_host(
                start, end, state
            ):
                self._add(
                    "SKY-D216",
                    "CRITICAL",
                    _SSRF_MESSAGE,
                    call.name_start,
                    cwe="CWE-918",
                )
                return

    def _process_url_read(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        receiver = call.receiver
        if not receiver:
            return
        ctor = re.match(
            r"^\s*(?:java\s*\.\s*net\s*\.\s*)?(?P<type>URL|URI)\s*\(", receiver
        )
        if ctor:
            open_paren = call.receiver_start + receiver.find("(", ctor.start("type"))
            close_paren = self.lexed.close_of(open_paren)
            spans = _split_spans(self.code, open_paren + 1, close_paren)
            if (
                spans
                and self._is_tainted(spans[0][0], spans[0][1], "url", state)
                and not self._fixes_host(spans[0][0], spans[0][1], state)
            ):
                self._add(
                    "SKY-D216",
                    "CRITICAL",
                    _SSRF_MESSAGE,
                    call.name_start,
                    cwe="CWE-918",
                )
            return
        root = _root_name(receiver)
        if root and state.types.get(root) in _URL_TYPES and root in state.tainted:
            if "url" in state.tainted[root] or root in state.fixed_host:
                return
            self._add(
                "SKY-D216", "CRITICAL", _SSRF_MESSAGE, call.name_start, cwe="CWE-918"
            )

    def _process_redirect_call(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        target = None
        if _is_constructor(call) and call.name == "RedirectView" and call.args:
            target = call.args[0]
        elif (
            call.name == "sendRedirect"
            and call.args
            and (
                receiver_type in RESPONSE_TYPES
                or call.receiver.strip() in _RESPONSE_NAMES
            )
        ):
            target = call.args[0]
        elif call.name == "respondRedirect" and call.args:
            target = call.args[0]
        if target is None:
            return
        if self._redirect_tainted(target[0], target[1], state):
            self._add(
                "SKY-D230", "HIGH", _REDIRECT_MESSAGE, call.name_start, cwe="CWE-601"
            )

    def _redirect_tainted(self, start: int, end: int, state: _State) -> bool:
        if not self._is_tainted(start, end, "redirect", state):
            return False
        names = self._tainted_names(start, end, state)
        if names and names <= state.guarded_redirect:
            return False
        return not self._fixes_host(start, end, state)

    def _process_redirect_strings(
        self, start: int, end: int, header: str, state: _State
    ) -> None:
        for literal in self.lexed.strings_in(start, end):
            if header[literal.start - start] != '"':
                continue
            lowered = literal.prefix.lower()
            prefix = next(
                (p for p in models.REDIRECT_PREFIXES if lowered.startswith(p)), None
            )
            if prefix is None:
                continue
            rest = literal.prefix[len(prefix) :]
            if models.url_prefix_fixes_host(rest):
                continue
            tainted = any(
                self._redirect_names_tainted(expr_start, expr_end, state)
                for expr_start, expr_end in literal.exprs
            )
            if not tainted and not literal.exprs:
                plus = re.match(r"\s*\+", self.code[literal.end : end])
                if plus:
                    tail_end = _expression_tail_end(
                        self.code, literal.end + plus.end(), end
                    )
                    tainted = self._redirect_names_tainted(
                        literal.end + plus.end(), tail_end, state
                    )
            if tainted:
                self._add(
                    "SKY-D230", "HIGH", _REDIRECT_MESSAGE, literal.start, cwe="CWE-601"
                )

    def _redirect_names_tainted(self, start: int, end: int, state: _State) -> bool:
        if not self._is_tainted(start, end, "redirect", state):
            return False
        names = self._tainted_names(start, end, state)
        return not (names and names <= state.guarded_redirect)

    def _process_xss(self, call: _Call, state: _State) -> None:
        if call.name in XSS_WRITER_METHODS | {"append"} and re.search(
            r"(?:\bwriter|\bgetWriter\s*\(\s*\))\s*$", call.receiver
        ):
            root = _root_name(call.receiver)
            if root in state.response_vars or root in _RESPONSE_NAMES:
                if self._any_arg_tainted(call.args, "xss", state):
                    self._add(
                        "SKY-D226",
                        "HIGH",
                        "Servlet response writes request-controlled data without HTML encoding.",
                        call.name_start,
                        cwe="CWE-79",
                    )
            return
        if call.name == "respondText" and call.args:
            html = any(
                _HTML_CONTENT_TYPE_RE.search(self.code[s:e]) for s, e in call.args[1:]
            )
            start, end = call.args[0]
            if html and self._is_tainted(start, end, "xss", state):
                self._add(
                    "SKY-D226",
                    "HIGH",
                    "HTML response contains request-controlled data without HTML encoding.",
                    call.name_start,
                    cwe="CWE-79",
                )

    def _process_deserialization(self, call: _Call, state: _State) -> None:
        if not _is_constructor(call) or not call.args:
            return
        if call.name == "ObjectInputStream":
            start, end = call.args[0]
            before = self.code[max(0, call.name_start - 40) : call.name_start]
            filtered = bool(re.search(r":\s*$", before)) or bool(
                re.search(
                    r"\bsetObjectInputFilter\s*\(|\bobjectInputFilter\s*=", self.code
                )
            )
            if filtered:
                self._add(
                    "SKY-D204",
                    "MEDIUM",
                    "ObjectInputStream deserializes with a class filter. Confirm the filter allows only expected classes.",
                    call.name_start,
                    cwe="CWE-502",
                )
            elif self._is_tainted(start, end, "code", state) or self._is_network_stream(
                start, end, state
            ):
                self._add(
                    "SKY-D204",
                    "CRITICAL",
                    "ObjectInputStream deserializes request or network data, which can run code. Use a data-only format or an ObjectInputFilter allowlist.",
                    call.name_start,
                    cwe="CWE-502",
                )
            else:
                self._add(
                    "SKY-D204",
                    "HIGH",
                    "ObjectInputStream deserializes data without a class filter. Use a data-only format or set an ObjectInputFilter allowlist.",
                    call.name_start,
                    cwe="CWE-502",
                )
            return
        if call.name == "XMLDecoder":
            start, end = call.args[0]
            if self.lexed.string_at(_skip_space(self.code, start)) is not None:
                return
            severity = "HIGH"
            if self._is_tainted(start, end, "code", state) or self._is_network_stream(
                start, end, state
            ):
                severity = "CRITICAL"
            self._add(
                "SKY-D233",
                severity,
                "XMLDecoder can call arbitrary methods while reading XML. Do not decode untrusted input; use a data-only format.",
                call.name_start,
                cwe="CWE-502",
            )

    def _process_xml(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        root = _root_name(call.receiver)
        if call.name in models.XML_UNKNOWN_CONFIG_METHODS and root in state.xml:
            state.xml_unknown.add(root)
            return
        if (
            call.name in models.XML_SETTING_METHODS
            and root in state.xml
            and len(call.args) >= 2
        ):
            key = self._xml_setting_key(*call.args[0])
            if key is not None:
                state.xml[root].settings[key] = self._xml_setting_value(*call.args[1])
            return
        xml = None
        if root and call.receiver.strip() == root and root in state.xml:
            xml = state.xml[root]
            if root in state.xml_unknown:
                return
        elif call.receiver:
            xml = self._xml_for_chain(
                call.receiver_start, call.receiver_start + len(call.receiver), state
            )
        if xml is None or xml.kind in {
            "Transformer",
            "TransformerFactory",
            "SchemaFactory",
        }:
            return
        if call.name not in models.XML_PARSE_SINKS.get(xml.kind, ()):
            return
        if not call.args:
            return
        start, end = call.args[0]
        if self._is_bundled_input(start, end):
            return
        if models.xml_settings_safe(xml.root_kind, xml.settings):
            return
        severity = "HIGH"
        if any(self._is_tainted(s, e, "code", state) for s, e in call.args):
            severity = "CRITICAL"
        self._add(
            "SKY-D236",
            severity,
            f"{xml.kind} parses XML with DTDs and external entities enabled (XXE). Set disallow-doctype-decl to true, or turn off external entities, before creating the parser.",
            call.name_start,
            category="xxe",
            cwe="CWE-611",
        )

    def _process_expression(
        self, call: _Call, receiver_type: str | None, state: _State
    ) -> None:
        if receiver_type is None:
            return
        needed = _EXPRESSION_TYPES_NEEDING_IMPORT.get(receiver_type)
        if needed and not any(item.startswith(needed) for item in self.imports):
            return
        positions = models.EXPRESSION_SINKS.get(receiver_type, {}).get(call.name, ())
        if not positions:
            return
        if not any(
            position < len(call.args)
            and self._is_tainted(
                call.args[position][0], call.args[position][1], "code", state
            )
            for position in positions
        ):
            return
        if (
            call.name in {"parseExpression", "parseRaw"}
            and "SimpleEvaluationContext" in self.code
        ):
            return
        if receiver_type in SCRIPT_RECEIVER_TYPES:
            message = "Script source is built from request-controlled data. Never evaluate input as code."
            cwe = "CWE-94"
        elif call.name in {
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
        self._add(
            "SKY-D237",
            "CRITICAL",
            message,
            call.name_start,
            category="expression_injection",
            cwe=cwe,
        )

    def _scan_file_patterns(self) -> None:
        code = self.code
        for match in re.finditer(
            r"\b(?:enableDefaultTyping|enableDefaultTypingAsProperty)\s*\(", code
        ):
            self._add(
                "SKY-D233",
                "HIGH",
                "Jackson default typing lets JSON choose the class to create. Use activateDefaultTyping with an allowlisting PolymorphicTypeValidator.",
                match.start(),
                cwe="CWE-502",
            )
        for match in re.finditer(r"\bactivateDefaultTyping\s*\(", code):
            close = self.lexed.close_of(match.end() - 1)
            if (
                close != -1
                and "LaissezFaireSubTypeValidator" in code[match.end() : close]
            ):
                self._add(
                    "SKY-D233",
                    "HIGH",
                    "Jackson default typing with LaissezFaireSubTypeValidator accepts any class. Use a validator that allowlists your own types.",
                    match.start(),
                    cwe="CWE-502",
                )
        for match in _KRYO_OPEN_RE.finditer(code):
            self._add(
                "SKY-D233",
                "HIGH",
                "Kryo with registration turned off deserializes any class named in the input. Keep registration required and register expected classes.",
                match.start(),
                cwe="CWE-502",
            )

    def _scan_android(self) -> None:
        code = self.code
        enabled_scopes = set()
        for match in _JS_ENABLED_RE.finditer(code):
            enabled_scopes.add(self._scope_key(match.start()))
        for match in _JS_BRIDGE_RE.finditer(code):
            if self._scope_key(match.start()) in enabled_scopes:
                self._add(
                    "SKY-D257",
                    "HIGH",
                    "WebView exposes a Java object to JavaScript (addJavascriptInterface) while JavaScript is enabled. Any page the WebView loads can call its @JavascriptInterface methods; load only trusted content or remove the bridge.",
                    match.start(),
                    category="android_webview",
                    cwe="CWE-749",
                )
        for match in _FILE_URL_ACCESS_RE.finditer(code):
            self._add(
                "SKY-D258",
                "MEDIUM",
                "WebView lets file:// pages read local files or any origin (allowFileAccessFromFileURLs / allowUniversalAccessFromFileURLs). Keep these settings false.",
                match.start(),
                category="android_webview",
                cwe="CWE-200",
            )

    def _scope_key(self, offset: int) -> int:
        owner = self._owner(offset)
        if owner is None:
            return -1
        return owner.start

    def _receiver_type(self, call: _Call, state: _State) -> str | None:
        receiver = call.receiver.strip()
        if not receiver:
            return None
        if re.fullmatch(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)", receiver):
            return "Runtime"
        if re.fullmatch(_IDENT, receiver):
            name = receiver.strip("`")
            if name in state.types:
                return state.types[name]
            return None
        return self._expression_type(
            call.receiver_start, call.receiver_start + len(call.receiver), state
        )

    def _chain_root_type(self, receiver: str, state: _State) -> str | None:
        root = _root_name(receiver)
        if root and root in state.types:
            return state.types[root]
        ctor = re.match(
            r"\s*(?P<type>[A-Z]\w*)\s*\.\s*(?:create|builder)\s*\(", receiver
        )
        if ctor:
            return ctor.group("type")
        return None

    def _expression_type(self, start: int, end: int, state: _State) -> str | None:
        text = self.code[start:end].strip()
        if not text:
            return None
        scope = re.search(r"\.\s*(?:apply|also)\s*\{", text)
        if scope and matching_close(text, scope.end() - 1, "{", "}") == len(text) - 1:
            text = text[: scope.start()].rstrip()
        cast = re.search(r"\sas\??\s+[\w.<>?]+$", text)
        if cast:
            text = text[: cast.start()].rstrip()
        if re.fullmatch(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)", text):
            return "Runtime"
        ctor = re.fullmatch(
            rf"(?:[a-z_][\w]*\s*\.\s*)*(?P<type>[A-Z]\w*)(?:\s*\.\s*(?P<inner>[A-Z]\w*))?\s*(?:{_GENERIC})?\s*\((?P<rest>[\s\S]*)\)",
            text,
        )
        if ctor and self._balanced_tail(text, ctor.start("rest") - 1):
            if ctor.group("inner"):
                return f"{ctor.group('type')}.{ctor.group('inner')}"
            return ctor.group("type")
        last = re.search(rf"\.\s*(?P<method>{_IDENT})\s*\([^()]*\)\s*$", text)
        if last and last.group("method") in models.CALL_RESULT_TYPES:
            return models.CALL_RESULT_TYPES[last.group("method")]
        if re.fullmatch(_IDENT, text) and text in state.types:
            return state.types[text]
        return None

    def _balanced_tail(self, text: str, open_index: int) -> bool:
        return matching_close(text, open_index, "(", ")") == len(text) - 1

    def _xml_for_chain(self, start: int, end: int, state: _State) -> _Xml | None:
        text = self.code[start:end].strip()
        if not text:
            return None
        root_match = re.match(
            r"^(?:[a-z_]\w*\s*\.\s*)*(?P<factory>[A-Z]\w*)\s*\.\s*(?P<method>\w+)\s*\(\s*\)",
            text,
        )
        xml = None
        rest = text
        if (
            root_match
            and root_match.group("factory") in models.XML_FACTORY_TYPES
            and root_match.group("method") in models.XML_FACTORY_METHODS
        ):
            kind = models.XML_FACTORY_TYPES[root_match.group("factory")]
            xml = _Xml(kind=kind, settings={}, root_kind=kind)
            rest = text[root_match.end() :]
        else:
            ctor = re.match(r"^(?P<type>[A-Z]\w*)\s*\(\s*\)", text)
            if ctor and ctor.group("type") in models.XML_PARSER_CONSTRUCTORS:
                kind = models.XML_PARSER_CONSTRUCTORS[ctor.group("type")]
                xml = _Xml(kind=kind, settings={}, root_kind=kind)
                rest = text[ctor.end() :]
            else:
                var = re.match(rf"^(?P<name>{_IDENT})", text)
                if var and var.group("name") in state.xml:
                    if var.group("name") in state.xml_unknown:
                        return None
                    xml = state.xml[var.group("name")]
                    rest = text[var.end() :]
        if xml is None:
            return None
        for step in re.finditer(r"\.\s*(?P<method>\w+)\s*(?:\(\s*\))?", rest):
            method = step.group("method")
            if method == "xmlReader":
                method = "getXMLReader"
            derived = models.XML_DERIVED_OBJECTS.get((xml.kind, method))
            if derived is None:
                if rest[step.end() :].strip():
                    return None
                break
            xml = _Xml(kind=derived, settings=xml.settings, root_kind=xml.root_kind)
        if rest.strip() and not re.fullmatch(
            r"(?:\s*\.\s*\w+\s*(?:\(\s*\))?)*\s*", rest
        ):
            return None
        return xml

    def _xml_setting_key(self, start: int, end: int) -> str | None:
        literal = self._literal_value(start, end)
        if literal is not None:
            return models.XML_SETTING_URIS.get(literal)
        text = self.code[start:end].strip()
        constant = re.fullmatch(
            r"(?:(?P<owner>[\w.]+)\s*\.\s*)?(?P<name>[A-Z_]+)", text
        )
        if constant and constant.group("name") in models.XML_SETTING_CONSTANTS:
            owner = constant.group("owner")
            if owner is None or owner in models.XML_CONSTANT_OWNERS:
                return models.XML_SETTING_CONSTANTS[constant.group("name")]
        return None

    def _xml_setting_value(self, start: int, end: int):
        text = self.code[start:end].strip()
        if text == "true":
            return True
        if text == "false":
            return False
        literal = self._literal_value(start, end)
        if literal is not None:
            return literal
        return _UNKNOWN

    def _is_bundled_input(self, start: int, end: int) -> bool:
        text = self.code[start:end]
        if self._literal_value(start, end) is not None:
            return True
        resource = re.search(
            r"\b(?:getResourceAsStream|getResource|getSystemResourceAsStream|getSystemResource|ClassPathResource)\s*\(",
            text,
        )
        if resource is None:
            return False
        open_paren = start + resource.end() - 1
        close_paren = self.lexed.close_of(open_paren)
        return all(
            self._is_constant_value(s, e)
            for s, e in _split_spans(self.code, open_paren + 1, close_paren)
        )

    def _is_network_stream(self, start: int, end: int, state: _State) -> bool:
        text = self.code[start:end]
        for match in re.finditer(
            rf"(?P<name>{_IDENT})\s*\.\s*(?:getInputStream\s*\(\s*\)|inputStream\b)",
            text,
        ):
            name = match.group("name")
            if (
                name in state.request_vars
                or state.types.get(name) in models.SOCKET_TYPES
            ):
                return True
        return bool(re.search(r"\bcall\s*\.\s*receive(?:Stream|Channel)\b", text))

    def _taint_kinds(
        self, start: int, end: int, state: _State
    ) -> frozenset[str] | None:
        tainted_any = False
        safe = set()
        for kind in _KINDS:
            if self._is_tainted(start, end, kind, state):
                tainted_any = True
            else:
                safe.add(kind)
        if not tainted_any:
            return None
        return frozenset(safe)

    def _is_tainted(self, start: int, end: int, kind: str, state: _State) -> bool:
        if start >= end:
            return False
        if kind == "xss":
            return any(
                self._hole_tainted(hole_start, hole_end, hole_kind, state)
                for hole_start, hole_end, hole_kind in self._html_holes(start, end)
            )
        return self._hole_tainted(start, end, kind, state)

    def _hole_tainted(self, start: int, end: int, kind: str, state: _State) -> bool:
        text = self._sanitized(start, end, kind)
        if self._has_source(text, state):
            return True
        name_kind = kind
        if kind == _HTML_RAW:
            name_kind = None
        return bool(self._tainted_names_in_text(text, name_kind, state))

    def _html_holes(self, start: int, end: int) -> list[tuple[int, int, str]]:
        literals = self.lexed.strings_in(start, end)
        whole = [(start, end, "xss")]
        if not any("<" in literal.literal_text for literal in literals):
            return whole
        code = self.code
        parts = []
        spans = []
        depth = 0
        cursor = start
        position = start
        found = False
        for literal in literals:
            if literal.start < cursor:
                continue
            for char in code[cursor : literal.start]:
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    depth -= 1
            cursor = literal.start
            if depth:
                continue
            found = True
            if code[position : literal.start].strip(_HTML_JOINERS):
                parts.append(("value", (), False))
                spans.append((position, literal.start))
            for index, piece in enumerate(literal.texts):
                parts.append(("text", _string_text(piece, literal.raw)))
                if index < len(literal.exprs):
                    parts.append(("value", (), False))
                    spans.append(literal.exprs[index])
            position = literal.end
            cursor = literal.end
        if not found:
            return whole
        if code[position:end].strip(_HTML_JOINERS):
            parts.append(("value", (), False))
            spans.append((position, end))
        holes = []
        for (hole_start, hole_end), (level, _) in zip(spans, hole_requirements(parts)):
            holes.append((hole_start, hole_end, _html_kind(level)))
        return holes

    def _encoder_call_pattern(self) -> re.Pattern:
        names = set(_HTML_ENCODER_OWNERS) | _ESAPI_ENCODER_METHODS
        for bound, path in self.import_bindings.items():
            if _imported_encoder(path) is not None:
                names.add(bound)
        alternatives = "|".join(sorted(re.escape(name) for name in names))
        return re.compile(rf"\b(?P<name>{alternatives})\s*\(")

    def _encoder_binding_ranges(self) -> dict[str, list[tuple[int, int]]]:
        """Record lexical bindings that take precedence over an encoder import."""
        code = self.code
        blocks = [
            (index, self.lexed.close_of(index))
            for index, char in enumerate(code)
            if char == "{" and self.lexed.close_of(index) != -1
        ]
        class_headers = []
        for match, owner in zip(_CLASS_RE.finditer(code), self.classes):
            header_end = owner.start
            if header_end == match.start():
                header_end = code.find("\n", match.end())
                if header_end == -1:
                    header_end = len(code)
                opening = code.find("(", match.end(), header_end)
                if opening != -1:
                    header_end = max(header_end, self.lexed.close_of(opening) + 1)
            class_headers.append((match.start(), header_end, owner))
        bindings: dict[str, list[tuple[int, int]]] = {}

        def add(name: str, start: int, end: int, type_name: str | None = None) -> None:
            name = name.strip("`")
            bindings.setdefault(name, []).append((start, end))
            self.encoder_binding_types.setdefault(name, []).append(
                (start, end, type_name)
            )

        def declaration(name: str, position: int, type_name: str | None = None) -> None:
            for keyword, header_end, owner in reversed(class_headers):
                if keyword < position < header_end:
                    if owner.end > owner.start:
                        add(name, owner.start, owner.end, type_name)
                    return
            enclosing = [span for span in blocks if span[0] < position < span[1]]
            if not enclosing:
                add(name, 0, len(code), type_name)
                return
            start, end = max(enclosing)
            # Members are visible throughout their class; locals start at their declaration.
            if not any(owner.start == start for owner in self.classes):
                start = position
            add(name, start, end, type_name)

        for function in self._functions():
            for param in function.params:
                add(param.name, function.start, function.end, param.type)
        for match in _FIELD_RE.finditer(code):
            declaration(
                match.group("name"),
                match.start(),
                match.group("type") or match.group("ctor"),
            )
        for match in re.finditer(r"\b(?:val|var)\s*\(([^()]*)\)", code):
            for name in match.group(1).split(","):
                name = name.split(":", 1)[0].strip()
                if _IDENT_RE.fullmatch(name):
                    declaration(name, match.start())
        for start, end in blocks:
            match = re.match(r"\s*([^{}\n]+?)\s*->", code[start + 1 : end])
            if not match or re.search(r"\b(?:val|var)\b", match.group(1)):
                continue
            for text in _split_top_level(match.group(1).strip().strip("()")):
                param = _parse_param(text)
                name = param.name if param else text.strip()
                if _IDENT_RE.fullmatch(name):
                    add(name, start, end, param.type if param else None)
        for match in re.finditer(
            rf"\b(?:for|catch)\s*\(\s*(?P<name>{_IDENT})\s*(?:in\b|:)", code
        ):
            opening = code.find("(", match.start(), match.end())
            closing = self.lexed.close_of(opening)
            if closing == -1:
                continue
            body = closing + 1
            while body < len(code) and code[body].isspace():
                body += 1
            if body < len(code) and code[body] == "{":
                add(match.group("name"), body, self.lexed.close_of(body))
        return bindings

    def _encoder_shadowed(self, name: str, position: int) -> bool:
        return any(
            start <= position < end
            for start, end in self.encoder_bindings.get(name, ())
        )

    def _html_encoder_method(self, match: re.Match) -> str | None:
        if match.start() not in self.encoder_methods:
            self.encoder_methods[match.start()] = self._resolve_html_encoder(match)
        return self.encoder_methods[match.start()]

    def _resolve_html_encoder(self, match: re.Match) -> str | None:
        name = match.group("name")
        code = self.code
        index = match.start() - 1
        while index >= 0 and code[index] in " \t\r\n":
            index -= 1
        if index < 0 or code[index] != "." or (index > 0 and code[index - 1] == "."):
            return self._unqualified_encoder(name, match.start())
        receiver_end = index
        if index > 0 and code[index - 1] == "?":
            receiver_end = index - 1
        receiver_start = _chain_start(code, receiver_end - 1, self.lexed)
        receiver = re.sub(r"\s+", "", code[receiver_start:receiver_end])
        if name in _ESAPI_ENCODER_METHODS:
            return self._esapi_encoder(name, receiver, match.start())
        root = receiver.split(".", 1)[0]
        if self._encoder_shadowed(root, match.start()):
            return None
        owners = _HTML_ENCODER_OWNERS.get(name)
        if owners is None:
            return None
        if receiver in owners:
            return name
        if receiver in self.declared_types:
            return None
        if self.import_bindings.get(receiver) in owners:
            return name
        return None

    def _unqualified_encoder(self, name: str, position: int) -> str | None:
        if name in self.declared_functions or self._encoder_shadowed(name, position):
            return None
        path = self.import_bindings.get(name)
        if path is None:
            return None
        return _imported_encoder(path)

    def _esapi_encoder(self, name: str, receiver: str, position: int) -> str | None:
        match = _ESAPI_RECEIVER_RE.fullmatch(receiver)
        if match:
            root = match.group("root")
            if self._encoder_shadowed(root.split(".", 1)[0], position):
                return None
            if root == _ESAPI_CLASS:
                return name
            if (
                self.import_bindings.get(root) == _ESAPI_CLASS
                and root not in self.declared_types
            ):
                return name
            return None
        if _IDENT_RE.fullmatch(receiver):
            bindings = [
                binding
                for binding in self.encoder_binding_types.get(receiver, ())
                if binding[0] <= position < binding[1]
            ]
            if bindings:
                start, _, type_name = max(
                    bindings, key=lambda item: (item[0], -item[1])
                )
                type_name = (type_name or "").rstrip("?")
                resolved = self.import_bindings.get(type_name, type_name)
                if resolved == "org.owasp.esapi.Encoder":
                    return name
                root, _, method = type_name.rpartition(".")
                if method == "encoder" and not self._encoder_shadowed(root, start):
                    if self.import_bindings.get(root, root) == _ESAPI_CLASS:
                        return name
        return None

    def _tainted_names(self, start: int, end: int, state: _State) -> set[str]:
        if start >= end:
            return set()
        return self._tainted_names_in_text(
            self._sanitized(start, end, "path"), None, state
        )

    def _tainted_names_in_text(
        self, text: str, kind: str | None, state: _State
    ) -> set[str]:
        names = set()
        for match in _IDENT_RE.finditer(text):
            name = match.group(0).strip("`")
            safe_kinds = state.tainted.get(name)
            if safe_kinds is None or (kind is not None and kind in safe_kinds):
                continue
            before = text[: match.start()].rstrip()
            if before.endswith(".") and not before.endswith(".."):
                continue
            after = text[match.end() :]
            if re.match(r"\s*=(?![=>])", after) and before.endswith(("(", ",")):
                continue
            if re.match(r"\s*:(?!:)", after):
                continue
            names.add(name)
        return names

    def _has_source(self, text: str, state: _State) -> bool:
        if _KTOR_SOURCE_RE.search(text):
            return True
        request_names = state.request_vars | _REQUEST_NAMES
        for match in re.finditer(
            rf"(?P<name>{_IDENT})\s*(?:\?|!!)?\s*\.\s*(?P<member>\w+)", text
        ):
            name = match.group("name")
            member = match.group("member")
            before = text[: match.start()].rstrip()
            if before.endswith("."):
                continue
            if name in request_names:
                following = text[match.end() :].lstrip()
                if member in REQUEST_SOURCE_METHODS and following.startswith("("):
                    return True
                if (
                    name in state.request_vars
                    and member in _SERVLET_PROPERTIES
                    and not following.startswith("(")
                ):
                    return True
            if name in state.server_request_vars and re.fullmatch(
                _SERVER_REQUEST_METHODS, member
            ):
                return True
        for match in re.finditer(r"\b(?P<method>\w+)\s*\(\s*(?P<arg>\w+)\s*[,)]", text):
            if match.group("method") in REQUEST_HELPER_METHODS and (
                match.group("arg") in state.request_vars
                or match.group("arg") in _REQUEST_NAMES
            ):
                return True
        return False

    def _sanitized(self, start: int, end: int, kind: str) -> str:
        code = self.code
        chars = list(code[start:end])

        def blank(lo: int, hi: int) -> None:
            for index in range(max(lo, start), min(hi, end)):
                if chars[index - start] not in "\n\r":
                    chars[index - start] = " "

        for match in _NUMERIC_CONVERSION_RE.finditer(code, start, end):
            chain_start = _chain_start(code, match.start() - 1, self.lexed)
            blank(chain_start, match.end())
        for match in _STATIC_SCALAR_RE.finditer(code, start, end):
            close = self.lexed.close_of(match.end() - 1)
            if close != -1:
                blank(match.start(), close + 1)
        if kind in ("xss", "xss_attr"):
            for match in self.encoder_call_re.finditer(code, start, end):
                method = self._html_encoder_method(match)
                if method is None:
                    continue
                if kind == "xss_attr" and method in _TEXT_ONLY_ENCODERS:
                    continue
                close = self.lexed.close_of(match.end() - 1)
                if close != -1:
                    blank(match.start(), close + 1)
        if kind == "path":
            for match in _BASENAME_CALL_RE.finditer(code, start, end):
                close = self.lexed.close_of(match.end() - 1)
                if close != -1:
                    blank(match.start(), close + 1)
            for match in re.finditer(
                r"\b(?:File|Paths\s*\.\s*get|Path\s*\.\s*of)\s*\(", code[start:end]
            ):
                open_paren = start + match.end() - 1
                close = self.lexed.close_of(open_paren)
                if (
                    close != -1
                    and close < end
                    and _BASENAME_AFTER_RE.match(code[close + 1 : end])
                ):
                    blank(start + match.start(), close + 1)
        return "".join(chars)

    def _is_string_built_sql(self, start: int, end: int, state: _State) -> bool:
        literals = self.lexed.strings_in(start, end)
        if not literals:
            return False
        if not any(_SQL_KEYWORD_RE.search(item.literal_text) for item in literals):
            return False
        for literal in literals:
            for expr_start, expr_end in literal.exprs:
                if not self._is_constant_expression(expr_start, expr_end, state):
                    return True
        masked = list(self.code[start:end])
        for literal in literals:
            for index in range(literal.start, literal.end):
                masked[index - start] = " "
        rest = "".join(masked)
        if "+" not in rest:
            return False
        operands = rest.replace("+", " ").strip()
        if not operands:
            return False
        return not self._is_constant_expression(start, end, state, ignore_strings=True)

    def _is_constant_expression(
        self, start: int, end: int, state: _State, *, ignore_strings: bool = False
    ) -> bool:
        text = self._sanitized(start, end, "sql")
        if ignore_strings:
            chars = list(text)
            for literal in self.lexed.strings_in(start, end):
                for index in range(literal.start, literal.end):
                    chars[index - start] = " "
            text = "".join(chars)
        for match in _IDENT_RE.finditer(text):
            name = match.group(0)
            before = text[: match.start()].rstrip()
            if before.endswith("."):
                continue
            if name in state.constants or name in {
                "trimIndent",
                "trimMargin",
                "true",
                "false",
                "null",
            }:
                continue
            return False
        return True

    def _is_constant_value(self, start: int, end: int) -> bool:
        text = self.code[start:end]
        for literal in self.lexed.strings_in(start, end):
            if literal.exprs:
                return False
        stripped = re.sub(r"\"[^\"]*\"|\"\"\"[\s\S]*?\"\"\"", "", text)
        stripped = re.sub(
            r"\b(?:arrayOf|listOf|mutableListOf|emptyArray|emptyList)\b", "", stripped
        )
        return re.fullmatch(r"[\s,()<>\w]*", stripped) is not None and not re.search(
            r"[A-Za-z_]", re.sub(r"<[^>]*>", "", stripped)
        )

    def _string_has_exprs(self, start: int, end: int) -> bool:
        return any(literal.exprs for literal in self.lexed.strings_in(start, end))

    def _literal_value(self, start: int, end: int) -> str | None:
        if end == -1 or start >= end:
            return None
        text = self.code[start:end]
        offset = start + len(text) - len(text.lstrip())
        literal = self.lexed.string_at(offset)
        if literal is None or literal.exprs:
            return None
        if self.code[literal.end : end].strip():
            return None
        return literal.literal_text

    def _fixes_host(self, start: int, end: int, state: _State) -> bool:
        text = self.code[start:end].strip()
        if not text:
            return False
        if re.fullmatch(_IDENT, text) and text in state.fixed_host:
            return True
        offset = _skip_space(self.code, start)
        literal = self.lexed.string_at(offset)
        if literal is not None:
            prefix = literal.prefix
            if not literal.exprs:
                prefix = literal.literal_text
            return models.url_prefix_fixes_host(prefix)
        wrapper = re.match(
            r"\s*(?:URI\s*\.\s*create|URI|URL|Url|java\s*\.\s*net\s*\.\s*(?:URI|URL))\s*\(",
            self.code[start:end],
        )
        if wrapper:
            open_paren = start + wrapper.end() - 1
            close = self.lexed.close_of(open_paren)
            spans = _split_spans(self.code, open_paren + 1, close)
            if spans:
                return self._fixes_host(spans[0][0], spans[0][1], state)
        return False

    def _any_arg_tainted(
        self, args: list[tuple[int, int]], kind: str, state: _State
    ) -> bool:
        return any(self._is_tainted(start, end, kind, state) for start, end in args)

    def _flatten_args(self, args: list[tuple[int, int]]) -> list[tuple[int, int]]:
        flat = []
        for start, end in args:
            inner = re.match(
                r"\s*(?:arrayOf|listOf|mutableListOf)\s*\(", self.code[start:end]
            )
            if inner:
                open_paren = start + inner.end() - 1
                close = self.lexed.close_of(open_paren)
                flat.extend(_split_spans(self.code, open_paren + 1, close))
            else:
                flat.append((start, end))
        return flat


def scan_kotlin_security(lexed: KotlinSource, file_path: str) -> list[dict]:
    return KotlinSecurityScanner(lexed, file_path).scan()


def _import_bindings(code: str) -> dict[str, str]:
    bindings = {}
    for match in _IMPORT_BINDING_RE.finditer(code):
        path = match.group("path").replace("`", "")
        if path.endswith("."):
            continue
        bound = match.group("alias")
        if bound:
            bound = bound.strip("`")
        else:
            bound = path.rpartition(".")[2]
        bindings[bound] = path
    return bindings


def _imported_encoder(path: str) -> str | None:
    owner, _, method = path.rpartition(".")
    if owner in _HTML_ENCODER_OWNERS.get(method, ()):
        return method
    return None


def _html_kind(level: int) -> str:
    if level == TEXT_SAFE:
        return "xss"
    if level == ATTR_SAFE:
        return "xss_attr"
    return _HTML_RAW


def _string_text(piece: str, raw: bool) -> str:
    if raw:
        return piece
    return _KOTLIN_ESCAPE_RE.sub(_unescape, piece)


def _unescape(match: re.Match) -> str:
    token = match.group(1)
    if len(token) == 5:
        return chr(int(token[1:], 16))
    return _KOTLIN_ESCAPES.get(token, token)


def _is_constructor(call: _Call) -> bool:
    if not call.name[:1].isupper():
        return False
    receiver = call.receiver.strip()
    return (
        not receiver
        or re.fullmatch(r"[a-z_]\w*(?:\s*\.\s*[a-z_]\w*)*", receiver) is not None
    )


def _simple_type(type_text: str | None) -> str:
    if not type_text:
        return ""
    text = type_text.strip().rstrip("?").strip()
    text = re.sub(_GENERIC, "", text)
    text = text.split("=")[0].strip().rstrip("?")
    if "." in text:
        parts = text.split(".")
        if len(parts) >= 2 and parts[-2][:1].isupper():
            return ".".join(parts[-2:])
        return parts[-1]
    return text


def _last_segment(receiver: str) -> str:
    text = receiver.strip()
    if not text or not re.fullmatch(r"[\w.\s]+", text):
        return ""
    return text.replace(" ", "").split(".")[-1]


def _root_name(chain: str) -> str | None:
    match = re.match(rf"\s*(?:this\s*\.\s*)?(?P<name>{_IDENT})", chain)
    if not match:
        return None
    return match.group("name").strip("`")


def _parse_param(text: str) -> _Param | None:
    match = _PARAM_RE.match(text.strip())
    if not match:
        return None
    annotations = {
        item.group("name").split(".")[-1]
        for item in _ANNOTATION_NAME_RE.finditer(match.group("annotations") or "")
    }
    return _Param(
        name=match.group("name").strip("`"),
        type=match.group("type").strip(),
        annotations=annotations,
    )


def _annotations_before(code: str, offset: int) -> set[str]:
    line_start = code.rfind("\n", 0, offset) + 1
    start = line_start
    end = line_start - 1
    while end > 0:
        prev_start = code.rfind("\n", 0, end) + 1
        line = code[prev_start:end].strip()
        if line.endswith(")") and not line.startswith("@"):
            open_paren = _matching_open(
                code, prev_start + code[prev_start:end].rfind(")")
            )
            if open_paren == -1:
                break
            prev_start = code.rfind("\n", 0, open_paren) + 1
            line = code[prev_start:end].strip()
        if not _is_annotation_line(line):
            break
        start = prev_start
        end = prev_start - 1
    text = code[start:offset]
    return {
        match.group("name").split(".")[-1]
        for match in _ANNOTATION_NAME_RE.finditer(text)
    }


def _is_annotation_line(line: str) -> bool:
    if line.startswith("@"):
        return True
    words = line.split()
    return bool(words) and all(word in _MODIFIER_WORDS for word in words)


def _matching_open(code: str, close_index: int) -> int:
    depth = 0
    for index in range(close_index, -1, -1):
        char = code[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_top_level(text: str) -> list[str]:
    return [text[start:end] for start, end in _split_spans(text, 0, len(text))]


def _split_spans(text: str, start: int, end: int) -> list[tuple[int, int]]:
    if end == -1 or start >= end:
        return []
    spans = []
    depth = 0
    piece_start = start
    for index in range(start, end):
        char = text[index]
        if char in "([{<":
            if char == "<" and not _looks_generic(text, index):
                continue
            depth += 1
        elif char in ")]}>":
            if char == ">" and (index > 0 and text[index - 1] in "-="):
                continue
            if char == ">" and depth == 0:
                continue
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            spans.append((piece_start, index))
            piece_start = index + 1
    if text[piece_start:end].strip():
        spans.append((piece_start, end))
    return [span for span in spans if text[span[0] : span[1]].strip()]


def _looks_generic(text: str, index: int) -> bool:
    return (
        index > 0
        and (text[index - 1].isalnum() or text[index - 1] == "_")
        and text[index - 1 : index + 2] != "< "
    )


def _skip_space(code: str, index: int) -> int:
    while index < len(code) and code[index] in " \t\r\n":
        index += 1
    return index


def _chain_start(code: str, index: int, lexed: KotlinSource) -> int:
    start = index + 1
    while index >= 0:
        while index >= 0 and code[index] in " \t":
            index -= 1
        if index < 0:
            break
        char = code[index]
        if char == "!" and index > 0 and code[index - 1] == "!":
            index -= 2
            continue
        if char in ")]":
            opener = "["
            if char == ")":
                opener = "("
            depth = 0
            while index >= 0:
                if code[index] == char:
                    depth += 1
                elif code[index] == opener:
                    depth -= 1
                    if depth == 0:
                        break
                index -= 1
            index -= 1
            start = index + 1
            while index >= 0 and code[index] in " \t":
                index -= 1
            if index >= 0 and (code[index].isalnum() or code[index] in "_`>"):
                continue
            if index >= 0 and code[index] == ".":
                index -= 1
                if index >= 0 and code[index] == "?":
                    index -= 1
                continue
            break
        if char == '"':
            literal = lexed.string_ending_at(index + 1)
            if literal is None:
                break
            start = literal.start
            break
        if char.isalnum() or char in "_`":
            while index >= 0 and (code[index].isalnum() or code[index] in "_`"):
                index -= 1
            start = index + 1
            probe = index
            while probe >= 0 and code[probe] in " \t\n":
                probe -= 1
            if probe >= 0 and code[probe] == ".":
                index = probe - 1
                if index >= 0 and code[index] == "?":
                    index -= 1
                continue
            break
        if char == ">":
            depth = 0
            probe = index
            while probe >= 0:
                if code[probe] == ">":
                    depth += 1
                elif code[probe] == "<":
                    depth -= 1
                    if depth == 0:
                        break
                elif code[probe] in "\n;={}":
                    probe = -1
                    break
                probe -= 1
            if probe <= 0:
                break
            index = probe - 1
            continue
        break
    return start


def _body_brace(code: str, index: int) -> int:
    depth = 0
    position = index
    while position < len(code):
        char = code[position]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(depth - 1, 0)
        elif char == "{" and depth == 0:
            return position
        elif char == "\n" and depth == 0:
            rest = code[position + 1 : position + 200].lstrip()
            if not rest.startswith(("{", ":", ",", "where", "(")) and not code[
                index:position
            ].rstrip().endswith((",", ":", "(")):
                return -1
        elif char in "};=" and depth == 0:
            return -1
        position += 1
    return -1


def _function_body(lexed: KotlinSource, index: int) -> tuple[int, int] | None:
    code = lexed.code
    depth = 0
    position = index
    while position < len(code):
        char = code[position]
        if char in "([<":
            depth += 1
        elif char in ")]>":
            if char == ">" and code[position - 1] == "-":
                position += 1
                continue
            depth = max(depth - 1, 0)
        elif depth == 0 and char == "{":
            close = lexed.close_of(position)
            if close == -1:
                return None
            return position + 1, close
        elif depth == 0 and char == "=":
            end = _expression_tail_end(code, position + 1, len(code), multiline=True)
            return position + 1, end
        elif (
            depth == 0
            and char in "}\n;"
            and not code[index:position].strip().endswith(":")
        ):
            rest = code[position + 1 : position + 200].lstrip()
            if char == "\n" and rest.startswith(("=", "{", ":", "where")):
                position += 1
                continue
            if char == "\n" and not code[index:position].strip():
                position += 1
                continue
            return None
        position += 1
    return None


def _expression_tail_end(
    code: str, start: int, limit: int, multiline: bool = False
) -> int:
    depth = 0
    position = start
    while position < limit:
        char = code[position]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return position
            depth -= 1
        elif depth == 0 and char in ",;":
            return position
        elif depth == 0 and char == "\n":
            if not code[start:position].strip():
                position += 1
                continue
            if not _continues(code, start, position, limit):
                return position
        position += 1
    return limit


def _continues(code: str, stmt_start: int, newline: int, limit: int) -> bool:
    text = code[stmt_start:newline].rstrip()
    if not text.strip():
        return True
    tail2 = text[-2:]
    if tail2 in {"++", "--", "!!"}:
        return False
    if tail2 == "?:" or tail2 == "->":
        return True
    if text[-1] in "=+-*/%&|.,(:[":
        return True
    following = code[newline + 1 : min(limit, newline + 200)].lstrip()
    if following.startswith(
        ("?.", "?:", ".", "&&", "||", "as ", "as?", ":")
    ) and not following.startswith(".."):
        return True
    return bool(re.match(r"(?:else|catch|finally)\b", following))


def _statements(lexed: KotlinSource, start: int, end: int) -> list[tuple[int, int]]:
    code = lexed.code
    statements = []
    stmt_start = start
    position = start
    while position < end:
        char = code[position]
        if char in "([{":
            close = lexed.close_of(position)
            if start <= close < end:
                position = close + 1
                continue
        elif char == ";":
            statements.append((stmt_start, position))
            stmt_start = position + 1
        elif char == "\n":
            if code[stmt_start:position].strip() and not _continues(
                code, stmt_start, position, end
            ):
                statements.append((stmt_start, position))
                stmt_start = position + 1
        position += 1
    if code[stmt_start:end].strip():
        statements.append((stmt_start, end))
    return statements


def _top_blocks(lexed: KotlinSource, start: int, end: int) -> list[tuple[int, int]]:
    code = lexed.code
    blocks = []
    position = code.find("{", start, end)
    while position != -1:
        close = lexed.close_of(position)
        if close == -1 or close > end:
            break
        blocks.append((position, close))
        position = code.find("{", close + 1, end)
    return blocks


def _statement_rest(after: str) -> str:
    end = len(after)
    for index, char in enumerate(after):
        if char in "\n;,)}":
            end = index
            break
    return after[:end]
