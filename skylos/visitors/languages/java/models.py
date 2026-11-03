"""Receiver-typed Java source, sink and parser-hardening models.

Sink names alone are ambiguous in Java (``query``, ``search``, ``lookup``,
``compile``), so each model here names the receiver types that make a call a
sink. The lists follow CodeQL's models-as-data and FindSecBugs' injection-sink
files; XML parser hardening follows CodeQL ``XmlParsers.qll`` per parser type.
"""

from __future__ import annotations

import re

SPRING_HANDLER_ANNOTATIONS = frozenset(
    {
        "RequestMapping",
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
    }
)

JAXRS_HANDLER_ANNOTATIONS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)

NON_INPUT_PARAM_ANNOTATIONS = frozenset(
    {
        "AuthenticationPrincipal",
        "Auth",
        "CurrentSecurityContext",
        "SessionAttribute",
        "RequestAttribute",
        "Value",
        "Context",
        "Suspended",
        "Autowired",
        "Qualifier",
        "Inject",
    }
)

NON_INPUT_PARAM_TYPES = frozenset(
    {
        "WebRequest",
        "NativeWebRequest",
        "ServletRequest",
        "HttpServletRequest",
        "ServletResponse",
        "HttpServletResponse",
        "ServerHttpResponse",
        "HttpSession",
        "WebSession",
        "PushBuilder",
        "Principal",
        "Authentication",
        "HttpMethod",
        "Locale",
        "TimeZone",
        "ZoneId",
        "OutputStream",
        "Writer",
        "PrintWriter",
        "RedirectAttributes",
        "Errors",
        "BindingResult",
        "SessionStatus",
        "UriComponentsBuilder",
        "ServletUriComponentsBuilder",
        "Pageable",
        "Sort",
        "Model",
        "ModelMap",
        "ExtendedModelMap",
        "Map",
        "ModelAndView",
        "AsyncResponse",
        "SecurityContext",
        "UriInfo",
        "HttpHeaders",
        "Request",
        "Providers",
        "Application",
        "Configuration",
        "ResourceContext",
        "Sse",
        "SseEventSink",
    }
)

SCALAR_PARAM_TYPES = frozenset(
    {
        "byte",
        "short",
        "int",
        "long",
        "float",
        "double",
        "boolean",
        "Byte",
        "Short",
        "Integer",
        "Long",
        "Float",
        "Double",
        "Boolean",
        "BigInteger",
        "BigDecimal",
        "UUID",
        "LocalDate",
        "LocalDateTime",
        "LocalTime",
        "Instant",
        "OffsetDateTime",
        "ZonedDateTime",
    }
)

UPLOAD_PARAM_TYPES = frozenset({"MultipartFile", "Part"})

SQL_RECEIVER_TYPES = frozenset(
    {
        "Statement",
        "PreparedStatement",
        "CallableStatement",
        "Connection",
        "JdbcTemplate",
        "JdbcOperations",
        "NamedParameterJdbcTemplate",
        "NamedParameterJdbcOperations",
        "SimpleJdbcTemplate",
        "EntityManager",
        "Session",
        "StatelessSession",
        "SharedSessionContract",
        "QueryRunner",
    }
)

SQL_RECEIVER_NAMES = frozenset(
    {
        "em",
        "entitymanager",
        "jdbctemplate",
        "namedparameterjdbctemplate",
        "jdbc",
        "stmt",
        "statement",
        "conn",
        "connection",
    }
)

SQL_DISTINCT_SINKS = {
    "prepareCall": (0,),
    "prepareStatement": (0,),
    "executeQuery": (0,),
    "executeUpdate": (0,),
    "executeLargeUpdate": (0,),
    "queryForObject": (0,),
    "queryForRowSet": (0,),
    "queryForList": (0,),
    "queryForMap": (0,),
    "queryForStream": (0,),
    "queryForInt": (0,),
    "queryForLong": (0,),
    "createNativeQuery": (0,),
    "createSQLQuery": (0,),
    "nativeSQL": (0,),
}

SQL_TYPED_SINKS = {
    "execute": (0,),
    "query": (0,),
    "update": (0,),
    "batchUpdate": (0,),
    "addBatch": (0,),
    "createQuery": (0,),
    "createSelectionQuery": (0,),
    "createMutationQuery": (0,),
}

LDAP_SEARCH_SINKS = {
    "DirContext": {"search": (0, 1)},
    "InitialDirContext": {"search": (0, 1)},
    "LdapContext": {"search": (0, 1)},
    "InitialLdapContext": {"search": (0, 1)},
    "EventDirContext": {"search": (0, 1)},
    "LdapTemplate": {
        "search": (0, 1),
        "searchForObject": (0, 1),
        "searchForContext": (0, 1),
        "find": (0, 1),
        "findOne": (0, 1),
        "authenticate": (0, 1),
    },
    "LdapOperations": {
        "search": (0, 1),
        "searchForObject": (0, 1),
        "searchForContext": (0, 1),
        "find": (0, 1),
        "findOne": (0, 1),
        "authenticate": (0, 1),
    },
    "LDAPConnection": {
        "search": (0, 2),
        "searchForEntry": (0, 2),
        "asyncSearch": (0, 3),
    },
    "LDAPInterface": {"search": (0, 2), "searchForEntry": (0, 2)},
}

XPATH_SINKS = {
    "XPath": {"compile": (0,), "evaluate": (0,), "evaluateExpression": (0,)},
}

EXPRESSION_SINKS = {
    "ExpressionParser": {"parseExpression": (0,), "parseRaw": (0,)},
    "SpelExpressionParser": {"parseExpression": (0,), "parseRaw": (0,)},
    "TemplateAwareExpressionParser": {"parseExpression": (0,)},
    "Context": {"lookup": (0,), "lookupLink": (0,)},
    "InitialContext": {"lookup": (0,), "lookupLink": (0,), "doLookup": (0,)},
    "DirContext": {"lookup": (0,), "lookupLink": (0,)},
    "InitialDirContext": {"lookup": (0,), "lookupLink": (0,)},
    "LdapContext": {"lookup": (0,), "lookupLink": (0,)},
    "InitialLdapContext": {"lookup": (0,), "lookupLink": (0,)},
    "JndiTemplate": {"lookup": (0,)},
    "JndiLocatorDelegate": {"lookup": (0,)},
    "LdapTemplate": {"lookup": (0,), "lookupContext": (0,), "findByDn": (0,)},
    "LdapOperations": {"lookup": (0,), "lookupContext": (0,), "findByDn": (0,)},
    "ScriptEngine": {"eval": (0,)},
    "Compilable": {"compile": (0,)},
    "GroovyShell": {"evaluate": (0,), "parse": (0,), "run": (0,)},
    "GroovyClassLoader": {"parseClass": (0,)},
    "Eval": {"me": (0, 2), "x": (1,), "xy": (2,), "xyz": (3,)},
    "Ognl": {"getValue": (0,), "setValue": (0,), "parseExpression": (0,)},
    "OgnlUtil": {
        "getValue": (0,),
        "setValue": (0,),
        "callMethod": (0,),
        "compile": (0,),
    },
    "ValueStack": {"findValue": (0,), "findString": (0,), "setValue": (0,)},
    "MVEL": {
        "eval": (0,),
        "evalToBoolean": (0,),
        "evalToString": (0,),
        "compileExpression": (0,),
        "executeAllExpression": (0,),
        "executeSetExpression": (0,),
    },
    "ExpressionFactory": {
        "createValueExpression": (1,),
        "createMethodExpression": (1,),
    },
    "ELProcessor": {"eval": (0,), "getValue": (0,), "setValue": (0,)},
    "JexlEngine": {"createExpression": (0,), "createScript": (0,)},
    "JxltEngine": {"createExpression": (0,), "createTemplate": (0,)},
}

TEMPLATE_SINKS = {
    "Velocity": {"evaluate": (3,)},
    "VelocityEngine": {"evaluate": (3,)},
    "StringTemplateLoader": {"putTemplate": (1,)},
    "TemplateEngine": {"createTemplate": (0,)},
}

TEMPLATE_CONSTRUCTORS = {"Template": (1,)}

SSRF_CONSTRUCTORS = {
    "HttpGet": (0,),
    "HttpPost": (0,),
    "HttpPut": (0,),
    "HttpDelete": (0,),
    "HttpHead": (0,),
    "HttpOptions": (0,),
    "HttpPatch": (0,),
    "HttpTrace": (0,),
}

SSRF_STATIC_SINKS = {
    "WebClient": {"create": (0,)},
    "RestClient": {"create": (0,)},
    "Jsoup": {"connect": (0,)},
    "RequestBuilder": {
        "get": (0,),
        "post": (0,),
        "put": (0,),
        "delete": (0,),
        "head": (0,),
        "options": (0,),
        "patch": (0,),
        "trace": (0,),
    },
}

WEB_CLIENT_TYPES = frozenset({"WebClient", "RestClient"})

REDIRECT_PREFIXES = ("redirect:", "ajaxredirect:")

CALL_RESULT_TYPES = {
    "getCurrentSession": "Session",
    "openSession": "Session",
    "openStatelessSession": "StatelessSession",
    "createStatement": "Statement",
    "getConnection": "Connection",
    "getJdbcTemplate": "JdbcTemplate",
    "getNamedParameterJdbcTemplate": "NamedParameterJdbcTemplate",
    "getJdbcOperations": "JdbcOperations",
    "createEntityManager": "EntityManager",
    "getEntityManager": "EntityManager",
    "newXPath": "XPath",
    "getEngineByName": "ScriptEngine",
    "getEngineByExtension": "ScriptEngine",
    "getEngineByMimeType": "ScriptEngine",
    "getLdapTemplate": "LdapTemplate",
}

SOCKET_TYPES = frozenset({"Socket", "SSLSocket"})

FIXED_HOST_PREFIX = re.compile(r"[?#]|[^?#:/\\][/\\]")

XML_FACTORY_METHODS = frozenset(
    {
        "newInstance",
        "newDefaultInstance",
        "newNSInstance",
        "newDefaultNSInstance",
        "newFactory",
        "newDefaultFactory",
    }
)

XML_FACTORY_TYPES = {
    "DocumentBuilderFactory": "DocumentBuilderFactory",
    "SAXParserFactory": "SAXParserFactory",
    "XMLInputFactory": "XMLInputFactory",
    "TransformerFactory": "TransformerFactory",
    "SAXTransformerFactory": "TransformerFactory",
    "SchemaFactory": "SchemaFactory",
}

XML_PARSER_CONSTRUCTORS = {
    "SAXBuilder": "SAXBuilder",
    "SAXReader": "SAXReader",
    "Digester": "Digester",
}

XML_DERIVED_OBJECTS = {
    ("DocumentBuilderFactory", "newDocumentBuilder"): "DocumentBuilder",
    ("SAXParserFactory", "newSAXParser"): "SAXParser",
    ("SAXParser", "getXMLReader"): "XMLReader",
    ("TransformerFactory", "newTransformer"): "Transformer",
}

XML_SETTING_METHODS = frozenset({"setFeature", "setAttribute", "setProperty"})

XML_UNKNOWN_CONFIG_METHODS = frozenset(
    {"setEntityResolver", "setXMLResolver", "setURIResolver", "setResourceResolver"}
)

XML_PARSE_SINKS = {
    "DocumentBuilder": frozenset({"parse"}),
    "SAXParser": frozenset({"parse"}),
    "XMLReader": frozenset({"parse"}),
    "XMLInputFactory": frozenset({"createXMLStreamReader", "createXMLEventReader"}),
    "SchemaFactory": frozenset({"newSchema"}),
    "SAXBuilder": frozenset({"build"}),
    "SAXReader": frozenset({"read"}),
    "Digester": frozenset({"parse"}),
    "Transformer": frozenset({"transform"}),
    "TransformerFactory": frozenset({"newTransformer", "newTemplates"}),
}

DISALLOW_DOCTYPE = "disallow-doctype-decl"
EXTERNAL_GENERAL = "external-general-entities"
EXTERNAL_PARAMETER = "external-parameter-entities"
LOAD_EXTERNAL_DTD = "load-external-dtd"
SECURE_PROCESSING = "secure-processing"
ACCESS_EXTERNAL_DTD = "access-external-dtd"
ACCESS_EXTERNAL_SCHEMA = "access-external-schema"
ACCESS_EXTERNAL_STYLESHEET = "access-external-stylesheet"
SUPPORT_DTD = "support-dtd"
SUPPORT_EXTERNAL_ENTITIES = "support-external-entities"

XML_SETTING_URIS = {
    "http://apache.org/xml/features/disallow-doctype-decl": DISALLOW_DOCTYPE,
    "http://xml.org/sax/features/external-general-entities": EXTERNAL_GENERAL,
    "http://xml.org/sax/features/external-parameter-entities": EXTERNAL_PARAMETER,
    "http://apache.org/xml/features/nonvalidating/load-external-dtd": LOAD_EXTERNAL_DTD,
    "http://javax.xml.XMLConstants/feature/secure-processing": SECURE_PROCESSING,
    "http://javax.xml.XMLConstants/property/accessExternalDTD": ACCESS_EXTERNAL_DTD,
    "http://javax.xml.XMLConstants/property/accessExternalSchema": ACCESS_EXTERNAL_SCHEMA,
    "http://javax.xml.XMLConstants/property/accessExternalStylesheet": ACCESS_EXTERNAL_STYLESHEET,
    "javax.xml.stream.supportDTD": SUPPORT_DTD,
    "javax.xml.stream.isSupportingExternalEntities": SUPPORT_EXTERNAL_ENTITIES,
}

XML_SETTING_CONSTANTS = {
    "FEATURE_SECURE_PROCESSING": SECURE_PROCESSING,
    "ACCESS_EXTERNAL_DTD": ACCESS_EXTERNAL_DTD,
    "ACCESS_EXTERNAL_SCHEMA": ACCESS_EXTERNAL_SCHEMA,
    "ACCESS_EXTERNAL_STYLESHEET": ACCESS_EXTERNAL_STYLESHEET,
    "SUPPORT_DTD": SUPPORT_DTD,
    "IS_SUPPORTING_EXTERNAL_ENTITIES": SUPPORT_EXTERNAL_ENTITIES,
}

XML_CONSTANT_OWNERS = frozenset(
    {
        "XMLConstants",
        "javax.xml.XMLConstants",
        "XMLInputFactory",
        "javax.xml.stream.XMLInputFactory",
    }
)

XML_PARSER_FAMILY = {
    "DocumentBuilderFactory": "dom",
    "DocumentBuilder": "dom",
    "SAXParserFactory": "sax",
    "SAXParser": "sax",
    "XMLReader": "sax",
    "SAXBuilder": "jdom",
    "SAXReader": "dom4j",
    "Digester": "sax",
    "XMLInputFactory": "stax",
    "TransformerFactory": "transform",
    "Transformer": "transform",
    "SchemaFactory": "schema",
}


def xml_settings_safe(kind: str, settings: dict) -> bool:
    family = XML_PARSER_FAMILY.get(kind)
    doctype_blocked = settings.get(DISALLOW_DOCTYPE) is True
    access_blocked = (
        settings.get(ACCESS_EXTERNAL_DTD) == ""
        and settings.get(ACCESS_EXTERNAL_SCHEMA) == ""
    )
    entities_off = (
        settings.get(EXTERNAL_GENERAL) is False
        and settings.get(EXTERNAL_PARAMETER) is False
    )
    if family == "dom":
        return doctype_blocked or entities_off or access_blocked
    if family in {"sax", "jdom"}:
        return (
            doctype_blocked
            or access_blocked
            or (entities_off and settings.get(LOAD_EXTERNAL_DTD) is False)
        )
    if family == "dom4j":
        return doctype_blocked or (
            entities_off and settings.get(LOAD_EXTERNAL_DTD) is False
        )
    if family == "stax":
        return (
            settings.get(SUPPORT_DTD) is False
            or settings.get(SUPPORT_EXTERNAL_ENTITIES) is False
        )
    if family == "transform":
        return (
            settings.get(ACCESS_EXTERNAL_DTD) == ""
            and settings.get(ACCESS_EXTERNAL_STYLESHEET) == ""
        )
    if family == "schema":
        return access_blocked
    return False


def url_prefix_fixes_host(prefix: str) -> bool:
    """A constant prefix that already chooses the host (CodeQL's
    RequestForgery prefix barrier, without its bare ``/`` case: ``"/" + x``
    becomes ``//evil.example`` when ``x`` starts with a slash)."""
    return bool(FIXED_HOST_PREFIX.search(prefix))
