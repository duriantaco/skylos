"""SKY-D253: a secret compared with request input by ``==``/``===``.

A timing oracle needs two things: an expected value the attacker does not
know (an environment or config credential, an HMAC the server computes, a
stored token or password) and a guess the attacker sends and can vary byte by
byte. The rule therefore classifies both operands of an equality instead of
reading names alone:

* ``request``: request data in a handler (``req.body.x``, ``req.get('x')``,
  ``request.headers.get('x')``, ``searchParams.get('x')``, ``formData.get``,
  a destructured ``({ body }: Request)`` field) or a local bound from one.
* ``param``: a parameter of the enclosing function (data of unknown origin).
* ``strong``: an environment or config credential, an HMAC digest, or a
  member the function itself filled from one of those.
* ``named``: a credential-named value that is neither request data nor a
  parameter (``user.resetToken``, ``storedHash``, ``this.apiKey``).
* ``digest``: the result of a hash call (``hash(x)``, ``md5(x)``,
  ``createHash(...).digest()``). The attacker cannot steer digest bytes, so a
  digest is neither a guess nor a usable expected value.
* ``literal``: a literal, ``null``/``undefined`` or a boolean.

A comparison is reported when request data meets a ``strong`` or ``named``
secret, or a parameter meets a ``strong`` secret. Literals, two request
fields (password and its confirmation), digests and names that only end in
token/hash (``location.hash``, ``SyntaxKind.FooToken``) stay quiet.
"""

from __future__ import annotations

import re

_EQUALITY = frozenset({"==", "===", "!=", "!=="})
_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "function",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_WRAPPERS = frozenset(
    {
        "as_expression",
        "await_expression",
        "non_null_expression",
        "parenthesized_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_LITERAL_TYPES = frozenset(
    {"string", "number", "true", "false", "null", "undefined", "regex"}
)
_SECRET_SUFFIXES = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "hmac",
    "signature",
    "digest",
    "hash",
)
# Environment and config keys: API_KEY, ADMIN_KEY and SECRET_KEY are
# credentials even though "key" alone is too common for local names.
_CONFIG_KEY_RE = re.compile(
    r"secret|token|passw|pwd|apikey|signature|hmac|digest|credential|(?:^|[^a-z])key$",
    re.IGNORECASE,
)
_DIGEST_CALL_RE = re.compile(
    r"^(?:hash\w*|\w*hash|digest|md5|sha\d*|\w*sha\d+|bcrypt\w*|scrypt\w*|"
    r"argon2\w*|pbkdf2\w*|crypt)$",
    re.IGNORECASE,
)
_REQUEST_ROOTS = frozenset({"req", "request"})
_REQUEST_FIELDS = frozenset(
    {"body", "query", "params", "headers", "cookies", "signedCookies", "payload"}
)
_REQUEST_ACCESSORS = frozenset({"get", "header", "param"})
_CONTEXT_ROOTS = frozenset({"ctx", "context"})
_CONTEXT_FIELDS = frozenset({"query", "params", "headers", "header", "cookies"})
_DESTRUCTURED_REQUEST_FIELDS = frozenset(
    {"body", "query", "params", "headers", "cookies", "payload"}
)
_GETTER_CONTAINERS = frozenset({"headers", "searchParams", "cookies"})
_PASSTHROUGH_METHODS = frozenset(
    {
        "toString",
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "normalize",
        "valueOf",
        "split",
        "slice",
        "substring",
        "substr",
        "replace",
        "at",
    }
)
_PASSTHROUGH_FUNCTIONS = frozenset({"String", "decodeURIComponent", "decodeURI"})
_CONFIG_ROOT_RE = re.compile(r"(?:^|_)(?:config|settings|conf)$|Config$|Settings$")
_MAX_DEPTH = 8


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _unwrap(node):
    for _ in range(16):
        if node is None or node.type not in _WRAPPERS:
            return node
        inner = None
        for child in node.named_children:
            if child.type.endswith("_type") or child.type in {
                "type_identifier",
                "predefined_type",
                "type_annotation",
                "type_arguments",
            }:
                continue
            inner = child
            break
        if inner is None:
            return node
        node = inner
    return node


def _normalized(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")


def _credential_name(name: str) -> bool:
    normalized = _normalized(name)
    return any(normalized.endswith(suffix) for suffix in _SECRET_SUFFIXES)


def _credential_key(name: str) -> bool:
    return bool(_CONFIG_KEY_RE.search(name))


def _operator(node) -> str | None:
    for child in node.children:
        if not child.is_named and child.type in _EQUALITY:
            return child.type
    return None


def _skip_nested(node, root) -> bool:
    return node is not root and node.type in _FUNCTION_TYPES


class _TimingAnalysis:
    def __init__(self, root, source: bytes, bindings, environment_lookup):
        self.root = root
        self.source = source
        self.bindings = bindings
        self._environment_lookup = environment_lookup
        self._scope_cache: dict[int, dict[str, list]] = {}

    # -- scopes -------------------------------------------------------------

    def _scopes(self, node):
        current = node.parent
        while current is not None:
            if current.type in _FUNCTION_TYPES:
                yield current
            current = current.parent
        yield self.root

    def _declarations(self, scope) -> dict[str, list]:
        """name -> [(kind, node, extra)] for bindings made directly in scope."""
        cached = self._scope_cache.get(scope.id)
        if cached is not None:
            return cached
        found: dict[str, list] = {}
        if scope.type in _FUNCTION_TYPES:
            for index, param in enumerate(self._parameters(scope)):
                pattern, default = param
                for name, field in self._pattern_names(pattern):
                    found.setdefault(name, []).append(
                        ("param", pattern, (index, field, default, scope))
                    )
        body = scope.child_by_field_name("body") if scope is not self.root else scope
        if body is not None:
            stack = [body]
            while stack:
                current = stack.pop()
                if _skip_nested(current, body):
                    continue
                if current.type == "variable_declarator":
                    name = current.child_by_field_name("name")
                    value = current.child_by_field_name("value")
                    if name is not None:
                        for bound, field in self._pattern_names(name):
                            found.setdefault(bound, []).append(
                                ("var", current, (field, value, name))
                            )
                elif current.type in {
                    "assignment_expression",
                    "augmented_assignment_expression",
                }:
                    left = _unwrap(current.child_by_field_name("left"))
                    if left is not None and left.type == "identifier":
                        found.setdefault(_text(self.source, left), []).append(
                            ("assign", current, current.child_by_field_name("right"))
                        )
                stack.extend(current.children)
        self._scope_cache[scope.id] = found
        return found

    def _parameters(self, function):
        single = function.child_by_field_name("parameter")
        if single is not None:
            return [(single, None)]
        params = function.child_by_field_name("parameters")
        if params is None:
            return []
        result = []
        for child in params.named_children:
            if child.type in {"required_parameter", "optional_parameter"}:
                pattern = child.child_by_field_name("pattern")
                default = child.child_by_field_name("value")
                if pattern is not None:
                    result.append((pattern, default))
            elif child.type in {"identifier", "object_pattern", "array_pattern"}:
                result.append((child, None))
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                if left is not None:
                    result.append((left, child.child_by_field_name("right")))
        return result

    def _pattern_names(self, pattern):
        """(bound name, (source field or None, default value or None))."""
        if pattern is None:
            return []
        if pattern.type in {"identifier", "undefined"}:
            return [(_text(self.source, pattern), (None, None))]
        names = []
        if pattern.type == "object_pattern":
            for child in pattern.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    name = _text(self.source, child)
                    names.append((name, (name, None)))
                elif child.type == "object_assignment_pattern":
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    if left is not None and left.type in {
                        "shorthand_property_identifier_pattern",
                        "identifier",
                    }:
                        name = _text(self.source, left)
                        names.append((name, (name, right)))
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    value = child.child_by_field_name("value")
                    field = _text(self.source, key).strip("'\"") if key else None
                    if value is not None and value.type == "identifier":
                        names.append((_text(self.source, value), (field, None)))
                    elif value is not None and value.type == "assignment_pattern":
                        inner = value.child_by_field_name("left")
                        if inner is not None and inner.type == "identifier":
                            names.append(
                                (
                                    _text(self.source, inner),
                                    (field, value.child_by_field_name("right")),
                                )
                            )
                    elif value is not None:
                        names.extend(
                            (name, (field, None))
                            for name, _ in self._pattern_names(value)
                        )
                elif child.type == "rest_pattern":
                    names.extend(
                        (name, (None, None))
                        for name, _ in self._pattern_names(
                            next(iter(child.named_children), None)
                        )
                    )
        elif pattern.type == "array_pattern":
            for child in pattern.named_children:
                names.extend(
                    (name, (None, None)) for name, _ in self._pattern_names(child)
                )
        elif pattern.type == "assignment_pattern":
            names.extend(self._pattern_names(pattern.child_by_field_name("left")))
        return names

    def _resolve(self, use, name: str):
        for scope in self._scopes(use):
            entries = self._declarations(scope).get(name)
            if entries:
                return entries
        return None

    # -- classification -----------------------------------------------------

    def classify(self, node, depth: int = 0) -> frozenset[str]:
        node = _unwrap(node)
        if node is None or depth > _MAX_DEPTH:
            return frozenset()
        kind = node.type
        if kind == "undefined" and (
            self._resolve(node, "undefined") or not self.bindings.unbound("undefined")
        ):
            return self._identifier(node, depth)
        if kind in _LITERAL_TYPES:
            return frozenset({"literal"})
        if kind == "template_string":
            parts = [
                _unwrap(next(iter(child.named_children), None))
                for child in node.named_children
                if child.type == "template_substitution"
            ]
            if not parts:
                return frozenset({"literal"})
            return self._union(parts, depth)
        if kind == "identifier":
            return self._identifier(node, depth)
        if self._environment_lookup(node):
            return self._environment_tags(node)
        if kind in {"member_expression", "subscript_expression"}:
            return self._member(node, depth)
        if kind == "call_expression":
            return self._call(node, depth)
        if kind == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and operator.type in {"||", "??", "&&"}:
                return self._union(
                    [
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ],
                    depth,
                )
            return frozenset()
        if kind == "ternary_expression":
            return self._union(
                [
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ],
                depth,
            )
        return frozenset()

    def _union(self, nodes, depth: int) -> frozenset[str]:
        tags: set[str] = set()
        literal = True
        for part in nodes:
            part_tags = self.classify(part, depth + 1)
            if "literal" not in part_tags:
                literal = False
            tags |= part_tags - {"literal"}
        if literal and nodes:
            return frozenset({"literal"})
        return frozenset(tags)

    def _environment_tags(self, node) -> frozenset[str]:
        key = self._environment_key(node)
        if key is None or _credential_key(key):
            return frozenset({"strong"})
        return frozenset()

    def _environment_key(self, node) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            return _text(self.source, prop) if prop is not None else None
        if node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            if index is not None and index.type == "string":
                return _text(self.source, index).strip("'\"`")
            return None
        if node.type == "call_expression":
            args = node.child_by_field_name("arguments")
            first = next(iter(args.named_children), None) if args else None
            if first is not None and first.type == "string":
                return _text(self.source, first).strip("'\"`")
        return None

    def _identifier(self, node, depth: int) -> frozenset[str]:
        name = _text(self.source, node)
        entries = self._resolve(node, name)
        if name == "undefined" and not entries and self.bindings.unbound("undefined"):
            return frozenset({"literal"})
        if not entries:
            return frozenset({"named"}) if _credential_name(name) else frozenset()
        tags: set[str] = set()
        for kind, decl, extra in entries:
            if kind == "param":
                tags |= self._parameter_tags(name, extra, depth)
            elif kind == "var":
                field, value, pattern = extra
                if value is None:
                    continue
                if pattern.type == "identifier":
                    tags |= self.classify(value, depth + 1)
                else:
                    tags |= self._destructured_tags(value, field, depth)
            elif kind == "assign":
                tags |= self.classify(extra, depth + 1)
        if "literal" in tags and len(tags) > 1:
            tags.discard("literal")
        if not tags & {"request", "param", "strong", "digest", "literal"} and (
            _credential_name(name)
        ):
            tags.add("named")
        return frozenset(tags)

    def _parameter_tags(self, name: str, extra, depth: int) -> set[str]:
        _index, (field, pattern_default), param_default, function = extra
        if (
            field is not None
            and field == name
            and name in (_DESTRUCTURED_REQUEST_FIELDS)
            and self._is_handler(function)
        ):
            return {"request"}
        tags = {"param"}
        if _credential_name(name):
            # A caller can pass the expected secret in (``verify(req,
            # expectedToken)``); it still needs request data on the other side.
            tags.add("named")
        for default in (pattern_default, param_default):
            if default is not None and "strong" in self.classify(default, depth + 1):
                tags.add("strong")
        return tags

    def _is_handler(self, function) -> bool:
        params = self._parameters(function)
        if not params:
            return False
        first = params[0][0]
        if first.type != "object_pattern":
            return False
        parent = first.parent
        annotation = parent.child_by_field_name("type") if parent is not None else None
        if annotation is not None and re.search(
            r"\bRequest\b|Request\b", _text(self.source, annotation)
        ):
            return True
        if len(params) >= 2:
            second = params[1][0]
            return second.type == "identifier" and _text(self.source, second) in {
                "res",
                "response",
                "reply",
            }
        return False

    def _destructured_tags(self, value, field, depth: int) -> set[str]:
        value = _unwrap(value)
        if value is None:
            return set()
        if self._is_environment_object(value):
            if field is None or _credential_key(field):
                return {"strong"}
            return set()
        value_tags = self.classify(value, depth + 1)
        if "request" in value_tags or self._is_request_object(value, depth):
            return {"request"}
        if "param" in value_tags:
            return {"param"}
        if "strong" in value_tags:
            return {"strong"}
        return set()

    def _is_environment_object(self, node) -> bool:
        node = _unwrap(node)
        if node is None or node.type != "member_expression":
            return False
        prop = node.child_by_field_name("property")
        obj = _unwrap(node.child_by_field_name("object"))
        if prop is None or obj is None or _text(self.source, prop) != "env":
            return False
        text = _text(self.source, obj)
        return text in {"process", "import.meta", "Bun"} and (
            text == "import.meta" or self.bindings.unbound(text)
        )

    # -- member and call shapes --------------------------------------------

    def _chain(self, node):
        """Root node and segment names of a member chain; calls to string
        methods are stepped through so ``req.headers.x.split(' ')[1]`` keeps
        its request root."""
        segments: list[str] = []
        current = _unwrap(node)
        for _ in range(24):
            if current is None:
                return None, []
            if current.type == "member_expression":
                prop = current.child_by_field_name("property")
                segments.append(_text(self.source, prop) if prop is not None else "*")
                current = _unwrap(current.child_by_field_name("object"))
            elif current.type == "subscript_expression":
                index = _unwrap(current.child_by_field_name("index"))
                if index is not None and index.type == "string":
                    segments.append(_text(self.source, index).strip("'\"`"))
                else:
                    segments.append("*")
                current = _unwrap(current.child_by_field_name("object"))
            elif current.type == "call_expression":
                callee = _unwrap(current.child_by_field_name("function"))
                if callee is None or callee.type != "member_expression":
                    return current, list(reversed(segments))
                prop = callee.child_by_field_name("property")
                method = _text(self.source, prop) if prop is not None else ""
                if method not in _PASSTHROUGH_METHODS:
                    return current, list(reversed(segments))
                current = _unwrap(callee.child_by_field_name("object"))
            else:
                return current, list(reversed(segments))
        return None, []

    def _is_request_object(self, node, depth: int) -> bool:
        """``req.body``, ``ctx.request.body``, ``await request.json()``,
        ``await request.formData()``."""
        node = _unwrap(node)
        if node is None:
            return False
        root, segments = self._chain(node)
        if root is None:
            return False
        if root.type == "identifier":
            name = _text(self.source, root)
            entries = self._resolve(root, name)
            is_request = (not entries and name in _REQUEST_ROOTS) or (
                entries
                and all(entry[0] == "param" for entry in entries)
                and name in _REQUEST_ROOTS
            )
            if is_request and segments[:1] and segments[0] in _REQUEST_FIELDS:
                return True
            is_context = name in _CONTEXT_ROOTS and (
                not entries or all(entry[0] == "param" for entry in entries)
            )
            if is_context and segments[:1] == ["request"] and len(segments) > 1:
                return segments[1] in {"body", "query", "headers", "header"}
            return bool(is_context and segments[:1] and segments[0] in _CONTEXT_FIELDS)
        if root.type == "call_expression" and not segments:
            callee = _unwrap(root.child_by_field_name("function"))
            if callee is None or callee.type != "member_expression":
                return False
            prop = callee.child_by_field_name("property")
            obj = _unwrap(callee.child_by_field_name("object"))
            if prop is None or obj is None or obj.type != "identifier":
                return False
            name = _text(self.source, obj)
            if _text(self.source, prop) not in {"json", "formData", "text"} or (
                name not in _REQUEST_ROOTS
            ):
                return False
            entries = self._resolve(obj, name)
            return not entries or all(entry[0] == "param" for entry in entries)
        return False

    def _member(self, node, depth: int) -> frozenset[str]:
        if self._is_request_value(node, depth):
            return frozenset({"request"})
        root, segments = self._chain(node)
        if root is None:
            return frozenset()
        last = segments[-1] if segments else ""
        tags: set[str] = set()
        if root.type == "identifier":
            root_name = _text(self.source, root)
            if self._config_root(root_name) and any(
                _credential_key(segment) for segment in segments
            ):
                return frozenset({"strong"})
            root_tags = self._identifier(root, depth + 1) - {"named"}
            if "request" in root_tags:
                return frozenset({"request"})
            if self._member_filled_from_secret(node, root, root_name, segments, depth):
                tags.add("strong")
            if "param" in root_tags:
                tags.add("param")
                if last and last != "*" and _credential_name(last):
                    tags.add("named")
                return frozenset(tags)
            if "strong" in root_tags and last and _credential_key(last):
                tags.add("strong")
        elif root.type == "this":
            if (
                len(segments) >= 2
                and self._config_root(segments[0])
                and any(_credential_key(segment) for segment in segments[1:])
            ):
                return frozenset({"strong"})
        elif root.type == "call_expression":
            root_tags = self._call(root, depth + 1)
            if "request" in root_tags:
                return frozenset({"request"})
            if "strong" in root_tags:
                return frozenset({"strong"})
        if last and last != "*" and _credential_name(last):
            tags.add("named")
        return frozenset(tags)

    def _config_root(self, name: str) -> bool:
        return bool(_CONFIG_ROOT_RE.search(name))

    def _is_request_value(self, node, depth: int) -> bool:
        if self._is_request_object(node, depth):
            return True
        root, segments = self._chain(node)
        if root is None or not segments:
            return False
        if root.type == "identifier":
            name = _text(self.source, root)
            entries = self._resolve(root, name)
            if not entries:
                return False
            for kind, decl, extra in entries:
                if kind == "param":
                    _index, (field, _default), _, function = extra
                    if (
                        field == name
                        and name in _DESTRUCTURED_REQUEST_FIELDS
                        and self._is_handler(function)
                    ):
                        return True
                    if name in _REQUEST_ROOTS and segments[0] in _REQUEST_FIELDS:
                        return True
                    if name in _CONTEXT_ROOTS and (
                        segments[0] in _CONTEXT_FIELDS
                        or (
                            segments[0] == "request"
                            and len(segments) > 1
                            and segments[1] in {"body", "query", "headers", "header"}
                        )
                    ):
                        return True
                elif kind == "var":
                    field, value, pattern = extra
                    if value is None or depth > _MAX_DEPTH:
                        continue
                    if pattern.type == "identifier" and (
                        self._is_request_object(value, depth + 1)
                        or "request" in self.classify(value, depth + 1)
                    ):
                        return True
                    if pattern.type != "identifier" and self._is_request_object(
                        value, depth + 1
                    ):
                        return True
        if root.type == "call_expression":
            return "request" in self._call(root, depth + 1)
        return False

    def _call(self, node, depth: int) -> frozenset[str]:
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None:
            return frozenset()
        args = node.child_by_field_name("arguments")
        arguments = [
            child
            for child in (args.named_children if args else [])
            if child.type != "comment"
        ]
        if callee.type == "identifier":
            name = _text(self.source, callee)
            if name in _PASSTHROUGH_FUNCTIONS and arguments:
                return self.classify(arguments[0], depth + 1)
            if _DIGEST_CALL_RE.match(name):
                return frozenset({"digest"})
            return frozenset()
        if callee.type != "member_expression":
            return frozenset()
        prop = callee.child_by_field_name("property")
        method = _text(self.source, prop) if prop is not None else ""
        receiver = _unwrap(callee.child_by_field_name("object"))
        if self._contains_hmac(node):
            return frozenset({"strong"})
        if method in {"digest"} or _DIGEST_CALL_RE.match(method):
            return frozenset({"digest"})
        if method in _PASSTHROUGH_METHODS and receiver is not None:
            return self.classify(receiver, depth + 1)
        if receiver is None:
            return frozenset()
        if method in _REQUEST_ACCESSORS and receiver.type == "identifier":
            name = _text(self.source, receiver)
            entries = self._resolve(receiver, name)
            if name in _REQUEST_ROOTS | _CONTEXT_ROOTS and (
                not entries or all(entry[0] == "param" for entry in entries)
            ):
                return frozenset({"request"})
        if method == "get":
            if self._config_receiver(receiver):
                key = arguments[0] if arguments else None
                if (
                    key is not None
                    and key.type == "string"
                    and _credential_key(_text(self.source, key))
                ):
                    return frozenset({"strong"})
                return frozenset()
            root, segments = self._chain(receiver)
            if segments and segments[-1] in _GETTER_CONTAINERS:
                if self._is_request_value(receiver, depth + 1) or (
                    root is not None
                    and root.type == "identifier"
                    and _text(self.source, root) in _REQUEST_ROOTS | _CONTEXT_ROOTS
                ):
                    return frozenset({"request"})
                if segments[-1] == "searchParams":
                    return frozenset({"request"})
            if receiver.type == "identifier" and self._is_form_data(receiver, depth):
                return frozenset({"request"})
        return frozenset()

    def _config_receiver(self, receiver) -> bool:
        if receiver.type == "identifier":
            return self._config_root(_text(self.source, receiver))
        if receiver.type == "member_expression":
            prop = receiver.child_by_field_name("property")
            return prop is not None and self._config_root(_text(self.source, prop))
        return False

    def _is_form_data(self, receiver, depth: int) -> bool:
        name = _text(self.source, receiver)
        entries = self._resolve(receiver, name)
        if not entries:
            return False
        for kind, decl, extra in entries:
            if kind == "param":
                parent = decl.parent
                annotation = (
                    parent.child_by_field_name("type") if parent is not None else None
                )
                if annotation is not None and "FormData" in _text(
                    self.source, annotation
                ):
                    return True
            elif kind == "var":
                _field, value, pattern = extra
                value = _unwrap(value)
                if (
                    pattern.type == "identifier"
                    and value is not None
                    and value.type == "call_expression"
                ):
                    callee = _unwrap(value.child_by_field_name("function"))
                    if callee is not None and callee.type == "member_expression":
                        prop = callee.child_by_field_name("property")
                        obj = _unwrap(callee.child_by_field_name("object"))
                        if (
                            prop is not None
                            and _text(self.source, prop) == "formData"
                            and obj is not None
                            and obj.type == "identifier"
                            and _text(self.source, obj) in _REQUEST_ROOTS
                        ):
                            return True
        return False

    def _contains_hmac(self, node) -> bool:
        current = _unwrap(node)
        for _ in range(12):
            if current is None or current.type != "call_expression":
                return False
            callee = _unwrap(current.child_by_field_name("function"))
            if callee is None:
                return False
            if callee.type == "identifier":
                return _text(self.source, callee) == "createHmac"
            if callee.type != "member_expression":
                return False
            prop = callee.child_by_field_name("property")
            if prop is not None and _text(self.source, prop) == "createHmac":
                return True
            current = _unwrap(callee.child_by_field_name("object"))
        return False

    def _member_filled_from_secret(self, node, root, root_name, segments, depth):
        """``data.confirm = process.env.X`` (also through ``const alias =
        data`` or ``Object.assign(data, {confirm: process.env.X})``) earlier in
        the enclosing function makes ``data.confirm`` a server secret."""
        if len(segments) != 1 or segments[0] == "*":
            return False
        field = segments[0]
        function = next(
            (scope for scope in self._scopes(node) if scope is not self.root), None
        )
        if function is None:
            return False
        names = {root_name}
        body = function.child_by_field_name("body")
        if body is None:
            return False
        nodes = []
        stack = [body]
        while stack:
            current = stack.pop()
            if _skip_nested(current, body):
                continue
            if current.start_byte >= node.start_byte:
                stack.extend(current.children)
                continue
            nodes.append(current)
            stack.extend(current.children)
        for current in nodes:
            if current.type == "variable_declarator":
                name = current.child_by_field_name("name")
                value = _unwrap(current.child_by_field_name("value"))
                if (
                    name is not None
                    and name.type == "identifier"
                    and value is not None
                    and value.type == "identifier"
                    and _text(self.source, value) in names
                ):
                    names.add(_text(self.source, name))
        for current in nodes:
            if current.type == "assignment_expression":
                left = _unwrap(current.child_by_field_name("left"))
                if left is None or left.type != "member_expression":
                    continue
                obj = _unwrap(left.child_by_field_name("object"))
                prop = left.child_by_field_name("property")
                if (
                    obj is not None
                    and obj.type == "identifier"
                    and _text(self.source, obj) in names
                    and prop is not None
                    and _text(self.source, prop) == field
                    and "strong"
                    in self.classify(current.child_by_field_name("right"), depth + 1)
                ):
                    return True
            elif current.type == "call_expression":
                callee = _unwrap(current.child_by_field_name("function"))
                if callee is None or _text(self.source, callee) != "Object.assign":
                    continue
                args = current.child_by_field_name("arguments")
                values = [c for c in (args.named_children if args else [])]
                if not values or _text(self.source, _unwrap(values[0])) not in names:
                    continue
                for source_object in values[1:]:
                    source_object = _unwrap(source_object)
                    if source_object is None or source_object.type != "object":
                        continue
                    for pair in source_object.named_children:
                        if pair.type != "pair":
                            continue
                        key = pair.child_by_field_name("key")
                        if (
                            key is not None
                            and _text(self.source, key).strip("'\"") == field
                            and "strong"
                            in self.classify(
                                pair.child_by_field_name("value"), depth + 1
                            )
                        ):
                            return True
        return False

    # -- verdict ------------------------------------------------------------

    def comparison_secret(self, node):
        """(secret operand, guess kind) when this equality is a timing oracle."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return None
        left_tags = self.classify(left)
        right_tags = self.classify(right)
        if "literal" in left_tags or "literal" in right_tags:
            return None
        for guess, guess_tags, secret, secret_tags in (
            (left, left_tags, right, right_tags),
            (right, right_tags, left, left_tags),
        ):
            if "digest" in guess_tags or "digest" in secret_tags:
                continue
            if (
                "request" in guess_tags
                and "request" not in secret_tags
                and secret_tags & {"strong", "named"}
            ):
                return secret, "request"
            if (
                "param" in guess_tags
                and "strong" not in guess_tags
                and "request" not in secret_tags
                and "strong" in secret_tags
            ):
                return secret, "param"
        return None

    def operand_name(self, node) -> str:
        node = _unwrap(node)
        if node is None:
            return "value"
        if node.type == "identifier":
            return _text(self.source, node)
        if self._environment_lookup(node):
            key = self._environment_key(node)
            if key:
                return key
        if node.type in {"member_expression", "subscript_expression"}:
            _root, segments = self._chain(node)
            for segment in reversed(segments):
                if segment != "*":
                    return segment
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            if callee is not None:
                return _text(self.source, callee).split(".")[-1].split("(")[0]
        return _text(self.source, node)[:40]


def check_timing_comparison(
    root_node,
    source_bytes: bytes,
    file_path: str,
    findings: list[dict],
    bindings,
    environment_lookup,
) -> None:
    """SKY-D253: a server secret compared with request input using ``==``."""
    analysis = _TimingAnalysis(
        root_node,
        source_bytes,
        bindings,
        lambda node: environment_lookup(node, source_bytes, bindings),
    )
    stack = [root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "binary_expression" or _operator(node) is None:
            continue
        verdict = analysis.comparison_secret(node)
        if verdict is None:
            continue
        secret, guess = verdict
        name = analysis.operand_name(secret)
        guess_label = (
            "request input" if guess == "request" else "a caller-supplied value"
        )
        findings.append(
            {
                "rule_id": "SKY-D253",
                "severity": "MEDIUM",
                "message": (
                    f"Timing-unsafe comparison of '{name}' with {guess_label}. "
                    "Use crypto.timingSafeEqual() for constant-time comparison."
                ),
                "file": str(file_path),
                "line": node.start_point[0] + 1,
                "col": 0,
            }
        )
