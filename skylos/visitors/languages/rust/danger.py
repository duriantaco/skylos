from __future__ import annotations

import re
from dataclasses import replace
from functools import lru_cache
from itertools import pairwise
from pathlib import Path

from . import (
    cookies,
    log_formats,
    permissions,
    request_patterns,
    reqwest,
    sensitive,
    sql,
    tls,
    transport,
)
from . import unbounded_input
from ._security_bindings import (
    SYMBOLIC,
    UNKNOWN,
    State,
    Value,
    bind_http_return,
    joined,
    unwrap,
    use_bindings,
)
from .core import RUST_LANG, _get_parser, _is_test_path
from .syntax import parse_rust_source
from .web_model import (
    GLOB_EXPORTS,
    HTML_ESCAPERS,
    HTML_MARKUP_RE,
    HTTP_CLIENT_CONSTRUCTORS,
    HTTP_CLIENT_TYPES,
    HTTP_FUNCTIONS,
    HTTP_VERBS,
    NON_TEXT_TYPES,
    REQUEST_EXTRACTORS,
    REQUEST_OBJECT_METHODS,
    REQUEST_OBJECTS,
    ROCKET_ROUTE_ATTRIBUTES,
    ROCKET_SEGMENT_RE,
    TRANSPARENT_WRAPPERS,
    URL_ENCODERS,
    fixes_host,
    request_label,
)

_TAINT_NAME_RE = re.compile(
    r"((?<![a-z])arg|cmd|command|dir|file|filename|input|name|path|payload|request"
    r"|url|uri)",
    re.I,
)
_FILE_PATH_ARGS = {
    "read": (0,),
    "read_to_string": (0,),
    "write": (0,),
    "copy": (0, 1),
    "remove_file": (0,),
    "remove_dir": (0,),
    "remove_dir_all": (0,),
    "rename": (0, 1),
    "File::open": (0,),
    "File::create": (0,),
    "File::create_new": (0,),
}
_FILESYSTEMS = ("std::fs::", "tokio::fs::", "async_std::fs::")
_PATH_TYPES = {"std::path::Path", "std::path::PathBuf"}
_PATH_CONSTRUCTORS = {
    f"{path}::{method}" for path in _PATH_TYPES for method in ("new", "from")
}
_SOURCES = {f"std::env::{name}" for name in ("args", "args_os", "var", "var_os")}
_ENV_LOOKUPS = {"std::env::var", "std::env::var_os"}
_CARGO_BUILD_VARIABLES = {
    "OUT_DIR",
    "CARGO_MANIFEST_DIR",
    "CARGO_MANIFEST_PATH",
    "TARGET",
    "HOST",
    "PROFILE",
    "OPT_LEVEL",
    "DEBUG",
    "NUM_JOBS",
}
_CARGO_BUILD_PREFIXES = ("CARGO_PKG_", "CARGO_CFG_", "CARGO_FEATURE_")
_TEST_CFG = ("(", "test", ")")
_TEST_ATTRIBUTES = {"test", "bench"}
_INERT_ATTRIBUTES = {
    "allow",
    "cfg",
    "cfg_attr",
    "cold",
    "deny",
    "deprecated",
    "doc",
    "expect",
    "inline",
    "must_use",
    "track_caller",
    "warn",
}
_CALLER_ROUNDS = 6
# Arguments that name a database pool, connection or transaction.
_STORE_ARGUMENT_RE = re.compile(
    r"(?:^|[.&*(\s])(?:pool|conn|connection|db|database|tx|transaction|executor)"
    r"(?:\(\))?\s*$"
)
_VALIDATOR_NAME_RE = re.compile(r"(?:is_)?valid|is_safe|is_allowed")
_VALIDATED = frozenset({"SKY-D212", "SKY-D215", "SKY-D216", "SKY-D228"})
_STORE_WRITES = ("create", "insert", "update", "upsert", "save", "replace", "store")
_MAX_CHAIN = 4
_OPERATOR_INPUT = "operator_input"
_D210 = "SKY-D210"
_D211 = "SKY-D211"
_D212 = "SKY-D212"
_D215 = "SKY-D215"
_D216 = "SKY-D216"
_D228 = "SKY-D228"
# Sinks that need request data; other inputs are not reported at all.
_REQUEST_ONLY_RULES = frozenset({_D216, _D228})
_SEVERITY = {
    _D210: "HIGH",
    _D211: "CRITICAL",
    _D212: "HIGH",
    _D215: "HIGH",
    _D216: "CRITICAL",
    _D228: "HIGH",
}
_CALL_SITE_MESSAGES = {
    _D212: (
        "Request data reaches a process command through {chain}; use a fixed "
        "program and an allowlist."
    ),
    _D215: (
        "Request data reaches a filesystem operation through {chain} without a "
        "proven path restriction."
    ),
    _D216: (
        "Request data chooses the URL of an outbound HTTP request through "
        "{chain}; check the destination against an allowlist (server-side "
        "request forgery)."
    ),
    _D228: (
        "Request data reaches HTML markup through {chain} without escaping "
        "(cross-site scripting)."
    ),
}
_REVIEW_MESSAGES = {
    _D212: (
        "Review (not listed, not blocking): an environment variable, a "
        "command-line argument or a parameter its callers choose selects a "
        "process or its shell code; no request data was traced into it. If "
        "untrusted input can reach it, use a fixed program and an allowlist."
    ),
    _D215: (
        "Review (not listed, not blocking): a path from an environment "
        "variable, a command-line argument or a parameter its callers choose "
        "reaches a filesystem operation; no request data was traced into it. "
        "If untrusted input can reach it, restrict it to an allowed directory."
    ),
}
_CHILD_MODULE_FILES = 256
_SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
_ITEMS = {
    "function_item",
    "struct_item",
    "enum_item",
    "trait_item",
    "type_item",
    "mod_item",
    "const_item",
    "static_item",
    "union_item",
    "macro_definition",
}
_PATH_READ_ONLY = {
    "starts_with",
    "ends_with",
    "is_absolute",
    "is_relative",
    "has_root",
    "exists",
    "is_file",
    "is_dir",
    "metadata",
    "symlink_metadata",
    "read_link",
    "display",
    "components",
    "iter",
    "parent",
    "ancestors",
    "extension",
    "file_stem",
    "as_os_str",
    "to_str",
    "to_string_lossy",
}


@lru_cache(maxsize=4096)
def _is_build_script(file_path):
    path = Path(file_path)
    return path.name == "build.rs" and (path.parent / "Cargo.toml").is_file()


@lru_cache(maxsize=4096)
def _declared_test_only(file_path):
    """The parent module declares this file as ``#[cfg(test)] mod name;``."""
    path = Path(file_path)
    name = path.stem
    owners = [path.parent / "mod.rs", path.parent / "lib.rs", path.parent / "main.rs"]
    if name == "mod":
        name = path.parent.name
        folder = path.parent.parent
        owners = [folder / "mod.rs", folder / "lib.rs", folder / "main.rs"]
        owners.append(folder.parent / f"{folder.name}.rs")
    else:
        owners.append(path.parent.parent / f"{path.parent.name}.rs")
    if RUST_LANG is None:
        return False
    declarations = []
    for owner in owners:
        try:
            if owner != path and owner.is_file():
                source = owner.read_bytes()
                root = parse_rust_source(
                    _get_parser(RUST_LANG), source, owner
                ).root_node
                if root.has_error:
                    return False
                declarations.extend(_test_module_declarations(root, source, name))
        except OSError:
            return False
    # A library and binary can both load the same source file. It is test-only
    # only when every observed declaration agrees; one production owner wins.
    return bool(declarations) and all(declarations)


def _test_module_declarations(root, source, name):
    def tokens(node):
        if node.type in {"line_comment", "block_comment"}:
            return ()
        if not node.children or node.type in {"string_literal", "raw_string_literal"}:
            return (source[node.start_byte : node.end_byte].decode("utf-8", "replace"),)
        return tuple(token for child in node.children for token in tokens(child))

    declarations = []
    test_only = path_override = False
    for child in root.named_children:
        if child.type in {"line_comment", "block_comment"}:
            continue
        if child.type == "attribute_item":
            attribute_tokens = tokens(child)
            test_only |= attribute_tokens == ("#", "[", "cfg", "(", "test", ")", "]")
            # A path attribute can load this file under a different module
            # name. Do not use default-name ownership as proof in that case.
            path_override |= attribute_tokens[:3] == ("#", "[", "path")
            continue
        if child.type == "mod_item":
            declared_name = child.child_by_field_name("name")
            if declared_name is not None and child.child_by_field_name("body") is None:
                actual = source[
                    declared_name.start_byte : declared_name.end_byte
                ].decode("utf-8", "replace")
                if path_override:
                    declarations.append(False)
                elif actual == name:
                    declarations.append(test_only)
        test_only = path_override = False
    return declarations


class _ScopeAttributes:
    def __init__(self, source):
        self.source = source

    def text(self, node):
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def cfg_key(self, node):
        """Compare exact cfg token trees; this does not evaluate features."""
        tokens = []
        pending = [node]
        while pending:
            part = pending.pop()
            if (
                part is None
                or part.has_error
                or part.type in {"line_comment", "block_comment"}
            ):
                continue
            if (
                part.type in {"string_literal", "raw_string_literal"}
                or not part.child_count
            ):
                tokens.append(self.text(part))
            else:
                pending.extend(reversed(part.children))
        return tuple(tokens)

    def scope_entries(self, node):
        conditional = scope_conditional = False
        guards = scope_guards = frozenset()
        unsupported = scope_unsupported = False
        for child in node.named_children:
            if child.type in {"attribute_item", "inner_attribute_item"}:
                attribute = next(
                    (part for part in child.named_children if part.type == "attribute"),
                    None,
                )
                names = (
                    [
                        part
                        for part in attribute.named_children
                        if part.type not in {"line_comment", "block_comment"}
                    ]
                    if attribute is not None
                    else []
                )
                optional = bool(names and self.text(names[0]) in {"cfg", "cfg_attr"})
                cfg = bool(names and self.text(names[0]) == "cfg")
                key = self.cfg_key(names[1]) if cfg and len(names) == 2 else ()
                if child.type == "inner_attribute_item":
                    scope_conditional |= optional
                    if key:
                        scope_guards |= {key}
                    scope_unsupported |= optional and not key
                else:
                    conditional |= optional
                    if key:
                        guards |= {key}
                    unsupported |= optional and not key
                continue
            if child.type in {"line_comment", "block_comment"}:
                continue
            yield (
                child,
                conditional or scope_conditional,
                guards | scope_guards,
                not (unsupported or scope_unsupported),
            )
            conditional = False
            guards, unsupported = frozenset(), False


class _SecurityFlow(_ScopeAttributes):
    def __init__(self, root, file_path, source, refuted=frozenset(), summaries=None, http_returns=None, *, siblings=None):
        self.root = root
        self.file = str(Path(file_path))
        super().__init__(source)
        self.findings = []
        self.return_values = []
        self.deferred_http = []
        self.http_returns_in = http_returns or {}
        self.http_returns = {}
        self.siblings = siblings
        self.refuted = refuted
        self.call_arguments = {}
        self.tls_callers = (
            {} if any(name in source for name in tls.OPTION_NAMES) else None
        )
        self.tls_parameters = []
        self.library_calls = set()
        self.build_script = _is_build_script(file_path)
        self.harness_file = (
            self.build_script
            or _is_test_path(file_path)
            or (siblings is None and _declared_test_only(file_path))
        )
        # Which parameters of this file's functions reach a sink, from the
        # previous round: {function start byte: {index: {(rule, via)}}}.
        self.summaries_in = summaries or {}
        self.summaries = {
            key: {index: set(entries) for index, entries in params.items()}
            for key, params in self.summaries_in.items()
        }
        self.functions = []
        self.local_functions = {}
        self.index_functions(root, None)

    def field(self, node, name):
        return node.child_by_field_name(name) if node is not None else None

    def index_functions(self, node, impl):
        """Name -> function items of this file, for calls to local helpers."""
        for child in node.named_children:
            if child.type == "function_item":
                name = self.field(child, "name")
                if name is not None:
                    self.local_functions.setdefault(self.text(name), []).append(
                        (child, impl)
                    )
                body = self.field(child, "body")
                if body is not None:
                    self.index_functions(body, None)
            elif child.type == "impl_item":
                body = self.field(child, "body")
                if body is not None:
                    self.index_functions(body, child)
            elif child.type in {"mod_item", "trait_item"}:
                body = self.field(child, "body")
                if body is not None:
                    self.index_functions(
                        body, None if child.type == "mod_item" else child
                    )
            elif child.type in {"declaration_list", "block"}:
                self.index_functions(child, impl)

    def emit(self, rule, message, node, value, *, extra=None):
        """Report a sink. A D212/D215 sink no request data reaches is a review
        item (unlisted, not blocking): its only inputs are environment
        variables, command-line arguments or a caller's parameter."""
        request = sorted(value.request_sources)
        sources = sorted(value.real_sources)
        metadata = {
            "security_evidence": {
                "evidence_kind": "bounded_rust_source_flow",
                "sources": sources,
                "analysis_complete": False,
                "assumption": (
                    "Request extractors and route parameters are request data; "
                    "a reachable sink does not by itself establish exploitability."
                    if request
                    else "Environment variables, command-line arguments and "
                    "parameters are chosen by the operator or the calling code."
                ),
            }
        }
        if rule == _D211 and sql.REMOTE_SOURCE in sources:
            metadata["security_evidence"]["assumption"] = (
                "The HTTP peer can supply SQL text. A source path alone does not establish exploitability."
            )
        if extra:
            metadata.update(extra)
        finding = {
            "rule_id": rule,
            "severity": _SEVERITY.get(rule, "HIGH"),
            "message": message,
            "file": self.file,
            "line": node.start_point[0] + 1,
            "col": node.start_point[1],
            "category": "danger",
            "metadata": metadata,
        }
        if not request and rule in _REVIEW_MESSAGES:
            finding["message"] = _REVIEW_MESSAGES[rule]
            finding["review_item"] = {"kind": "unproven_source", "blocking": False}
            metadata["rust_source"] = _OPERATOR_INPUT
        self.findings.append(finding)

    def owner(self):
        return self.functions[-1] if self.functions else None

    def record_summary(self, rule, value, via):
        """Remember which parameters of the enclosing functions reach a sink."""
        for label in value.sources:
            if not label.startswith(SYMBOLIC):
                continue
            _prefix, key, index = label.split("#")
            entries = self.summaries.setdefault(int(key), {}).setdefault(
                int(index), set()
            )
            entries.add((rule, via))

    def reaches(self, rule, value):
        """``value`` is unencoded data for ``rule``'s sink; a path proven to
        stay inside its root does not reach a filesystem sink."""
        if rule in value.cleared:
            return False
        return not (rule == _D215 and value.contained)

    def sink(self, rule, message, node, value, state, *, via="", extra=None):
        """A value reaches a sink: record parameter summaries and report
        request data (and, for D212/D215, operator input as review)."""
        if not self.reaches(rule, value):
            return
        if rule == _D216 and _TEST_CFG in state.conditions:
            return
        if (
            rule == _D216
            and self.deferred_http
            and self.deferred_http[-1] is not None
            and reqwest.has_dispatch(via)
        ):
            self.deferred_http[-1].append((via, value))
            return
        self.record_summary(rule, value, via)
        if rule in _REQUEST_ONLY_RULES:
            if not value.request_sources or _TEST_CFG in state.conditions:
                return
        elif not value.real_sources:
            return
        self.emit(rule, message, node, value, extra=extra)

    def declarations(self, node, state):
        # Rust items (including use declarations) apply throughout their scope.
        local_names = set()
        for child, conditional in self.scope_statements(node):
            if child.type in _ITEMS:
                name = self.field(child, "name")
                if name is not None:
                    ident = self.text(name)
                    value = UNKNOWN
                    if (
                        child.type == "function_item"
                        and not conditional
                        and ident not in local_names
                    ):
                        value = Value(local_function=child.start_byte)
                    elif (
                        child.type == "const_item"
                        and not conditional
                        and ident not in local_names
                    ):
                        initializer = self.field(child, "value")
                        if (
                            initializer is not None
                            and initializer.type == "boolean_literal"
                        ):
                            value = tls.literal(initializer)
                    state.bind(ident, value)
                    local_names.add(ident)
        if self.siblings and node == self.root:
            for name, api in self.siblings.roots.items():
                state.bind(name, Value(api=api))
        bindings = {}
        globs = []
        for child, conditional, guards, complete_guards in self.scope_entries(node):
            if child.type == "use_declaration":
                for name, path in use_bindings(child, self.text):
                    if name == "*":
                        globs.append((state.resolve(path), conditional))
                        continue
                    api = state.resolve(path)
                    if (
                        self.siblings
                        and api
                        and api.startswith("@crate::")
                        and any(
                            name not in _INERT_ATTRIBUTES
                            for name, _ in self.attributes(child)
                        )
                    ):
                        api = None
                    value = (
                        Value(guarded_api=(guards, api))
                        if conditional and guards and complete_guards and api
                        else UNKNOWN
                        if conditional
                        else Value(api=api)
                    )
                    bindings.setdefault(name, set()).add(value)
        for name, values in bindings.items():
            # Conflicting imports and local declarations cannot prove an API.
            if name in state.frames[-1] or len(values) != 1:
                state.bind(name, UNKNOWN)
            else:
                state.bind(name, next(iter(values)))
        # A glob of a modelled module provides its names unless an explicit
        # import or a local item of that name exists; two globs that both
        # provide a name make it ambiguous.
        provided = {}
        for module, conditional in globs:
            for name in GLOB_EXPORTS.get(module, sql.MYSQL_GLOBS.get(module, ())):
                if name in state.frames[-1]:
                    continue
                provided.setdefault(name, set()).add(
                    None if conditional else f"{module}::{name}"
                )
        for name, apis in provided.items():
            api = next(iter(apis)) if len(apis) == 1 else None
            state.bind(name, Value(api=api) if api else UNKNOWN)

    def scope_statements(self, node):
        for child, conditional, _guards, _complete in self.scope_entries(node):
            yield child, conditional

    def module(self, node, inherited=None):
        state = inherited.copy() if inherited is not None else State()
        state.frames.append({})
        self.declarations(node, state)
        for child, _conditional, guards, _complete in self.scope_entries(node):
            context = state.copy()
            context.conditions |= guards
            if child.type == "function_item":
                self.function(child, context)
            elif child.type in {"impl_item", "mod_item", "trait_item"}:
                if child.type == "impl_item":
                    self.certificate_verifier(child, context)
                body = self.field(child, "body")
                if body is not None:
                    self.module(body, context)

    def attributes(self, node):
        found = []
        sibling = node.prev_named_sibling
        while sibling is not None and sibling.type in {
            "attribute_item",
            "line_comment",
            "block_comment",
        }:
            if sibling.type == "attribute_item":
                attribute = next(
                    (
                        part
                        for part in sibling.named_children
                        if part.type == "attribute"
                    ),
                    None,
                )
                parts = []
                if attribute is not None:
                    parts = [
                        part
                        for part in attribute.named_children
                        if part.type not in {"line_comment", "block_comment"}
                    ]
                if parts:
                    key = ()
                    if len(parts) == 2:
                        key = self.cfg_key(parts[1])
                    found.append((self.text(parts[0]), key))
            sibling = sibling.prev_named_sibling
        return found

    def harness_item(self, node):
        for name, key in self.attributes(node):
            if name == "cfg" and key == _TEST_CFG:
                return True
            if name.rsplit("::", 1)[-1] in _TEST_ATTRIBUTES:
                return True
        return False

    def inner_harness(self, node):
        for child in node.named_children:
            if child.type != "inner_attribute_item":
                continue
            key = self.cfg_key(child)
            if key[-5:-4] == ("cfg",) and key[-4:-1] == _TEST_CFG:
                return True
        return False

    def named_like_input(self, node):
        params = self.field(node, "parameters")
        for param in params.named_children if params is not None else ():
            pattern = self.field(param, "pattern")
            if (
                pattern is not None
                and pattern.type == "identifier"
                and _TAINT_NAME_RE.search(self.text(pattern))
            ):
                return True
        return False

    def harness_scope(self, node, state):
        if self.harness_file or _TEST_CFG in state.conditions:
            return True
        return self.harness_item(node)

    def function(self, node, inherited):
        state = inherited.copy()
        state.frames.append({})
        type_params = self.field(node, "type_parameters")
        for param in type_params.named_children if type_params is not None else ():
            name = self.field(param, "name")
            if name is not None:
                state.bind(self.text(name), UNKNOWN)
        harness = self.harness_scope(node, state)
        if harness:
            state.conditions |= {_TEST_CFG}
        route_params = self.rocket_route_parameters(node)
        params = self.field(node, "parameters")
        index = 0
        for param in params.named_children if params is not None else ():
            if param.type != "parameter":
                continue
            symbolic = frozenset({f"{SYMBOLIC}{node.start_byte}#{index}"})
            index += 1
            pattern = self.field(param, "pattern")
            api, inner = self.parameter_type(self.field(param, "type"), state)
            if api in REQUEST_EXTRACTORS:
                sources = frozenset()
                if inner not in NON_TEXT_TYPES:
                    sources = frozenset({request_label(f"extractor {api}")})
                kind = None
                if (
                    pattern is not None
                    and pattern.type == "tuple_struct_pattern"
                    and inner
                    and state.resolve(inner) == "std::string::String"
                ):
                    kind = sql.TEXT
                elif (
                    inner == "usize"
                    and pattern is not None
                    and pattern.type == "tuple_struct_pattern"
                    and not any("usize" in frame for frame in state.frames)
                ):
                    kind = request_patterns.SIZE
                self.bind_pattern(
                    pattern, Value(sources=sources | symbolic, kind=kind), state
                )
                continue
            if pattern is None or pattern.type != "identifier":
                self.bind_pattern(pattern, Value(sources=symbolic), state)
                continue
            name = self.text(pattern)
            sources = frozenset()
            kind = "path" if api in _PATH_TYPES else None
            if api in {sensitive.SECRET, unbounded_input.SOCKET}:
                kind = api
            if api in permissions.FS_TYPES:
                kind = self.fs_type_kind(self.field(param, "type"), state)
            if api in REQUEST_OBJECTS:
                kind = (
                    "actix_http_request"
                    if api in {"actix_web::HttpRequest", "actix_web::web::HttpRequest"}
                    else "http_request"
                )
            elif api in reqwest.TYPES:
                kind = reqwest.TYPES[api]
            elif api in cookies.RECEIVERS:
                kind = api
            elif api in sql.EXECUTOR_TYPES:
                kind = sql.executor_type(api, inner, state)
            elif (
                api == sql.CONNECTION
                or api in sql.MYSQL_TYPES
                or api in tls.HANDLE_TYPES
            ):
                kind = api
            elif api in HTTP_CLIENT_TYPES:
                kind = "http_client"
            if self.text(self.field(param, "type")) == "bool":
                kind = tls.PARAMETER
            if name in route_params:
                # A typed route parameter was validated by its FromParam.
                if self.rocket_text_type(param, state):
                    sources = frozenset({request_label(f"route parameter <{name}>")})
            elif (
                _TAINT_NAME_RE.search(name)
                and not harness
                and (node.start_byte, name) not in self.refuted
            ):
                sources = frozenset({f"parameter:{name}"})
            http_transport = (
                transport.HTTP_ALLOWED
                if api in {"reqwest::Client", "reqwest::blocking::Client"}
                else None
            )
            state.bind_value(name, Value(sources=sources | symbolic, kind=kind, http_transport=http_transport))
        self.return_values.append([])
        self.functions.append(node)
        self.deferred_http.append(None)
        try:
            body = self.field(node, "body")
            tail, continuing = self.block(body, state)
            returned = self.return_values[-1]
            if continuing:
                returned.append(tail if self.has_tail_expression(body) else UNKNOWN)
            # Require all returning branches to agree on the HTTP value type.
            if returned and all(
                v.kind and ("reqwest_" in v.kind or v.kind == "rust_helper_future")
                for v in returned
            ):
                value = joined(returned)
                if value.kind:
                    self.http_returns[node.start_byte] = value
        finally:
            self.deferred_http.pop()
            self.functions.pop()
            self.return_values.pop()

    def has_tail_expression(self, body):
        if body is None:
            return False
        last = next(
            (
                child
                for child in reversed(body.named_children)
                if child.type not in {"line_comment", "block_comment"}
            ),
            None,
        )
        return bool(
            last is not None
            and last.type not in _ITEMS | {"use_declaration", "let_declaration"}
            and not (last.children and last.children[-1].type == ";")
        )

    def parameter_type(self, type_node, state):
        """(resolved outer type, text of its first type argument)."""
        inner = None
        while type_node is not None and type_node.type in {
            "reference_type",
            "generic_type",
        }:
            if type_node.type == "generic_type":
                outer = state.resolve(self.text(self.field(type_node, "type")))
                arguments = self.field(type_node, "type_arguments")
                first = next(
                    (
                        child
                        for child in (arguments.named_children if arguments else ())
                        if child.type
                        not in {"lifetime", "line_comment", "block_comment"}
                    ),
                    None,
                )
                if outer in TRANSPARENT_WRAPPERS and first is not None:
                    type_node = first
                    continue
                inner = self.text(first) if first is not None else None
            type_node = self.field(type_node, "type")
        return state.resolve(self.text(type_node)), inner

    def fs_type_kind(self, node, state):
        if node is not None and node.type == "reference_type":
            mutable = any(child.type == "mutable_specifier" for child in node.named_children)
            node = self.field(node, "type")
        else:
            mutable = True
        if node is None or node.type not in {"type_identifier", "scoped_type_identifier"}:
            return None
        identity = state.resolve(self.text(node))
        if identity in permissions.FS_TYPES and (mutable or identity in {permissions.METADATA, permissions.FILE}):
            return identity
        return None

    def rocket_route_parameters(self, node):
        """Names in ``<name>``/``<name..>`` segments and ``data = "<name>"``
        of a Rocket route attribute on this function."""
        names = set()
        for name, key in self.attributes(node):
            if name.rsplit("::", 1)[-1] not in ROCKET_ROUTE_ATTRIBUTES:
                continue
            for token in key:
                if token.startswith('"'):
                    names.update(ROCKET_SEGMENT_RE.findall(token))
        return names

    def rocket_text_type(self, param, state):
        """``&str``, ``String``, ``Cow<str>`` and their ``Option``s carry the
        segment's text; other ``FromParam`` types validated it."""
        type_node = self.field(param, "type")
        while type_node is not None:
            if type_node.type == "reference_type":
                type_node = self.field(type_node, "type")
                continue
            if type_node.type == "generic_type":
                outer = self.text(self.field(type_node, "type")).rsplit("::", 1)[-1]
                arguments = self.field(type_node, "type_arguments")
                first = next(
                    (
                        child
                        for child in (arguments.named_children if arguments else ())
                        if child.type != "lifetime"
                    ),
                    None,
                )
                if outer in {"Option", "Cow", "Result"} and first is not None:
                    type_node = first
                    continue
                return False
            break
        text = self.text(type_node) if type_node is not None else ""
        return text in {"str", "String"} or state.resolve(text) in {
            "std::string::String",
        }

    def bind_pattern(self, node, value, state):
        if node is None:
            return
        if node.type in {"identifier", "shorthand_field_identifier"}:
            state.bind_value(self.text(node), value)
            return
        for index, child in enumerate(node.children):
            if child.is_named and node.field_name_for_child(index) not in {
                "type",
                "condition",
                "name",
            }:
                self.bind_pattern(child, value, state)

    def block(self, node, state):
        if node is None:
            return UNKNOWN, True
        state.frames.append({})
        self.declarations(node, state)
        value, continuing = UNKNOWN, True
        for child, conditional, guards, _complete in self.scope_entries(node):
            if not continuing:
                break
            before = state.copy() if conditional else None
            prior_conditions = state.conditions
            state.conditions |= guards
            value, continuing = self.statement(child, state)
            state.conditions = prior_conditions
            if before is not None:
                if continuing:
                    for index, frame in enumerate(state.frames):
                        for name, after in frame.items():
                            prior = before.frames[index].get(name, before.get(name))
                            frame[name] = joined([prior, after])
                else:
                    state.frames = before.frames
                # The statement can be absent in another feature selection.
                value, continuing = joined([UNKNOWN, value]), True
        state.frames.pop()
        return value, continuing

    def statement(self, node, state):
        if node is None:
            return UNKNOWN, True
        kind = node.type
        if kind == "expression_statement":
            children = node.named_children
            return self.statement(children[0], state) if children else (UNKNOWN, True)
        if kind == "let_declaration":
            initializer = self.field(node, "value")
            value = self.expression(initializer, state)
            type_node = self.field(node, "type")
            if type_node is not None:
                fs_kind = self.fs_type_kind(type_node, state)
                if fs_kind or value.kind in permissions.FS_TYPES:
                    value = replace(value, kind=fs_kind)
                api, inner = self.parameter_type(type_node, state)
                if request_patterns.integer_vec(
                    type_node, state
                ) and request_patterns.empty_constructor(initializer, state):
                    value = Value(kind=request_patterns.EMPTY_VEC)
                if api in tls.HANDLE_TYPES:
                    value = replace(value, kind=reqwest.TYPES.get(api, api))
                elif api in sql.EXECUTOR_TYPES or api in sql.MYSQL_TYPES:
                    value = Value(kind=sql.executor_type(api, inner, state))
            pattern = self.field(node, "pattern")
            if pattern is not None and pattern.type == "identifier":
                if any(c.type == "mutable_specifier" for c in node.children):
                    if (value.kind or "").startswith("rust_fixed_bytes_"):
                        value = replace(value, kind=None)
                else:
                    key_kind = sensitive.repeated_key_kind(initializer)
                    if key_kind:
                        value = replace(value, kind=key_kind)
            self.bind_pattern(pattern, value, state)
            return value, True
        if kind == "assignment_expression":
            value = self.expression(self.field(node, "right"), state)
            left = self.field(node, "left")
            if left is not None and left.type == "identifier":
                state.assign(self.text(left), replace(value, kind=None) if (value.kind or "").startswith("rust_fixed_bytes_") else value)
            else:
                self.assign_request_url(left, value, state)
            return value, True
        if kind == "return_expression":
            value = joined(
                self.expression(child, state) for child in node.named_children
            )
            if self.return_values:
                self.return_values[-1].append(value)
            return value, False
        if kind == "block":
            return self.block(node, state)
        if kind == "if_expression":
            return self.branch(node, state)
        if kind == "match_expression":
            return self.match(node, state)
        if kind in {"while_expression", "for_expression", "loop_expression"}:
            before, branch = state.copy(), state.copy()
            condition = self.expression(self.field(node, "condition"), branch)
            if kind == "while_expression" and condition == tls.FALSE:
                return UNKNOWN, True
            value = self.expression(self.field(node, "value"), branch)
            if (
                kind == "for_expression"
                and value.kind == sql.MAPPED_ROWS
                and not value.items
            ):
                self.sql_result(node, replace(value, kind=sql.EXECUTED + sql.MAPPED_ROWS + "::next"), branch)
            branch.frames.append({})
            self.bind_pattern(
                self.field(node, "pattern"),
                replace(
                    value,
                    kind=None,
                    api=None,
                    canonical=False,
                    contained=False,
                ),
                branch,
            )
            self.block(self.field(node, "body"), branch)
            branch.frames.pop()
            state.merge([before, branch])
            return UNKNOWN, True
        if kind == "function_item":
            self.function(node, state)
            return UNKNOWN, True
        if kind in _ITEMS or kind == "use_declaration":
            return UNKNOWN, True
        return self.expression(node, state), True

    def let_conditions(self, condition):
        """``if let P = v`` and ``if let P = v && let Q = w`` conditions."""
        if condition is None:
            return []
        if condition.type == "let_condition":
            return [condition]
        if condition.type == "let_chain":
            return [c for c in condition.named_children if c.type == "let_condition"]
        return []

    def branch(self, node, state):
        condition = self.field(node, "condition")
        unix_condition = None
        if condition is not None and condition.type == "macro_invocation":
            macro = self.text(self.field(condition, "macro"))
            if state.resolve(macro) == "std::cfg" or (
                macro == "cfg" and not any("cfg" in frame for frame in state.frames)
            ):
                tokens = next((child for child in condition.named_children if child.type == "token_tree"), None)
                unix_condition = permissions.unix_cfg(self.cfg_key(tokens)[1:-1])
        bound = [
            (
                self.field(item, "pattern"),
                self.expression(self.field(item, "value"), state),
            )
            for item in self.let_conditions(condition)
        ]
        condition_value = UNKNOWN if bound else self.expression(condition, state)
        alternatives, values = [], []
        for truth, body in [
            (True, self.field(node, "consequence")),
            (False, self.field(node, "alternative")),
        ]:
            if condition_value.kind == tls.BOOLEAN and condition_value.literal in {
                "true",
                "false",
            }:
                if truth != (condition_value.literal == "true"):
                    continue
            branch = state.copy()
            if (
                condition is not None
                and condition.type == "identifier"
                and condition_value.kind == tls.BOOLEAN
            ):
                branch.assign(self.text(condition), tls.TRUE if truth else tls.FALSE)
            if unix_condition is not None and truth != unix_condition:
                branch.conditions |= {("(", "not", "(", "unix", ")", ")")}
            if truth and bound:
                branch.frames.append({})
                for pattern, value in bound:
                    self.bind_pattern(
                        pattern,
                        replace(
                            value, kind=None, api=None, canonical=False, contained=False
                        ),
                        branch,
                    )
            self.containment(condition, truth, branch)
            if body is not None and body.type == "else_clause":
                body = body.named_children[-1] if body.named_children else None
            value, continuing = (
                self.statement(body, branch) if body is not None else (UNKNOWN, True)
            )
            if truth and bound:
                branch.frames.pop()
            if continuing:
                alternatives.append(branch)
                values.append(value)
        if alternatives:
            state.merge(alternatives)
        return sql.join_strings(values), bool(alternatives)

    def match(self, node, state):
        subject = self.expression(self.field(node, "value"), state)
        body = self.field(node, "body")
        alternatives, values = [], []
        for arm in body.named_children if body is not None else ():
            if arm.type != "match_arm":
                continue
            branch = state.copy()
            branch.frames.append({})
            pattern = self.field(arm, "pattern")
            self.bind_pattern(
                pattern,
                replace(
                    subject,
                    kind=None,
                    api=None,
                    canonical=False,
                    contained=False,
                ),
                branch,
            )
            self.expression(self.field(pattern, "condition"), branch)
            value, continuing = self.statement(self.field(arm, "value"), branch)
            branch.frames.pop()
            if continuing:
                alternatives.append(branch)
                values.append(value)
        if alternatives:
            state.merge(alternatives)
        return sql.join_strings(values), bool(alternatives)

    def invalidate_path(self, node, state):
        # Invalidating at the escape point also covers a subsequently stored
        # mutable view, without pretending to model Rust's complete alias graph.
        if node is None:
            return
        if node.type == "identifier":
            old = state.get(self.text(node))
            if old.kind in reqwest.REQUESTS:
                state.assign(self.text(node), Value(kind=old.kind))
            if old.kind in cookies.TYPES:
                state.assign(self.text(node), UNKNOWN)
            if old.kind in {
                tls.BOOLEAN,
                tls.PARAMETER,
                tls.INPUT_LINE,
                tls.EMPTY_BUFFER,
            }:
                state.assign(self.text(node), replace(old, kind=None, literal=None))
            if old.kind == sensitive.EXPOSED:
                state.assign(self.text(node), replace(old, kind=None))
            if sql.mutable_sql_value(old):
                state.assign(self.text(node), replace(old, kind=None, password_write=None))
            if old.kind == "path":
                state.assign(
                    self.text(node),
                    replace(
                        old,
                        sources=old.sources | {"unknown mutable path operation"},
                        canonical=False,
                        contained=False,
                    ),
                )
        elif node.type == "call_expression":
            callee = self.field(node, "function")
            if callee is not None and callee.type == "field_expression":
                self.invalidate_path(self.field(callee, "value"), state)
        elif node.type in {"reference_expression", "parenthesized_expression"}:
            child = self.field(node, "value") or next(iter(node.named_children), None)
            self.invalidate_path(child, state)

    def assign_request_url(self, left, value, state):
        while left is not None and left.type == "parenthesized_expression":
            left = next(iter(left.named_children), None)
        if (
            left is None
            or left.type != "unary_expression"
            or left.children[0].type != "*"
        ):
            return
        call = next(iter(left.named_children), None)
        callee = self.field(call, "function")
        if callee is None or callee.type != "field_expression":
            return
        receiver = self.field(callee, "value")
        arguments = self.field(call, "arguments")
        if (
            receiver is not None
            and receiver.type == "identifier"
            and self.text(self.field(callee, "field")) == "url_mut"
            and arguments is not None
            and not arguments.named_children
        ):
            name = self.text(receiver)
            kind = state.get(name).kind
            if kind in reqwest.REQUESTS:
                state.assign(name, reqwest.destination(value, kind))

    def containment(self, node, truth, state):
        if node is None:
            return
        if node.type == "unary_expression" and self.text(node).lstrip().startswith("!"):
            self.containment(node.named_children[-1], not truth, state)
            return
        callee = self.field(node, "function")
        if truth and node.type == "call_expression" and self.validator(callee):
            # ``if !is_valid_domain(domain) { return ..; }``: past the guard,
            # the checked values passed a predicate the project wrote for them.
            arguments = self.field(node, "arguments")
            for argument in arguments.named_children if arguments is not None else ():
                while argument.type in {
                    "reference_expression",
                    "parenthesized_expression",
                }:
                    inner = self.field(argument, "value") or next(
                        iter(argument.named_children), None
                    )
                    if inner is None:
                        break
                    argument = inner
                if argument.type == "identifier":
                    name = self.text(argument)
                    value = state.get(name)
                    state.assign(
                        name, replace(value, cleared=value.cleared | _VALIDATED)
                    )
            return
        if (
            not truth
            or node.type != "call_expression"
            or callee is None
            or callee.type != "field_expression"
        ):
            return
        receiver = self.field(callee, "value")
        arguments = self.field(node, "arguments")
        args = list(arguments.named_children) if arguments is not None else []
        if (
            self.text(self.field(callee, "field")) != "starts_with"
            or receiver.type != "identifier"
            or len(args) != 1
        ):
            return
        value = state.get(self.text(receiver))
        root = self.expression(args[0], state)
        if (
            value.kind == root.kind == "path"
            and value.canonical
            and root.canonical
            and not root.sources
            and root.literal is not None
        ):
            state.assign(self.text(receiver), replace(value, contained=True))

    def deferred_body(self, body, state):
        effects = []
        self.deferred_http.append(effects)
        self.return_values.append([])
        try:
            tail, continuing = self.statement(body, state)
            returned = self.return_values[-1]
            if continuing:
                if (
                    body is not None
                    and body.type == "block"
                    and not self.has_tail_expression(body)
                ):
                    tail = UNKNOWN
                returned.append(tail)
            result = joined(returned)
        finally:
            self.return_values.pop()
            self.deferred_http.pop()
        return Value(
            kind="rust_helper_future", pending_http=tuple(effects), awaited=result
        )

    def expression(self, node, state):
        if node is None:
            return UNKNOWN
        kind = node.type
        if kind == "boolean_literal":
            return tls.literal(node)
        if kind == "unary_expression" and node.children[0].type == "!":
            child = node.named_children[-1]
            operand = self.expression(child, state)
            if operand.kind == tls.BOOLEAN:
                return tls.inverted(operand)
            return replace(operand, kind=None, api=None, literal=None, canonical=False, contained=False)
        if kind == "async_block":
            body = next((c for c in node.named_children if c.type == "block"), None)
            return self.deferred_body(body, state.copy())
        if kind == "identifier":
            return state.get(self.text(node))
        if kind == "scoped_identifier":
            return Value(api=state.resolve(self.text(node)))
        if kind == "await_expression":
            value = self.expression(node.named_children[0], state)
            return self.await_value(node.children[-1], value, state)
        if kind in {"string_literal", "raw_string_literal"}:
            text = self.text(node)
            first, last = text.find('"'), text.rfind('"')
            return Value(kind="string", literal=text[first + 1 : last])
        if kind in {
            "reference_expression",
            "parenthesized_expression",
            "try_expression",
        }:
            child = self.field(node, "value") or next(iter(node.named_children), None)
            if kind == "reference_expression" and any(
                part.type == "mutable_specifier" for part in node.named_children
            ):
                self.invalidate_path(child, state)
            value = self.expression(child, state)
            return unwrap(value) if kind == "try_expression" else value
        if kind in {
            "block",
            "if_expression",
            "match_expression",
            "assignment_expression",
        }:
            return self.statement(node, state)[0]
        if (
            kind == "binary_expression"
            and self.text(self.field(node, "operator")) == "+"
        ):
            left = self.expression(self.field(node, "left"), state)
            right = self.expression(self.field(node, "right"), state)
            combined = sql.join_strings([left, right])
            return replace(
                combined,
                kind=combined.kind if combined.kind in sql.TEXT_KINDS else None,
                api=None,
                literal=None,
                canonical=False,
                contained=False,
            )
        if kind == "array_expression":
            items = tuple(
                self.expression(child, state) for child in node.named_children
            )
            return replace(joined(items), items=items)
        if kind == "closure_expression":
            # A definition is not execution. Captured values remain available
            # for checking its body, but writes cannot alter the outer state.
            closure = state.copy()
            closure.frames.append({})
            params = self.field(node, "parameters")
            for param in params.named_children if params is not None else ():
                pattern = self.field(param, "pattern") or param
                self.bind_pattern(pattern, UNKNOWN, closure)
            body = self.field(node, "body")
            if params is not None and not params.named_children:
                future = self.deferred_body(body, closure)
                is_async = any(token.type == "async" for token in node.children)
                return replace(
                    future,
                    kind="rust_async_closure" if is_async else "rust_closure",
                    return_sources=future.awaited.sources,
                )
            self.return_values.append([])
            try:
                tail, _continuing = self.statement(body, closure)
                if body is not None and body.type == "block":
                    statements = [
                        child for child, _conditional in self.scope_statements(body)
                    ]
                    last = statements[-1] if statements else None
                    if (
                        last is None
                        or last.type == "let_declaration"
                        or last.type in _ITEMS
                        or last.type == "use_declaration"
                        or (last.children and last.children[-1].type == ";")
                    ):
                        tail = UNKNOWN
                returned = joined([tail, *self.return_values[-1]])
            finally:
                self.return_values.pop()
            # A bounded source summary is not a path restriction, provider
            # identity, or authorization to apply the closure's writes outside.
            return Value(kind="closure", return_sources=returned.sources)
        if kind == "call_expression":
            return self.call(node, state)
        if kind == "macro_invocation":
            return self.macro(node, state)
        if kind == "index_expression" and node.named_children:
            # ``items[i]``: the index selects an element; it does not become
            # part of its text.
            base, *indexes = node.named_children
            for index in indexes:
                self.expression(index, state)
            return replace(
                self.expression(base, state),
                kind=None,
                api=None,
                literal=None,
                canonical=False,
                contained=False,
            )
        # Unknown transformations retain inputs; no helper spelling is a proof.
        return replace(
            joined(self.expression(child, state) for child in node.named_children),
            kind=None,
            api=None,
            literal=None,
            canonical=False,
            contained=False,
        )

    _FORMAT_MACROS = frozenset({"std::format", "std::format_args"})
    _WRITE_MACROS = frozenset({"std::write", "std::writeln"})

    def macro(self, node, state):
        value = joined(self.expression(child, state) for child in node.named_children)
        api = state.resolve(self.text(self.field(node, "macro")))
        tokens = next((c for c in node.named_children if c.type == "token_tree"), None)
        if tokens is not None and api in sensitive.LOG_MACROS:
            if sensitive.logs_secret(api, tokens, state):
                self.sensitive_finding(
                    node,
                    state,
                    (
                        "SKY-D251",
                        "HIGH",
                        f"{api}! logs the exposed contents of a SecretString. Remove the value from the log.",
                    ),
                )
            if log_formats.logs_request_text(tokens, state):
                self.sensitive_finding(
                    node,
                    state,
                    (
                        "SKY-D392",
                        "MEDIUM",
                        f"{api}! displays decoded request text directly in a log message. Escape line breaks before writing a text log.",
                    ),
                )
        if tokens is not None and api in self._FORMAT_MACROS | self._WRITE_MACROS:
            formatted = self.formatted(
                node, tokens.children[1:-1], state, writer=api in self._WRITE_MACROS
            )
            if formatted is not None and api in self._FORMAT_MACROS:
                return formatted
        elif tokens is not None:
            # ``json!({"d": format!(..)})``: formats inside other macros.
            self.token_value(tokens.children[1:-1], state)
        return replace(value, kind=None, api=None, canonical=False, contained=False)

    def formatted(self, node, tokens, state, *, writer=False):
        """The string a ``format!``-family macro builds, and its sinks: HTML
        markup with inserted request data (D228). The result knows which
        inserted value, if any, chooses a URL's host."""
        groups = [[]]
        for token in tokens:
            if token.type == ",":
                groups.append([])
            elif token.type not in {"line_comment", "block_comment"}:
                groups[-1].append(token)
        if writer:
            groups = groups[1:]
        if not groups or len(groups[0]) != 1:
            return None
        template_node = groups[0][0]
        if template_node.type not in {"string_literal", "raw_string_literal"}:
            return None
        template = self.expression(template_node, state).literal or ""
        positional, named = [], {}
        for group in groups[1:]:
            if not group:
                continue
            if (
                len(group) >= 3
                and group[0].type == "identifier"
                and group[1].type == "="
            ):
                value = self.format_argument(group[2:], state)
                named[self.text(group[0])] = sql.format_argument(value, group[2:])
            else:
                value = self.format_argument(group, state)
                positional.append(sql.format_argument(value, group))
        parts, literal, index, next_position = [], [], 0, 0
        while index < len(template):
            if template.startswith(("{{", "}}"), index):
                literal.append(template[index])
                index += 2
                continue
            if template[index] != "{":
                literal.append(template[index])
                index += 1
                continue
            end = template.find("}", index + 1)
            if end < 0:
                break
            name, _, format_spec = template[index + 1 : end].partition(":")
            name = name.strip()
            if not name:
                value = (
                    positional[next_position]
                    if next_position < len(positional)
                    else UNKNOWN
                )
                next_position += 1
            elif name.isdigit():
                value = (
                    positional[int(name)] if int(name) < len(positional) else UNKNOWN
                )
            elif name in named:
                value = named[name]
            elif name.isidentifier():
                value = state.get(name)
            else:
                value = UNKNOWN
            if format_spec and value.kind in sql.TEXT_KINDS:
                value = replace(value, kind=None)
            if format_spec and value.kind == sensitive.EXPOSED:
                value = replace(value, kind=None)
            parts.append(("".join(literal), value))
            literal = []
            index = end + 1
        tail = "".join(literal)
        inserted = joined(value for _text, value in parts) if parts else UNKNOWN
        if not parts or fixes_host(parts[0][0]):
            host = UNKNOWN
        elif not parts[0][0]:
            following = parts[1][0] if len(parts) > 1 else tail
            # ``format!("{base}/path/{x}")``: only the leading value can
            # choose the host, as for a setting followed by a separator.
            host = parts[0][1] if following[:1] in {"/", "?", "#"} else None
        else:
            host = None
        if parts and HTML_MARKUP_RE.search(template):
            self.sink(
                _D228,
                "Request data is inserted into HTML markup without escaping "
                "(cross-site scripting); escape it (html_escape::encode_text) "
                "or render it with an auto-escaping template.",
                template_node,
                inserted,
                state,
            )
        return replace(
            inserted,
            kind=sql.formatted_kind(parts, inserted),
            secret_in_url=transport.exposed_url(parts),
            interpolated_request_pattern=(
                bool(parts)
                and bool(parts[0][0].strip())
                and bool(tail.strip())
                and any(v.kind == sql.TEXT and v.request_sources for _, v in parts)
            ),
            api=None,
            literal=None if parts else template,
            canonical=False,
            contained=False,
            host=host,
        )

    @staticmethod
    def rendered_string_length(value):
        return Value(sources=value.sources, cleared=value.cleared | {_D228})

    def format_argument(self, tokens, state):
        # Macro arguments arrive as flat tokens. Only the entire expression
        # `known_string.len()` gives a byte count with no input text.
        if (
            len(tokens) == 4
            and tokens[0].type == "identifier"
            and tokens[1].type == "."
            and tokens[2].text == b"len"
            and tokens[3].type == "token_tree"
            and tokens[3].children[0].type == "("
            and not any(
                child.type not in {"line_comment", "block_comment"}
                for child in tokens[3].named_children
            )
        ):
            receiver = state.get(self.text(tokens[0]))
            if receiver.kind in sql.TEXT_KINDS and not receiver.items:
                return self.rendered_string_length(receiver)
        value = self.token_value(tokens, state)
        if value.kind in {sensitive.SECRET, sensitive.EXPOSED}:
            return replace(
                value,
                kind=sensitive.EXPOSED
                if sensitive.exposed_argument(tokens, state)
                else None,
            )
        return value

    def token_value(self, tokens, state):
        """Approximate the value of a macro argument from its tokens: names
        read their bindings, calls of known encoders clear their result, and
        nested ``format!`` calls are analysed as such."""
        values = []
        index, count = 0, len(tokens)
        while index < count:
            token = tokens[index]
            after_dot = index > 0 and tokens[index - 1].type == "."
            if token.type == "identifier" and not after_dot:
                names = [self.text(token)]
                end = index + 1
                while (
                    end + 1 < count
                    and tokens[end].type == "::"
                    and tokens[end + 1].type == "identifier"
                ):
                    names.append(self.text(tokens[end + 1]))
                    end += 2
                path = "::".join(names)
                if (
                    end + 1 < count
                    and tokens[end].type == "!"
                    and tokens[end + 1].type == "token_tree"
                ):
                    inner_tokens = tokens[end + 1].children[1:-1]
                    api = state.resolve(path)
                    result = None
                    if api in self._FORMAT_MACROS:
                        result = self.formatted(tokens[end + 1], inner_tokens, state)
                    values.append(result or self.token_value(inner_tokens, state))
                    index = end + 2
                    continue
                if (
                    end < count
                    and tokens[end].type == "token_tree"
                    and self.text(tokens[end]).startswith("(")
                ):
                    inner = self.token_value(tokens[end].children[1:-1], state)
                    values.append(self.encoded(state.resolve(path), inner))
                    index = end + 1
                    continue
                if len(names) == 1:
                    values.append(state.get(names[0]))
                index = end
                continue
            if token.type == "token_tree":
                values.append(self.token_value(token.children[1:-1], state))
            index += 1
        return joined(values) if values else UNKNOWN

    @staticmethod
    def encoded(api, value):
        if api in URL_ENCODERS:
            return replace(value, cleared=value.cleared | {_D216, _D228}, host=None)
        if api in HTML_ESCAPERS:
            return replace(value, cleared=value.cleared | {_D228}, host=None)
        return value

    def local_targets(self, callee, method_style, state):
        """Function items of this file a call can reach, and whether its first
        argument is the receiver. Only unambiguous helpers count."""
        enclosing_impl = None
        owner = self.owner()
        if owner is not None:
            parent = owner.parent
            while parent is not None and parent.type not in {
                "impl_item",
                "source_file",
            }:
                parent = parent.parent
            if parent is not None and parent.type == "impl_item":
                enclosing_impl = parent
        if method_style:
            receiver = self.field(callee, "value")
            if receiver is None or receiver.type != "self":
                return []
            name = self.text(self.field(callee, "field"))
            return [
                (node, False)
                for node, impl in self.local_functions.get(name, ())
                if impl is not None and impl == enclosing_impl
            ]
        if callee.type == "identifier":
            binding = state.get(self.text(callee)).local_function
            found = [
                (node, False)
                for node, impl in self.local_functions.get(self.text(callee), ())
                if impl is None and node.start_byte == binding
            ]
            return found if len(found) == 1 else []
        if callee.type == "scoped_identifier":
            path = self.field(callee, "path")
            name = self.field(callee, "name")
            if path is None or name is None or self.text(path) != "Self":
                return []
            return [
                (node, True)
                for node, impl in self.local_functions.get(self.text(name), ())
                if impl is not None and impl == enclosing_impl
            ]
        return []

    def local_call(self, node, targets, args, state):
        """Request data passed to a local helper whose parameter reaches a sink
        is reported here, at the call that hands it over."""
        if len(targets) != 1:
            return None
        target, receiver_first = targets[0]
        params = self.field(target, "parameters")
        has_self = params is not None and any(
            part.type == "self_parameter" for part in params.named_children
        )
        values = args[1:] if receiver_first and has_self else args
        if (
            self.tls_callers is not None
            and not self.harness_file
            and _TEST_CFG not in state.conditions
        ):
            switches = [
                (i, arg)
                for i, arg in enumerate(values)
                if arg.kind in {tls.BOOLEAN, tls.PARAMETER} and not arg.items
            ]
            awaited = node.parent is not None and node.parent.type == "await_expression"
            if (
                switches
                and (awaited or not is_async_function(target))
                and tls.direct_call_path(node)
            ):
                for index, arg in switches:
                    key = f"{SYMBOLIC}{target.start_byte}#{index}"
                    self.tls_callers.setdefault(key, set()).add(arg)
        return self.apply_helper(
            node,
            self.text(self.field(target, "name")),
            target.start_byte,
            values,
            state,
            self.summaries_in.get(target.start_byte, {}),
            self.http_returns_in.get(target.start_byte),
            is_async_function(target),
        )

    def apply_helper(
        self, node, name, target_key, values, state, sinks, returned, is_async
    ):
        effects = []
        for index, argument in enumerate(values):
            for rule, via in sorted(sinks.get(index, ())):
                chain = f"{name}()" + (f" -> {via}" if via else "")
                if chain.count("->") > _MAX_CHAIN:
                    continue
                value = (
                    argument.host
                    if rule == _D216 and argument.host is not None
                    else argument
                )
                if not self.reaches(rule, value):
                    continue
                if rule == _D216:
                    if is_async and reqwest.has_dispatch(via):
                        effects.append((chain, value))
                    else:
                        self.helper_http_sink(node, chain, value, state)
                else:
                    self.record_summary(rule, value, chain)
                    if not value.request_sources or _TEST_CFG in state.conditions:
                        continue
                    self.emit(
                        rule,
                        _CALL_SITE_MESSAGES[rule].format(chain=chain),
                        node,
                        value,
                        extra={"rust_flow": {"via": chain}},
                    )
        result = (
            bind_http_return(returned, target_key, values)
            if returned is not None
            else None
        )
        if is_async and (effects or result is not None):
            return Value(
                kind="rust_helper_future",
                pending_http=tuple(effects),
                awaited=result
                if result is not None
                else Value(sources=joined(values).sources),
            )
        return result

    def helper_http_sink(self, node, via, value, state):
        self.sink(
            _D216,
            _CALL_SITE_MESSAGES[_D216].format(chain=via),
            node,
            value,
            state,
            via=via,
            extra={"rust_flow": {"via": via}},
        )

    def poll_helper(self, node, value, state):
        for via, destination in value.pending_http:
            self.helper_http_sink(node, via, destination, state)
        return value.awaited if value.awaited is not None else UNKNOWN

    def url_sink(self, node, value, description, state):
        """The URL of an outbound HTTP request (D216). Only the part that
        chooses the host counts: request data after a fixed
        ``scheme://host/`` is not server-side request forgery."""
        url = value.host if value.host is not None else value
        self.sink(
            _D216,
            f"Request data chooses the URL of an outbound HTTP request "
            f"({description}); check the destination against an allowlist "
            "(server-side request forgery).",
            node,
            url,
            state,
            via=description,
        )

    def await_value(self, node, value, state, operation="await"):
        if value.kind == sql.VALUE_FUTURE and not value.items:
            return value.awaited or UNKNOWN
        if (value.kind or "").startswith(sql.FUTURE) and not value.items:
            return self.sql_result(
                node,
                replace(value, kind=sql.EXECUTED + value.kind[len(sql.FUTURE) :]),
                state,
            )
        if value.kind == "rust_helper_future":
            return self.poll_helper(node, value, state)
        if value.kind == "reqwest_future":
            self.authenticated_http(node, value, state)
            self.url_sink(node, value, f"reqwest dispatch ({operation})", state)
            return Value(kind="result_reqwest_async_response")
        if value.kind == "reqwest_text_future" and not value.items:
            return Value(kind="result_" + sql.REMOTE_TEXT)
        return replace(
            value, kind=None, api=None, literal=None, canonical=False, contained=False
        )

    def reqwest_result(self, node, result, operation, state):
        if result.kind == "reqwest_blocking_dispatch":
            callee = self.field(node, "function")
            method_name = self.field(callee, "field") or node
            self.authenticated_http(method_name, result, state)
            self.url_sink(method_name, result, f"reqwest dispatch ({operation})", state)
            return Value(kind="result_reqwest_blocking_response")
        return result

    def tls_setting(self, node, kind, name, args, state):
        if len(args) != 1:
            return None
        setting = tls.setting(kind, name)
        if setting is None:
            return None
        owner, check, disabled = setting
        switch = args[0]
        if not switch.items and switch.kind == tls.BOOLEAN:
            if switch.literal == disabled.literal:
                self.tls_off(
                    node, f"{owner}::{name} disables TLS {check} verification.", state
                )
            elif switch.literal is None:
                self.tls_off(
                    node,
                    f"{owner}::{name} can disable TLS {check} verification depending on its Boolean input.",
                    state,
                )
        elif (
            switch.kind == tls.PARAMETER
            and not switch.items
            and not self.harness_file
            and _TEST_CFG not in state.conditions
            and tls.direct_call_path(node)
        ):
            message = f"A local caller supplies a setting that can disable TLS {check} verification in {owner}::{name}."
            self.tls_parameters.append((switch, disabled, node, message, state))
        # The native-tls and reqwest setters return their builder. Curl's
        # setters return Result<(), Error> and leave the handle in place.
        return UNKNOWN if kind in tls.CURL else Value(kind=kind)

    def authenticated_http(self, node, value, state):
        if value.secret_in_url and not value.items:
            self.configuration_finding(
                "SKY-D391",
                node,
                state,
                "rust_reqwest_url_secret",
                "An exposed SecretString is included in the request URL. URLs can be logged. Send the secret in an appropriate header or body.",
                severity="HIGH",
            )
        if value.http_transport == transport.AUTHENTICATED and not value.items:
            self.configuration_finding(
                "SKY-D356",
                node,
                state,
                "rust_reqwest_http_auth",
                "The reqwest client was asked to send HTTP authentication to a cleartext HTTP URL. Use HTTPS.",
            )

    def configuration_finding(
        self, rule, node, state, evidence, message, *, severity="MEDIUM"
    ):
        if self.harness_file or _TEST_CFG in state.conditions:
            return
        owner = node.parent
        while owner is not None and owner.type != "function_item":
            if owner.type in {"closure_expression", "async_block"}:
                return
            owner = owner.parent
        self.findings.append(
            {
                "rule_id": rule,
                "severity": severity,
                "category": "danger",
                "file": self.file,
                "line": node.start_point[0] + 1,
                "col": node.start_point[1],
                "message": message,
                "metadata": {"security_evidence": {"evidence_kind": evidence}},
            }
        )

    def tls_off(self, node, message, state):
        if self.harness_file or _TEST_CFG in state.conditions:
            return
        self.findings.append(
            {
                "rule_id": _D210,
                "severity": _SEVERITY[_D210],
                "message": message,
                "file": self.file,
                "line": node.start_point[0] + 1,
                "col": node.start_point[1],
                "category": "danger",
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": "rust_tls_configuration",
                        "analysis_complete": True,
                    }
                },
            }
        )

    def sensitive_finding(self, node, state, finding):
        rule, severity, message = finding
        self.configuration_finding(
            rule, node, state, "rust_resolved_api", message, severity=severity
        )

    def certificate_verifier(self, node, state):
        """``impl ServerCertVerifier for X`` whose ``verify_server_cert``
        returns ``ServerCertVerified::assertion()`` without any check: every
        certificate, including an attacker's, is accepted."""
        trait = self.field(node, "trait")
        if trait is None or self.harness_item(node):
            return
        trait_path = state.resolve(self.text(trait)) or ""
        if self.text(trait).rsplit("::", 1)[-1] != "ServerCertVerifier" or not (
            trait_path.startswith(("rustls::", "tokio_rustls::"))
        ):
            return
        body = self.field(node, "body")
        for item in body.named_children if body is not None else ():
            if item.type != "function_item":
                continue
            if self.text(self.field(item, "name")) != "verify_server_cert":
                continue
            block = self.field(item, "body")
            statements = [
                child
                for child in (block.named_children if block is not None else ())
                if child.type not in {"line_comment", "block_comment"}
            ]
            if len(statements) != 1:
                continue
            only = statements[0]
            if only.type == "expression_statement" and only.named_children:
                only = only.named_children[0]
            if only.type == "return_expression" and only.named_children:
                only = only.named_children[0]
            text = re.sub(r"\s+", "", self.text(only))
            if re.fullmatch(
                r"Ok\((?:[A-Za-z_][A-Za-z0-9_]*::)*ServerCertVerified::assertion\(\)\)",
                text,
            ):
                type_name = self.text(self.field(node, "type"))
                self.tls_off(
                    item,
                    f"TLS certificate verification is disabled: {type_name}'s "
                    "verify_server_cert accepts every certificate "
                    "(ServerCertVerified::assertion() without checks), so any "
                    "server can impersonate the peer.",
                    state,
                )

    def argument_nodes(self, node):
        arguments = self.field(node, "arguments")
        if arguments is None:
            return []
        return [
            child
            for child in arguments.named_children
            if child.type not in {"line_comment", "block_comment"}
        ]

    def call(self, node, state):
        callee = self.field(node, "function")
        arg_nodes = self.argument_nodes(node)
        if callee is not None and callee.type == "generic_function":
            member = self.field(callee, "function")
            type_args = self.field(callee, "type_arguments")
            if (
                member is not None
                and member.type == "field_expression"
                and self.text(self.field(member, "field")) == "parse"
                and not arg_nodes
                and type_args is not None
                and [self.text(c) for c in type_args.named_children] == ["bool"]
            ):
                source = self.expression(self.field(member, "value"), state)
                if source.kind == tls.INPUT_LINE and not source.items:
                    return Value(kind="result_" + tls.BOOLEAN)
                return replace(
                    source,
                    kind=None,
                    api=None,
                    literal=None,
                    canonical=False,
                    contained=False,
                )
            callee = member or callee
        if callee is not None and callee.type == "field_expression":
            receiver_node = self.field(callee, "value")
            receiver = self.expression(receiver_node, state)
            method = self.text(self.field(callee, "field"))
            buffer = tls.stdin_buffer(receiver, method, arg_nodes, state)
            args = [self.expression(arg, state) for arg in arg_nodes]
            if buffer is not None:
                state.assign(buffer, replace(state.get(buffer), kind=tls.INPUT_LINE))
            network_buffer = unbounded_input.read_destination(
                receiver, method, arg_nodes, state
            )
            if network_buffer is not None:
                offset = unbounded_input.target_statement_offset(node)
                if offset is not None:
                    state.assign(self.text(network_buffer), Value(kind=unbounded_input.READ_BUFFERS[method], network_read_statement=offset))
            self.record_call(node, args)
            targets = self.local_targets(callee, True, state)
            if targets:
                returned = self.local_call(node, targets, args, state)
                if returned is not None:
                    return returned
            return self.method(node, receiver_node, receiver, method, args, state)
        callable_value = self.expression(callee, state)
        args = [self.expression(arg, state) for arg in arg_nodes]
        if not args and callable_value.kind in {"rust_closure", "rust_async_closure"}:
            if callable_value.kind == "rust_async_closure":
                return replace(callable_value, kind="rust_helper_future")
            result = self.poll_helper(node, callable_value, state)
            # Closure summaries only prove data origins and reqwest lifecycle.
            if result.kind and (
                "reqwest_" in result.kind or result.kind == "rust_helper_future"
            ):
                return result
            return Value(sources=callable_value.return_sources)
        combined = joined(args)
        if callable_value.return_sources:
            combined = joined([combined, Value(sources=callable_value.return_sources)])
        api = state.resolve(self.text(callee))
        # Easy2::<Handler>::new and its qualified setters select the same
        # handle API regardless of the response handler type.
        owner_node = self.field(callee, "path")
        if owner_node is not None and owner_node.type == "generic_type":
            owner = state.resolve(self.text(self.field(owner_node, "type")))
            if sensitive.legacy_encryptor(
                owner, owner_node, self.text(self.field(callee, "name")), args, state
            ):
                return Value(kind="rustcrypto_legacy_encryptor")
            if self.text(
                self.field(callee, "name")
            ) == "with_capacity" and request_patterns.integer_vec(owner_node, state):
                api = "std::vec::Vec::with_capacity"
            if owner in {"curl::easy::Easy2", sql.BUILDER}:
                api = owner + "::" + self.text(self.field(callee, "name"))
        if (
            len(args) == 1
            and args[0].kind == "rust_closure"
            and api
            in {
                "std::thread::spawn",
                "tokio::task::spawn_blocking",
                "async_std::task::spawn_blocking",
            }
        ):
            self.poll_helper(node, args[0], state)
            return UNKNOWN
        if self.siblings and api in self.siblings.helpers:
            scope = node.parent
            while scope is not None and scope.type not in {"source_file", "mod_item"}:
                scope = scope.parent
            if scope is not None and scope.type == "source_file":
                name, key, sinks, returned, is_async = self.siblings.helpers[api]
                return self.apply_helper(node, name, key, args, state, sinks, returned, is_async) or UNKNOWN
        if api is None:
            self.record_call(node, args)
            targets = self.local_targets(callee, False, state)
            if targets:
                returned = self.local_call(node, targets, args, state)
                if returned is not None:
                    return returned
        else:
            self.library_calls.add((node.start_byte, node.end_byte))
        if api:
            cookie = cookies.constructor(api, arg_nodes, state, self.text)
            if cookie is not None:
                return cookie
        fs_value = self.permission_call(node, callee, api, args, arg_nodes, state)
        if fs_value is not None:
            return fs_value
        if api == "std::string::String::new" and not args:
            return Value(kind=tls.EMPTY_BUFFER)
        if api == "std::io::stdin" and not args:
            return Value(kind=tls.STDIN)
        if api == "std::fs::exists" and len(args) == 1:
            return Value(kind="result_" + tls.BOOLEAN)
        handle = tls.constructor(api, len(args))
        if handle:
            return Value(kind=handle)
        if api and len(args) == 2:
            owner, _, name = api.rpartition("::")
            result = self.tls_setting(
                self.field(callee, "name") or callee,
                reqwest.TYPES.get(owner, owner),
                name,
                args[1:],
                state,
            )
            if result is not None:
                return result
        if len(args) == 1:
            argument = args[0]
            if (
                api in request_patterns.REGEX
                and argument.kind == sql.TEXT
                and argument.interpolated_request_pattern
                and not argument.items
            ):
                self.sensitive_finding(
                    node,
                    state,
                    (
                        "SKY-D389",
                        "MEDIUM",
                        "Request text is inserted between fixed parts of a regular expression. Escape literal input with regex::escape.",
                    ),
                )
            if (
                api
                in {
                    "std::string::String::with_capacity",
                    "std::vec::Vec::with_capacity",
                }
                and argument.kind == request_patterns.SIZE
                and not argument.items
                and (
                    api.startswith("std::string::")
                    or (owner_node is not None and owner_node.type == "generic_type")
                )
                and request_patterns.unchecked_capacity(node, state)
            ):
                self.sensitive_finding(
                    node,
                    state,
                    (
                        "SKY-D390",
                        "HIGH",
                        "A request supplies the allocation capacity directly. Enforce a maximum before allocating.",
                    ),
                )
        if api in {
            "serde_json::from_reader",
            "serde_json::from_slice",
            "serde_json::from_str",
        } and unbounded_input.unbounded_decode(api, node, args, state):
            self.sensitive_finding(
                node,
                state,
                (
                    "SKY-D233",
                    "MEDIUM",
                    "An unbounded network input is decoded into a Vec. Limit the stream or the buffer size before parsing JSON.",
                ),
            )
        sensitive_value = sensitive.identifier_call(api, args, state)
        if sensitive_value is not None:
            return sensitive_value
        finding = sensitive.call_finding(api, args, state)
        if finding:
            self.sensitive_finding(node, state, finding)
        if api in _ENV_LOOKUPS and self.cargo_build_variable(args):
            return Value(kind="result_string")
        if api in _SOURCES:
            return Value(sources=frozenset({api}), kind="result_string")
        if api and api.startswith(("reqwest::", "reqwest_middleware::")):
            result = reqwest.function(api, args)
            if result is not None:
                return self.reqwest_result(node, result, api, state)
        if len(args) == 1 and args[0].kind in {"reqwest_future", "rust_helper_future"}:
            if api in reqwest.SPAWN:
                self.await_value(node, args[0], state, api)
                return UNKNOWN
            if api == "async_std::task::block_on":
                return self.await_value(node, args[0], state, api)
            if api in {"std::boxed::Box::pin", "std::pin::Pin::new"}:
                return args[0]
        if api in HTTP_FUNCTIONS:
            position = HTTP_FUNCTIONS[api]
            if position < len(args):
                self.url_sink(node, args[position], api, state)
            return UNKNOWN
        sql_result = sql.function(api, args, state)
        if sql_result is not None:
            return self.sql_result(node, sql_result, state)
        if api in HTTP_CLIENT_CONSTRUCTORS:
            return Value(kind="http_client")
        if api in URL_ENCODERS or api in HTML_ESCAPERS:
            return replace(
                self.encoded(api, combined), kind=None, api=None, literal=None
            )
        if api == "url::Url::parse" and args:
            return replace(args[0], kind="result_string", api=None, literal=None)
        if api == "std::process::Command::new":
            executable = args[0] if args else UNKNOWN
            self.sink(
                _D212,
                "Request data selects the process executable; validate or "
                "allowlist it.",
                node,
                executable,
                state,
            )
            return replace(
                executable, kind="command", shell=executable.literal in _SHELLS
            )
        filesystem = next(
            (prefix for prefix in _FILESYSTEMS if api and api.startswith(prefix)), None
        )
        if filesystem:
            operation = api[len(filesystem) :]
            if filesystem == "async_std::fs::" and operation == "File::create_new":
                operation = ""  # Not part of async-std's File API.
            for index in _FILE_PATH_ARGS.get(operation, ()):
                if index < len(args):
                    self.sink(
                        _D215,
                        "Request data reaches a filesystem operation without "
                        "a proven path restriction.",
                        node,
                        args[index],
                        state,
                        via=f"{api}()",
                    )
            if filesystem == "std::fs::" and operation == "canonicalize":
                return replace(
                    combined, kind="result_path", canonical=True, contained=False
                )
        if api in permissions.FS_CALL_RESULTS:
            return Value(sources=combined.sources, kind=permissions.FS_CALL_RESULTS[api])
        if api in _PATH_CONSTRUCTORS:
            return replace(combined, kind="path", canonical=False)
        if api == "std::string::String::from":
            return combined if combined.kind in sql.TEXT_KINDS else replace(combined, kind="string")
        if self.stored_data(self.text(callee), arg_nodes):
            return UNKNOWN
        # Unknown calls may mutate a borrowed path after its guard.
        for argument in arg_nodes:
            if argument.type == "reference_expression" and any(
                child.type == "mutable_specifier" for child in argument.named_children
            ):
                target = self.field(argument, "value")
                if target is not None and target.type == "identifier":
                    old = state.get(self.text(target))
                    state.assign(
                        self.text(target),
                        replace(
                            old,
                            sources=old.sources | {"unknown mutable borrow"},
                            canonical=False,
                            contained=False,
                        ),
                    )
        return replace(
            combined,
            kind=None,
            api=None,
            literal=None,
            canonical=False,
            contained=False,
        )

    def cargo_build_variable(self, args):
        if not self.build_script or len(args) != 1 or args[0].literal is None:
            return False
        name = args[0].literal
        return name in _CARGO_BUILD_VARIABLES or name.startswith(_CARGO_BUILD_PREFIXES)

    def record_call(self, node, args):
        key = (node.start_byte, node.end_byte)
        prior = self.call_arguments.get(key)
        if prior is not None and len(prior) == len(args):
            args = [joined(pair) for pair in zip(prior, args)]
        self.call_arguments[key] = list(args)

    def private_functions(self, node, exposed, harness, found):
        if self.inner_harness(node):
            harness = True
        for child in node.named_children:
            hidden = harness
            previous = child.prev_named_sibling
            if (
                not hidden
                and previous is not None
                and previous.type == "attribute_item"
            ):
                hidden = self.harness_item(child)
            if child.type == "function_item":
                private = (
                    not exposed
                    and self.field(child, "body") is not None
                    and not any(
                        part.type == "visibility_modifier" for part in child.children
                    )
                    and all(
                        name.rsplit("::", 1)[-1] in _INERT_ATTRIBUTES
                        for name, _key in self.attributes(child)
                    )
                )
                if not hidden:
                    name = self.text(self.field(child, "name"))
                    found.setdefault(name, []).append((child, private))
                self.private_functions(child, False, hidden, found)
            elif child.type == "trait_item":
                self.private_functions(child, True, hidden, found)
            elif child.type == "impl_item":
                trait = self.field(child, "trait") is not None
                self.private_functions(child, trait, hidden, found)
            elif child.type == "declaration_list":
                self.private_functions(child, exposed, hidden, found)
            else:
                self.private_functions(child, False, hidden, found)

    def mentions(self, node, harness, names, found):
        if self.inner_harness(node):
            harness = True
        for child in node.children:
            hidden = harness
            previous = child.prev_named_sibling
            if (
                not hidden
                and child.is_named
                and previous is not None
                and previous.type == "attribute_item"
            ):
                hidden = self.harness_item(child)
            if child.type in {"identifier", "field_identifier"}:
                name = self.text(child)
                if name in names and not hidden:
                    found.setdefault(name, []).append(child)
            elif child.children:
                self.mentions(child, hidden, names, found)

    def call_site(self, node):
        target, parent = node, node.parent
        method_style = False
        if parent is not None and parent.type in {
            "scoped_identifier",
            "field_expression",
        }:
            last = self.field(parent, "name") or self.field(parent, "field")
            if last is None or last.start_byte != node.start_byte:
                return None
            method_style = parent.type == "field_expression"
            target, parent = parent, parent.parent
        if parent is not None and parent.type == "generic_function":
            function = self.field(parent, "function")
            if function is None or function.start_byte != target.start_byte:
                return None
            target, parent = parent, parent.parent
        if parent is None or parent.type != "call_expression":
            return None
        function = self.field(parent, "function")
        if (
            function is None
            or function.start_byte != target.start_byte
            or function.end_byte != target.end_byte
        ):
            return None
        return parent, method_style

    def child_module_files(self, node, nested, found):
        for child in node.named_children:
            if child.type == "mod_item":
                body = self.field(child, "body")
                if body is not None:
                    self.child_module_files(body, True, found)
                    continue
                if self.harness_item(child):
                    continue
                name = self.text(self.field(child, "name"))
                attributes = [text for text, _key in self.attributes(child)]
                if nested or "path" in attributes:
                    found.append(None)
                    continue
                path = Path(self.file)
                folder = path.parent
                if path.name not in {"mod.rs", "lib.rs", "main.rs"}:
                    folder = folder / path.stem
                found.append(folder / f"{name}.rs")
                found.append(folder / name)
            elif child.type in {"declaration_list", "block", "function_item"}:
                self.child_module_files(child, nested, found)

    def names_used_by_child_modules(self, names):
        """A private item is visible to its module's descendants, which live
        in other files; a name one of them mentions has callers not seen here."""
        targets = []
        self.child_module_files(self.root, False, targets)
        if any(target is None for target in targets):
            return set(names)
        used = set()
        budget = _CHILD_MODULE_FILES
        for target in targets:
            files = []
            if target.is_file():
                files = [target]
            elif target.is_dir():
                files = sorted(target.rglob("*.rs"))
            for file in files:
                budget -= 1
                if budget < 0:
                    return set(names)
                try:
                    text = file.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    return set(names)
                words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))
                used |= names & words
        return used

    def refuted_parameters(self):
        definitions = {}
        self.private_functions(self.root, False, self.harness_file, definitions)
        names = {
            name
            for name, items in definitions.items()
            if all(private for _node, private in items)
            and any(self.named_like_input(node) for node, _private in items)
        }
        if not names:
            return frozenset()
        names -= self.names_used_by_child_modules(names)
        if not names:
            return frozenset()
        found = {}
        self.mentions(self.root, self.harness_file, names, found)
        refuted = set()
        for name in names:
            own = {
                self.field(node, "name").start_byte
                for node, _private in definitions[name]
            }
            sites = []
            complete = True
            for mention in found.get(name, ()):
                if mention.start_byte in own:
                    continue
                site = self.call_site(mention)
                if site is None:
                    complete = False
                    break
                call, method_style = site
                if (call.start_byte, call.end_byte) in self.library_calls:
                    continue
                recorded = self.call_arguments.get((call.start_byte, call.end_byte))
                if recorded is None:
                    complete = False
                    break
                sites.append((recorded, method_style))
            if not complete or not sites:
                continue
            for node, _private in definitions[name]:
                params = self.field(node, "parameters")
                declared = list(params.named_children) if params is not None else []
                receiver = any(part.type == "self_parameter" for part in declared)
                positional = [part for part in declared if part.type == "parameter"]
                if len(positional) + int(receiver) != len(declared):
                    continue
                aligned = []
                for recorded, method_style in sites:
                    values = recorded
                    if receiver and not method_style:
                        values = recorded[1:]
                    aligned.append(values)
                if any(len(values) != len(positional) for values in aligned):
                    continue
                for index, param in enumerate(positional):
                    pattern = self.field(param, "pattern")
                    if pattern is None or pattern.type != "identifier":
                        continue
                    if all(not values[index].real_sources for values in aligned):
                        refuted.add((node.start_byte, self.text(pattern)))
        return frozenset(refuted)

    def permission_call(self, node, callee, api, args, arg_nodes, state):
        if api == permissions.PERMISSIONS + "::set_readonly" and len(args) == 2:
            self.permission_review(node, api, arg_nodes[1], state)
            return UNKNOWN
        if api in permissions.MODE_RECEIVERS and len(args) == 2:
            if args[0].kind == permissions.MODE_RECEIVERS[api] and not args[0].items:
                self.permission_review(node, api, arg_nodes[1], state)
            return UNKNOWN
        name = self.text(self.field(callee, "name"))
        if name not in {"from_mode", "set_mode", "mode"}:
            return None
        receiver = self.field(callee, "path")
        explicit_trait = None
        if (
            receiver is not None
            and receiver.type == "bracketed_type"
            and receiver.named_children
        ):
            qualified = receiver.named_children[0]
            explicit_trait = (
                state.resolve(self.text(self.field(qualified, "alias"))) or ""
            )
            receiver = self.field(qualified, "type")
        fs_type = state.resolve(self.text(receiver))
        if name == "from_mode" and fs_type == permissions.PERMISSIONS:
            trait = permissions.UNIX_FS + "PermissionsExt"
            count = 1
        else:
            trait = permissions.MODE_TRAITS.get((fs_type, name))
            count = 2
        if not trait or len(args) != count:
            return None
        if explicit_trait != trait and (
            explicit_trait is not None or not permissions.trait_in_scope(state, trait)
        ):
            return None
        self.permission_review(node, f"{trait}::{name}", arg_nodes[-1], state)
        return Value(kind=permissions.PERMISSIONS) if name == "from_mode" else UNKNOWN

    def permission_review(self, node, api, argument, state):
        while (
            argument.type == "parenthesized_expression"
            and len(argument.named_children) == 1
        ):
            argument = argument.named_children[0]
        literal = self.text(argument)
        if api == permissions.PERMISSIONS + "::set_readonly":
            if argument.type != "boolean_literal" or literal != "false":
                return
            rule = permissions.READONLY_RULE
        else:
            if (
                argument.type != "integer_literal"
                or not permissions.ambiguous_mode_literal(literal)
            ):
                return
            rule = permissions.MODE_RULE
        if any(permissions.unix_cfg(cfg[1:-1]) is False for cfg in state.conditions):
            return
        self.findings.append(
            permissions.review_finding(rule, node, self.file, api, literal)
        )

    def sql_result(self, node, result, state):
        if not (result.kind or "").startswith(sql.EXECUTED):
            return result
        exposed_password = (
            result.password_write is not None and result.password_write.complete
        )
        if _TEST_CFG in state.conditions or not (
            result.real_sources or exposed_password
        ):
            return UNKNOWN
        # A closure or async block may be created and discarded without
        # running its database call. This local rule does not trace callbacks.
        owner = node.parent
        while owner is not None and owner.type != "function_item":
            if owner.type in {"closure_expression", "async_block"}:
                return UNKNOWN
            owner = owner.parent
        api = result.kind[len(sql.EXECUTED) :]
        if exposed_password:
            self.sensitive_finding(
                node,
                state,
                (
                    "SKY-D387",
                    "HIGH",
                    "A SQLx write binds an exposed SecretString directly to a password column. Store a password hash.",
                ),
            )
        if not result.real_sources:
            return UNKNOWN
        self.sink(
            _D211,
            f"Externally supplied text reaches the SQL statement executed by {api}. "
            "Use a fixed query and bind values separately.",
            node,
            Value(sources=result.real_sources),
            state,
            via=api,
            extra={"rust_flow": {"via": api}},
        )
        return UNKNOWN

    def method(self, node, receiver_node, receiver, name, args, state):
        if (
            receiver.kind == request_patterns.EMPTY_VEC
            and name in {"reserve", "reserve_exact"}
            and len(args) == 1
            and args[0].kind == request_patterns.SIZE
            and not args[0].items
            and request_patterns.unchecked_capacity(node, state)
        ):
            self.sensitive_finding(
                node,
                state,
                (
                    "SKY-D390",
                    "HIGH",
                    "A request supplies the additional Vec capacity directly. Enforce a maximum before reserving memory.",
                ),
            )
        if (
            (receiver.kind or "").startswith("rust_fixed_bytes_")
            and name in {"into", "as_slice", "as_ref"}
            and not args
        ):
            return Value(kind=receiver.kind)
        if receiver.kind in {"rustcrypto_legacy_encryptor", "sha1::Sha1", "md5::Md5"}:
            finding = sensitive.crypto_method_finding(receiver, name, args, state)
            if finding:
                self.sensitive_finding(node, state, finding)
        if receiver.kind in {sensitive.SECRET, sensitive.EXPOSED}:
            result = sensitive.method_result(receiver, name, args, state)
            if result is not None:
                return result
            if (
                receiver.kind == sensitive.EXPOSED
                and receiver_node.type == "identifier"
                and name not in {"len", "is_empty"}
            ):
                state.assign(self.text(receiver_node), replace(receiver, kind=None))
        if sensitive.writes_password(receiver, name, args):
            self.sensitive_finding(node, state, ("SKY-D387", "HIGH", "A rusqlite write binds an exposed SecretString directly to a password column. Store a password hash."))
        combined = joined([receiver, *args])
        sql_result = sql.method(receiver, name, args, state)
        if (
            receiver.password_write is not None
            and sql_result is None
            and receiver_node.type == "identifier"
        ):
            # A method such as Query::try_bind can alter the next bind position.
            state.assign(
                self.text(receiver_node), replace(receiver, password_write=None)
            )
        if receiver.kind == sql.BUILDER and receiver_node.type == "identifier":
            if sql_result is None:
                state.assign(self.text(receiver_node), UNKNOWN)
            elif sql_result.kind == sql.BUILDER:
                # A setter returns &mut self. If that reference escapes, subsequent
                # mutations through the alias could replace the original SQL.
                standalone = (
                    node.parent is not None
                    and node.parent.type == "expression_statement"
                )
                state.assign(
                    self.text(receiver_node), sql_result if standalone else UNKNOWN
                )
        if sql_result is not None:
            return self.sql_result(node, sql_result, state)
        if receiver.kind in sql.TEXT_KINDS:
            if name == "len" and not args and not receiver.items:
                return self.rendered_string_length(receiver)
            if not args and name in {
                "as_str",
                "as_ref",
                "to_string",
                "to_owned",
                "clone",
            }:
                return receiver
            if receiver_node.type == "identifier" and name not in {
                "len",
                "is_empty",
                "parse",
                "as_bytes",
            }:
                state.assign(self.text(receiver_node), replace(receiver, kind=None))
        arg_nodes = self.argument_nodes(node)
        if not receiver.items:
            if receiver.kind in cookies.RECEIVERS or receiver.kind in cookies.TYPES:
                cookie = cookies.method(
                    node, receiver_node, receiver, name, args, arg_nodes, state, self
                )
                if cookie is not None:
                    return cookie
            tls_input = tls.input_method(receiver, receiver_node, name, args, state)
            if tls_input is not None:
                return tls_input
        if not receiver.items:
            if (
                receiver.kind == permissions.PERMISSIONS
                and name == "set_readonly"
                and len(arg_nodes) == 1
            ):
                self.permission_review(
                    node,
                    permissions.PERMISSIONS + "::set_readonly",
                    arg_nodes[0],
                    state,
                )
                return UNKNOWN
            trait = permissions.MODE_TRAITS.get((receiver.kind, name))
            if (
                trait
                and len(arg_nodes) == 1
                and permissions.trait_in_scope(state, trait)
            ):
                self.permission_review(node, f"{trait}::{name}", arg_nodes[0], state)
                return receiver if name == "mode" else UNKNOWN
            if (
                receiver.kind == permissions.METADATA
                and name == "permissions"
                and not args
            ):
                return Value(kind=permissions.PERMISSIONS)
            if (
                receiver.kind in {permissions.FILE, "path"}
                and name == "metadata"
                and not args
            ):
                return Value(kind="result_" + permissions.METADATA)
            if (
                receiver.kind == permissions.PERMISSIONS
                and name == "clone"
                and not args
            ):
                return receiver
            if receiver.kind == permissions.OPTIONS and len(args) == 1:
                if name in {
                    "read",
                    "write",
                    "append",
                    "truncate",
                    "create",
                    "create_new",
                }:
                    return receiver
                if name == "open":
                    return Value(kind="result_" + permissions.FILE)
            if (
                receiver.kind == permissions.BUILDER
                and name == "recursive"
                and len(args) == 1
            ):
                return receiver
        if name in tls.OPTIONS and not receiver.items:
            method = self.field(self.field(node, "function"), "field") or node
            result = self.tls_setting(method, receiver.kind, name, args, state)
            if result is not None:
                return result
        if (
            receiver.kind == tls.NATIVE
            and len(args) == 1
            and name
            in {
                "add_root_certificate",
                "disable_built_in_roots",
                "identity",
                "max_protocol_version",
                "min_protocol_version",
                "request_alpns",
                "use_sni",
            }
        ):
            return receiver
        if name in {"set_verify", "set_verify_callback"} and arg_nodes:
            mode = state.resolve(self.text(arg_nodes[0])) or ""
            if mode.startswith("openssl::") and mode.endswith("SslVerifyMode::NONE"):
                self.tls_off(
                    node,
                    "TLS certificate verification is disabled "
                    "(SslVerifyMode::NONE): any server can impersonate the peer.",
                    state,
                )
        if (
            name in {"unwrap", "expect"}
            and receiver.kind
            and receiver.kind.startswith(("result_", "option_"))
        ):
            return unwrap(receiver)
        if receiver.kind and receiver.kind.startswith("reqwest_"):
            if name == "url_mut" and receiver.kind in reqwest.REQUESTS and not args:
                # A mutable URL reference can escape. Only a direct replacement
                # (handled when visiting the assignment) establishes a new host.
                self.invalidate_path(receiver_node, state)
                return UNKNOWN
            result = reqwest.method(receiver, name, args)
            if result is not None:
                if (
                    name == "query"
                    and receiver.kind in reqwest.REQUEST_BUILDERS
                    and len(arg_nodes) == 1
                    and not receiver.items
                    and transport.query_pairs(arg_nodes[0], state, self.text)
                ):
                    result = replace(result, secret_in_url=True)
                return self.reqwest_result(
                    node, result, f"reqwest blocking {name}()", state
                )
            if (
                receiver.kind in reqwest.REQUESTS
                and receiver_node.type == "identifier"
                and (receiver.http_transport or receiver.secret_in_url)
            ):
                state.assign(self.text(receiver_node), replace(receiver, http_transport=None, secret_in_url=False))
        if receiver.kind == "http_client":
            if name in HTTP_VERBS:
                position = HTTP_VERBS[name]
                if position < len(args):
                    self.url_sink(node, args[position], f"client.{name}()", state)
                return Value(kind="http_request_builder")
            return Value(kind="http_client")
        if (
            receiver.kind in {"http_request", "actix_http_request"}
            and name in REQUEST_OBJECT_METHODS
        ):
            raw_query = (
                receiver.kind == "actix_http_request"
                and name == "query_string"
                and not args
            )
            return Value(
                sources=frozenset({request_label(f"request.{name}()")}),
                kind=sql.TEXT if raw_query else None,
            )
        if receiver.kind == "path":
            if name == "file_name" and not args:
                return Value(
                    sources=receiver.sources, kind="option_basename", contained=True
                )
            if name == "canonicalize" and not args:
                return replace(
                    receiver, kind="result_path", canonical=True, contained=False
                )
            if name in {"join", "with_file_name", "with_extension"}:
                restricted = not receiver.real_sources and all(
                    not value.real_sources
                    or (value.kind == "basename" and value.contained)
                    for value in args
                )
                return replace(
                    combined, kind="path", canonical=False, contained=restricted
                )
            if name in {"push", "set_file_name", "set_extension"}:
                if args:
                    self.sink(
                        _D215,
                        "Request data modifies a filesystem path without a "
                        "proven path restriction.",
                        node,
                        args[0],
                        state,
                        via=f"PathBuf::{name}()",
                    )
                restricted = not receiver.real_sources and all(
                    not value.real_sources
                    or (value.kind == "basename" and value.contained)
                    for value in args
                )
                changed = replace(
                    combined, kind="path", canonical=False, contained=restricted
                )
                if receiver_node.type == "identifier":
                    state.assign(self.text(receiver_node), changed)
                return changed
            if name in {"as_path", "to_path_buf", "clone"} and not args:
                return receiver
            if name not in _PATH_READ_ONLY:
                self.invalidate_path(receiver_node, state)
        if receiver.kind == "command":
            if name in {"arg", "args"}:
                values = [
                    item
                    for value in args
                    for item in (
                        value.items or (replace(value, kind="unknown_args"),)
                        if name == "args"
                        else (value,)
                    )
                ]
                history = (*receiver.items, *values)
                switch = receiver.shell_switch or any(
                    value.literal in {"-c", "/C", "-Command"} for value in values
                )
                changed = replace(
                    combined,
                    kind="command",
                    shell=receiver.shell,
                    shell_switch=switch,
                    literal=receiver.literal,
                    items=history,
                )
                if receiver_node.type == "identifier":
                    state.assign(self.text(receiver_node), changed)
                payload = self.shell_payload(changed)
                previous_payload = self.shell_payload(receiver)
                if payload.sources and payload.sources != previous_payload.sources:
                    self.sink(
                        _D212,
                        "Request data reaches a shell command argument.",
                        node,
                        payload,
                        state,
                        via="shell -c",
                    )
                return changed
            if name in {"spawn", "output", "status"}:
                return UNKNOWN
        if (
            receiver.kind in {"string", "basename"}
            and name in {"as_str", "to_string", "to_owned", "clone"}
            and not args
        ):
            return receiver
        if self.stored_data(name, arg_nodes):
            return UNKNOWN
        return replace(
            combined,
            kind=None,
            api=None,
            literal=None,
            canonical=False,
            contained=False,
        )

    def validator(self, callee):
        """A predicate written to accept only safe values: a function of this
        file declared ``-> bool``, or a call named ``is_valid*``/``valid*``/
        ``is_safe*``/``is_allowed*``."""
        if callee is None or callee.type not in {"identifier", "scoped_identifier"}:
            return False
        name = self.text(callee).rsplit("::", 1)[-1]
        if _VALIDATOR_NAME_RE.match(name):
            return True
        if callee.type != "identifier":
            return False
        found = self.local_functions.get(name, ())
        return bool(found) and all(
            self.text(self.field(node, "return_type")) == "bool"
            for node, _impl in found
        )

    def stored_data(self, callee_text, arg_nodes):
        """A query that takes a database pool or connection returns stored
        rows, not the request values that selected them
        (``Post::read(&mut context.pool(), id)``,
        ``PostQuery { sort, .. }.list(&mut context.pool())``). A write that
        returns the row it stored (``create``, ``insert``, ``update``,
        ``save``) keeps its input's sources."""
        name = callee_text.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
        if name.startswith(_STORE_WRITES):
            return False
        return any(_STORE_ARGUMENT_RE.search(self.text(arg)) for arg in arg_nodes)

    @staticmethod
    def shell_payload(command):
        if not command.shell:
            return UNKNOWN
        for index, value in enumerate(command.items):
            if value.literal in {"-c", "/C", "-Command"}:
                rest = command.items[index + 1 :]
                if command.literal in {"cmd", "cmd.exe", "powershell", "pwsh"}:
                    return joined(rest)
                return rest[0] if rest else UNKNOWN
            if value.kind == "unknown_args" and value.sources:
                # An unresolved argument sequence may include both the switch
                # and its payload; it cannot establish a fixed command slot.
                return value
        return UNKNOWN


def is_async_function(node):
    return any(
        token.type == "async"
        for child in node.named_children
        if child.type == "function_modifiers"
        for token in child.children
    )


def analyze_security_flow(root_node, file_path, source, *, siblings=None):
    flow = _SecurityFlow(root_node, file_path, source, siblings=siblings)
    flow.module(root_node)
    refuted = frozenset()
    for _round in range(_CALLER_ROUNDS):
        # Parameter summaries grow until every local helper chain is known;
        # caller proofs shrink the parameters that count as operator input.
        # The Cargo pass already selected production modules. Its only rule
        # requires request data, so it needs no extra filesystem caller proofs.
        proven = flow.refuted_parameters() if siblings is None else refuted
        if proven <= refuted and flow.summaries == flow.summaries_in and flow.http_returns == flow.http_returns_in:
            break
        refuted = refuted | proven
        flow = _SecurityFlow(root_node, file_path, source, refuted, flow.summaries, flow.http_returns, siblings=siblings)
        flow.module(root_node)
    for switch, disabled, node, message, state in flow.tls_parameters:
        if any(
            tls.caller_disables(key, disabled, flow.tls_callers)
            for key in switch.sources
        ):
            flow.tls_off(node, message, state)
    return flow


def scan_danger(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None:
        return []
    flow = analyze_security_flow(root_node, file_path, source)
    return _dedupe_findings(flow.findings)


def _module_source_guards(root):
    """Index cfg on ordinary mod declarations. Unresolved source selection abstains."""
    if root is None or root.has_error:
        return None
    reader = _ScopeAttributes(root.text)
    guards = {}
    doc_comment_import = False
    doctest_calls = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type in {"source_file", "declaration_list"}:
            for child, _, conditions, _ in reader.scope_entries(node):
                if node == root and ("(", "doctest", ")") in conditions:
                    if child.type == "extern_crate_declaration":
                        previous = child.prev_named_sibling
                        doc_comment_import |= (
                            reader.text(child.child_by_field_name("name"))
                            == "doc_comment"
                            and child.child_by_field_name("alias") is None
                            and reader.cfg_key(previous) == ("#", "[", "macro_use", "]")
                        )
                    elif child.type == "expression_statement" and child.named_children:
                        invocation = child.named_children[0]
                        if re.fullmatch(
                            rb'doctest!\s*\(\s*"[^"\\]*\.md"\s*\)', invocation.text
                        ):
                            doctest_calls.add(invocation.start_byte)
                if child.type == "mod_item":
                    name = child.child_by_field_name("name")
                    guards[name.start_point[0] + 1, reader.text(name)] = any(
                        permissions.unix_cfg(cfg[1:-1]) is False for cfg in conditions
                    )
        if node.type == "mod_item" and node.parent.type not in {
            "source_file",
            "declaration_list",
        }:
            return None
        if (
            node.type == "macro_definition"
            and reader.text(node.child_by_field_name("name")) == "doctest"
        ):
            return None
        if node.type in {"attribute", "token_tree"}:
            tokens = reader.cfg_key(node)
            pairs = set(pairwise(tokens))
            if ("path", "=") in pairs or ("include", "!") in pairs or "mod" in tokens:
                return None
        if node.type == "macro_invocation":
            macro = reader.text(node.child_by_field_name("macro")).split("::")[-1]
            if macro == "include":
                return None
            statement = (
                node.parent if node.parent.type == "expression_statement" else node
            )
            # doc-comment's imported Markdown helper embeds documentation in
            # a rustdoc test. Other item macros can emit module declarations.
            if statement.parent.type in {"source_file", "declaration_list"} and not (
                doc_comment_import and node.start_byte in doctest_calls
            ):
                return None
        if node.type != "token_tree":
            pending.extend(node.named_children)
    return guards


def _conditionally_loaded(module):
    while module.parent is not None:
        parent = module.parent
        if any(
            item.kind == "mod" and item.target is module and item.cfg
            for item in parent.items.get(module.path[-1], ())
        ):
            return True
        module = parent
    return False


def drop_non_unix_permission_reviews(findings, project, scope, errors):
    """Drop only reviews whose every observed Cargo module path excludes Unix."""
    from skylos.constants import DEFAULT_EXCLUDE_FOLDERS

    rule_ids = (permissions.READONLY_RULE, permissions.MODE_RULE)
    if (
        project is None
        or not project.complete
        or not project.all_targets_scanned
        or not project.crates
        or errors
        or scope.get("kind")
        not in ("repository_root", "repository_root_with_exclusions")
        or scope.get("scan_path") != str(project.root)
        or scope.get("changed_files_only")
        or not set(scope.get("excluded_folders", ())).issubset(DEFAULT_EXCLUDE_FOLDERS)
    ):
        return findings
    candidates = {
        module.file
        for row in findings
        if row.get("rule_id") in rule_ids
        for module in project.modules_of(row["file"])
        if module.crate.package is not None and _conditionally_loaded(module)
    }
    if not candidates:
        return findings
    guards = {}
    non_unix = set()
    portable = set()
    pending = [(crate.root, False) for crate in project.crates]
    while pending:
        module, excluded = pending.pop()
        if module is None:
            return findings
        if module.file not in guards:
            file_guards = _module_source_guards(project.source_tree(module.file))
            if file_guards is None:
                return findings
            guards[module.file] = file_guards
        if module.file in candidates:
            (non_unix if excluded else portable).add(module.file)
        for items in module.items.values():
            for item in items:
                if item.kind == "mod":
                    key = (item.line, item.name)
                    if key not in guards[module.file]:
                        return findings
                    pending.append((item.target, excluded or guards[module.file][key]))
    files = {project.files[path] for path in non_unix - portable}
    return [
        row
        for row in findings
        if row.get("rule_id") not in rule_ids or row["file"] not in files
    ]


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
