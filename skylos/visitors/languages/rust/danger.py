from __future__ import annotations

import re
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

from ._security_bindings import (
    SYMBOLIC,
    UNKNOWN,
    State,
    Value,
    joined,
    unwrap,
    use_bindings,
)
from .core import RUST_LANG, _get_parser, _is_test_path
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
_D212 = "SKY-D212"
_D215 = "SKY-D215"
_D216 = "SKY-D216"
_D228 = "SKY-D228"
# Sinks that need request data; other inputs are not reported at all.
_REQUEST_ONLY_RULES = frozenset({_D216, _D228})
_SEVERITY = {
    _D210: "HIGH",
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
                root = _get_parser(RUST_LANG).parse(source).root_node
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


class _SecurityFlow:
    def __init__(self, root, file_path, source, refuted=frozenset(), summaries=None):
        self.root = root
        self.file = str(Path(file_path))
        self.source = source
        self.findings = []
        self.return_values = []
        self.refuted = refuted
        self.call_arguments = {}
        self.library_calls = set()
        self.build_script = _is_build_script(file_path)
        self.harness_file = (
            self.build_script
            or _is_test_path(file_path)
            or _declared_test_only(file_path)
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

    def text(self, node):
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

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
        self.record_summary(rule, value, via)
        if rule in _REQUEST_ONLY_RULES:
            if not value.request_sources or _TEST_CFG in state.conditions:
                return
        elif not value.real_sources:
            return
        self.emit(rule, message, node, value, extra=extra)

    def declarations(self, node, state):
        # Rust items (including use declarations) apply throughout their scope.
        for child, _conditional in self.scope_statements(node):
            if child.type in _ITEMS:
                name = self.field(child, "name")
                if name is not None:
                    state.bind(self.text(name), UNKNOWN)
        bindings = {}
        globs = []
        for child, conditional, guards, complete_guards in self.scope_entries(node):
            if child.type == "use_declaration":
                for name, path in use_bindings(child, self.text):
                    if name == "*":
                        globs.append((state.resolve(path), conditional))
                        continue
                    api = state.resolve(path)
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
            for name in GLOB_EXPORTS.get(module, ()):
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

    def cfg_key(self, node):
        """Compare exact cfg token trees; this does not evaluate features."""
        if node is None or node.has_error:
            return ()
        if node.type in {"line_comment", "block_comment"}:
            return ()
        if node.type in {"string_literal", "raw_string_literal"} or not node.children:
            return (self.text(node),)
        return tuple(part for child in node.children for part in self.cfg_key(child))

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
                self.bind_pattern(pattern, Value(sources=sources | symbolic), state)
                continue
            if pattern is None or pattern.type != "identifier":
                self.bind_pattern(pattern, Value(sources=symbolic), state)
                continue
            name = self.text(pattern)
            sources = frozenset()
            kind = "path" if api in _PATH_TYPES else None
            if api in REQUEST_OBJECTS:
                kind = "http_request"
            elif api in HTTP_CLIENT_TYPES:
                kind = "http_client"
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
            state.bind(name, Value(sources=sources | symbolic, kind=kind))
        self.return_values.append([])
        self.functions.append(node)
        try:
            self.block(self.field(node, "body"), state)
        finally:
            self.functions.pop()
            self.return_values.pop()

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
            state.bind(self.text(node), value)
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
            value = self.expression(self.field(node, "value"), state)
            pattern = self.field(node, "pattern")
            self.bind_pattern(pattern, value, state)
            return value, True
        if kind == "assignment_expression":
            value = self.expression(self.field(node, "right"), state)
            left = self.field(node, "left")
            if left is not None and left.type == "identifier":
                state.assign(self.text(left), value)
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
            self.expression(self.field(node, "condition"), branch)
            value = self.expression(self.field(node, "value"), branch)
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
        bound = [
            (
                self.field(item, "pattern"),
                self.expression(self.field(item, "value"), state),
            )
            for item in self.let_conditions(condition)
        ]
        if not bound:
            self.expression(condition, state)
        alternatives, values = [], []
        for truth, body in [
            (True, self.field(node, "consequence")),
            (False, self.field(node, "alternative")),
        ]:
            branch = state.copy()
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
        return joined(values), bool(alternatives)

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
        return joined(values), bool(alternatives)

    def invalidate_path(self, node, state):
        # Invalidating at the escape point also covers a subsequently stored
        # mutable view, without pretending to model Rust's complete alias graph.
        if node is None:
            return
        if node.type == "identifier":
            old = state.get(self.text(node))
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

    def expression(self, node, state):
        if node is None:
            return UNKNOWN
        kind = node.type
        if kind == "identifier":
            return state.get(self.text(node))
        if kind == "scoped_identifier":
            return Value(api=state.resolve(self.text(node)))
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
                named[self.text(group[0])] = self.token_value(group[2:], state)
            else:
                positional.append(self.token_value(group, state))
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
            name = template[index + 1 : end].split(":", 1)[0].strip()
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
            kind="string",
            api=None,
            literal=None if parts else template,
            canonical=False,
            contained=False,
            host=host,
        )

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

    def local_targets(self, callee, method_style):
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
            found = [
                (node, False)
                for node, impl in self.local_functions.get(self.text(callee), ())
                if impl is None
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
        for target, receiver_first in targets:
            params = self.field(target, "parameters")
            declared = list(params.named_children) if params is not None else []
            has_self = any(part.type == "self_parameter" for part in declared)
            values = args[1:] if receiver_first and has_self else args
            summary = self.summaries_in.get(target.start_byte, {})
            name = self.text(self.field(target, "name"))
            for index, argument in enumerate(values):
                for rule, via in sorted(summary.get(index, ())):
                    chain = f"{name}()" + (f" -> {via}" if via else "")
                    if chain.count("->") > _MAX_CHAIN:
                        continue  # recursion: the shorter chain is already known
                    value = argument
                    if rule == _D216 and argument.host is not None:
                        value = argument.host
                    if not self.reaches(rule, value):
                        continue
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

    def call(self, node, state):
        callee = self.field(node, "function")
        args_node = self.field(node, "arguments")
        arg_nodes = list(args_node.named_children) if args_node is not None else []
        if callee is not None and callee.type == "field_expression":
            receiver_node = self.field(callee, "value")
            receiver = self.expression(receiver_node, state)
            args = [self.expression(arg, state) for arg in arg_nodes]
            self.record_call(node, args)
            targets = self.local_targets(callee, True)
            if targets:
                self.local_call(node, targets, args, state)
            method = self.text(self.field(callee, "field"))
            return self.method(node, receiver_node, receiver, method, args, state)
        if callee is not None and callee.type == "generic_function":
            # ``Webmention::new::<Url>(..)``: the turbofish is not part of the path.
            callee = self.field(callee, "function") or callee
        callable_value = self.expression(callee, state)
        args = [self.expression(arg, state) for arg in arg_nodes]
        combined = joined(args)
        if callable_value.return_sources:
            combined = joined([combined, Value(sources=callable_value.return_sources)])
        api = state.resolve(self.text(callee))
        if api is None:
            self.record_call(node, args)
            targets = self.local_targets(callee, False)
            if targets:
                self.local_call(node, targets, args, state)
        else:
            self.library_calls.add((node.start_byte, node.end_byte))
        if api in _ENV_LOOKUPS and self.cargo_build_variable(args):
            return Value(kind="result_string")
        if api in _SOURCES:
            return Value(sources=frozenset({api}), kind="result_string")
        if api in HTTP_FUNCTIONS:
            position = HTTP_FUNCTIONS[api]
            if position < len(args):
                self.url_sink(node, args[position], api, state)
            return UNKNOWN
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
        if api in _PATH_CONSTRUCTORS:
            return replace(combined, kind="path", canonical=False)
        if api == "std::string::String::from":
            return replace(combined, kind="string")
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

    def method(self, node, receiver_node, receiver, name, args, state):
        combined = joined([receiver, *args])
        arguments = self.field(node, "arguments")
        arg_nodes = list(arguments.named_children) if arguments is not None else []
        if (
            name in {"danger_accept_invalid_certs", "danger_accept_invalid_hostnames"}
            and len(arg_nodes) == 1
            and self.text(arg_nodes[0]) == "true"
        ):
            self.tls_off(
                node,
                f"TLS certificate verification is disabled ({name}(true)): any "
                "server can impersonate the peer.",
                state,
            )
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
        if receiver.kind == "http_client":
            if name in HTTP_VERBS:
                position = HTTP_VERBS[name]
                if position < len(args):
                    self.url_sink(node, args[position], f"client.{name}()", state)
                return Value(kind="http_request_builder")
            return Value(kind="http_client")
        if receiver.kind == "http_request" and name in REQUEST_OBJECT_METHODS:
            return Value(sources=frozenset({request_label(f"request.{name}()")}))
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


def scan_danger(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None:
        return []
    flow = _SecurityFlow(root_node, file_path, source)
    flow.module(root_node)
    refuted = frozenset()
    for _round in range(_CALLER_ROUNDS):
        # Parameter summaries grow until every local helper chain is known;
        # caller proofs shrink the parameters that count as operator input.
        proven = flow.refuted_parameters()
        if proven <= refuted and flow.summaries == flow.summaries_in:
            break
        refuted = refuted | proven
        flow = _SecurityFlow(root_node, file_path, source, refuted, flow.summaries)
        flow.module(root_node)
    return _dedupe_findings(flow.findings)


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
