from __future__ import annotations

import re
from pathlib import Path

from skylos.rules.danger.danger_web.html_context import (
    ATTR_SAFE,
    TEXT_SAFE,
    URL_SAFE,
    hole_requirements,
)

from . import models

_SUPERGLOBALS = {
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_FILES",
}
_CALLABLE_TYPES = {
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "arrow_function",
}
_CLEAN_CASTS = {"int", "integer", "float", "double", "bool", "boolean"}
_CLEAN_BINARY_OPERATORS = {
    "==",
    "===",
    "!=",
    "!==",
    "<>",
    "<",
    ">",
    "<=",
    ">=",
    "<=>",
    "&&",
    "||",
    "and",
    "or",
    "xor",
    "instanceof",
    "-",
    "*",
    "/",
    "%",
    "**",
}
_CLEAN_UNARY_OPERATORS = {"!", "-", "+"}
_CONSTANT_NODE_TYPES = {
    "nowdoc",
    "integer",
    "float",
    "boolean",
    "null",
    "name",
    "qualified_name",
    "class_constant_access_expression",
    "string_content",
    "escape_sequence",
    "nowdoc_string",
    "nowdoc_body",
    "heredoc_start",
    "heredoc_end",
}
_STRING_TYPES = {"string", "encapsed_string", "heredoc", "shell_command_expression"}
_SPREAD_TYPES = {
    "argument",
    "parenthesized_expression",
    "arguments",
    "sequence_expression",
}
_RECEIVER_ONLY_FOLDED = {name.casefold() for name in models.RECEIVER_ONLY_METHODS}
_REQUEST_SOURCE_FOLDED = {name.casefold() for name in models.REQUEST_SOURCE_METHODS}
_DB_FACADE_SINKS_FOLDED = {name.casefold() for name in models.DB_FACADE_SINKS}
_RAW_SQL_METHODS = {
    "whereRaw",
    "orWhereRaw",
    "havingRaw",
    "orHavingRaw",
    "orderByRaw",
    "groupByRaw",
    "selectRaw",
    "fromRaw",
}
_RAW_SQL_FOLDED = {name.casefold() for name in _RAW_SQL_METHODS}
_PRINTF_SPEC = re.compile(
    r"%(?:(\d+)\$)?[-+ 0]*(?:'.)?[-+ 0]*\d*(?:\.\d+)?([bcdeEfFgGhHosuxX%])"
)
_FIXED_HOST = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.\-]*://[^/?#\s]+[/?#]")
_NON_HTML_CONTENT_TYPE = re.compile(r"^\s*content-type\s*:\s*(?P<type>[^;\s]+)", re.I)
_SEVERITY = {
    "SKY-D201": "CRITICAL",
    "SKY-D204": "CRITICAL",
    "SKY-D211": "CRITICAL",
    "SKY-D212": "CRITICAL",
    "SKY-D215": "HIGH",
    "SKY-D216": "CRITICAL",
    "SKY-D226": "HIGH",
    "SKY-D228": "HIGH",
    "SKY-D255": "CRITICAL",
    "SKY-D349": "CRITICAL",
}
_CWE = {
    "SKY-D201": "CWE-95",
    "SKY-D203": "CWE-78",
    "SKY-D204": "CWE-502",
    "SKY-D211": "CWE-89",
    "SKY-D212": "CWE-78",
    "SKY-D215": "CWE-22",
    "SKY-D216": "CWE-918",
    "SKY-D226": "CWE-79",
    "SKY-D228": "CWE-79",
    "SKY-D255": "CWE-98",
    "SKY-D349": "CWE-1336",
}
_SQL_MESSAGE = "Request-controlled data is built into an SQL string; use placeholders."
_XSS_MESSAGE = (
    "XSS: request data is printed as HTML without escaping for its context; "
    "use htmlspecialchars() (esc_html/esc_attr/esc_url, e()) and never print it "
    "inside a script, event handler or unchecked URL."
)

_FILE_SINKS = {
    "file_get_contents",
    "file_put_contents",
    "fopen",
    "readfile",
    "unlink",
    "file",
    "copy",
    "rename",
    "mkdir",
    "rmdir",
    "chmod",
}
_NUMERIC_SANITIZERS = {"intval", "floatval"}
# Drupal: Symfony request bags, Form API input, and the static escapers.
_REQUEST_BAGS = {"query", "request", "cookies"}
_FORM_STATE_GETTERS = {"getValue", "getValues"}
_HTML_CLASS = "drupal\\component\\utility\\html"
_XSS_CLASS = "drupal\\component\\utility\\xss"
# Xss::filterAdmin() uses this documented HTML-body tag list. A literal
# subset passed to the same filter is no less restrictive than filterAdmin.
_XSS_BODY_TAGS = frozenset(
    "a abbr acronym address article aside b bdi bdo big blockquote br caption "
    "cite code col colgroup command dd del details dfn div dl dt em figcaption "
    "figure footer h1 h2 h3 h4 h5 h6 header hgroup hr i img ins kbd li mark menu "
    "meter nav ol output p pre progress q rp rt ruby s samp section small span "
    "strong sub summary sup table tbody td tfoot th thead time tr tt u ul var wbr".split()
)
_MARKUP_CLASSES = {
    "drupal\\core\\render\\markup",
    "drupal\\views\\render\\viewsrenderpipelinemarkup",
}
_CONVENTIONAL_CLASSES = {
    "html": _HTML_CLASS,
    "xss": _XSS_CLASS,
    "markup": "drupal\\core\\render\\markup",
    "viewsrenderpipelinemarkup": "drupal\\views\\render\\viewsrenderpipelinemarkup",
}
_TAINT_CONTEXTS = {
    "path",
    "sql",
    "sql_quoted",
    "template",
    "deserialize",
    "html",
    "attribute",
    "url",
    "raw",
    "shell",
    "shell_quoted",
    "shell_command",
    "code",
    "ssrf",
}
_SHELL_STARTS = {"shell": "argument", "shell_command": "program"}
_SHELL_CONTROL = frozenset(";&|\n()`")
_SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
_SHELL_OPTION_ARGUMENTS = frozenset({"-o", "+o", "-O", "+O"})
_POSIX_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh"})
_POWERSHELLS = frozenset({"powershell", "pwsh"})
_CMD_COMMAND_FLAGS = frozenset({"/c", "/k", "/r"})
_EVAL_FLAGS = {
    "python": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "php": frozenset({"-r"}),
}
_COMMAND_WRAPPERS = frozenset(
    {
        "sudo",
        "doas",
        "env",
        "nohup",
        "nice",
        "time",
        "timeout",
        "exec",
        "command",
        "xargs",
        "setsid",
    }
)
_WRAPPER_OPTION_ARGUMENTS = {
    "env": {"-u", "--unset", "-C", "--chdir", "-a", "--argv0"},
    "sudo": {
        "-u",
        "--user",
        "-g",
        "--group",
        "-h",
        "--host",
        "-p",
        "--prompt",
        "-C",
        "--close-from",
        "-D",
        "--chdir",
        "-R",
        "--chroot",
        "-r",
        "--role",
        "-t",
        "--type",
        "-T",
        "--command-timeout",
    },
    "doas": {"-u", "-C"},
    "nice": {"-n", "--adjustment"},
    "time": {"-f", "--format", "-o", "--output"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "exec": {"-a"},
    "xargs": {
        "-a",
        "--arg-file",
        "-d",
        "--delimiter",
        "-E",
        "-I",
        "-L",
        "--max-lines",
        "-n",
        "--max-args",
        "-P",
        "--max-procs",
        "-s",
        "--max-chars",
    },
}
_INTERPRETER_OPTION_ARGUMENTS = {
    "python": {"-W", "-X"},
    "node": {
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--input-type",
        "-C",
        "--conditions",
        "--inspect-port",
        "--title",
    },
    "nodejs": {
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--input-type",
        "-C",
        "--conditions",
        "--inspect-port",
        "--title",
    },
    "perl": {"-I", "-M", "-m", "-F"},
    "ruby": {"-r", "-I", "-C", "-E", "--encoding", "-F", "-K"},
    "php": {"-c", "--php-ini", "-d", "--define", "-z", "--zend-extension"},
}
_INTERPRETER_SCRIPT_OPTIONS = {"python": {"-m"}, "php": {"-f", "--file"}}
_ATTACHED_SHORT_EVAL = frozenset({"python", "perl", "ruby", "php"})
_REPEATED_EVAL = frozenset({"node", "nodejs", "perl", "ruby"})
_DYNAMIC = "dynamic"
_NON_HTML = "$#non-html-response"
_VARIABLE = re.compile(r"\$\w+")
_SAFE_ATOM = r"(?:\\d|\\w|\[(?:[A-Za-z0-9_]-[A-Za-z0-9_]|[A-Za-z0-9_]|\\d|\\w|\\-|-)+\]|[A-Za-z0-9_])"
_SAFE_PATTERN_BODY = re.compile(
    r"(?:\^|\\A)(?:" + _SAFE_ATOM + r"(?:[+*?]|\{\d+(?:,\d*)?\})?)+(?:\$|\\z|\\Z)"
)
_FILTER_INPUT_SOURCES = {
    "INPUT_GET",
    "INPUT_POST",
    "INPUT_REQUEST",
    "INPUT_COOKIE",
    "INPUT_SERVER",
}
_DOUBLE_QUOTED_ESCAPES = re.compile(
    r"\\(?:[nrtvef\\$\"]|[0-7]{1,3}|x[0-9a-fA-F]{1,2}|u\{[0-9a-fA-F]+\})"
)


def _php_literal_text(value: str, *, double_quoted: bool) -> str:
    if not double_quoted:
        return re.sub(r"\\([\\'])", r"\1", value)
    replacements = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "e": "\x1b",
        "f": "\f",
        "\\": "\\",
        "$": "$",
        '"': '"',
    }

    def replace(match):
        escape = match[0][1:]
        if escape in replacements:
            return replacements[escape]
        if escape.startswith("x"):
            return chr(int(escape[1:], 16))
        if escape.startswith("u{"):
            codepoint = int(escape[2:-1], 16)
            if codepoint <= 0x10FFFF:
                return chr(codepoint)
            return match[0]
        return chr(int(escape, 8) & 0xFF)

    return _DOUBLE_QUOTED_ESCAPES.sub(replace, value)


def _program_name(word: str) -> str:
    name = re.split(r"[\\/]", word)[-1].casefold()
    if name.endswith(".exe"):
        name = name[:-4]
    return name.rstrip("0123456789.")


def _powershell_command_flag(word: str) -> bool:
    flag = word[1:].casefold()
    if not flag:
        return False
    return (
        "command".startswith(flag) or "encodedcommand".startswith(flag) or flag == "ec"
    )


class _ShellWords:
    def __init__(self, start: str) -> None:
        self.quote = ""
        self.escaped = False
        self.word = ""
        self.in_word = False
        self.dynamic = False
        self.word_role = ""
        self.redirect = False
        self.word_redirect = False
        self.next_role = start
        self.mode = ""
        self.options_done = False
        self.skip_next = False
        self.wrapper = ""
        self.wrapper_operand = False

    def feed(self, value: str) -> None:
        for char in value:
            self._char(char)

    def hole(self) -> str:
        self._start_word()
        self.dynamic = True
        if self.quote:
            return "shell_quoted"
        if self.word_role == "code":
            return "shell_command"
        if self.word_role == "argument" and self._attached_eval_option(self.word):
            return "shell_command"
        if self.word_role == "wrapped":
            if self.wrapper == "env" and self.word.startswith(
                ("--split-string=", "-S")
            ):
                return "shell_command"
            if not (
                self.skip_next
                or self.wrapper_operand
                or (not self.options_done and self.word.startswith("-"))
                or _SHELL_ASSIGNMENT.match(self.word)
            ):
                return "shell_command"
        if self.word_role == "program" and not _SHELL_ASSIGNMENT.match(self.word):
            return "shell_command"
        return "shell"

    def _start_word(self) -> None:
        if self.in_word:
            return
        self.in_word = True
        self.word = ""
        self.dynamic = False
        self.word_redirect = self.redirect
        self.redirect = False
        if self.word_redirect:
            self.word_role = "argument"
        else:
            self.word_role = self.next_role

    def _char(self, char: str) -> None:
        if self.escaped:
            self.escaped = False
            self.word += char
            return
        if self.quote == "'":
            if char == "'":
                self.quote = ""
            else:
                self.word += char
            return
        if self.quote == '"':
            if char == "\\":
                self.escaped = True
            elif char == '"':
                self.quote = ""
            else:
                self.word += char
            return
        if char == "\\":
            self._start_word()
            self.word += char
            self.escaped = True
        elif char in "'\"":
            self._start_word()
            self.quote = char
        elif char in " \t\r":
            self._end_word()
        elif char in "<>":
            self._end_word()
            self.redirect = True
        elif char == "&" and self.redirect and not self.in_word:
            return
        elif char in _SHELL_CONTROL:
            self._end_word()
            self.redirect = False
            self.next_role = "program"
            self.mode = ""
            self.options_done = False
            self.skip_next = False
        else:
            self._start_word()
            self.word += char

    def _end_word(self) -> None:
        if not self.in_word:
            return
        self.in_word = False
        if self.word_redirect:
            return
        literal = not self.dynamic
        if self.word_role == "program":
            self._program_word(self.word, literal)
        elif self.word_role == "wrapped":
            self._wrapped_word(self.word, literal)
        elif self.word_role == "code":
            self._code_word(self.word, literal)
        elif self.word_role == "script":
            self.mode = ""
            self.next_role = "argument"
        else:
            self._argument_word(self.word, literal)

    def _program_word(self, word: str, literal: bool) -> None:
        if literal and _SHELL_ASSIGNMENT.match(word):
            return
        self.next_role = "argument"
        self.mode = ""
        self.options_done = False
        self.skip_next = False
        self.wrapper = ""
        self.wrapper_operand = False
        if not literal:
            return
        name = _program_name(word)
        if name in _POSIX_SHELLS:
            self.mode = "posix"
        elif name == "cmd":
            self.mode = "cmd"
        elif name in _POWERSHELLS:
            self.mode = "powershell"
        elif name == "eval":
            self.mode = "rest"
            self.next_role = "code"
        elif name in _EVAL_FLAGS:
            self.mode = name
        elif name in _COMMAND_WRAPPERS:
            self.wrapper = name
            self.wrapper_operand = name == "timeout"
            self.next_role = "wrapped"

    def _wrapped_word(self, word: str, literal: bool) -> None:
        if self.skip_next:
            self.skip_next = False
            return
        if not literal and not self.options_done and word.startswith("-"):
            return
        if literal and not self.options_done:
            if word == "--":
                self.options_done = True
                return
            if self.wrapper == "command" and word in {"-v", "-V"}:
                self.wrapper = ""
                self.next_role = "argument"
                return
            if self.wrapper == "env" and word in {"-S", "--split-string"}:
                self.wrapper = ""
                self.mode = "env-split"
                self.next_role = "code"
                return
            if self.wrapper == "env" and word.startswith(("--split-string=", "-S")):
                self.wrapper = ""
                self.next_role = "argument"
                return
            if word.startswith("-"):
                self.skip_next = word in _WRAPPER_OPTION_ARGUMENTS.get(self.wrapper, ())
                return
        if (
            self.wrapper in {"env", "sudo"}
            and literal
            and _SHELL_ASSIGNMENT.match(word)
        ):
            return
        if self.wrapper_operand:
            self.wrapper_operand = False
            return
        self._program_word(word, literal)

    def _attached_eval_option(self, word: str) -> bool:
        if self.options_done or self.skip_next:
            return False
        for flag in _EVAL_FLAGS.get(self.mode, ()):
            if flag.startswith("--") and word.startswith(flag + "="):
                return True
            if (
                self.mode in _ATTACHED_SHORT_EVAL
                and len(flag) == 2
                and word.startswith(flag)
            ):
                return True
        return False

    def _code_word(self, word: str, literal: bool) -> None:
        if self.mode == "rest":
            return
        if (
            self.mode == "posix"
            and literal
            and not self.options_done
            and len(word) > 1
            and word[0] in "-+"
        ):
            if word == "--":
                self.options_done = True
            return
        if self.mode not in _REPEATED_EVAL:
            self.mode = ""
        self.next_role = "argument"

    def _argument_word(self, word: str, literal: bool) -> None:
        mode = self.mode
        if self.skip_next:
            self.skip_next = False
            return
        if mode == "posix":
            if literal and not self.options_done and len(word) > 1 and word[0] in "-+":
                if word == "--":
                    self.options_done = True
                elif word in _SHELL_OPTION_ARGUMENTS:
                    self.skip_next = True
                elif word[0] == "-" and word[1] != "-" and "c" in word[1:]:
                    self.next_role = "code"
                return
            self.mode = ""
        elif not literal:
            return
        elif mode == "cmd" and word.casefold() in _CMD_COMMAND_FLAGS:
            self.mode = "rest"
            self.next_role = "code"
        elif (
            mode == "powershell" and word[:1] in "-/" and _powershell_command_flag(word)
        ):
            self.mode = "rest"
            self.next_role = "code"
        elif mode in _EVAL_FLAGS:
            if word == "--":
                self.mode = ""
                self.options_done = True
            elif word in _EVAL_FLAGS[mode]:
                self.next_role = "code"
            elif self._attached_eval_option(word):
                if mode not in _REPEATED_EVAL:
                    self.mode = ""
            elif word in _INTERPRETER_SCRIPT_OPTIONS.get(mode, ()):
                self.next_role = "script"
            elif word.startswith("-"):
                self.skip_next = word in _INTERPRETER_OPTION_ARGUMENTS.get(mode, ())
            else:
                self.mode = ""


def scan_danger(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None:
        return []

    findings: list[dict] = []

    def text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def child_by_type(node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def is_superglobal_var(node) -> bool:
        return (
            node is not None
            and node.type == "variable_name"
            and text(node).strip() in _SUPERGLOBALS
        )

    def is_filter_input_source(node) -> bool:
        if node is None or node.type != "function_call_expression":
            return False
        call_name = functions.get(node.start_byte, "")
        if call_name not in {"filter_input", "filter_input_array"}:
            return False
        args = child_by_type(node, "arguments")
        if args is None:
            return False
        values = [text(child).strip().lstrip("\\") for child in args.children]
        if call_name == "filter_input" and any(
            value in models.TYPED_FILTERS for value in values
        ):
            return False
        return any(value in _FILTER_INPUT_SOURCES for value in values)

    def filter_clears(node, context) -> bool:
        args = child_by_type(node, "arguments")
        if args is None:
            return False
        values = {text(child).strip().lstrip("\\") for child in args.children}
        if values & models.TYPED_FILTERS:
            return True
        return bool(values & models.HTML_FILTERS) and context in {"html", "attribute"}

    def field_text(node, field: str) -> str:
        child = node.child_by_field_name(field)
        if child is None:
            return ""
        return text(child).strip().lstrip("\\")

    static_classes: dict[int, str] = {}
    functions: dict[int, str] = {}
    catch_all_handlers: set[int] = set()

    def index_namespace(nodes, namespace: str) -> None:
        aliases = {}
        declared = set()
        declared_functions = set()

        def declarations(node):
            if node.type in {
                "class_declaration",
                "interface_declaration",
                "trait_declaration",
                "enum_declaration",
            }:
                declared.add(field_text(node, "name").casefold())
            if node.type == "function_definition":
                declared_functions.add(field_text(node, "name").casefold())
            for child in node.named_children:
                declarations(child)

        for node in nodes:
            declarations(node)
            if node.type != "namespace_use_declaration":
                continue
            group = child_by_type(node, "namespace_use_group")
            prefix = None
            if group is not None:
                prefix = child_by_type(node, "namespace_name")
            clauses = (group or node).named_children
            for clause in clauses:
                if (
                    clause.type != "namespace_use_clause"
                    or text(clause).startswith("const ")
                    or text(node).startswith("use const ")
                ):
                    continue
                if text(clause).startswith("function ") or text(node).startswith(
                    "use function "
                ):
                    kind = "function"
                else:
                    kind = "class"
                names = clause.named_children
                if not names:
                    continue
                target = text(names[0]).lstrip("\\")
                if prefix is not None:
                    target = text(prefix) + "\\" + target
                if len(names) > 1:
                    alias = text(names[-1])
                else:
                    alias = target.rpartition("\\")[2]
                aliases[kind, alias.casefold()] = target.casefold()

        def visit(node):
            if node.type == "scoped_call_expression":
                scope = node.child_by_field_name("scope")
                value = ""
                if scope is not None:
                    value = text(scope).strip()
                parts = value.lstrip("\\").split("\\")
                first = parts[0].casefold()
                if value.startswith("\\"):
                    resolved = value.lstrip("\\").casefold()
                elif first == "namespace":
                    resolved = (
                        "\\".join([namespace, *parts[1:]]).casefold().lstrip("\\")
                    )
                elif ("class", first) in aliases:
                    resolved = "\\".join(
                        [aliases["class", first], *parts[1:]]
                    ).casefold()
                elif not namespace and len(parts) == 1 and first not in declared:
                    # Retain the existing bare Drupal spellings, but never an
                    # explicit local declaration or a different imported class.
                    resolved = _CONVENTIONAL_CLASSES.get(first, first)
                else:
                    resolved = "\\".join(filter(None, [namespace, value])).casefold()
                static_classes[node.start_byte] = resolved
            elif node.type == "function_call_expression":
                function = node.child_by_field_name("function")
                value = ""
                if function is not None:
                    value = text(function).strip()
                parts = value.lstrip("\\").split("\\")
                first = parts[0].casefold()
                if value.startswith("\\"):
                    resolved = value.lstrip("\\").casefold()
                elif first == "namespace":
                    resolved = (
                        "\\".join([namespace, *parts[1:]]).casefold().lstrip("\\")
                    )
                elif len(parts) == 1 and ("function", first) in aliases:
                    resolved = aliases["function", first]
                elif len(parts) > 1:
                    prefix = aliases.get(
                        ("class", first), "\\".join(filter(None, [namespace, parts[0]]))
                    )
                    resolved = "\\".join([prefix, *parts[1:]]).casefold()
                elif first in declared_functions:
                    resolved = "\\".join(filter(None, [namespace, first])).casefold()
                    # A global local declaration cannot be a PHP builtin.
                    if not namespace:
                        resolved = "<local>\\" + resolved
                else:
                    # PHP falls back to global functions for an unqualified
                    # name without a namespace-local definition or import.
                    resolved = first
                functions[node.start_byte] = resolved
            elif node.type == "catch_clause":
                types = node.child_by_field_name("type")
                if types is not None:
                    for type_node in types.named_children:
                        value = text(type_node).strip()
                        canonical = value.lstrip("\\").casefold()
                        if value.startswith("\\") and canonical == "throwable":
                            catch_all_handlers.add(node.start_byte)
                        elif aliases.get(("class", canonical)) == "throwable":
                            catch_all_handlers.add(node.start_byte)
                        elif (
                            not namespace
                            and canonical == "throwable"
                            and canonical not in declared
                        ):
                            catch_all_handlers.add(node.start_byte)
            for child in node.named_children:
                visit(child)

        for node in nodes:
            visit(node)

    def index_scopes(node) -> None:
        namespace = ""
        pending = []
        for child in node.named_children:
            if child.type != "namespace_definition":
                pending.append(child)
                continue
            index_namespace(pending, namespace)
            pending = []
            name = child_by_type(child, "namespace_name")
            namespace = ""
            if name is not None:
                namespace = text(name)
            body = child.child_by_field_name("body")
            if body is not None:
                index_namespace(body.named_children, namespace)
                namespace = ""
        index_namespace(pending, namespace)

    index_scopes(root_node)

    def static_call(node) -> tuple[str, str]:
        return (
            static_classes.get(node.start_byte, ""),
            field_text(node, "name").casefold(),
        )

    def unwrap(node):
        while (
            node is not None
            and node.type in {"argument", "parenthesized_expression"}
            and node.named_children
        ):
            node = node.named_children[-1]
        return node

    def literal_text(node):
        node = unwrap(node)
        if node is None or node.type not in {"string", "encapsed_string"}:
            return None
        if any(
            child.type not in {"string_content", "escape_sequence"}
            for child in node.named_children
        ):
            return None
        literal = text(node)
        offset = 0
        if literal[:1] in {"b", "B"}:
            offset = 1
        return _php_literal_text(
            literal[offset + 1 : -1], double_quoted=literal[offset : offset + 1] == '"'
        )

    def call_arguments(node) -> list:
        args = node.child_by_field_name("arguments")
        if args is None:
            args = child_by_type(node, "arguments")
        if args is None:
            return []
        values = []
        for child in args.named_children:
            if child.type == "argument" and child.named_children:
                values.append(child.named_children[-1])
            else:
                values.append(child)
        return values

    request_param_cache: dict[int, set[str]] = {}

    def callable_request_params(callable_node) -> set[str]:
        cached = request_param_cache.get(callable_node.start_byte)
        if cached is not None:
            return cached
        names = set()
        params = callable_node.child_by_field_name("parameters")
        if params is not None:
            for param in params.named_children:
                type_node = param.child_by_field_name("type")
                name_node = param.child_by_field_name("name")
                if type_node is None or name_node is None:
                    continue
                type_name = (
                    text(type_node).strip().lstrip("?\\").rpartition("\\")[2].casefold()
                )
                if type_name.endswith(models.REQUEST_TYPE_SUFFIXES):
                    names.add(text(name_node).strip())
        request_param_cache[callable_node.start_byte] = names
        return names

    def is_request_variable(node) -> bool:
        name = text(node).strip()
        if name in models.REQUEST_VARIABLE_NAMES:
            return True
        parent = node.parent
        while parent is not None:
            if parent.type in _CALLABLE_TYPES:
                if name in callable_request_params(parent):
                    return True
                if parent.type in {"function_definition", "method_declaration"}:
                    return False
            parent = parent.parent
        return False

    def is_request_receiver(node) -> bool:
        node = unwrap(node)
        if node is None:
            return False
        if node.type == "variable_name":
            return is_request_variable(node)
        if node.type == "member_access_expression":
            return field_text(node, "name") == "request"
        if node.type == "function_call_expression":
            return functions.get(
                node.start_byte, ""
            ) == "request" and not call_arguments(node)
        if node.type == "member_call_expression":
            return field_text(node, "name") in models.REQUEST_FACTORIES
        if node.type == "scoped_call_expression":
            return static_call(node)[1] == "request" and not call_arguments(node)
        return False

    def server_key_tainted(key) -> bool:
        if key is None:
            return False
        name = literal_text(key)
        if name is None:
            return True
        if name.startswith("REDIRECT_") and name != "REDIRECT_URL":
            name = name[len("REDIRECT_") :]
        return name.startswith("HTTP_") or name in models.USER_CONTROLLED_SERVER_KEYS

    def root_variable(node):
        node = unwrap(node)
        while node is not None and node.type in {
            "subscript_expression",
            "member_access_expression",
        }:
            if not node.named_children:
                return None
            node = node.named_children[0]
        if node is not None and node.type == "variable_name":
            return text(node).strip()
        return None

    def is_request_source(node) -> bool:
        if node.type == "function_call_expression":
            name = functions.get(node.start_byte, "")
            if is_filter_input_source(node):
                return True
            if name in models.SOURCE_FUNCTIONS:
                return True
            if name in models.SOURCE_FUNCTIONS_WITH_ARGUMENT:
                return bool(call_arguments(node))
            if name in models.INPUT_STREAM_READERS:
                args = call_arguments(node)
                return bool(args) and literal_text(args[0]) == "php://input"
            return False
        if node.type == "member_call_expression":
            if is_drupal_source(node):
                return True
            method = field_text(node, "name")
            target = node.child_by_field_name("object")
            if method in models.UPLOAD_NAME_METHODS:
                return True
            if (
                method in {"get", "all"}
                and target is not None
                and target.type == "member_access_expression"
                and field_text(target, "name") in models.REQUEST_OBJECT_BAGS
                and is_request_receiver(target.child_by_field_name("object"))
            ):
                return True
            if is_request_receiver(target):
                if method in models.REQUEST_SOURCE_METHODS:
                    return True
                if method in models.REQUEST_SOURCE_METHODS_WITH_ARGUMENT:
                    return bool(call_arguments(node))
            return (
                target is not None
                and target.type == "member_access_expression"
                and field_text(target, "name") == "input"
                and text(target.child_by_field_name("object") or target).strip()
                == "$this"
                and method in models.CODEIGNITER_INPUT_METHODS
            )
        if node.type == "scoped_call_expression":
            owner, method = static_call(node)
            return owner in models.REQUEST_FACADES and method in _REQUEST_SOURCE_FOLDED
        return False

    def is_drupal_source(node) -> bool:
        if node.type != "member_call_expression":
            return False
        method = field_text(node, "name")
        target = node.child_by_field_name("object")
        if method == "getUserInput":
            return True
        if method in _FORM_STATE_GETTERS:
            return target is not None and text(target).strip() == "$form_state"
        return (
            method in {"get", "all"}
            and target is not None
            and target.type == "member_access_expression"
            and field_text(target, "name") in _REQUEST_BAGS
        )

    def has_safe_xss_tags(node) -> bool:
        args = node.child_by_field_name("arguments")
        if args is None or len(args.named_children) == 1:
            return True
        if len(args.named_children) != 2:
            return False
        tag_argument = args.named_children[1]
        if len(tag_argument.named_children) != 1:
            return False
        tags = tag_argument.named_children[0]
        if tags.type == "null":
            return True
        if tags.type != "array_creation_expression":
            return False
        for element in tags.named_children:
            if (
                element.type != "array_element_initializer"
                or len(element.named_children) != 1
            ):
                return False
            value = element.named_children[0]
            if value.type not in {"string", "encapsed_string"}:
                return False
            if any(
                child.type not in {"string_content", "escape_sequence"}
                for child in value.named_children
            ):
                return False
            literal = text(value)
            tag = _php_literal_text(literal[1:-1], double_quoted=literal[:1] == '"')
            if tag not in _XSS_BODY_TAGS:
                return False
        return True

    def is_tainted_subscript(node, tainted_vars, context) -> bool:
        parts = node.named_children
        if not parts:
            return False
        guarded = tainted_vars.get(guard_key(node))
        if guarded is not None:
            return context in guarded
        base = parts[0]
        key = None
        if len(parts) > 1:
            key = parts[1]
        if (
            base.type == "variable_name"
            and text(base).strip() == models.SERVER_SUPERGLOBAL
        ):
            return server_key_tainted(key)
        if literal_text(key) in models.FILES_SERVER_KEYS and (
            root_variable(base) not in models.REQUEST_SUPERGLOBALS
        ):
            return False
        return is_tainted_expr(base, tainted_vars, context)

    def html_escaper_contexts(node, name) -> set[str]:
        if name in {"htmlspecialchars", "htmlentities"}:
            args = call_arguments(node)
            if len(args) > 1 and "ENT_NOQUOTES" in text(args[1]):
                return {"html"}
        return {"html", "attribute"}

    def function_clears(node, context) -> bool:
        name = functions.get(node.start_byte, "")
        if name in models.NUMERIC_RESULT_FUNCTIONS or name in models.LOOKUP_FUNCTIONS:
            return True
        if name in models.HTML_ESCAPERS:
            return context in html_escaper_contexts(node, name)
        if name in models.HTML_BODY_FILTERS:
            if name == "strip_tags" and len(call_arguments(node)) > 1:
                return False
            return context == "html"
        if name == "esc_url":
            return context in {"html", "attribute", "url"}
        if name in models.URL_ENCODERS:
            return context in {
                "html",
                "attribute",
                "url",
                "sql_quoted",
                "shell",
                "shell_quoted",
            }
        if name in models.SHELL_ESCAPERS:
            return context == "shell"
        if name in models.SQL_QUOTERS:
            return context in {"sql", "sql_quoted"}
        if name in models.SQL_ESCAPERS:
            return context == "sql_quoted"
        return False

    def is_wpdb(node) -> bool:
        return node is not None and "wpdb" in text(node)

    def member_call_taint(node, tainted_vars, context):
        method = field_text(node, "name")
        target = node.child_by_field_name("object")
        if method in models.SQL_QUOTER_METHODS and context in {"sql", "sql_quoted"}:
            return False
        if method in models.SQL_ESCAPER_METHODS and context == "sql_quoted":
            return False
        if method == "prepare" and is_wpdb(target):
            args = call_arguments(node)
            if not args:
                return False
            return is_tainted_sql(args[0], tainted_vars)
        if method in models.HTML_ESCAPER_METHODS and context in {"html", "attribute"}:
            return False
        if method in models.URL_ESCAPER_METHODS and context in {
            "html",
            "attribute",
            "url",
        }:
            return False
        if method in models.TYPED_REQUEST_METHODS and is_request_receiver(target):
            return False
        folded = method.casefold()
        if folded in _RECEIVER_ONLY_FOLDED or folded.startswith("fetch"):
            return is_tainted_expr(target, tainted_vars, context)
        return None

    def guard_key(node) -> str:
        node = unwrap(node)
        if node is None:
            return ""
        if node.type == "subscript_expression" and len(node.named_children) == 2:
            index = literal_text(node.named_children[1])
            if index is None:
                index = "".join(text(node.named_children[1]).split())
            return f"{guard_key(node.named_children[0])}[{index!r}]"
        return "".join(text(node).split())

    def guard_target(node):
        node = unwrap(node)
        while (
            node is not None
            and node.type == "function_call_expression"
            and functions.get(node.start_byte, "") in models.CASE_FUNCTIONS
        ):
            args = call_arguments(node)
            if not args:
                return None
            node = unwrap(args[0])
        return node

    def safe_pattern(pattern: str) -> bool:
        value = pattern.strip()
        if len(value) < 2 or value[0].isalnum() or value[0] == "\\":
            return False
        closing = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(value[0], value[0])
        end = value.rfind(closing)
        if end <= 0:
            return False
        modifiers = value[end + 1 :]
        if "m" in modifiers or "x" in modifiers:
            return False
        return _SAFE_PATTERN_BODY.fullmatch(value[1:end]) is not None

    def guard_effects(condition, tainted_vars):
        node = unwrap(condition)
        if node is None:
            return set(), set()
        if node.type == "unary_op_expression":
            operator = node.child_by_field_name("operator")
            argument = node.child_by_field_name("argument")
            if operator is not None and text(operator) == "!" and argument is not None:
                when_true, when_false = guard_effects(argument, tainted_vars)
                return when_false, when_true
            return set(), set()
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if operator is None or left is None or right is None:
                return set(), set()
            op = text(operator).casefold()
            if op in {"&&", "and"}:
                left_true, left_false = guard_effects(left, tainted_vars)
                right_true, right_false = guard_effects(right, tainted_vars)
                return left_true | right_true, left_false & right_false
            if op in {"||", "or"}:
                left_true, left_false = guard_effects(left, tainted_vars)
                right_true, right_false = guard_effects(right, tainted_vars)
                return left_true & right_true, left_false | right_false
            if op not in {"===", "==", "!==", "!="}:
                return set(), set()
            equal = op in {"===", "=="}
            for literal, other in ((left, right), (right, left)):
                value = text(unwrap(literal)).strip().casefold()
                if value in {"true", "false", "1", "0"}:
                    when_true, when_false = guard_effects(other, tainted_vars)
                    if (value in {"true", "1"}) == equal:
                        return when_true, when_false
                    return when_false, when_true
                if literal_text(literal) is None:
                    continue
                target = guard_target(other)
                if target is None or target.type not in {
                    "variable_name",
                    "subscript_expression",
                }:
                    continue
                if equal:
                    return {guard_key(target)}, set()
                return set(), {guard_key(target)}
            return set(), set()
        if node.type != "function_call_expression":
            return set(), set()
        name = functions.get(node.start_byte, "")
        args = call_arguments(node)
        if not args:
            return set(), set()
        target = unwrap(args[0])
        if name == "isset" and target.type == "subscript_expression":
            parts = target.named_children
            if len(parts) == 2 and not is_tainted_expr(parts[0], tainted_vars, "raw"):
                return {guard_key(parts[1])}, set()
            return set(), set()
        if name == "filter_var" and filter_clears(node, "raw"):
            return {guard_key(target)}, set()
        if name == "preg_match":
            pattern = literal_text(args[0])
            if len(args) < 2 or pattern is None or not safe_pattern(pattern):
                return set(), set()
            return {guard_key(args[1])}, set()
        if name not in models.GUARD_FUNCTIONS:
            return set(), set()
        if name in {"in_array", "array_key_exists"}:
            if (
                len(args) < 2
                or is_dynamic(args[1], tainted_vars)
                or is_tainted_expr(args[1], tainted_vars, "raw")
            ):
                return set(), set()
            # A loose comparison against true accepts every truthy path string.
            # Only a source-proved strict comparison can narrow the needle to
            # the fixed members; an unknown flag is not a safety proof.
            if name == "in_array" and (
                len(args) < 3 or text(unwrap(args[2])).strip().casefold() != "true"
            ):
                return set(), set()
        return {guard_key(target)}, set()

    def conditional_values(node, tainted_vars) -> list:
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        alternative = node.child_by_field_name("alternative")
        values = []
        if body is None:
            values.append(condition)
        else:
            guarded, _ = guard_effects(condition, tainted_vars)
            if guard_key(body) not in guarded:
                values.append(body)
        values.append(alternative)
        return [value for value in values if value is not None]

    def match_values(node) -> list:
        body = node.child_by_field_name("body")
        if body is None:
            return []
        values = []
        for arm in body.named_children:
            value = arm.child_by_field_name("return_expression")
            if value is not None:
                values.append(value)
        return values

    def is_tainted_expr(node, tainted_vars: dict[str, set[str]], context: str) -> bool:
        if node is None:
            return False
        if context in _SHELL_STARTS:
            parts = shell_parts(node)
            if not is_single_value(parts, node):
                return is_tainted_shell_parts(
                    parts, tainted_vars, _SHELL_STARTS[context]
                )
        if node.type == "function_call_expression":
            call_name = functions.get(node.start_byte, "")
            if call_name in {"filter_input", "filter_var"} and filter_clears(
                node, context
            ):
                return False
        if is_request_source(node):
            return True
        if node.type == "cast_expression":
            cast = child_by_type(node, "cast_type")
            if cast is not None and text(cast).strip().casefold() in _CLEAN_CASTS:
                return False
        if node.type == "subscript_expression":
            return is_tainted_subscript(node, tainted_vars, context)
        if node.type == "function_call_expression" and function_clears(node, context):
            return False
        if node.type == "member_call_expression":
            cleared = member_call_taint(node, tainted_vars, context)
            if cleared is not None:
                return cleared
        if node.type == "conditional_expression":
            return any(
                is_tainted_expr(value, tainted_vars, context)
                for value in conditional_values(node, tainted_vars)
            )
        if node.type == "match_expression":
            return any(
                is_tainted_expr(value, tainted_vars, context)
                for value in match_values(node)
            )
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if (
                operator is not None
                and text(operator).casefold() in _CLEAN_BINARY_OPERATORS
            ):
                return False
        if node.type == "unary_op_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and text(operator) in _CLEAN_UNARY_OPERATORS:
                return False
        if node.type == "scoped_call_expression":
            owner, method = static_call(node)
            if (owner, method) in models.STATIC_ALL_SANITIZERS:
                return False
            if method in _RECEIVER_ONLY_FOLDED:
                return False
            owner, method = static_call(node)
            if (
                owner == _HTML_CLASS
                and method == "escape"
                and context in {"html", "attribute"}
            ):
                return False
            if (
                owner == _XSS_CLASS
                and method in {"filter", "filteradmin"}
                and context == "html"
            ):
                # A caller-supplied allowed-tag list can even allow <script>.
                if method == "filteradmin" or has_safe_xss_tags(node):
                    return False
        if is_superglobal_var(node):
            return True
        if node.type == "variable_name":
            return context in tainted_vars.get(text(node).strip().lstrip("$"), set())
        if node.type == "function_call_expression":
            call_name = functions.get(node.start_byte, "")
            if call_name in _NUMERIC_SANITIZERS or (
                context == "path" and call_name == "basename"
            ):
                return False
        return any(
            is_tainted_expr(child, tainted_vars, context) for child in node.children
        )

    def literal_parts(node, double_quoted, pieces):
        parts = []
        for child in pieces:
            if child.type in {"string_content", "escape_sequence"}:
                parts.append(
                    (
                        "text",
                        _php_literal_text(text(child), double_quoted=double_quoted),
                    )
                )
            else:
                parts.append(("value", (child,), False))
        return parts

    def format_parts(format_node, values, spread=None):
        literal = literal_text(format_node)
        if literal is None:
            parts = [("value", (format_node,), False)]
            parts.extend(("value", (value,), False) for value in values)
            if spread is not None:
                parts.append(("value", (spread,), False))
            return parts
        parts = []
        position = 0
        automatic = 0
        for match in _PRINTF_SPEC.finditer(literal):
            parts.append(("text", literal[position : match.start()]))
            position = match.end()
            kind = match.group(2)
            if kind == "%":
                parts.append(("text", "%"))
                continue
            if match.group(1):
                index = int(match.group(1)) - 1
            else:
                index = automatic
                automatic += 1
            numeric = kind not in {"s", "c"}
            if spread is not None:
                parts.append(("value", (spread,), numeric))
            elif 0 <= index < len(values):
                parts.append(("value", (values[index],), numeric))
            else:
                parts.append(("value", (), numeric))
        parts.append(("text", literal[position:]))
        return parts

    def array_values(node):
        node = unwrap(node)
        if node is None or node.type != "array_creation_expression":
            return None
        values = []
        for element in node.named_children:
            if (
                element.type != "array_element_initializer"
                or not element.named_children
            ):
                return None
            values.append(element.named_children[-1])
        return values

    def sprintf_parts(node, name):
        args = call_arguments(node)
        if not args:
            return [("value", (node,), False)]
        if name == "vsprintf":
            if len(args) < 2:
                return [("value", (node,), False)]
            listed = array_values(args[1])
            if listed is None:
                return format_parts(args[0], [], spread=args[1])
            return format_parts(args[0], listed)
        return format_parts(args[0], args[1:])

    def string_parts(node):
        if (
            node.type in {"argument", "parenthesized_expression"}
            and len(node.named_children) == 1
        ):
            return string_parts(node.named_children[0])
        if node.type == "binary_expression" and any(
            child.type == "." for child in node.children
        ):
            return [
                part for child in node.named_children for part in string_parts(child)
            ]
        if node.type in {"string", "encapsed_string"}:
            literal = text(node)
            offset = 0
            if literal[:1] in {"b", "B"}:
                offset = 1
            double_quoted = literal[offset : offset + 1] == '"'
            if all(
                child.type in {"string_content", "escape_sequence"}
                for child in node.named_children
            ):
                return [
                    (
                        "text",
                        _php_literal_text(
                            literal[offset + 1 : -1], double_quoted=double_quoted
                        ),
                    )
                ]
            return literal_parts(node, double_quoted, node.named_children)
        if node.type == "heredoc":
            body = node.child_by_field_name("value")
            if body is None:
                return []
            return literal_parts(body, True, body.named_children)
        if node.type == "nowdoc":
            body = node.child_by_field_name("value")
            if body is None:
                return []
            return [("text", text(body))]
        if node.type == "function_call_expression":
            name = functions.get(node.start_byte, "")
            if name in {"sprintf", "vsprintf"}:
                return sprintf_parts(node, name)
        return [("value", (node,), False)]

    def html_parts(node):
        return string_parts(node)

    def shell_parts(node):
        inner = node
        while (
            inner.type in {"argument", "parenthesized_expression"}
            and len(inner.named_children) == 1
        ):
            inner = inner.named_children[0]
        if inner.type == "shell_command_expression":
            return literal_parts(inner, True, inner.named_children)
        return string_parts(node)

    def is_single_value(parts, node) -> bool:
        if len(parts) != 1 or parts[0][0] != "value" or len(parts[0][1]) != 1:
            return False
        value = parts[0][1][0]
        return (value.start_byte, value.end_byte, value.type) == (
            node.start_byte,
            node.end_byte,
            node.type,
        )

    def is_tainted_shell_parts(parts, tainted_vars, start: str) -> bool:
        if all(part[0] == "text" for part in parts):
            return False
        words = _ShellWords(start)
        for part in parts:
            if part[0] == "text":
                words.feed(part[1])
                continue
            context = words.hole()
            if part[2]:
                continue
            if any(is_tainted_expr(value, tainted_vars, context) for value in part[1]):
                return True
        return False

    def level_context(level) -> str:
        if level == TEXT_SAFE:
            return "html"
        if level == ATTR_SAFE:
            return "attribute"
        if level == URL_SAFE:
            return "url"
        return "raw"

    def starts_with_path(node) -> bool:
        node = unwrap(node)
        while node is not None and node.type == "function_call_expression":
            if functions.get(node.start_byte, "") not in models.HTML_ESCAPERS:
                return False
            args = call_arguments(node)
            if not args:
                return False
            node = unwrap(args[0])
        if node is None or node.type != "subscript_expression":
            return False
        parts = node.named_children
        return (
            len(parts) == 2
            and text(parts[0]).strip() == models.SERVER_SUPERGLOBAL
            and literal_text(parts[1]) in models.PATH_SERVER_KEYS
        )

    def value_context(value, level) -> str:
        if level == URL_SAFE and starts_with_path(value):
            return "attribute"
        return level_context(level)

    def is_tainted_html_parts(parts, tainted_vars) -> bool:
        requirements = iter(hole_requirements(parts))
        for part in parts:
            if part[0] == "text":
                continue
            level, _ = next(requirements)
            if part[2]:
                continue
            if any(
                is_tainted_expr(value, tainted_vars, value_context(value, level))
                for value in part[1]
            ):
                return True
        return False

    def is_tainted_html(node, tainted_vars: dict[str, set[str]]) -> bool:
        return is_tainted_html_parts(html_parts(node), tainted_vars)

    def sql_hole_states(parts) -> list[str]:
        state = "code"
        states = []
        for part in parts:
            if part[0] != "text":
                states.append(state)
                continue
            value = part[1]
            index = 0
            while index < len(value):
                char = value[index]
                if state == "code":
                    if char == "'":
                        state = "single"
                    elif char == '"':
                        state = "double"
                    elif char == "`":
                        state = "backtick"
                    elif char == "#" or value.startswith("--", index):
                        state = "line_comment"
                    elif value.startswith("/*", index):
                        state = "block_comment"
                        index += 1
                elif state in {"single", "double"}:
                    quote = "'"
                    if state == "double":
                        quote = '"'
                    if char == "\\":
                        index += 1
                    elif char == quote:
                        if value.startswith(quote, index + 1):
                            index += 1
                        else:
                            state = "code"
                elif state == "backtick":
                    if char == "`":
                        state = "code"
                elif state == "line_comment":
                    if char == "\n":
                        state = "code"
                elif value.startswith("*/", index):
                    state = "code"
                    index += 1
                index += 1
        return states

    def is_tainted_sql(node, tainted_vars) -> bool:
        parts = string_parts(node)
        states = iter(sql_hole_states(parts))
        for part in parts:
            if part[0] == "text":
                continue
            state = next(states)
            if part[2]:
                continue
            context = "sql"
            if state in {"single", "double"}:
                context = "sql_quoted"
            if any(is_tainted_expr(value, tainted_vars, context) for value in part[1]):
                return True
        return False

    def is_tainted_url(node, tainted_vars) -> bool:
        prefix = ""
        for part in string_parts(node):
            if part[0] == "text":
                prefix += part[1]
                continue
            if _FIXED_HOST.match(prefix) or "?" in prefix or "#" in prefix:
                return False
            if part[2]:
                continue
            if any(is_tainted_expr(value, tainted_vars, "ssrf") for value in part[1]):
                return True
        return False

    def is_dynamic(node, tainted_vars) -> bool:
        node = unwrap(node)
        if node is None:
            return False
        kind = node.type
        if kind in _CONSTANT_NODE_TYPES:
            return False
        if kind in _STRING_TYPES or kind == "heredoc_body":
            return any(is_dynamic(child, tainted_vars) for child in node.named_children)
        if kind == "cast_expression":
            cast = child_by_type(node, "cast_type")
            if cast is not None and text(cast).strip().casefold() in _CLEAN_CASTS:
                return False
            return is_dynamic(node.child_by_field_name("value"), tainted_vars)
        if kind == "variable_name":
            name = text(node).strip()
            if name in models.DYNAMIC_SUPERGLOBALS:
                return True
            contexts = tainted_vars.get(name.lstrip("$"))
            return contexts is None or _DYNAMIC in contexts
        if kind == "subscript_expression":
            if not node.named_children:
                return True
            guarded = tainted_vars.get(guard_key(node))
            if guarded is not None:
                return _DYNAMIC in guarded
            return is_dynamic(node.named_children[0], tainted_vars)
        if kind == "function_call_expression":
            name = functions.get(node.start_byte, "")
            if name in models.NUMERIC_RESULT_FUNCTIONS or name in models.SHELL_ESCAPERS:
                return False
            if name in models.PURE_STRING_FUNCTIONS:
                return any(
                    is_dynamic(arg, tainted_vars) for arg in call_arguments(node)
                )
            return True
        if kind == "conditional_expression":
            return any(
                is_dynamic(value, tainted_vars)
                for value in conditional_values(node, tainted_vars)
            )
        if kind == "match_expression":
            return any(is_dynamic(value, tainted_vars) for value in match_values(node))
        if kind == "binary_expression":
            operator = node.child_by_field_name("operator")
            if (
                operator is not None
                and text(operator).casefold() in _CLEAN_BINARY_OPERATORS
            ):
                return False
            return any(is_dynamic(child, tainted_vars) for child in node.named_children)
        if kind == "unary_op_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and text(operator) in _CLEAN_UNARY_OPERATORS:
                return False
            return any(is_dynamic(child, tainted_vars) for child in node.named_children)
        if kind in {"array_creation_expression", "array_element_initializer"} or (
            kind in _SPREAD_TYPES
        ):
            return any(is_dynamic(child, tainted_vars) for child in node.named_children)
        return True

    def value_contexts(rhs, tainted_vars) -> set[str]:
        contexts = set()
        for context in _TAINT_CONTEXTS:
            if context == "html":
                tainted = is_tainted_html(rhs, tainted_vars)
            elif context == "sql":
                tainted = is_tainted_sql(rhs, tainted_vars)
            elif context == "ssrf":
                tainted = is_tainted_url(rhs, tainted_vars)
            else:
                tainted = is_tainted_expr(rhs, tainted_vars, context)
            if tainted:
                contexts.add(context)
        if is_dynamic(rhs, tainted_vars):
            contexts.add(_DYNAMIC)
        return contexts

    def assigned_variables(target) -> list[str]:
        names = []
        for child in target.named_children:
            node = child
            if node.type == "pair" and node.named_children:
                node = node.named_children[-1]
            if node.type == "by_ref" and node.named_children:
                node = node.named_children[-1]
            if node.type == "variable_name":
                names.append(text(node).strip().lstrip("$"))
            elif node.type == "list_literal":
                names.extend(assigned_variables(node))
        return names

    def handle_assignment(node, tainted_vars: dict[str, set[str]]):
        if node.type == "augmented_assignment_expression":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            operator = node.child_by_field_name("operator")
            if lhs is None or rhs is None or operator is None:
                return
            if lhs.type == "variable_name" and text(operator) in {".=", "??="}:
                name = text(lhs).strip().lstrip("$")
                previous = tainted_vars.get(name)
                if previous is None:
                    previous = {_DYNAMIC}
                tainted_vars[name] = set(previous) | value_contexts(rhs, tainted_vars)
            return
        if node.type != "assignment_expression":
            return
        assign = node
        lhs = assign.child_by_field_name("left")
        rhs = assign.child_by_field_name("right")
        if lhs is None or rhs is None:
            parts = [child for child in assign.children if child.type != "="]
            if len(parts) >= 2:
                lhs, rhs = parts[0], parts[1]
        if lhs is None or rhs is None:
            return
        if lhs.type == "variable_name":
            name = text(lhs).strip().lstrip("$")
            tainted_vars[name] = value_contexts(rhs, tainted_vars)
            forget_guards(tainted_vars, name)

        elif lhs.type == "list_literal":
            contexts = value_contexts(rhs, tainted_vars)
            for name in assigned_variables(lhs):
                tainted_vars[name] = set(contexts)
                forget_guards(tainted_vars, name)
        elif lhs.type == "subscript_expression":
            target = lhs
            while target.type == "subscript_expression" and target.named_children:
                target = target.named_children[0]
            if target.type != "variable_name":
                return
            base = text(target).strip()
            if base in models.DYNAMIC_SUPERGLOBALS:
                return
            name = base.lstrip("$")
            previous = tainted_vars.get(name)
            if previous is None:
                previous = {_DYNAMIC}
            tainted_vars[name] = set(previous) | value_contexts(rhs, tainted_vars)
            forget_guards(tainted_vars, name)

    def handle_array_mutation(node, tainted_vars):
        if node.type != "function_call_expression":
            return
        name = functions.get(node.start_byte, "")
        if name not in {"array_push", "array_unshift", "array_splice"}:
            return
        args = call_arguments(node)
        if not args or unwrap(args[0]).type != "variable_name":
            return
        target = text(unwrap(args[0])).strip().lstrip("$")
        previous = tainted_vars.get(target, {_DYNAMIC})
        replacements = args[3:4] if name == "array_splice" else args[1:]
        contexts = set(previous)
        for value in replacements:
            contexts.update(value_contexts(value, tainted_vars))
        tainted_vars[target] = contexts
        forget_guards(tainted_vars, target)

    def add_finding(
        rule_id: str, message: str, node, severity=None, low_risk=None
    ) -> None:
        if severity is None:
            severity = _SEVERITY.get(rule_id, "HIGH")
        finding = {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "file": str(Path(file_path)),
            "line": node.start_point[0] + 1,
            "col": node.start_point[1],
            "category": "danger",
        }
        cwe = _CWE.get(rule_id)
        if cwe:
            finding["cwe"] = cwe
        if low_risk is not None:
            finding["low_risk_context"] = low_risk
        findings.append(finding)

    def first_argument(node):
        args = node.child_by_field_name("arguments")
        if args is None:
            return None
        return next((c for c in args.children if c.type not in {"(", ")", ","}), None)

    def report_sql(node, argument, tainted_vars) -> None:
        if argument is None:
            return
        value = unwrap(argument)
        if value is None or value.type == "array_creation_expression":
            return
        if is_tainted_sql(value, tainted_vars):
            add_finding("SKY-D211", _SQL_MESSAGE, node)

    def is_sql_receiver(target) -> bool:
        target = unwrap(target)
        if target is None:
            return False
        if target.type == "member_access_expression":
            name = field_text(target, "name")
        elif target.type == "variable_name":
            name = text(target).strip().lstrip("$")
        else:
            return False
        name = name.casefold()
        return name in models.SQL_RECEIVER_NAMES or name.endswith(
            ("pdo", "db", "conn", "connection", "database")
        )

    def chain_root(node):
        while node is not None and node.type == "member_call_expression":
            node = node.child_by_field_name("object")
        return node

    def static_owner(node):
        node = unwrap(node)
        if node is None or node.type != "scoped_call_expression":
            return ""
        return static_call(node)[0]

    def check_sql_sinks(node, args, tainted_vars) -> None:
        if not args:
            return
        if node.type == "member_call_expression":
            method = field_text(node, "name")
            target = node.child_by_field_name("object")
            if (
                method in models.SQL_METHOD_SINKS
                or (
                    method in models.SQL_RECEIVER_METHOD_SINKS
                    and is_sql_receiver(target)
                )
                or (method in models.WPDB_METHOD_SINKS and is_wpdb(target))
                or (
                    method.casefold() in _DB_FACADE_SINKS_FOLDED
                    and static_owner(chain_root(target)) in models.DB_FACADES
                )
            ):
                if method == "where" and not any(
                    part[0] == "text" for part in string_parts(args[0])
                ):
                    return
                report_sql(node, args[0], tainted_vars)
        elif node.type == "scoped_call_expression":
            owner, method = static_call(node)
            if (
                owner in models.DB_FACADES and method in _DB_FACADE_SINKS_FOLDED
            ) or method in _RAW_SQL_FOLDED:
                report_sql(node, args[0], tainted_vars)
        else:
            name = functions.get(node.start_byte, "")
            if name in models.SQL_FUNCTION_SINKS:
                position = models.SQL_FUNCTION_SINKS[name]
                if position < len(args):
                    report_sql(node, args[position], tainted_vars)
            elif name in models.SQL_CONNECTION_FIRST_FUNCTIONS:
                position = 0
                if len(args) >= models.SQL_CONNECTION_FIRST_FUNCTIONS[name]:
                    position = 1
                report_sql(node, args[position], tainted_vars)

    def report_command(node, label, command, tainted_vars) -> None:
        if is_tainted_expr(command, tainted_vars, "shell_command"):
            add_finding(
                "SKY-D212",
                f"Command injection: request data reaches the {label} command. "
                "Pass each value as its own escapeshellarg() argument, outside quotes "
                "and never as the program or a shell's -c code, or use a fixed command; "
                "escapeshellcmd() still lets the input add arguments.",
                node,
            )
        elif is_dynamic(command, tainted_vars):
            add_finding(
                "SKY-D203",
                f"{label} runs an OS command built from non-constant values. "
                "Use a fixed command and escapeshellarg() for each argument.",
                node,
                severity="HIGH",
            )
        else:
            add_finding(
                "SKY-D203",
                f"{label} runs a fixed OS command.",
                node,
                severity="LOW",
                low_risk={
                    "reason": "constant-shell-command",
                    "detail": "the command is fixed and any inserted value is a number or quoted with escapeshellarg()",
                },
            )

    def report_program(node, label, program, tainted_vars) -> None:
        if is_tainted_expr(program, tainted_vars, "shell"):
            add_finding(
                "SKY-D212",
                f"Command injection: request data chooses the program that {label} runs. "
                "Run a fixed program and validate its arguments.",
                node,
            )
        elif is_dynamic(program, tainted_vars):
            add_finding(
                "SKY-D203",
                f"{label} runs a program chosen by a non-constant value. Run a fixed program.",
                node,
                severity="HIGH",
            )

    def check_command_sinks(node, name, args, tainted_vars) -> None:
        if not args:
            return
        label = f"{name}()"
        if name in models.PROGRAM_FUNCTIONS:
            report_program(node, label, args[0], tainted_vars)
            return
        listed = array_values(args[0])
        if name == "proc_open" and listed is not None:
            if listed:
                report_program(node, label, listed[0], tainted_vars)
            return
        report_command(node, label, args[0], tainted_vars)

    def regex_modifiers(pattern: str) -> str:
        value = pattern.lstrip()
        if not value or value[0].isalnum() or value[0] == "\\":
            return ""
        closing = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(value[0], value[0])
        end = value.rfind(closing)
        if end <= 0:
            return ""
        return value[end + 1 :]

    def check_code_sinks(node, name, args, tainted_vars) -> None:
        if name in models.CODE_FUNCTIONS:
            code = args
            if name == "eval":
                code = args[:1]
            if any(is_tainted_expr(value, tainted_vars, "code") for value in code):
                add_finding(
                    "SKY-D201",
                    f"Code injection: request data reaches {name}(), which runs it as PHP code.",
                    node,
                )
            elif any(is_dynamic(value, tainted_vars) for value in code):
                add_finding(
                    "SKY-D201",
                    f"{name}() runs a non-constant string as PHP code.",
                    node,
                    severity="HIGH",
                )
        elif name == "assert" and args:
            if is_tainted_expr(args[0], tainted_vars, "code"):
                add_finding(
                    "SKY-D201",
                    "assert() evaluates a string argument as PHP code before PHP 8.0, and this one is request data.",
                    node,
                    severity="HIGH",
                )
        elif name == "preg_replace" and len(args) >= 2:
            patterns = array_values(args[0])
            if patterns is None:
                patterns = [args[0]]
            literals = [literal_text(pattern) for pattern in patterns]
            if not any(
                literal is not None and "e" in regex_modifiers(literal)
                for literal in literals
            ):
                return
            if any(is_tainted_expr(value, tainted_vars, "code") for value in args[1:3]):
                add_finding(
                    "SKY-D201",
                    "Code injection: preg_replace() with the /e modifier runs the replacement as PHP code, and request data reaches it.",
                    node,
                )
            else:
                add_finding(
                    "SKY-D201",
                    "preg_replace() with the /e modifier runs the replacement as PHP code; use preg_replace_callback().",
                    node,
                    severity="HIGH",
                )

    def report_url(node, label, url, tainted_vars) -> None:
        if url is not None and is_tainted_url(url, tainted_vars):
            add_finding(
                "SKY-D216",
                f"SSRF: request data chooses the URL for {label}. Use a fixed scheme and host, or allowlist the host.",
                node,
            )

    def check_url_sinks(node, name, args, tainted_vars) -> None:
        if node.type == "function_call_expression":
            if name in models.URL_FUNCTION_SINKS:
                position = models.URL_FUNCTION_SINKS[name]
                if position < len(args):
                    report_url(node, f"{name}()", args[position], tainted_vars)
            elif name == "curl_setopt" and len(args) >= 3:
                if text(unwrap(args[1])).strip().lstrip("\\") == "CURLOPT_URL":
                    report_url(node, "curl_setopt(CURLOPT_URL)", args[2], tainted_vars)
            elif name == "curl_setopt_array" and len(args) >= 2:
                array = unwrap(args[1])
                if array is not None and array.type == "array_creation_expression":
                    for element in array.named_children:
                        if (
                            element.type == "array_element_initializer"
                            and len(element.named_children) == 2
                            and text(element.named_children[0]).strip().lstrip("\\")
                            == "CURLOPT_URL"
                        ):
                            report_url(
                                node,
                                "curl_setopt_array(CURLOPT_URL)",
                                element.named_children[1],
                                tainted_vars,
                            )
            return
        if node.type == "scoped_call_expression":
            owner, method = static_call(node)
            if owner not in models.HTTP_FACADES:
                return
        elif node.type == "member_call_expression":
            if static_owner(chain_root(node.child_by_field_name("object"))) not in (
                models.HTTP_FACADES
            ):
                return
            method = field_text(node, "name").casefold()
        else:
            return
        position = models.HTTP_FACADE_URL_ARGUMENT.get(method)
        if position is not None and position < len(args):
            report_url(node, f"Http::{method}()", args[position], tainted_vars)

    def unserialize_restricted(args) -> bool:
        if len(args) < 2:
            return False
        options = unwrap(args[1])
        if options is None or options.type != "array_creation_expression":
            return False
        for element in options.named_children:
            if (
                element.type != "array_element_initializer"
                or len(element.named_children) != 2
            ):
                continue
            if literal_text(element.named_children[0]) != "allowed_classes":
                continue
            value = unwrap(element.named_children[1])
            return value is not None and (
                text(value).strip().casefold() == "false"
                or value.type == "array_creation_expression"
            )
        return False

    def check_call_sinks(node, tainted_vars: dict[str, set[str]]) -> None:
        args = call_arguments(node)
        arg = first_argument(node)
        if node.type == "scoped_call_expression" and arg is not None:
            owner, method = static_call(node)
            if (
                owner in _MARKUP_CLASSES
                and method == "create"
                and is_tainted_html(arg, tainted_vars)
            ):
                add_finding(
                    "SKY-D226",
                    "Request-controlled data is marked safe with Markup::create(); escape it or use a render array.",
                    node,
                )
        check_sql_sinks(node, args, tainted_vars)
        name = ""
        if node.type == "function_call_expression":
            name = functions.get(node.start_byte, "")
        check_url_sinks(node, name, args, tainted_vars)
        if node.type != "function_call_expression":
            return
        if name in models.COMMAND_FUNCTIONS or name in models.PROGRAM_FUNCTIONS:
            check_command_sinks(node, name, args, tainted_vars)
        check_code_sinks(node, name, args, tainted_vars)
        if (
            name == "unserialize"
            and arg is not None
            and is_tainted_expr(arg, tainted_vars, "deserialize")
            and not unserialize_restricted(args)
        ):
            add_finding(
                "SKY-D204",
                "unserialize on user-controlled data is unsafe and can lead to code execution.",
                node,
            )
        if (
            name in _FILE_SINKS
            and arg is not None
            and is_tainted_expr(arg, tainted_vars, "path")
        ):
            add_finding(
                "SKY-D215",
                "Request-controlled path reaches a filesystem sink without path validation.",
                node,
            )

    def is_short_echo(node) -> bool:
        if node.type != "expression_statement":
            return False
        previous = node.prev_sibling
        if previous is None:
            return False
        if previous.type == "text_interpolation" and previous.children:
            previous = previous.children[-1]
        return previous.type == "php_tag" and text(previous).strip() == "<?="

    def output_parts(node):
        kind = node.type
        if kind == "echo_statement":
            parts = []
            for child in node.named_children:
                values = [child]
                if child.type == "sequence_expression":
                    values = sequence_items(child)
                for value in values:
                    parts.extend(string_parts(value))
            return parts
        if kind == "print_intrinsic" and node.named_children:
            return string_parts(node.named_children[0])
        if kind == "exit_statement":
            values = [child for child in node.named_children]
            if not values or values[0].type == "integer":
                return None
            return string_parts(values[0])
        if is_short_echo(node) and node.named_children:
            return string_parts(node.named_children[0])
        if kind != "function_call_expression":
            return None
        name = functions.get(node.start_byte, "")
        args = call_arguments(node)
        if not args:
            return None
        if name == "die":
            if unwrap(args[0]).type == "integer":
                return None
            return string_parts(args[0])
        if name == "printf":
            return format_parts(args[0], args[1:])
        if name == "vprintf":
            if len(args) < 2:
                return format_parts(args[0], [])
            listed = array_values(args[1])
            if listed is None:
                return format_parts(args[0], [], spread=args[1])
            return format_parts(args[0], listed)
        if name in models.DEBUG_OUTPUT_FUNCTIONS:
            if len(args) > 1 and text(unwrap(args[1])).strip().casefold() != "false":
                return None
            return [("value", (args[0],), False)]
        if name == "var_dump":
            return [("value", (value,), False) for value in args]
        return None

    def sequence_items(node) -> list:
        items = []
        for child in node.named_children:
            if child.type == "sequence_expression":
                items.extend(sequence_items(child))
            else:
                items.append(child)
        return items

    output_levels: dict[tuple[int, int], int] = {}

    def declares_non_html(node) -> bool:
        name = functions.get(node.start_byte, "")
        args = call_arguments(node)
        if not args:
            return False
        literal = literal_text(args[0])
        if literal is None:
            return False
        if name == "header":
            match = _NON_HTML_CONTENT_TYPE.match(literal)
            return match is not None and "html" not in match.group("type").casefold()
        folded = name.replace("_", "").casefold()
        return (
            "contenttype" in folded
            and "/" in literal
            and "html" not in literal.casefold()
        )

    def index_output(root, node, parts) -> None:
        if node.type in _CALLABLE_TYPES and node is not root:
            body = node.child_by_field_name("body")
            if body is None:
                body = child_by_type(node, "compound_statement")
            if body is not None:
                index_output_stream(body)
            return
        if node.type == "text":
            parts.append(("text", text(node)))
            return
        sink_parts = output_parts(node)
        if sink_parts is not None:
            parts.extend(sink_parts)
        for child in node.named_children:
            index_output(root, child, parts)

    def index_output_stream(root) -> None:
        parts = []
        for child in root.named_children:
            index_output(root, child, parts)
        requirements = iter(hole_requirements(parts))
        for part in parts:
            if part[0] == "text":
                continue
            level, _ = next(requirements)
            for value in part[1]:
                output_levels[(value.start_byte, value.end_byte)] = level

    index_output_stream(root_node)

    def check_output(node, tainted_vars) -> None:
        parts = output_parts(node)
        if parts is None or _NON_HTML in tainted_vars:
            return
        for part in parts:
            if part[0] != "value" or part[2]:
                continue
            for value in part[1]:
                level = output_levels.get((value.start_byte, value.end_byte), TEXT_SAFE)
                if is_tainted_expr(value, tainted_vars, value_context(value, level)):
                    add_finding("SKY-D228", _XSS_MESSAGE, node)
                    return

    def is_terminating(node) -> bool:
        if node.type == "exit_statement":
            return True
        if node.type != "expression_statement" or not node.named_children:
            return False
        call = node.named_children[0]
        return (
            call.type == "function_call_expression"
            and functions.get(call.start_byte, "") in models.TERMINATING_FUNCTIONS
        )

    def array_fields(array) -> dict:
        fields = {}
        for child in array.named_children:
            if (
                child.type == "array_element_initializer"
                and len(child.named_children) == 2
            ):
                key = text(child.named_children[0]).strip("'\"")
                fields[key] = child
        return fields

    def is_inline_template(element) -> bool:
        array = element.parent
        if array is None or array.type != "array_creation_expression":
            return False
        fields = array_fields(array)
        type_element = fields.get("#type")
        return (
            type_element is not None
            and text(type_element.named_children[1]).strip("'\"") == "inline_template"
            and fields.get("#template") == element
        )

    def report_template(source_node) -> None:
        add_finding(
            "SKY-D349",
            "Request-controlled data is compiled as an inline Twig template; pass it in #context instead.",
            source_node,
        )

    def update_template_builder(node, tainted_vars, builders) -> None:
        if node.type == "unset_statement":
            for target in node.named_children:
                if target.type == "variable_name":
                    builders.pop(text(target), None)
                elif target.type == "subscript_expression":
                    parts = target.named_children
                    if len(parts) != 2 or parts[0].type != "variable_name":
                        continue
                    name = text(parts[0])
                    states = builders.get(name)
                    if states is None:
                        continue
                    key = text(parts[1]).strip("'\"")
                    if key == "#template":
                        builders[name] = frozenset(
                            (None, inline) for _, inline in states
                        )
                    elif key == "#type":
                        builders[name] = frozenset(
                            (origin, False) for origin, _ in states
                        )
            return
        if node.type != "assignment_expression":
            return
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        if left.type == "variable_name":
            name = text(left)
            states = None
            if right.type == "array_creation_expression":
                fields = array_fields(right)
                template = fields.get("#template")
                origin = None
                if template is not None and is_tainted_expr(
                    template.named_children[1], tainted_vars, "template"
                ):
                    origin = template
                type_element = fields.get("#type")
                inline = (
                    type_element is not None
                    and text(type_element.named_children[1]).strip("'\"")
                    == "inline_template"
                )
                states = frozenset({(origin, inline)})
            elif right.type == "variable_name":
                # PHP arrays are copied by value. Keep an immutable snapshot;
                # subsequent writes to either local builder cannot affect its copy.
                states = builders.get(text(right))
            builders.pop(name, None)
            if states is None:
                return
        elif left.type == "subscript_expression":
            parts = left.named_children
            if len(parts) != 2 or parts[0].type != "variable_name":
                return
            name = text(parts[0])
            states = builders.get(name)
            if states is None:
                return
            key = text(parts[1]).strip("'\"")
            if key == "#type":
                inline = text(right).strip("'\"") == "inline_template"
                states = frozenset((origin, inline) for origin, _ in states)
            elif key == "#template":
                origin = None
                if is_tainted_expr(right, tainted_vars, "template"):
                    origin = node
                states = frozenset((origin, inline) for _, inline in states)
            else:
                return
        else:
            return
        builders[name] = states
        for origin, inline in sorted(states, key=template_state_order):
            if origin is not None and inline:
                report_template(origin)

    def template_state_order(state):
        origin, inline = state
        offset = -1
        if origin is not None:
            offset = origin.start_byte
        return offset, inline

    def join_states(outputs, tainted_vars, builders) -> None:
        merged_taint = {}
        merged_builders = {}
        for branch_taint, branch_builders in outputs:
            for name, contexts in branch_taint.items():
                merged_taint.setdefault(name, set()).update(contexts)
            for name, alternatives in branch_builders.items():
                merged_builders.setdefault(name, set()).update(alternatives)
        for name in list(merged_taint):
            if all(name in branch_taint for branch_taint, _ in outputs):
                continue
            if name.startswith("$"):
                del merged_taint[name]
            else:
                merged_taint[name].add(_DYNAMIC)
        tainted_vars.clear()
        tainted_vars.update(merged_taint)
        builders.clear()
        builders.update(
            (name, frozenset(alternatives))
            for name, alternatives in merged_builders.items()
        )

    def snapshot(tainted_vars, builders):
        return dict(tainted_vars), dict(builders)

    def record_exit(flow, kind, tainted_vars, builders, level=0) -> None:
        flow.setdefault((kind, level), []).append(snapshot(tainted_vars, builders))

    def forward_exits(source, destination, *, consume_breaks=False):
        normal = []
        for (kind, level), states in source.items():
            if consume_breaks and kind in {"break", "continue"}:
                if level == 1:
                    normal.extend(states)
                    continue
                level -= 1
            if destination is not None:
                destination.setdefault((kind, level), []).extend(states)
        return normal

    def clean_guarded(tainted_vars, targets) -> None:
        for target in targets:
            if _VARIABLE.fullmatch(target):
                tainted_vars[target[1:]] = set()
            elif target.startswith("$") and "[" in target:
                tainted_vars[target] = set()

    def forget_guards(tainted_vars, name) -> None:
        prefix = f"${name}["
        for key in [key for key in tainted_vars if key.startswith(prefix)]:
            del tainted_vars[key]

    def walk_conditional(node, tainted_vars, builders, flow) -> bool:
        fallthrough_taint = dict(tainted_vars)
        fallthrough_builders = dict(builders)
        outputs = []
        clauses = [node]
        clauses.extend(
            child
            for child in node.named_children
            if child.type in {"else_if_clause", "else_clause"}
        )
        for clause in clauses:
            condition = clause.child_by_field_name("condition")
            if condition is not None:
                if not walk_nodes(
                    [condition], fallthrough_taint, fallthrough_builders, flow
                ):
                    break
            branch_taint = dict(fallthrough_taint)
            branch_builders = dict(fallthrough_builders)
            when_true = set()
            when_false = set()
            if condition is not None:
                when_true, when_false = guard_effects(condition, fallthrough_taint)
            clean_guarded(branch_taint, when_true)
            body = clause.child_by_field_name("body")
            reachable = True
            if body is not None:
                reachable = walk_nodes([body], branch_taint, branch_builders, flow)
            if reachable:
                outputs.append((branch_taint, branch_builders))
            clean_guarded(fallthrough_taint, when_false)
            if condition is None:
                break
        else:
            # With no final else, all conditions can be false.
            outputs.append((fallthrough_taint, fallthrough_builders))
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    def bind_foreach(header, tainted_vars) -> None:
        if len(header) < 2:
            return
        contexts = value_contexts(header[0], tainted_vars)
        targets = [header[1]]
        if header[1].type == "pair":
            targets = list(header[1].named_children)
        for target in targets:
            if target.type == "by_ref" and target.named_children:
                target = target.named_children[-1]
            if target.type == "variable_name":
                tainted_vars[text(target).strip().lstrip("$")] = set(contexts)
            elif target.type == "list_literal":
                for name in assigned_variables(target):
                    tainted_vars[name] = set(contexts)

    def walk_loop(node, tainted_vars, builders, flow) -> bool:
        # Colon-form for loops repeat body fields. These are all conditional
        # body statements, rather than unconditional header effects.
        bodies = node.children_by_field_name("body")
        updates = node.children_by_field_name("update")
        if node.type == "do_statement":
            header = []
            updates = node.children_by_field_name("condition")
        else:
            header = [
                child
                for child in node.named_children
                if child not in bodies and child not in updates
            ]
        if not walk_nodes(header, tainted_vars, builders, flow):
            return False
        outputs = []
        if node.type != "do_statement":
            outputs.append(snapshot(tainted_vars, builders))
        body_taint = dict(tainted_vars)
        body_builders = dict(builders)
        if node.type == "foreach_statement":
            bind_foreach(header, body_taint)
        body_flow = {}
        reachable = walk_nodes(bodies, body_taint, body_builders, body_flow)
        continued = body_flow.pop(("continue", 1), [])
        if reachable:
            continued.append(snapshot(body_taint, body_builders))
        for update_taint, update_builders in continued:
            if walk_nodes(updates, update_taint, update_builders, body_flow):
                outputs.append((update_taint, update_builders))
        outputs.extend(forward_exits(body_flow, flow, consume_breaks=True))
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    def walk_switch(node, tainted_vars, builders, flow) -> bool:
        condition = node.child_by_field_name("condition")
        if condition is not None:
            if not walk_nodes([condition], tainted_vars, builders, flow):
                return False
        body = node.child_by_field_name("body")
        if body is None:
            return True
        dispatch_taint = dict(tainted_vars)
        dispatch_builders = dict(builders)
        dispatch_entries = {}
        dispatch_reachable = True
        fallthrough = None
        outputs = []
        case_flow = {}
        cases = [
            case
            for case in body.named_children
            if case.type in {"case_statement", "default_statement"}
        ]
        default = None
        for case in cases:
            if case.type == "default_statement":
                default = case
                continue
            if not dispatch_reachable:
                continue
            value = case.child_by_field_name("value")
            if value is not None:
                dispatch_reachable = walk_nodes(
                    [value], dispatch_taint, dispatch_builders, case_flow
                )
            if dispatch_reachable:
                dispatch_entries[case.start_byte] = snapshot(
                    dispatch_taint, dispatch_builders
                )
        if dispatch_reachable:
            if default is not None:
                dispatch_entries[default.start_byte] = snapshot(
                    dispatch_taint, dispatch_builders
                )
            else:
                outputs.append(snapshot(dispatch_taint, dispatch_builders))
        for case in cases:
            # Dispatch evaluates labels until a match; falling through an
            # earlier body jumps over all subsequent label expressions.
            incoming = []
            entry = dispatch_entries.get(case.start_byte)
            if entry is not None:
                incoming.append(entry)
            if fallthrough is not None:
                incoming.append(fallthrough)
            if not incoming:
                continue
            case_taint = {}
            case_builders = {}
            join_states(incoming, case_taint, case_builders)
            value = case.child_by_field_name("value")
            statements = [child for child in case.named_children if child != value]
            if walk_nodes(statements, case_taint, case_builders, case_flow):
                fallthrough = snapshot(case_taint, case_builders)
            else:
                fallthrough = None
        if fallthrough is not None:
            outputs.append(fallthrough)
        outputs.extend(forward_exits(case_flow, flow, consume_breaks=True))
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    def walk_try(node, tainted_vars, builders, flow) -> bool:
        body = node.child_by_field_name("body")
        if body is None:
            return True
        body_taint = dict(tainted_vars)
        body_builders = dict(builders)
        pending = {}
        outputs = []
        if walk_nodes([body], body_taint, body_builders, pending):
            outputs.append(snapshot(body_taint, body_builders))
        exceptions = pending.pop(("throw", 0), [])
        catches = [
            child for child in node.named_children if child.type == "catch_clause"
        ]
        if catches and exceptions:
            for catch in catches:
                catch_taint = {}
                catch_builders = {}
                join_states(exceptions, catch_taint, catch_builders)
                catch_body = catch.child_by_field_name("body")
                if catch_body is not None:
                    if walk_nodes([catch_body], catch_taint, catch_builders, pending):
                        outputs.append(snapshot(catch_taint, catch_builders))
            # Exception classes are otherwise unknown. A non-catch-all handler
            # cannot prove that every exceptional path stops at this try.
            if not any(catch.start_byte in catch_all_handlers for catch in catches):
                pending.setdefault(("throw", 0), []).extend(exceptions)
        elif exceptions:
            pending.setdefault(("throw", 0), []).extend(exceptions)
        final = child_by_type(node, "finally_clause")
        if final is not None:
            final_body = final.child_by_field_name("body")
            if final_body is not None:
                final_outputs = []
                final_flow = {}
                for final_taint, final_builders in outputs:
                    if walk_nodes(
                        [final_body], final_taint, final_builders, final_flow
                    ):
                        final_outputs.append(snapshot(final_taint, final_builders))
                for completion, states in pending.items():
                    for final_taint, final_builders in states:
                        if walk_nodes(
                            [final_body], final_taint, final_builders, final_flow
                        ):
                            final_flow.setdefault(completion, []).append(
                                snapshot(final_taint, final_builders)
                            )
                outputs = final_outputs
                pending = final_flow
        forward_exits(pending, flow)
        join_states(outputs, tainted_vars, builders)
        return bool(outputs)

    visited_callables: set[int] = set()

    def walk_nodes(
        nodes, tainted_vars: dict[str, set[str]], builders: dict, flow=None
    ) -> bool:
        for child in nodes:
            if child.type in {"function_definition", "method_declaration"}:
                visited_callables.add(child.start_byte)
                body = child_by_type(child, "compound_statement")
                if body is not None:
                    walk_scope(body, {}, {})
                continue
            if child.type == "arrow_function":
                # Its body is an expression, so visit that expression itself
                # as a child, including a possible outermost sink call.
                walk_scope(child, dict(tainted_vars), {})
                continue
            if child.type == "anonymous_function":
                body = child.child_by_field_name("body")
                if body is not None:
                    walk_scope(body, dict(tainted_vars), {})
                continue
            if child.type == "if_statement":
                if not walk_conditional(child, tainted_vars, builders, flow):
                    return False
                continue
            if child.type in {
                "while_statement",
                "for_statement",
                "foreach_statement",
                "do_statement",
            }:
                if not walk_loop(child, tainted_vars, builders, flow):
                    return False
                continue
            if child.type == "switch_statement":
                if not walk_switch(child, tainted_vars, builders, flow):
                    return False
                continue
            if child.type == "try_statement":
                if not walk_try(child, tainted_vars, builders, flow):
                    return False
                continue

            if child.type in {
                "function_call_expression",
                "member_call_expression",
                "scoped_call_expression",
            }:
                check_call_sinks(child, tainted_vars)
                handle_array_mutation(child, tainted_vars)
            if child.type == "function_call_expression" and declares_non_html(child):
                tainted_vars[_NON_HTML] = set()
            check_output(child, tainted_vars)
            if child.type == "shell_command_expression":
                report_command(child, "The backtick operator", child, tainted_vars)

            # Render array ['#type' => 'inline_template', '#template' => ...]:
            # Twig compiles the value as template source.
            if child.type == "array_element_initializer":
                parts = child.named_children
                if (
                    len(parts) == 2
                    and text(parts[0]).strip("'\"") == "#template"
                    and is_inline_template(child)
                    and is_tainted_expr(parts[1], tainted_vars, "template")
                ):
                    report_template(child)

            if child.type in _IMPORT_EXPR_TYPES:
                expr = None
                for expr_child in child.children:
                    if expr_child.type not in {
                        "include",
                        "include_once",
                        "require",
                        "require_once",
                    }:
                        expr = expr_child
                        break
                if expr is not None and is_tainted_expr(expr, tainted_vars, "path"):
                    add_finding(
                        "SKY-D255",
                        "File inclusion: a request-controlled path reaches include/require, "
                        "which runs the file as PHP. Map the input to a fixed list of files.",
                        child,
                    )

            if not walk_scope(child, tainted_vars, builders, flow):
                return False
            # A throwing RHS never replaces the old value on its catch path.
            handle_assignment(child, tainted_vars)
            update_template_builder(child, tainted_vars, builders)
            if flow is not None:
                if child.type in {
                    "function_call_expression",
                    "member_call_expression",
                    "scoped_call_expression",
                    "object_creation_expression",
                    *_IMPORT_EXPR_TYPES,
                }:
                    record_exit(flow, "throw", tainted_vars, builders)
                if child.type in {"break_statement", "continue_statement"}:
                    level = 1
                    argument = next(iter(child.named_children), None)
                    if argument is not None and text(argument).isdigit():
                        level = max(1, int(text(argument)))
                    kind = child.type.removesuffix("_statement")
                    record_exit(flow, kind, tainted_vars, builders, level)
                    return False
                if child.type == "return_statement":
                    record_exit(flow, "return", tainted_vars, builders)
                    return False
                if child.type == "throw_expression":
                    record_exit(flow, "throw", tainted_vars, builders)
                    return False
            elif child.type == "return_statement":
                return False
            if is_terminating(child):
                return False
        return True

    def walk_scope(
        node, tainted_vars: dict[str, set[str]], builders: dict, flow=None
    ) -> bool:
        return walk_nodes(node.children, tainted_vars, builders, flow)

    walk_scope(root_node, {}, {})

    # Named callable declarations retain independent static analysis even
    # when an earlier statement terminates the surrounding execution path.
    pending_nodes = [root_node]
    named_callables = []
    while pending_nodes:
        node = pending_nodes.pop()
        if node.type in {"function_definition", "method_declaration"}:
            named_callables.append(node)
        pending_nodes.extend(node.named_children)
    for node in sorted(named_callables, key=lambda item: item.start_byte):
        if node.start_byte in visited_callables:
            continue
        visited_callables.add(node.start_byte)
        body = child_by_type(node, "compound_statement")
        if body is not None:
            walk_scope(body, {}, {})

    return _dedupe_findings(findings)


_IMPORT_EXPR_TYPES = {
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
}


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, int]] = set()
    deduped: list[dict] = []
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


_BLADE_RAW_ECHO = re.compile(r"\{!!(.*?)!!\}", re.S)
_BLADE_COMMENT = re.compile(r"\{\{--.*?--\}\}", re.S)
_BLADE_MESSAGE = (
    "XSS: Blade {!! !!} prints request data without escaping; use {{ }} "
    "or escape it with e() first."
)


def blade_raw_echo_source(source: bytes) -> bytes | None:
    """PHP with one `echo (...)` per Blade raw echo, each on its template line."""
    template = source.decode("utf-8", "replace")
    template = _BLADE_COMMENT.sub(
        lambda match: "\n" * match.group(0).count("\n"), template
    )
    rows = [""] * (template.count("\n") + 1)
    found = False
    for match in _BLADE_RAW_ECHO.finditer(template):
        expression = " ".join(match.group(1).split())
        if not expression:
            continue
        line = template.count("\n", 0, match.start())
        rows[line] += f"echo ({expression}); "
        found = True
    if not found:
        return None
    return ("<?php " + "\n".join(rows)).encode("utf-8")


def blade_raw_echo_findings(findings: list[dict]) -> list[dict]:
    converted = []
    for finding in findings:
        if finding["rule_id"] == "SKY-D228":
            finding = dict(finding, rule_id="SKY-D226", message=_BLADE_MESSAGE)
        converted.append(finding)
    return converted
