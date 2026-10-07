"""Feature removal below module level, for deleted and overwritten tests.

A test deleted together with what it exercised is not a weakened check: the
code it tested is gone. Module-level removal (a deleted module, a dropped
export, a deleted route) is read elsewhere; this module reads the rest:

* (Python) a function, method or class the test uses that the change
  removed from non-test code and that nothing at head defines or names, and
  that was not renamed (a similar definition added under another name);
  JavaScript names are resolved through imports in ``js_inventory``; or
* text the test asserts (UI copy, an error code, a prompt section) that the
  change deleted from non-test code and that no non-test file at head still
  contains, where the line holding it was removed rather than reworded.

It also says what a test was about, so an in-place rewrite that leaves the
old test's subject with no test at all can be told from an edit.
"""

from __future__ import annotations

import ast
import difflib
import re
import subprocess
from collections import Counter
from pathlib import PurePosixPath

from skylos.done.base import _GIT_TIMEOUT_SECONDS, Comparison, _command
from skylos.done.inventory import RewrittenTest, TestItem, _dump_tokens, _tokens
from skylos.done.js_inventory import (
    JS_SUFFIXES,
    JsTestItem,
    _descendants,
    _parse,
    _string_value,
    _text,
)

# A removed definition this similar to one added elsewhere was renamed.
RENAME_SIMILARITY = 0.8
# Asserted text shorter than this is too common to identify a feature.
MIN_LITERAL = 12
# The fewest words (identifiers, strings) unique to a test that can say what
# it was about.
MIN_SUBJECT_WORDS = 2
# Titles sharing this share of the shorter one's words name the same subject:
# a rewrite between them is an edit, never "overwritten by something else".
TITLE_OVERLAP = 0.5
_MAX_LITERALS = 30
_MAX_GREPS = 40
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_DOC_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".adoc")
_JS_DEFINITION_FIELDS = {
    "function_declaration": "name",
    "generator_function_declaration": "name",
    "class_declaration": "name",
    "abstract_class_declaration": "name",
    "method_definition": "name",
    "method_signature": "name",
    "abstract_method_signature": "name",
    "public_field_definition": "name",
    "property_signature": "name",
    "variable_declarator": "name",
    "pair": "key",
}
# Words every test uses: never a subject.
_COMMON_WORDS = frozenset(
    {
        "self",
        "assert",
        "None",
        "True",
        "False",
        "len",
        "str",
        "int",
        "list",
        "dict",
        "expect",
        "toBe",
        "toEqual",
        "const",
        "await",
        "async",
        "return",
        "function",
        "this",
        "true",
        "false",
        "null",
        "undefined",
    }
)


def _is_test_path(path: str) -> bool:
    from skylos.done.answer_sites import _is_test_code

    return _is_test_code(path, set())


def _is_source(path: str) -> bool:
    return (
        bool(path)
        and not _is_test_path(path)
        and not path.lower().endswith(_DOC_SUFFIXES)
        and PurePosixPath(path).name.lower() not in {"changelog", "readme"}
    )


class SubjectRemoval:
    """Why a deleted test's subject is gone at head, if it is."""

    def __init__(self, comparison: Comparison) -> None:
        self.comparison = comparison
        self.changed = [
            item
            for item in comparison.changed
            if _is_source(item.base_path or item.path)
        ]
        self._removed: set[str] | None = None
        self._added_bodies: dict[str, list[str]] | None = None
        self._base_bodies: dict[str, list[str]] = {}
        self._head_hits: dict[tuple[str, bool], set[str] | None] = {}
        self._greps = 0
        self._trees: dict[str, ast.Module | None] = {}
        self._js_roots: dict[str, object] = {}
        self._texts: dict[tuple[bool, str], str | None] = {}

    def base_text(self, path: str | None) -> str | None:
        """``comparison.base_text``, read once per path (each read is a Git
        call)."""
        return self._text(True, path)

    def head_text(self, path: str | None) -> str | None:
        return self._text(False, path)

    def _text(self, base: bool, path: str | None) -> str | None:
        if not path:
            return None
        key = (base, path)
        if key not in self._texts:
            read = self.comparison.base_text if base else self.comparison.head_text
            self._texts[key] = read(path)
        return self._texts[key]

    # -- public --------------------------------------------------------------

    def reason(self, test: TestItem) -> str | None:
        if not self.changed:
            return None
        names, literals = self._uses(test)
        for name in sorted(names & self.removed_names() if names else ()):
            if not self._renamed(name) and self._gone(name, word=True):
                return f"uses {name}, which the change removed"
        for literal in literals[:_MAX_LITERALS]:
            if self._deleted_text(literal):
                return f"checks {_shown(literal)}, which the change removed"
        return None

    # -- what the test uses -----------------------------------------------

    def _uses(self, test: TestItem) -> tuple[set[str], list[str]]:
        if isinstance(test, JsTestItem):
            # Names are resolved through imports in js_inventory (exports and
            # members of imported objects); only asserted text is read here.
            return set(), _unique(self._js_literals(test))
        function = self._python_function(test)
        if function is None:
            return set(), []
        names: set[str] = set()
        literals: list[str] = []
        docstring = ast.get_docstring(function, clean=False)
        for node in ast.walk(function):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if re.fullmatch(r"[A-Za-z_][\w.]*", value):
                    names.update(value.split("."))  # patch("pkg.mod.name")
                if len(value.strip()) >= MIN_LITERAL and value != docstring:
                    literals.append(value.strip())
        local = {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        } | {arg.arg for arg in ast.walk(function.args) if isinstance(arg, ast.arg)}
        return names - local - _COMMON_WORDS, _unique(literals)

    def _js_literals(self, test: JsTestItem) -> list[str]:
        """Strings, regular expression sources and static template text in a
        JS/TS test's body (at least ``MIN_LITERAL`` characters)."""
        if test.path not in self._js_roots:
            source = self.base_text(test.path)
            self._js_roots[test.path] = _parse(test.path, source) if source else None
        root = self._js_roots[test.path]
        if root is None:
            return []
        call = next(
            (
                node
                for node in _descendants(root)
                if node.type == "call_expression"
                and node.start_point[0] + 1 == test.line
            ),
            None,
        )
        if call is None:
            return []
        arguments = call.child_by_field_name("arguments")
        title = (
            arguments.named_children[0]
            if arguments and arguments.named_children
            else None
        )
        found = []
        for node in _descendants(call):
            if title is not None and node.id == title.id:
                continue  # the test's own title is not text it checks
            if node.type == "string":
                found.append(_string_value(node))
            elif node.type == "regex":
                pattern = node.child_by_field_name("pattern")
                found.append(_text(pattern) if pattern is not None else "")
            elif node.type == "template_string" and not any(
                child.type == "template_substitution" for child in node.children
            ):
                found.append(_text(node).strip("`"))
        return [text.strip() for text in found if len(text.strip()) >= MIN_LITERAL]

    def _python_function(self, test: TestItem):
        if test.path not in self._trees:
            try:
                self._trees[test.path] = ast.parse(self.base_text(test.path) or "")
            except (SyntaxError, ValueError):
                self._trees[test.path] = None
        tree = self._trees[test.path]
        if tree is None:
            return None
        return next(
            (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.lineno == test.line
                and node.name == test.name.split(" [", 1)[0]
            ),
            None,
        )

    # -- removed definitions --------------------------------------------------

    def removed_names(self) -> set[str]:
        """Names defined in changed non-test code at the base and in no
        changed non-test file at head."""
        if self._removed is None:
            before: set[str] = set()
            after: set[str] = set()
            for item in self.changed:
                if item.base_path:
                    found = _definitions(item.base_path, self.base_text(item.base_path))
                    before |= set(found)
                    for name, body in found.items():
                        self._base_bodies.setdefault(name, body)
                if item.head_path:
                    after |= set(
                        _definitions(item.head_path, self.head_text(item.head_path))
                    )
            self._removed = {
                name
                for name in before - after
                if len(name) >= 3 and not name.startswith("__")
            }
        return self._removed

    def _renamed(self, name: str) -> bool:
        """A definition with a similar body was added under another name."""
        body = self._base_bodies.get(name)
        if not body or len(body) < 8:
            return False
        if self._added_bodies is None:
            self._added_bodies = {}
            for item in self.changed:
                if not item.head_path:
                    continue
                head = _definitions(item.head_path, self.head_text(item.head_path))
                base = (
                    _definitions(item.base_path, self.base_text(item.base_path))
                    if item.base_path
                    else {}
                )
                for added, tokens in head.items():
                    if added not in base:
                        self._added_bodies[added] = tokens
        for tokens in self._added_bodies.values():
            matcher = difflib.SequenceMatcher(None, body, tokens, autojunk=False)
            if (
                matcher.real_quick_ratio() >= RENAME_SIMILARITY
                and matcher.quick_ratio() >= RENAME_SIMILARITY
                and matcher.ratio() >= RENAME_SIMILARITY
            ):
                return True
        return False

    # -- removed text ---------------------------------------------------------

    def _deleted_text(self, literal: str) -> bool:
        holders = [
            item
            for item in self.changed
            if item.base_path and literal in (self.base_text(item.base_path) or "")
        ]
        if not holders:
            return False
        for item in holders:
            if item.head_path and _reworded(
                self.base_text(item.base_path) or "",
                self.head_text(item.head_path) or "",
                literal,
            ):
                return False
        return self._gone(literal, word=False)

    def still_in_code(self, words: set[str]) -> set[str]:
        """The distinctive words (``describe_vpc_endpoints``,
        ``AWS::EC2::VPCEndpoint``, ``DocumentationVersion``) that a non-test
        file at head still contains: code that is still there."""
        return {
            word
            for word in sorted(w for w in words if _distinctive(w))[:8]
            if self._holders(word, word=False)
        }

    def stopped_using(self, module: str) -> bool:
        """The change removed the last use of ``module`` (a component no
        longer rendered, a helper no longer called): a changed non-test file
        named it at the base, and no non-test file but itself names it at
        head."""
        pure = PurePosixPath(module)
        stem = pure.parent.name if pure.stem == "index" else pure.name.split(".")[0]
        if len(stem) < 5 or not _is_source(module):
            return False
        word = re.compile(rf"(?<![\w$]){re.escape(stem)}(?![\w$])")
        if not any(
            item.base_path != module
            and word.search(self.base_text(item.base_path) or "")
            for item in self.changed
            if item.base_path
        ):
            return False
        holders = self._holders(stem, word=True)
        return holders is not None and not (holders - {module})

    def _gone(self, needle: str, *, word: bool) -> bool:
        """No non-test file at head contains ``needle`` (False when Git
        cannot say)."""
        holders = self._holders(needle, word=word)
        return holders is not None and not holders

    def _holders(self, needle: str, *, word: bool) -> set[str] | None:
        key = (needle, word)
        if key not in self._head_hits:
            if self._greps >= _MAX_GREPS:
                return None
            self._greps += 1
            self._head_hits[key] = _head_sources(self.comparison, needle, word=word)
        return self._head_hits[key]


class LostSubjects:
    """What an overwritten test was about, and whether any test still is.

    A test's subject is the words (identifiers and strings) its body uses
    that no other base test uses. A test overwritten in place by a test of
    something else leaves its subject untested: no head test uses any of
    those words. Fewer than ``MIN_SUBJECT_WORDS`` such words cannot tell.
    The caller then asks whether the code those words name is still there
    (``SubjectRemoval.still_in_code``): coverage lost for live code blocks,
    a subject removed with its code is feature removal.
    """

    def __init__(self, base_tests: list[TestItem], head_tests: list[TestItem]):
        self._base = base_tests
        self._head = head_tests
        self._counts: Counter | None = None
        self._head_words: set[str] = set()

    def of(self, rewrite: RewrittenTest) -> set[str] | None:
        if _titles_overlap(rewrite.before.name, rewrite.after.name):
            return None  # the new title still names the old subject
        if self._counts is None:
            self._counts = Counter(
                word for test in self._base for word in subject_words(test)
            )
            self._head_words = {
                word for test in self._head for word in subject_words(test)
            }
        unique = {w for w in subject_words(rewrite.before) if self._counts[w] == 1}
        if len(unique) < MIN_SUBJECT_WORDS or unique & self._head_words:
            return None
        return unique


def _title_words(title: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", re.sub(r"^test_?", "", title.lower()))
    return {
        w[:-1] if w.endswith("s") and len(w) > 3 else w for w in words if len(w) > 2
    }


def _titles_overlap(first: str, second: str) -> bool:
    """Half or more of the shorter title's words are in the other title
    ("project overview gates previous scan fetches" and "project overview
    no longer fetches previous-scan findings" name one subject)."""
    a, b = _title_words(first), _title_words(second)
    if not a or not b:
        return False
    return len(a & b) >= TITLE_OVERLAP * min(len(a), len(b))


def subject_words(test: TestItem) -> set[str]:
    """Identifiers and strings in a test's body, the ones a reader would say
    the test is about (``describe_vpc_endpoints``, ``AWS::EC2::VPCEndpoint``)."""
    if isinstance(test, JsTestItem):
        tokens = [t.strip('"') for t in _tokens_of_js(test)]
    else:
        # Names and values are quoted in a dump; AST node types are not.
        tokens = [t[1:-1] for t in _dump_tokens(test.body_dump) if t[:1] in {"'", '"'}]
    return {
        token
        for token in tokens
        if 4 <= len(token) <= 80
        and not any(char.isspace() for char in token)  # docstrings, messages
        and not token.replace(".", "").replace("-", "").isdigit()
        and token not in _COMMON_WORDS
    }


def _distinctive(word: str) -> bool:
    """A name that identifies code rather than an English word: at least 8
    characters with camelCase, ``snake_case``, ``::``/``.`` qualifiers or
    letters and digits mixed, and no spaces."""
    return (
        len(word) >= 8
        and " " not in word
        and bool(
            re.search(r"[a-z][A-Z]|_[A-Za-z]|::|[A-Za-z]\.[A-Za-z]|[A-Za-z]\d", word)
        )
    )


def _tokens_of_js(test: JsTestItem) -> list[str]:
    """JS bodies are stored as space-joined tokens; a string token keeps its
    quotes and may hold spaces."""
    return re.findall(r'"(?:[^"\\]|\\.)*"|\S+', test.body_dump)


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _shown(text: str) -> str:
    return repr(text if len(text) <= 40 else text[:37] + "...")


def _reworded(base: str, head: str, literal: str) -> bool:
    """The line holding ``literal`` is still there with other text in its
    place (an edited message), rather than removed."""
    for line in base.splitlines():
        if literal not in line:
            continue
        before, _, after = line.partition(literal)
        if len((before + after).strip()) < 8:
            continue  # a line of text, nothing around it to recognize
        pattern = re.compile(
            r"\s*"
            + re.escape(before.strip())
            + r".+"
            + re.escape(after.strip())
            + r"\s*"
        )
        if any(pattern.fullmatch(other) for other in head.splitlines()):
            return True
    return False


def _definitions(path: str | None, source: str | None) -> dict[str, list[str]]:
    """Names defined in one file (functions, methods, classes, assignments,
    object members) with the tokens of each definition."""
    if not path or source is None:
        return {}
    if path.endswith(".py"):
        return _python_definitions(source)
    if path.endswith(JS_SUFFIXES) and not path.endswith(".d.ts"):
        return _js_definitions(path, source)
    return {}


def _python_definitions(source: str) -> dict[str, list[str]]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return {}
    found: dict[str, list[str]] = {}
    # Module and class bodies (through if/try/with, not into functions):
    # their assignments and imports are names others use or patch.
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    for scope in scopes:
        for node in _scope_statements(scope.body):
            for name in _bound_names(node):
                found.setdefault(name, [])
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.setdefault(node.name, list(_dump_tokens(ast.dump(node))))
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            found.setdefault(node.attr, [])  # an instance attribute
    return found


def _scope_statements(body):
    """Statements of a module or class body, including those nested in
    if/try/with/for blocks, but not inside functions or classes."""
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for field in ("body", "orelse", "finalbody"):
            nested = getattr(node, field, None)
            if isinstance(nested, list):
                yield from _scope_statements(nested)
        for handler in getattr(node, "handlers", None) or ():
            yield from _scope_statements(handler.body)


def _bound_names(node) -> list[str]:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return [t.id for t in targets if isinstance(t, ast.Name)]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [
            (alias.asname or alias.name).split(".")[0]
            for alias in node.names
            if alias.name != "*"
        ]
    return []


def _js_definitions(path: str, source: str) -> dict[str, list[str]]:
    root = _parse(path, source)
    if root is None:
        return {}
    found: dict[str, list[str]] = {}
    for node in _descendants(root):
        if node.type == "shorthand_property_identifier":
            found.setdefault(_text(node), [])
            continue
        field = _JS_DEFINITION_FIELDS.get(node.type)
        if field is None:
            continue
        name = node.child_by_field_name(field)
        if name is None:
            continue
        text = _string_value(name) if name.type == "string" else _text(name)
        if _IDENTIFIER_RE.match(text or ""):
            found.setdefault(text, list(_tokens(_text(node))))
    return found


def _head_sources(comparison: Comparison, needle: str, *, word: bool):
    """Non-test files in the working tree that hold ``needle``; None when
    Git cannot say."""
    if not needle or "\n" in needle:
        return None
    args = ["grep", "--untracked", "-I", "-l", "-z", "-F"]
    if word:
        args.append("-w")
    args += ["-e", needle, "--", "."]
    try:
        result = subprocess.run(
            _command(comparison._context, tuple(args)),
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            cwd=str(comparison._context.root),
            env=comparison._context.env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 1:
        return set()
    if result.returncode != 0:
        return None
    paths = result.stdout.decode("utf-8", errors="replace").split("\0")
    return {path for path in paths if path and _is_source(path)}
