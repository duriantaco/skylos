"""Tests for CWE mapping, new quality rules, and SARIF CWE output."""

from __future__ import annotations

import ast
import textwrap

from skylos.rules.quality.standards import (
    CWE_MAP,
    STANDARD_REFS,
    enrich_finding,
    get_cwe_taxa,
)
from skylos.rules.quality.logic import (
    DuplicateStringLiteralRule,
    TooManyReturnsRule,
    BooleanTrapRule,
    NoEffectStatementRule,
)
from skylos.reporting.sarif import SarifExporter


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------


class TestCWEMapping:
    def test_all_logic_rules_mapped(self):
        for rid in ["SKY-L001", "SKY-L002", "SKY-L007", "SKY-L011", "SKY-L014"]:
            assert rid in CWE_MAP, f"{rid} missing from CWE_MAP"

    def test_multi_cwe_rule(self):
        assert len(CWE_MAP["SKY-L011"]) == 2

    def test_complexity_rules_mapped(self):
        assert "SKY-Q301" in CWE_MAP
        assert "SKY-Q302" in CWE_MAP

    def test_typescript_type_safety_rules_mapped(self):
        assert CWE_MAP["SKY-T103"][0]["id"] == "CWE-704"
        assert CWE_MAP["SKY-T104"][0]["id"] == "CWE-710"
        assert CWE_MAP["SKY-T105"][0]["id"] == "CWE-704"
        assert CWE_MAP["SKY-T106"][0]["id"] == "CWE-704"

    def test_new_quality_signal_rules_are_mapped(self):
        assert CWE_MAP["SKY-L034"][0]["id"] == "CWE-665"
        assert CWE_MAP["SKY-L035"][0]["id"] == "CWE-710"
        assert CWE_MAP["SKY-Q405"][0]["id"] == "CWE-755"
        assert CWE_MAP["SKY-Q406"][0]["id"] == "CWE-252"
        assert CWE_MAP["SKY-Q407"][0]["id"] == "CWE-252"

    def test_standard_refs(self):
        assert "McCabe Cyclomatic Complexity" in STANDARD_REFS["SKY-Q301"]
        assert "ISO/IEC 9126" in STANDARD_REFS["SKY-Q702"]
        assert "TypeScript Handbook: Type Assertions" in STANDARD_REFS["SKY-T103"]
        assert "TypeScript compiler directive comments" in STANDARD_REFS["SKY-T104"]
        assert "Runtime input validation" in STANDARD_REFS["SKY-T105"]
        assert "Public API type safety" in STANDARD_REFS["SKY-T106"]
        assert "Python sequence repetition semantics" in STANDARD_REFS["SKY-L034"]
        assert "ESLint no-async-promise-executor" in STANDARD_REFS["SKY-Q405"]

    def test_corrected_cwe_mappings_match_rule_behavior(self):
        """Regression: lock the reviewed CWE IDs and official names."""
        expected = {
            "SKY-L001": ("CWE-665", "Improper Initialization"),
            "SKY-L006": ("CWE-710", "Improper Adherence to Coding Standards"),
            "SKY-L024": ("CWE-710", "Improper Adherence to Coding Standards"),
            "SKY-L027": ("CWE-1106", "Insufficient Use of Symbolic Constants"),
            "SKY-L028": ("CWE-1119", "Excessive Use of Unconditional Branching"),
            "SKY-L029": ("CWE-710", "Improper Adherence to Coding Standards"),
            "SKY-Q401": ("CWE-710", "Improper Adherence to Coding Standards"),
            "SKY-Q701": ("CWE-710", "Improper Adherence to Coding Standards"),
            "SKY-Q804": ("CWE-710", "Improper Adherence to Coding Standards"),
            "SKY-U005": ("CWE-710", "Improper Adherence to Coding Standards"),
        }

        for rule_id, (cwe_id, cwe_name) in expected.items():
            assert CWE_MAP[rule_id] == [{"id": cwe_id, "name": cwe_name}]


class TestEnrichFinding:
    def test_enriches_known_rule(self):
        f = {"rule_id": "SKY-L008"}
        enrich_finding(f)
        assert f["cwe"] == [
            {
                "id": "CWE-772",
                "name": "Missing Release of Resource after Effective Lifetime",
            }
        ]

    def test_enriches_with_standard_refs(self):
        f = {"rule_id": "SKY-Q701"}
        enrich_finding(f)
        assert "CK Metrics: CBO (Coupling Between Objects)" in f["standard_refs"]

    def test_unknown_rule_gets_empty(self):
        f = {"rule_id": "CUSTOM-FOO"}
        enrich_finding(f)
        assert f["cwe"] == []
        assert f["standard_refs"] == []


class TestGetCWETaxa:
    def test_returns_unique_entries(self):
        taxa = get_cwe_taxa()
        ids = [t["id"] for t in taxa]
        assert len(ids) == len(set(ids))

    def test_entry_format(self):
        taxa = get_cwe_taxa()
        for t in taxa:
            assert "id" in t
            assert "name" in t
            assert "shortDescription" in t
            assert "text" in t["shortDescription"]


# ---------------------------------------------------------------------------
# DuplicateStringLiteralRule (SKY-L027)
# ---------------------------------------------------------------------------


class TestDuplicateStringLiteralRule:
    def _run(self, code, threshold=3):
        rule = DuplicateStringLiteralRule(threshold=threshold)
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        return rule.visit_node(tree, ctx)

    def test_detects_duplicates(self):
        code = """
x = "hello world"
y = "hello world"
z = "hello world"
"""
        results = self._run(code)
        assert results is not None
        assert len(results) == 1
        assert results[0]["value"] == 3
        assert results[0]["severity"] == "LOW"

    def test_escalates_severity(self):
        code = "\n".join([f'x{i} = "repeated string"' for i in range(7)])
        results = self._run(code)
        assert results[0]["severity"] == "MEDIUM"

    def test_skips_short_strings(self):
        code = """
a = "ab"
b = "ab"
c = "ab"
"""
        assert self._run(code) is None

    def test_skips_test_files(self):
        rule = DuplicateStringLiteralRule()
        code = """
x = "hello world"
y = "hello world"
z = "hello world"
"""
        tree = ast.parse(textwrap.dedent(code))
        # Test helpers and package inits under tests/, and examples, repeat
        # inputs by design; the basename alone does not decide it.
        for filename in (
            "tests/test_foo.py",
            "tests/utils/bases/engine.py",
            "tests/test_pkg/__init__.py",
            "examples/demo.py",
        ):
            assert rule.visit_node(tree, {"filename": filename}) is None

    def test_test_named_module_without_test_framework_still_reports(self, tmp_path):
        rule = DuplicateStringLiteralRule()
        shipped = tmp_path / "pkg" / "test_like.py"
        shipped.parent.mkdir()
        shipped.write_text('a = "hello world"\nb = "hello world"\nc = "hello world"\n')
        tree = ast.parse(shipped.read_text())
        context = {"filename": str(shipped), "project_root": str(tmp_path)}
        assert rule.visit_node(tree, context) is not None

    def test_skips_fstring_fragments_but_counts_replacement_field_literals(self):
        code = """
def render(x, y, z):
    real = "Visitor: Sig "
    return (
        real, f"Visitor: Sig {x}", f"Visitor: Sig {y}", f"Visitor: Sig {z}",
        f"{x:%Y-%m-%d}", f"{y:%Y-%m-%d}", f"{z:%Y-%m-%d}",
        f"{x or 'anonymous-user'}", f"{y or 'anonymous-user'}", f"{z or 'anonymous-user'}",
    )
"""
        results = self._run(code)
        assert [result["name"] for result in results] == ["anonymous-user"]

    def test_skips_class_level_tables_but_not_scalar_class_attributes(self):
        code = """
from typing import ClassVar

class Types:
    CLASSES = {"a": "pkg.http.XmlResponse", "b": "pkg.http.XmlResponse", "c": "pkg.http.XmlResponse"}
    lookup: ClassVar[dict] = {"a": "pkg.Text", "b": "pkg.Text", "c": "pkg.Text"}

class Labels:
    first = "Queue Options"
    second = "Queue Options"
    third = "Queue Options"
"""
        results = self._run(code)
        assert [result["name"] for result in results] == ["Queue Options"]

    def test_skips_kwargs_keys_but_not_plain_parameter_keys(self):
        code = """
def send(signal, **named):
    named.pop("dont_log", None)
    named.get("dont_log")
    named.setdefault("dont_log", False)

def relay(signal, named):
    named.pop("keep_alive", None)
    named.get("keep_alive")
    named.setdefault("keep_alive", False)
"""
        results = self._run(code)
        assert [result["name"] for result in results] == ["keep_alive"]

    def test_skips_literal_type_members(self):
        code = """
from typing import Literal

Mode = Literal["skip-bad", "keep-all"]

def check(mode: Mode):
    if mode == "skip-bad":
        return 1
    return mode == "skip-bad"
"""
        assert self._run(code) is None

    def test_skips_python_registry_names_but_not_lookalikes(self):
        code = """
def decode(data, v):
    return (
        data.decode("utf-8"), data.decode("utf-8"), data.decode("utf-8"),
        data.decode("ascii", "replace"), data.decode("ascii", "replace"),
        data.decode("ascii", "replace"),
        v == "https", v == "https", v == "https",
        v == "utf-8-ish", v == "utf-8-ish", v == "utf-8-ish",
        v == "use utf-8 here", v == "use utf-8 here", v == "use utf-8 here",
    )
"""
        results = self._run(code)
        assert sorted(result["name"] for result in results) == [
            "use utf-8 here",
            "utf-8-ish",
        ]

    def test_skips_docstrings(self):
        code = '''
def foo():
    """This is a long docstring value"""
    pass

def bar():
    """This is a long docstring value"""
    pass

def baz():
    """This is a long docstring value"""
    pass
'''
        assert self._run(code) is None

    def test_skips_quoted_return_annotations(self):
        code = """
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    class ForwardThing:
        pass


def foo() -> "ForwardThing | None":
    return None
"""
        assert self._run(code, threshold=1) is None

    def test_skips_quoted_argument_and_variable_annotations(self):
        code = """
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    class ForwardThing:
        pass


def foo(item: "ForwardThing") -> None:
    selected: "ForwardThing | None" = item
    return None
"""
        assert self._run(code, threshold=1) is None

    def test_skips_nested_quoted_annotations(self):
        code = """
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    class ForwardThing:
        pass


def foo() -> list["ForwardThing"]:
    return []
"""
        assert self._run(code, threshold=1) is None

    def test_below_threshold(self):
        code = """
x = "hello world"
y = "hello world"
"""
        assert self._run(code) is None

    def test_skips_filesystem_paths(self):
        code = """
a = "skylos/analyzer.py"
b = "skylos/analyzer.py"
c = "skylos/analyzer.py"
d = "test/"
e = "test/"
f = "test/"
"""
        assert self._run(code) is None

    def test_skips_markup_fragments(self):
        code = """
a = "</li>"
b = "</li>"
c = "</li>"
d = '" data-search="'
e = '" data-search="'
f = '" data-search="'
"""
        assert self._run(code) is None

    def test_skips_schema_vocabulary_and_rule_ids(self):
        code = """
a = "rule_id"
b = "rule_id"
c = "rule_id"
d = "SKY-Q802"
e = "SKY-Q802"
f = "SKY-Q802"
g = "CRITICAL"
h = "CRITICAL"
i = "CRITICAL"
"""
        assert self._run(code) is None

    def test_route_like_strings_still_report(self):
        code = """
a = "/api/users"
b = "/api/users"
c = "/api/users"
"""
        results = self._run(code)
        assert results is not None
        assert results[0]["name"] == "/api/users"

    def test_skips_module_level_declarative_tables(self):
        code = """
RULE_METADATA = {
    "one": ("detector", "detector"),
    "two": ("detector", "detector"),
    "three": ("detector", "detector"),
}
"""
        assert self._run(code) is None

    def test_skips_module_level_constants(self):
        code = """
FIRST_LABEL = "same label"
SECOND_LABEL = "same label"
THIRD_LABEL = "same label"
"""
        assert self._run(code) is None

    def test_function_local_duplicates_still_report(self):
        code = """
def build_messages():
    first = "same label"
    second = "same label"
    third = "same label"
    return first, second, third
"""
        results = self._run(code)
        assert results is not None
        assert results[0]["name"] == "same label"


# ---------------------------------------------------------------------------
# TooManyReturnsRule (SKY-L028)
# ---------------------------------------------------------------------------


class TestTooManyReturnsRule:
    def _run(self, code, threshold=5):
        rule = TooManyReturnsRule(threshold=threshold)
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        results = []
        for node in ast.walk(tree):
            r = rule.visit_node(node, ctx)
            if r:
                results.extend(r)
        return results

    def test_detects_too_many(self):
        code = """
def foo(x):
    if x == 1: return 1
    if x == 2: return 2
    if x == 3: return 3
    if x == 4: return 4
    if x == 5: return 5
    return 0
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["value"] == 6
        assert results[0]["severity"] == "LOW"

    def test_escalates_severity(self):
        lines = ["def foo(x):"]
        for i in range(10):
            lines.append(f"    if x == {i}: return {i}")
        code = "\n".join(lines)
        results = self._run(code)
        assert results[0]["severity"] == "MEDIUM"

    def test_below_threshold(self):
        code = """
def foo(x):
    if x: return 1
    return 0
"""
        assert self._run(code) == []

    def test_ignores_nested_functions(self):
        code = """
def outer():
    def inner():
        return 1
        return 2
        return 3
        return 4
        return 5
    return 0
"""
        results = self._run(code, threshold=5)
        # The inner function has exactly the allowed five returns.
        assert results == []


# ---------------------------------------------------------------------------
# BooleanTrapRule (SKY-L029)
# ---------------------------------------------------------------------------


class TestBooleanTrapRule:
    def _run(self, code):
        rule = BooleanTrapRule()
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        results = []
        for node in ast.walk(tree):
            r = rule.visit_node(node, ctx)
            if r:
                results.extend(r)
        return results

    def test_detects_bool_default(self):
        code = """
bool = str
def foo(x, flag=True, items: list[str]=True, text: str=False):
    pass
"""
        results = self._run(code)
        assert {result["simple_name"] for result in results} == {"flag", "items", "text"}

    def test_detects_bool_annotation(self):
        # The global declaration makes ``bool`` the builtin again inside
        # ``inner``. ``bar`` is nested, so it needs a positional literal call.
        code = """
def outer():
    bool = str
    def inner():
        global bool
        def bar(x, enable: bool):
            pass
        bar(1, True)
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["simple_name"] == "enable"
        assert "called positionally with True at line 8" in results[0]["message"]

    def test_public_function_keeps_api_shape_message(self):
        results = self._run("def publish(data, notify: bool = False):\n    pass\n")
        assert [result["simple_name"] for result in results] == ["notify"]
        assert "public or callback contract" in results[0]["message"]

    def test_skips_overload_stubs_and_declared_overrides(self):
        code = """
import typing_extensions
from typing import overload, override

@overload
def fetch(url: str, raw: bool = False) -> bytes: ...
def fetch(url, raw: bool = False):
    return url

class Fancy(External):
    @override
    def render(self, compact: bool = False):
        return compact

class Plain(External):
    @typing_extensions.override
    def render(self, compact: bool = False):
        return compact
"""
        results = self._run(code)
        assert [(result["name"], result["line"]) for result in results] == [
            ("fetch.raw", 7)
        ]

    def test_skips_same_module_overrides_but_keeps_base(self):
        code = """
class Store:
    def save(self, commit=True):
        return commit

class Cached(Store):
    pass

class Sharded(Cached):
    def save(self, commit=True):
        return commit

class Remote(External):
    def save(self, commit=True):
        return commit
"""
        results = self._run(code)
        assert [result["line"] for result in results] == [3, 14]

    def test_skips_defs_used_as_values(self):
        code = """
def on_event(payload, retry=False):
    return payload

register(on_event)

class Plugin:
    def start(self):
        bus.connect(self.on_close)

    def on_close(self, error=False):
        return error

    @classmethod
    def build(cls):
        o = cls()
        bus.connect(o.on_open)

    def on_open(self, replay=False):
        return replay

def deco(fn):
    def wrapper(arg, quiet=False):
        return fn(arg)
    return wrapper
"""
        assert self._run(code) == []

    def test_aliases_conditional_calls_and_unrelated_receivers_still_report(self):
        code = """
class Result:
    def get(self, timeout=None, propagate=True):
        return timeout
    wait = get

    def join(self, propagate=True):
        return propagate

    def collect(self, native):
        return (self.join_native if native else self.join)(propagate=True)

class Panel:
    def __init__(self, app):
        self.durable = app.conf.durable

    def conf(self, with_defaults=False):
        return with_defaults
"""
        results = self._run(code)
        assert [result["name"] for result in results] == [
            "get.propagate",
            "join.propagate",
            "conf.with_defaults",
        ]

    def test_private_and_nested_defs_need_positional_literal_calls(self):
        code = """
def _apply(rows, strict_mode=False):
    return rows

def _load(path, cache=False):
    return path

def _render(x, flag=False):
    return x

class Emitter:
    def _emit(self, final=False):
        return final

    def _send(self, msg, urgent=False):
        return msg

    @staticmethod
    def _fmt(value, upper=False):
        return value

    def flush(self, flag):
        self._emit(True)
        self._send(True)
        Emitter._fmt("v", True)
        _apply([], True)
        _load([], cache=True)
        _render([], flag)

def outer():
    def step(x, final=False):
        return x
    def helper(x, final=False):
        return x
    helper(1, final=True)
    return step(1, False)

def helper(x, final=False):
    return x
"""
        results = self._run(code)
        found = {result["name"]: result["message"] for result in results}
        assert sorted(found) == [
            "_apply.strict_mode",
            "_emit.final",
            "_fmt.upper",
            "helper.final",
            "step.final",
        ]
        assert "called positionally with True at line 26" in found["_apply.strict_mode"]
        assert "called positionally with True at line 23" in found["_emit.final"]
        assert "called positionally with True at line 25" in found["_fmt.upper"]
        assert "called positionally with False at line 36" in found["step.final"]
        assert "public or callback contract" in found["helper.final"]

    def test_skips_test_and_example_modules(self):
        rule = BooleanTrapRule()
        tree = ast.parse("def make(x, flag=False):\n    return x\n")
        for filename in ("tests/helpers.py", "examples/demo.py"):
            context = {"filename": filename}
            results = [
                r
                for node in ast.walk(tree)
                for r in rule.visit_node(node, context) or []
            ]
            assert results == []

    def test_skips_allowed_names(self):
        code = """
def foo(verbose=True, debug=False, force=True):
    pass
"""
        assert self._run(code) == []

    def test_skips_dunder(self):
        code = """
def __init__(self, flag=True):
    pass
"""
        assert self._run(code) == []

    def test_skips_self_cls(self):
        code = """
def foo(self, flag=True):
    pass
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["simple_name"] == "flag"

    def test_no_false_positives_on_non_bool(self):
        code = """
bool = str
Alias = bool
def foo(x, y: list[str] | None=None, z="hello", enabled: bool="yes", active: Alias="yes"):
    pass
"""
        assert self._run(code) == []


# ---------------------------------------------------------------------------
# NoEffectStatementRule (SKY-L033)
# ---------------------------------------------------------------------------


class TestNoEffectStatementRule:
    def _run(self, code):
        rule = NoEffectStatementRule()
        tree = ast.parse(textwrap.dedent(code))
        ctx = {"filename": "app.py"}
        results = []
        for node in ast.walk(tree):
            r = rule.visit_node(node, ctx)
            if r:
                results.extend(r)
        return results

    def test_detects_useless_expression_statement(self):
        code = """
def authorize(level, required):
    level >= required
    return grant_access()
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["rule_id"] == "SKY-L033"
        assert results[0]["value"] == "discarded_comparison"
        assert results[0]["line"] == 3

    def test_detects_discarded_pure_uuid_call(self):
        code = """
import uuid

def make_id():
    uuid.uuid4()
"""
        results = self._run(code)
        assert len(results) == 1
        assert results[0]["name"] == "uuid.uuid4"
        assert results[0]["value"] == "discarded_result"

    def test_skips_side_effecting_calls(self):
        code = """
def foo(logger):
    print("hello")
    logger.info("hello")
"""
        assert self._run(code) == []

    def test_skips_expressions_containing_side_effecting_calls(self):
        code = """
def foo(logger):
    (logger.info("hello"), 1)
"""
        assert self._run(code) == []

    def test_skips_docstrings_ellipsis_and_await(self):
        code = '''
async def foo(task):
    """Docstring."""
    ...
    await task()
'''
        assert self._run(code) == []


# ---------------------------------------------------------------------------
# SARIF CWE output
# ---------------------------------------------------------------------------


class TestSarifCWE:
    def test_sarif_includes_taxonomies(self):
        findings = [
            {
                "rule_id": "SKY-L001",
                "message": "test",
                "severity": "HIGH",
                "file": "x.py",
                "line": 1,
                "col": 0,
                "cwe": [{"id": "CWE-665", "name": "Improper Initialization"}],
            },
        ]
        sarif = SarifExporter(findings).generate()
        assert "taxonomies" in sarif["runs"][0]
        taxa = sarif["runs"][0]["taxonomies"]
        assert taxa[0]["name"] == "CWE"

    def test_sarif_rule_has_relationships(self):
        findings = [
            {
                "rule_id": "SKY-L008",
                "message": "test",
                "severity": "MEDIUM",
                "file": "x.py",
                "line": 1,
                "col": 0,
                "cwe": [{"id": "CWE-772", "name": "Missing Release"}],
            },
        ]
        sarif = SarifExporter(findings).generate()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "relationships" in rules[0]
        assert rules[0]["relationships"][0]["target"]["id"] == "CWE-772"

    def test_sarif_no_cwe_no_relationships(self):
        findings = [
            {
                "rule_id": "CUSTOM-1",
                "message": "test",
                "severity": "LOW",
                "file": "x.py",
                "line": 1,
                "col": 0,
            },
        ]
        sarif = SarifExporter(findings).generate()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "relationships" not in rules[0]
