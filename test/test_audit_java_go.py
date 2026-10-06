import json
import os

import pytest

from skylos.visitors.languages.go import go as go_visitor
from skylos.visitors.languages.go.quality import _calc_complexity
from skylos.visitors.languages.java import scan_java_file
from skylos.visitors.languages.java.core import JavaCore
from skylos.analyzer import Skylos


def _write_fixture(root, filename, source):
    root = root.resolve()
    path = root / filename
    path.resolve().relative_to(root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(source)
    return path


def _scan_fixture(tmp_path, monkeypatch, language, source, config):
    if language == "java":
        path = _write_fixture(tmp_path, "Limits.java", source)
        return scan_java_file(str(path), config)[6]
    path = _write_fixture(tmp_path, "limits.go", source)
    monkeypatch.setattr(
        go_visitor,
        "_get_module_result",
        lambda *_args: {"findings": [], "symbols": None},
    )
    return go_visitor.scan_go_file(path, config)[6]


_LIMIT_CASES = [
    (
        "complexity",
        "SKY-Q301",
        "int check(int x) { if (x > 0) return 1; return 0; }",
        "func check(x int) int { if x > 0 { return 1 }; return 0 }",
        1,
        2,
    ),
    (
        "nesting",
        "SKY-Q302",
        "void check(int x) { if (x > 0) { if (x > 1) {} } }",
        "func check(x int) { if x > 0 { if x > 1 {} } }",
        1,
        2,
    ),
    (
        "max_args",
        "SKY-C303",
        "void check(int a, int b) {}",
        "func check(a, b int) {}",
        1,
        2,
    ),
    (
        "max_lines",
        "SKY-C304",
        "void check() {\n int x = 1;\n}",
        "func check() {\n x := 1\n _ = x\n}",
        2,
        5,
    ),
]


@pytest.mark.parametrize("language", ["java", "go"])
@pytest.mark.parametrize("scoped", [False, True], ids=["global", "language"])
@pytest.mark.parametrize("key,rule,java_body,go_body,low,high", _LIMIT_CASES)
def test_java_go_quality_respects_configured_limits(
    tmp_path, monkeypatch, language, scoped, key, rule, java_body, go_body, low, high
):
    source = (
        "class Limits { " + java_body + " }"
        if language == "java"
        else "package main\n" + go_body
    )
    config = {key: low}
    if scoped:
        config = {key: high, "languages": {language: {key: low}}}
    findings = _scan_fixture(tmp_path, monkeypatch, language, source, config)
    assert any(f["rule_id"] == rule for f in findings)


@pytest.mark.parametrize("language", ["java", "go"])
@pytest.mark.parametrize("key,rule,java_body,go_body,low,high", _LIMIT_CASES)
def test_java_go_quality_language_limit_overrides_global_limit(
    tmp_path, monkeypatch, language, key, rule, java_body, go_body, low, high
):
    source = (
        "class Limits { " + java_body + " }"
        if language == "java"
        else "package main\n" + go_body
    )
    config = {key: low, "languages": {language: {key: high}}}
    findings = _scan_fixture(tmp_path, monkeypatch, language, source, config)
    assert not any(f["rule_id"] == rule for f in findings)


def test_go_native_call_pairs_keep_exact_caller_and_callee_identity():
    symbols = {
        "defs": [
            {"name": "server.main", "type": "function", "file": "main.go"},
            {"name": "server.dead", "type": "function", "file": "main.go"},
            {"name": "worker.handle", "type": "function", "file": "worker.go"},
        ],
        "refs": [],
        "call_pairs": [
            {"caller": "server.main", "callee": "worker.handle"},
            {"caller": "server.dead", "callee": "other.handle"},
        ],
    }

    definitions, _ = go_visitor._convert_symbols(symbols, "main.go")

    by_name = {definition.name: definition for definition in definitions}
    assert by_name["server.main"].calls == {"worker.handle"}
    assert by_name["server.dead"].calls == {"other.handle"}


def test_go_native_call_pairs_connect_local_called_by_and_omit_missing_callers():
    symbols = {
        "defs": [
            {"name": "server.main", "type": "function", "file": "main.go"},
            {"name": "server.work", "type": "function", "file": "main.go"},
        ],
        "refs": [],
        "call_pairs": [
            {"caller": "server.main", "callee": "server.work"},
            {"caller": "other.main", "callee": "server.work"},
        ],
    }

    definitions, _ = go_visitor._convert_symbols(symbols, "main.go")

    by_name = {definition.name: definition for definition in definitions}
    assert by_name["server.main"].calls == {"server.work"}
    assert by_name["server.work"].called_by == {"server.main"}


@pytest.mark.parametrize("call_pairs", [None, []])
def test_go_native_output_without_calls_remains_compatible(call_pairs):
    symbols = {
        "defs": [{"name": "server.main", "type": "function", "file": "main.go"}],
        "refs": [],
        "call_pairs": call_pairs,
    }

    definitions, references = go_visitor._convert_symbols(symbols, "main.go")

    assert definitions[0].calls == set()
    assert references == []


@pytest.mark.parametrize(
    "body,expected",
    [
        ("switch x {}", 1),
        ("switch x { case 1: return; case 2: return; default: return }", 3),
        (
            "switch x.(type) { case int: return; case string: return; default: return }",
            3,
        ),
        ("select { case <-ch: return; case ch <- 1: return; default: return }", 3),
        ("switch x { case 1: if a && b { return }; default: return }", 4),
    ],
)
def test_go_complexity_counts_case_decisions_without_switch_or_default(body, expected):
    source = ("package main\nfunc check() { " + body + " }").encode()
    tree = go_visitor.Parser(go_visitor.GO_LANG).parse(source)
    function = next(
        node
        for node in tree.root_node.named_children
        if node.type == "function_declaration"
    )

    assert _calc_complexity(function) == expected


def test_go_wrapper_does_not_run_disabled_quality_or_return_security_findings(
    tmp_path, monkeypatch
):
    path = _write_fixture(tmp_path, "limits.go", "package main\nfunc main() {}")
    monkeypatch.setattr(
        go_visitor,
        "_get_module_result",
        lambda *_args: {
            "findings": [{"file": str(path), "rule_id": "SKY-G212"}],
            "symbols": None,
        },
    )

    def quality_must_not_run(*_args, **_kwargs):
        pytest.fail("disabled Go quality scanner ran")

    monkeypatch.setattr(go_visitor, "scan_go_quality", quality_must_not_run)

    result = go_visitor.scan_go_file(
        path, {}, enable_quality_rules=False, enable_danger_rules=False
    )

    assert result[6] == []
    assert result[7] == []


@pytest.mark.parametrize("reverse", [False, True])
def test_java_explicit_static_call_does_not_rescue_a_same_named_other_owner(reverse):
    classes = [
        "class Active { private static void work() {} static void entry() { Active.work(); } }",
        "class Dormant { private static void work() {} }",
    ]
    if reverse:
        classes.reverse()
    core = JavaCore("App.java", "\n".join(classes).encode())
    core.scan()
    analyzer = Skylos()
    analyzer.defs = {definition.name: definition for definition in core.defs}
    analyzer.refs = core.refs

    analyzer._mark_refs()

    assert analyzer.defs["Active.work"].references > 0
    assert analyzer.defs["Dormant.work"].references == 0
    assert analyzer.defs["Active.entry"].calls == {"Active.work"}


def test_java_qualified_call_to_same_named_method_is_not_self_recursion():
    core = JavaCore(
        "App.java",
        b"class Adapter { static void work() { Worker.work(); } } "
        b"class Worker { static void work() {} }",
    )
    core.scan()

    assert ("Worker.work", "App.java") in core.refs
    assert ("work", "App.java") not in core.refs


def test_java_explicit_self_recursion_does_not_rescue_a_dead_method():
    core = JavaCore(
        "App.java", b"class Worker { static void work() { Worker.work(); } }"
    )
    core.scan()

    assert ("Worker.work", "App.java") not in core.refs
    assert ("work", "App.java") not in core.refs


@pytest.mark.parametrize("grep_verify", [True, False])
def test_java_same_named_forwarding_keeps_cross_file_target_live(
    tmp_path, monkeypatch, grep_verify
):
    _write_fixture(
        tmp_path,
        "Entry.java",
        "public class Entry { public static void main(String[] args) { Worker.work(); } }\n"
        "class Worker { static void work() { Helper.work(); } }\n",
    )
    _write_fixture(
        tmp_path,
        "Helper.java",
        "class Helper { static void work() {} static void stale() {} }\n",
    )
    config = _write_fixture(tmp_path, "pyproject.toml", "[tool.skylos]\n")
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    result = json.loads(
        Skylos().analyze(
            str(tmp_path), grep_verify=grep_verify, config_file=str(config)
        )
    )

    unused = {finding["name"] for finding in result.get("unused_functions", [])}
    assert "Helper.work" not in unused
    assert "Worker.work" not in unused
    assert "Helper.stale" in unused
    assert result.get("analysis_errors", []) == []
