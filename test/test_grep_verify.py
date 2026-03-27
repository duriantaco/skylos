from unittest.mock import patch

from skylos.grep_verify import (
    GrepStrategy,
    detect_language,
    filter_grep_results,
    grep_verify_findings,
    is_definition_line,
    is_substring_match,
    module_candidates,
    multi_strategy_search,
    parallel_multi_strategy_search,
    parameter_owner_name,
    repo_relative_path,
    source_globs_for_language,
    _deterministic_suppress_multilang,
)


class TestIsDefinitionLine:
    def test_def_line_matches(self):
        finding = {"file": "/repo/foo.py", "line": 10, "simple_name": "bar"}
        assert is_definition_line("/repo/foo.py:10:def bar():", finding)

    def test_nearby_line_matches(self):
        finding = {"file": "/repo/foo.py", "line": 10, "simple_name": "bar"}
        assert is_definition_line("/repo/foo.py:11:    pass", finding)

    def test_class_definition(self):
        finding = {"file": "/repo/foo.py", "line": 5, "simple_name": "MyClass"}
        assert is_definition_line("/repo/foo.py:5:class MyClass:", finding)

    def test_assignment_definition(self):
        finding = {"file": "/repo/foo.py", "line": 3, "simple_name": "X"}
        assert is_definition_line("/repo/foo.py:3:X = 42", finding)

    def test_usage_not_definition(self):
        finding = {"file": "/repo/foo.py", "line": 10, "simple_name": "bar"}
        assert not is_definition_line("/repo/other.py:50:    bar()", finding)

    def test_typevar_definition(self):
        finding = {"file": "/repo/foo.py", "line": 2, "simple_name": "T"}
        assert is_definition_line('/repo/foo.py:2:T = TypeVar("T")', finding)


class TestFilterGrepResults:
    def test_separates_defs_and_usages(self):
        finding = {"file": "/repo/foo.py", "line": 5, "simple_name": "func"}
        lines = [
            "/repo/foo.py:5:def func():",
            "/repo/bar.py:20:    func()",
            "/repo/baz.py:30:    result = func(x)",
        ]
        defs, usages = filter_grep_results(lines, finding)
        assert len(defs) == 1
        assert len(usages) == 2

    def test_all_usages(self):
        finding = {"file": "/repo/foo.py", "line": 5, "simple_name": "func"}
        lines = [
            "/repo/bar.py:20:    func()",
            "/repo/baz.py:30:    func()",
        ]
        defs, usages = filter_grep_results(lines, finding)
        assert len(defs) == 0
        assert len(usages) == 2

    def test_empty_lines(self):
        finding = {"file": "/repo/foo.py", "line": 5, "simple_name": "func"}
        defs, usages = filter_grep_results([], finding)
        assert defs == []
        assert usages == []


class TestIsSubstringMatch:
    def test_exact_word_is_not_substring(self):
        assert not is_substring_match("/repo/foo.py:10:    bar()", "bar")

    def test_substring_of_longer_word(self):
        assert is_substring_match("/repo/foo.py:10:    foobar()", "bar")

    def test_prefix_substring(self):
        assert is_substring_match("/repo/foo.py:10:    barfoo()", "bar")

    def test_word_boundary_with_underscore(self):
        # underscore is not alphanumeric, so this should NOT be a substring match
        assert not is_substring_match("/repo/foo.py:10:    _bar()", "bar")

    def test_word_at_start(self):
        assert not is_substring_match("bar()", "bar")

    def test_word_at_end(self):
        assert not is_substring_match("/repo/foo.py:10:import bar", "bar")


class TestRepoRelativePath:
    def test_basic(self, tmp_path):
        f = tmp_path / "src" / "mod.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        rel = repo_relative_path(str(f), str(tmp_path))
        assert rel == "src/mod.py"

    def test_fallback_on_unrelated(self):
        result = repo_relative_path("/other/path.py", "/repo")
        assert "path.py" in result


class TestModuleCandidates:
    def test_simple_module(self, tmp_path):
        f = tmp_path / "skylos" / "analyzer.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert "skylos.analyzer" in candidates

    def test_init_file(self, tmp_path):
        f = tmp_path / "skylos" / "__init__.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert "skylos" in candidates

    def test_src_prefix(self, tmp_path):
        f = tmp_path / "src" / "pkg" / "mod.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert "pkg.mod" in candidates

    def test_non_python(self, tmp_path):
        f = tmp_path / "readme.md"
        f.touch()
        assert module_candidates(str(f), str(tmp_path)) == []


class TestParameterOwnerName:
    def test_parameter_finding(self):
        finding = {"type": "parameter", "full_name": "mod.MyClass.method.arg"}
        assert parameter_owner_name(finding) == "mod.MyClass.method"

    def test_non_parameter(self):
        finding = {"type": "function", "full_name": "mod.func"}
        assert parameter_owner_name(finding) == ""

    def test_no_dot(self):
        finding = {"type": "parameter", "full_name": "arg"}
        assert parameter_owner_name(finding) == ""


class TestGrepVerifyFindings:
    def test_finds_usage_in_another_file(self, tmp_path):
        (tmp_path / "lib.py").write_text("def helper():\n    return 42\n")
        (tmp_path / "main.py").write_text("from lib import helper\nhelper()\n")

        findings = [
            {
                "name": "helper",
                "full_name": "lib.helper",
                "simple_name": "helper",
                "type": "function",
                "file": str(tmp_path / "lib.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "lib.helper" in verdicts
        assert verdicts["lib.helper"].alive

    def test_no_usage_stays_dead(self, tmp_path):
        (tmp_path / "lib.py").write_text("def orphan():\n    return 0\n")

        findings = [
            {
                "name": "orphan",
                "full_name": "lib.orphan",
                "simple_name": "orphan",
                "type": "function",
                "file": str(tmp_path / "lib.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "lib.orphan" not in verdicts

    def test_getattr_dispatch_rescues(self, tmp_path):
        (tmp_path / "plugin.py").write_text(
            "class Handler:\n    def process(self):\n        pass\n"
        )
        (tmp_path / "runner.py").write_text(
            'handler = Handler()\ngetattr(handler, "process")()\n'
        )

        findings = [
            {
                "name": "Handler.process",
                "full_name": "plugin.Handler.process",
                "simple_name": "process",
                "type": "method",
                "file": str(tmp_path / "plugin.py"),
                "line": 2,
                "confidence": 80,
            }
        ]
        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "plugin.Handler.process" in verdicts
        assert verdicts["plugin.Handler.process"].alive

    def test_time_budget_respected(self, tmp_path):
        """Processing stops when time budget exceeded."""
        (tmp_path / "mod.py").write_text("def a():\n    pass\ndef b():\n    pass\n")

        findings = [
            {
                "name": f"func_{i}",
                "full_name": f"mod.func_{i}",
                "simple_name": f"func_{i}",
                "type": "function",
                "file": str(tmp_path / "mod.py"),
                "line": 1,
                "confidence": 80,
            }
            for i in range(100)
        ]
        verdicts = grep_verify_findings(findings, str(tmp_path), time_budget=0.0)
        assert len(verdicts) < 50

    def test_import_rescues(self, tmp_path):
        (tmp_path / "types.py").write_text("class MyType:\n    pass\n")
        (tmp_path / "consumer.py").write_text("from types import MyType\nx: MyType\n")

        findings = [
            {
                "name": "MyType",
                "full_name": "types.MyType",
                "simple_name": "MyType",
                "type": "class",
                "file": str(tmp_path / "types.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "types.MyType" in verdicts
        assert verdicts["types.MyType"].alive

    def test_test_reference_rescues(self, tmp_path):
        """Symbol referenced in test file → alive."""
        (tmp_path / "lib.py").write_text("def compute():\n    return 1\n")
        (tmp_path / "test_lib.py").write_text(
            "from lib import compute\ndef test_compute():\n    assert compute() == 1\n"
        )

        findings = [
            {
                "name": "compute",
                "full_name": "lib.compute",
                "simple_name": "compute",
                "type": "function",
                "file": str(tmp_path / "lib.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "lib.compute" in verdicts
        assert verdicts["lib.compute"].alive


class TestMethodCallWhitespace:
    def test_method_call_with_space_before_paren(self, tmp_path):
        (tmp_path / "lib.py").write_text(
            "class Foo:\n    def do_stuff(self):\n        pass\n"
        )
        (tmp_path / "main.py").write_text("foo = Foo()\nfoo.do_stuff (42)\n")

        findings = [
            {
                "name": "Foo.do_stuff",
                "full_name": "lib.Foo.do_stuff",
                "simple_name": "do_stuff",
                "type": "method",
                "file": str(tmp_path / "lib.py"),
                "line": 2,
                "confidence": 80,
            }
        ]
        results = multi_strategy_search(findings[0], str(tmp_path))
        assert "method_calls" in results


class TestQualifiedReferenceSubstring:
    def test_qualified_ref_no_substring_match(self, tmp_path):
        (tmp_path / "mod.py").write_text("def bar():\n    pass\n")
        (tmp_path / "other.py").write_text("import foo\nfoo.bar_baz()\n")

        findings = [
            {
                "name": "bar",
                "full_name": "foo.bar",
                "simple_name": "bar",
                "type": "function",
                "file": str(tmp_path / "mod.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        results = multi_strategy_search(findings[0], str(tmp_path))
        assert "qualified_references" not in results

    def test_qualified_ref_exact_match(self, tmp_path):
        (tmp_path / "mod.py").write_text("def bar():\n    pass\n")
        (tmp_path / "other.py").write_text("import foo\nresult = foo.bar()\n")

        findings = [
            {
                "name": "bar",
                "full_name": "foo.bar",
                "simple_name": "bar",
                "type": "function",
                "file": str(tmp_path / "mod.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        results = multi_strategy_search(findings[0], str(tmp_path))
        assert "qualified_references" in results


class TestAnalyzerIntegration:
    def test_grep_verify_rescues_dynamic_dispatch(self, tmp_path):
        (tmp_path / "plugin.py").write_text(
            'def handle_event():\n    return "handled"\n'
        )
        (tmp_path / "dispatcher.py").write_text(
            'import plugin\ngetattr(plugin, "handle_event")()\n'
        )

        from skylos.analyzer import analyze
        import json

        result_on = json.loads(analyze(str(tmp_path), conf=60, grep_verify=True))
        result_off = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))

        unused_names_on = {
            f.get("simple_name") for f in result_on.get("unused_functions", [])
        }
        unused_names_off = {
            f.get("simple_name") for f in result_off.get("unused_functions", [])
        }

        assert len(unused_names_on) <= len(unused_names_off)


class TestAnalyzerGrepVerifyOrdering:
    def test_candidates_are_sorted_by_rescue_priority(self, tmp_path):
        from skylos.analyzer import Skylos
        from skylos.visitor import Definition

        source = tmp_path / "mod.py"
        source.write_text("pass\n")

        analyzer = Skylos()
        analyzer._project_root = tmp_path

        specs = [
            ("mod.value", "variable", 50, 90),
            ("mod.Orphan", "class", 30, 60),
            ("mod.helper", "function", 20, 60),
            ("mod.Widget.run", "method", 40, 60),
            ("mod.helper.arg", "parameter", 10, 40),
        ]

        analyzer.defs = {}
        for name, kind, line, confidence in specs:
            definition = Definition(name, kind, source, line)
            definition.confidence = confidence
            analyzer.defs[name] = definition

        with patch("skylos.grep_verify.grep_verify_findings", return_value={}) as mock_grep:
            analyzer._grep_verify()

        ordered_names = [
            finding["full_name"] for finding in mock_grep.call_args.args[0]
        ]
        assert ordered_names == [
            "mod.helper.arg",
            "mod.Widget.run",
            "mod.helper",
            "mod.Orphan",
            "mod.value",
        ]


class TestDetectLanguage:
    def test_python(self):
        assert detect_language("foo.py") == "python"
        assert detect_language("bar.pyi") == "python"

    def test_typescript(self):
        assert detect_language("app.ts") == "typescript"
        assert detect_language("Component.tsx") == "typescript"
        assert detect_language("index.js") == "typescript"
        assert detect_language("util.jsx") == "typescript"
        assert detect_language("config.mjs") == "typescript"

    def test_go(self):
        assert detect_language("main.go") == "go"

    def test_java(self):
        assert detect_language("App.java") == "java"

    def test_rust(self):
        assert detect_language("lib.rs") == "rust"

    def test_unknown_defaults_python(self):
        assert detect_language("data.csv") == "python"
        assert detect_language("") == "python"


class TestModuleCandidatesMultiLang:
    def test_typescript_module(self, tmp_path):
        f = tmp_path / "src" / "components" / "Button.tsx"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert (
            "src/components/Button" in candidates or "components/Button" in candidates
        )

    def test_typescript_index(self, tmp_path):
        f = tmp_path / "src" / "utils" / "index.ts"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert any("utils" in c for c in candidates)

    def test_go_module(self, tmp_path):
        f = tmp_path / "pkg" / "handler" / "routes.go"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert any("handler" in c for c in candidates)

    def test_java_module(self, tmp_path):
        f = tmp_path / "src" / "main" / "java" / "com" / "example" / "App.java"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert "com.example.App" in candidates

    def test_rust_module(self, tmp_path):
        f = tmp_path / "src" / "utils.rs"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert "utils" in candidates


class TestIsDefinitionLineMultiLang:
    def test_ts_function(self):
        finding = {"file": "/repo/app.ts", "line": 10, "simple_name": "handleClick"}
        assert is_definition_line("/repo/app.ts:10:function handleClick() {", finding)

    def test_ts_const(self):
        finding = {"file": "/repo/app.ts", "line": 5, "simple_name": "config"}
        assert is_definition_line("/repo/app.ts:5:const config = {", finding)

    def test_ts_export_function(self):
        finding = {"file": "/repo/app.ts", "line": 3, "simple_name": "helper"}
        assert is_definition_line("/repo/app.ts:3:export function helper() {", finding)

    def test_ts_interface(self):
        finding = {"file": "/repo/types.ts", "line": 1, "simple_name": "Props"}
        assert is_definition_line("/repo/types.ts:1:interface Props {", finding)

    def test_go_func(self):
        finding = {"file": "/repo/main.go", "line": 5, "simple_name": "Handler"}
        assert is_definition_line(
            "/repo/main.go:5:func Handler(w http.ResponseWriter) {", finding
        )

    def test_go_type_struct(self):
        finding = {"file": "/repo/model.go", "line": 3, "simple_name": "User"}
        assert is_definition_line("/repo/model.go:3:type User struct {", finding)

    def test_rust_fn(self):
        finding = {"file": "/repo/lib.rs", "line": 1, "simple_name": "process"}
        assert is_definition_line(
            "/repo/lib.rs:1:pub fn process() -> Result<()> {", finding
        )

    def test_rust_struct(self):
        finding = {"file": "/repo/lib.rs", "line": 5, "simple_name": "Config"}
        assert is_definition_line("/repo/lib.rs:5:pub struct Config {", finding)

    def test_java_class(self):
        finding = {"file": "/repo/App.java", "line": 3, "simple_name": "App"}
        assert is_definition_line("/repo/App.java:3:public class App {", finding)


class TestDeterministicSuppressMultiLang:
    def test_ts_jest_test(self):
        finding = {
            "file": "src/utils.test.ts",
            "simple_name": "testHelper",
            "type": "function",
        }
        assert _deterministic_suppress_multilang(finding)

    def test_ts_index_barrel_import(self):
        finding = {
            "file": "src/components/index.ts",
            "simple_name": "Button",
            "type": "import",
        }
        assert _deterministic_suppress_multilang(finding)

    def test_go_test_func(self):
        finding = {
            "file": "handler_test.go",
            "simple_name": "TestHandler",
            "type": "function",
        }
        assert _deterministic_suppress_multilang(finding)

    def test_java_override(self):
        finding = {
            "file": "App.java",
            "simple_name": "toString",
            "type": "method",
            "decorators": ["@Override"],
        }
        assert _deterministic_suppress_multilang(finding)

    def test_rust_test_attr(self):
        finding = {
            "file": "lib.rs",
            "simple_name": "test_something",
            "type": "function",
            "decorators": ["#[test]"],
        }
        assert _deterministic_suppress_multilang(finding)

    def test_python_not_suppressed(self):
        finding = {
            "file": "main.py",
            "simple_name": "helper",
            "type": "function",
        }
        assert not _deterministic_suppress_multilang(finding)


class TestSourceGlobs:
    def test_python_globs(self):
        globs = source_globs_for_language("python")
        assert "*.py" in globs

    def test_typescript_globs(self):
        globs = source_globs_for_language("typescript")
        assert "*.ts" in globs
        assert "*.tsx" in globs
        assert "*.js" in globs

    def test_go_globs(self):
        globs = source_globs_for_language("go")
        assert "*.go" in globs

    def test_unknown_defaults_python(self):
        globs = source_globs_for_language("unknown")
        assert "*.py" in globs


class TestGrepStrategy:
    def test_basic_creation(self):
        s = GrepStrategy(
            name="test",
            build_pattern=lambda: r"\bfoo\b",
            is_strong=True,
        )
        assert s.name == "test"
        assert s.is_strong
        assert s.key == "test"

    def test_custom_result_key(self):
        s = GrepStrategy(
            name="test",
            build_pattern=lambda: r"\bfoo\b",
            result_key="custom",
        )
        assert s.key == "custom"


class TestParallelMultiStrategySearch:
    def test_parallel_python_matches_sequential(self, tmp_path):
        (tmp_path / "lib.py").write_text("def helper():\n    return 42\n")
        (tmp_path / "main.py").write_text("from lib import helper\nresult = helper()\n")

        finding = {
            "name": "helper",
            "full_name": "lib.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "lib.py"),
            "line": 1,
        }

        seq_results = multi_strategy_search(finding, str(tmp_path))
        par_results = parallel_multi_strategy_search(
            finding, str(tmp_path), max_workers=2
        )

        assert bool(seq_results) == bool(par_results)

    def test_parallel_ts_file(self, tmp_path):
        (tmp_path / "util.ts").write_text(
            "export function helper(): number { return 42; }\n"
        )
        (tmp_path / "app.ts").write_text(
            "import { helper } from './util';\nhelper();\n"
        )

        finding = {
            "name": "helper",
            "full_name": "util.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "util.ts"),
            "line": 1,
        }

        results = parallel_multi_strategy_search(finding, str(tmp_path), max_workers=2)
        assert any(
            key in results for key in ("references", "ts_imports", "ts_barrel_export")
        )

    def test_parallel_empty_name(self):
        finding = {"simple_name": "", "type": "function", "file": "foo.py"}
        results = parallel_multi_strategy_search(finding, "/nonexistent")
        assert results == {}


class TestGrepVerifyParallel:
    def test_parallel_mode(self, tmp_path):
        (tmp_path / "lib.py").write_text("def helper():\n    return 42\n")
        (tmp_path / "main.py").write_text("from lib import helper\nhelper()\n")

        findings = [
            {
                "name": "helper",
                "full_name": "lib.helper",
                "simple_name": "helper",
                "type": "function",
                "file": str(tmp_path / "lib.py"),
                "line": 1,
                "confidence": 80,
            }
        ]
        verdicts = grep_verify_findings(
            findings,
            str(tmp_path),
            parallel=True,
            max_workers=2,
        )
        assert "lib.helper" in verdicts
        assert verdicts["lib.helper"].alive
