import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from skylos.core import grep_verify as grep_verify_module
from skylos.core import grep_verify_common as grep_verify_common_module
from skylos.core.grep_cache import GrepCache
from skylos.core.grep_verify import (
    GrepStrategy,
    GrepVerdict,
    GrepVerificationResult,
    _deterministic_suppress_multilang,
    _store_cached_group_results,
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
)
from skylos.core.grep_verify_common import (
    _GREP_BATCH_SIZE,
    GrepRequest,
    _GrepBatchResults,
    _GrepDeadlineExceeded,
    _GrepEvidence,
    _GrepExecutionIncomplete,
    _GrepInputLimitExceeded,
    _GrepOutputLimitExceeded,
    _is_python_source_reference,
    _python_regex,
    _run_bounded_subprocess,
    _run_grep,
    _run_grep_request,
    _trusted_which,
    execute_grep_batch,
    replay_grep_results,
)

requires_ripgrep = pytest.mark.skipif(
    shutil.which("rg") is None,
    reason="ripgrep is required for this regression test",
)


def _invalid_utf8_decode_error() -> UnicodeDecodeError:
    return UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid UTF-8")


def _rg_json_match(path: str, line_number: int, content: str) -> str:
    return json.dumps(
        {
            "type": "match",
            "data": {
                "path": {"text": path},
                "lines": {"text": content},
                "line_number": line_number,
                "absolute_offset": 0,
                "submatches": [],
            },
        }
    )


def _rg_json_output(*matches: tuple[str, int, str]) -> str:
    return "\n".join(_rg_json_match(*match) for match in matches) + "\n"


def _stdout_process(output: str) -> subprocess.Popen[bytes]:
    payload = output.encode("utf-8")
    script = (
        "import sys; sys.stdin.buffer.read(); "
        f"sys.stdout.buffer.write({payload!r})"
    )
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _fixed_grep_request(
    pattern: str = "needle",
    project_root: str = "/repo",
    max_results: int = 5,
) -> GrepRequest:
    return GrepRequest(
        pattern=pattern,
        project_root=project_root,
        use_regex=False,
        include_globs=("*.py",),
        fixed_string=True,
        max_results=max_results,
    )


def _regex_grep_request(
    pattern: str,
    project_root: str = "/repo",
    max_results: int = 5,
) -> GrepRequest:
    return GrepRequest(
        pattern=pattern,
        project_root=project_root,
        use_regex=True,
        include_globs=("*.py",),
        fixed_string=False,
        max_results=max_results,
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

    def test_posix_paths_remain_case_sensitive(self):
        finding = {"file": "/repo/Foo.py", "line": 10, "simple_name": "helper"}
        assert not is_definition_line("/repo/foo.py:10:helper()", finding)

    def test_windows_drive_paths_compare_case_insensitively(self):
        finding = {
            "file": r"C:\Repo\Foo.py",
            "line": 10,
            "simple_name": "helper",
        }
        with patch(
            "skylos.core.grep_verify_common._HOST_PATH_CASE_INSENSITIVE",
            True,
        ):
            assert is_definition_line(r"c:\repo\foo.py:10:helper()", finding)

    def test_windows_path_comparison_does_not_expand_unicode(self):
        finding = {
            "file": r"C:\Repo\straße.py",
            "line": 10,
            "simple_name": "helper",
        }
        with patch(
            "skylos.core.grep_verify_common._HOST_PATH_CASE_INSENSITIVE",
            True,
        ):
            assert not is_definition_line(
                r"C:\Repo\strasse.py:10:helper()", finding
            )

    def test_drive_shaped_posix_paths_remain_case_sensitive(self):
        finding = {
            "file": "C:/Repo/Foo.py",
            "line": 10,
            "simple_name": "helper",
        }

        with patch(
            "skylos.core.grep_verify_common._HOST_PATH_CASE_INSENSITIVE",
            False,
        ):
            assert not is_definition_line("c:/repo/foo.py:10:helper()", finding)

    def test_unbounded_plain_line_number_is_treated_as_unstructured(self):
        huge_line = "/repo/foo.py:" + ("9" * 5_000) + ":helper()"
        finding = {
            "file": "/repo/foo.py",
            "line": 10,
            "simple_name": "helper",
        }

        assert not is_definition_line(huge_line, finding)

    def test_plain_evidence_candidate_search_is_bounded(self):
        evidence = "prefix" + (":1:value" * 10_000)
        finding = {"file": "/repo/foo.py", "line": 1, "simple_name": "helper"}

        with patch(
            "skylos.core.grep_verify_common._looks_like_source_path",
            return_value=False,
        ) as looks_like_path:
            assert not is_definition_line(evidence, finding)

        assert looks_like_path.call_count == 256

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

    def test_unrelated_parameter_declarations_do_not_rescue(self, tmp_path):
        first = tmp_path / "first.py"
        second = tmp_path / "second.py"
        first.write_text("def target(unused_value: str) -> None:\n    pass\n")
        second.write_text("def unrelated(unused_value: str) -> None:\n    pass\n")

        findings = [
            {
                "name": "unused_value",
                "full_name": "first.target.unused_value",
                "simple_name": "unused_value",
                "type": "parameter",
                "file": str(first),
                "line": 1,
                "confidence": 80,
            },
            {
                "name": "unused_value",
                "full_name": "second.unrelated.unused_value",
                "simple_name": "unused_value",
                "type": "parameter",
                "file": str(second),
                "line": 1,
                "confidence": 80,
            },
        ]

        assert multi_strategy_search(findings[0], str(tmp_path)) == {}
        assert multi_strategy_search(findings[1], str(tmp_path)) == {}
        assert grep_verify_findings(findings, str(tmp_path)) == {}

    def test_parameter_search_retains_owner_contract_evidence(self, tmp_path):
        source = tmp_path / "callbacks.py"
        source.write_text(
            "def target(unused_value: str) -> None:\n"
            "    pass\n"
            "\n"
            "register(callback=target)\n"
        )
        finding = {
            "name": "unused_value",
            "full_name": "callbacks.target.unused_value",
            "simple_name": "unused_value",
            "type": "parameter",
            "file": str(source),
            "line": 1,
            "confidence": 80,
        }

        results = multi_strategy_search(finding, str(tmp_path))

        assert set(results) == {"callback_registrations"}
        assert "register(callback=target)" in results["callback_registrations"][0]

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

    def test_getattr_dispatch_single_quotes_rescues(self, tmp_path):
        (tmp_path / "plugin.py").write_text(
            "class Handler:\n    def process(self):\n        pass\n"
        )
        (tmp_path / "runner.py").write_text(
            "handler = Handler()\ngetattr(handler, 'process')()\n"
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
        assert verdicts == {}
        assert verdicts.complete is False
        assert verdicts.budget_exhausted is True
        assert verdicts.candidate_count == 100
        assert verdicts.verified_count == 0

    def test_different_deadline_prefixes_produce_the_same_fail_closed_result(
        self, tmp_path
    ):
        findings = [
            {
                "name": f"func_{index}",
                "full_name": f"mod.func_{index}",
                "simple_name": f"func_{index}",
                "type": "function",
                "file": str(tmp_path / "mod.py"),
                "line": index + 1,
                "confidence": 80,
            }
            for index in range(3)
        ]

        def run_with_clock(clock):
            with (
                patch(
                    "skylos.core.grep_verify.time.monotonic",
                    side_effect=clock,
                ),
                patch(
                    "skylos.core.grep_verify._plan_batched_finding",
                    side_effect=lambda finding, *_args: (
                        GrepVerdict(alive=True, rationale=finding["full_name"]),
                        None,
                    ),
                ),
            ):
                return grep_verify_findings(
                    findings,
                    str(tmp_path),
                    time_budget=0.15,
                )

        one_candidate_checked = run_with_clock([0.0, 0.1, 0.2])
        two_candidates_checked = run_with_clock([0.0, 0.05, 0.1, 0.2])

        assert one_candidate_checked == two_candidates_checked == {}
        assert one_candidate_checked.verified_count == 1
        assert two_candidates_checked.verified_count == 2
        assert one_candidate_checked.budget_exhausted is True
        assert two_candidates_checked.budget_exhausted is True

    def test_last_candidate_finishing_at_deadline_is_complete(self, tmp_path):
        finding = {
            "name": "helper",
            "full_name": "mod.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "mod.py"),
            "line": 1,
            "confidence": 80,
        }
        now = [0.0]

        def complete_at_deadline(*_args):
            now[0] = 0.5
            return None, None

        with (
            patch(
                "skylos.core.grep_verify.time.monotonic",
                side_effect=lambda: now[0],
            ),
            patch(
                "skylos.core.grep_verify._plan_batched_finding",
                side_effect=complete_at_deadline,
            ),
        ):
            verdicts = grep_verify_findings(
                [finding],
                str(tmp_path),
                time_budget=0.5,
            )

        assert verdicts == {}
        assert verdicts.complete is True
        assert verdicts.candidate_count == 1
        assert verdicts.verified_count == 1

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

    def test_serial_mode_reuses_cache(self, tmp_path):
        (tmp_path / "lib.py").write_text("def helper():\n    return 42\n")

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
        cache = GrepCache()

        with patch(
            "skylos.core.grep_verify.multi_strategy_search",
            return_value={"references": ["main.py:1:helper()"]},
        ) as mock_search:
            first = grep_verify_findings(findings, str(tmp_path), cache=cache)
            second = grep_verify_findings(findings, str(tmp_path), cache=cache)

        assert mock_search.call_count == 1
        assert "lib.helper" in first
        assert "lib.helper" in second

    def test_explicit_empty_full_name_is_skipped(self, tmp_path):
        (tmp_path / "lib.py").write_text("def helper():\n    return 42\n")

        findings = [
            {
                "name": "helper",
                "full_name": "",
                "simple_name": "helper",
                "type": "function",
                "file": str(tmp_path / "lib.py"),
                "line": 1,
                "confidence": 80,
            }
        ]

        with patch("skylos.core.grep_verify.multi_strategy_search") as mock_search:
            verdicts = grep_verify_findings(findings, str(tmp_path))

        assert verdicts == {}
        mock_search.assert_not_called()

    def test_deterministic_suppression_skips_search_and_cache(self, tmp_path):
        findings = [
            {
                "name": "Button",
                "full_name": "src.components.Button",
                "simple_name": "Button",
                "type": "import",
                "file": str(tmp_path / "src" / "components" / "index.ts"),
                "line": 1,
                "confidence": 80,
            }
        ]
        cache = GrepCache()

        with (
            patch("skylos.core.grep_verify.multi_strategy_search") as mock_search,
            patch("skylos.core.grep_verify._cached_group_results") as mock_cached_group,
        ):
            verdicts = grep_verify_findings(findings, str(tmp_path), cache=cache)

        verdict = verdicts["src.components.Button"]
        assert verdict.alive is True
        assert verdict.suppression_code == "lang_deterministic"
        mock_search.assert_not_called()
        mock_cached_group.assert_not_called()

    def test_serial_cache_group_name_for_typescript(self, tmp_path):
        finding = {
            "name": "helper",
            "full_name": "util.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "util.ts"),
            "line": 1,
            "confidence": 80,
        }
        cache = GrepCache()

        with patch(
            "skylos.core.grep_verify._load_cached_group_results", return_value={}
        ) as mock_cache_load:
            grep_verify_findings([finding], str(tmp_path), cache=cache)

        assert mock_cache_load.call_args.args[0] is cache
        assert mock_cache_load.call_args.args[1] == "serial_typescript"


class TestBatchedGrepVerify:
    def test_python_regex_preserves_ascii_posix_alnum_semantics(self):
        regex = _python_regex(r"\.[[:alnum:]_]+")

        assert regex is not None
        assert regex.search(".ascii_name") is not None
        assert regex.fullmatch(".café") is None

    def test_python_regex_rejects_untranslated_posix_classes(self):
        assert _python_regex("[[:digit:]]+") is None

    def test_python_regex_preserves_ascii_posix_space_semantics(self):
        regex = _python_regex(r"\.helper[[:space:]]*\(")

        assert regex is not None
        assert regex.search(".helper \t(") is not None
        assert regex.search(".helper\N{NO-BREAK SPACE}(") is None

    def test_compatible_requests_share_one_ripgrep_process(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        foo_request = GrepRequest(pattern=r"\bfoo\b", **common)
        bar_request = GrepRequest(pattern=r"\bbar\b", **common)
        process_result = Mock(
            returncode=0,
            stdout=_rg_json_output(
                ("/repo/z.py", 9, "bar()\n"),
                ("/repo/z.py", 2, "foo()\n"),
                ("/repo/a.py", 3, "foo(); bar()\n"),
            ),
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ) as mock_run,
        ):
            results = execute_grep_batch([foo_request, bar_request])

        assert mock_run.call_count == 1
        assert results[foo_request] == (
            "/repo/a.py:3:foo(); bar()",
            "/repo/z.py:2:foo()",
        )
        assert results[bar_request] == (
            "/repo/a.py:3:foo(); bar()",
            "/repo/z.py:9:bar()",
        )
        assert results[foo_request][0] is results[bar_request][0]
        assert "--json" in mock_run.call_args.args[0]
        assert mock_run.call_args.kwargs["input_text"] == (
            r"\bfoo\b" "\n" r"\bbar\b" "\n"
        )

    def test_batch_classifier_never_matches_a_symbol_from_the_path(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        ghost_request = GrepRequest(pattern=r"\bghost\b", **common)
        used_request = GrepRequest(pattern=r"\bused\b", **common)

        for path in (
            r"C:\repo\ghost\module.py",
            "/repo/pkg:ghost/module.py",
            "/repo/pkg:123:ghost/module.py",
        ):
            process_result = Mock(
                returncode=0,
                stdout=_rg_json_output((path, 9, "used()\n")),
                stderr="",
            )
            with (
                patch(
                    "skylos.core.grep_verify_common.shutil.which",
                    return_value="/usr/bin/rg",
                ),
                patch(
                    "skylos.core.grep_verify_common._run_bounded_subprocess",
                    return_value=process_result,
                ),
            ):
                results = execute_grep_batch([ghost_request, used_request])

            assert results[ghost_request] == ()
            assert results[used_request] == (f"{path}:9:used()",)

    def test_json_match_preserves_colon_path_and_crlf_content(self):
        request = GrepRequest(
            pattern=r"\bcall\b",
            project_root="/repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        path = r"C:\repo\pkg:part\a.py"
        process_result = Mock(
            returncode=0,
            stdout=_rg_json_output((path, 12, "call()\r\n")),
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ),
        ):
            results = execute_grep_batch([request])

        assert results[request] == (f"{path}:12:call()",)

    def test_structured_colon_path_remains_unambiguous_downstream(self):
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root="/repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        for path in (r"C:\repo\lib.py", "/repo/pkg:123:part/lib.py"):
            process_result = Mock(
                returncode=0,
                stdout=_rg_json_output((path, 1, "helper=1\n")),
                stderr="",
            )
            with (
                patch(
                    "skylos.core.grep_verify_common.shutil.which",
                    return_value="/usr/bin/rg",
                ),
                patch(
                    "skylos.core.grep_verify_common._run_bounded_subprocess",
                    return_value=process_result,
                ),
            ):
                evidence = execute_grep_batch([request])[request][0]

            definitions, usages = filter_grep_results(
                [evidence],
                {
                    "file": path,
                    "line": 1,
                    "simple_name": "helper",
                    "type": "variable",
                },
            )
            assert definitions == [evidence]
            assert usages == []

        assert not _is_python_source_reference(
            r"C:\repo\README.md:1:helper", "helper"
        )

    def test_json_content_with_path_fragments_and_unicode_separator_survives(self):
        request = GrepRequest(
            pattern="value",
            project_root="/repo",
            use_regex=False,
            include_globs=("*.py",),
            fixed_string=True,
            max_results=5,
        )
        content = 'value = "/.git/hooks/\u2028/node_modules/pkg"'
        json_line = _rg_json_match("/repo/main.py", 4, f"{content}\n").replace(
            r"\u2028", "\u2028"
        )
        process_result = Mock(returncode=0, stdout=f"{json_line}\n", stderr="")

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ),
        ):
            results = execute_grep_batch([request])

        assert results[request] == (f"/repo/main.py:4:{content}",)

    def test_non_ascii_and_newline_patterns_run_directly(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        ascii_request = GrepRequest(pattern=r"\bascii\b", **common)
        unicode_request = GrepRequest(pattern=r"\bकु\b", **common)
        newline_request = GrepRequest(pattern="first\nsecond", **common)
        process_result = Mock(
            returncode=0,
            stdout=_rg_json_output(("/repo/a.py", 1, "ascii()\n")),
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ) as mock_run,
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                side_effect=lambda request, **_kwargs: [
                    f"direct:{request.pattern}"
                ],
            ) as mock_direct,
        ):
            results = execute_grep_batch(
                [ascii_request, unicode_request, newline_request]
            )

        assert mock_run.call_count == 1
        assert mock_run.call_args.kwargs["input_text"] == r"\bascii\b" "\n"
        assert mock_direct.call_args_list[0].args == (unicode_request,)
        assert mock_direct.call_args_list[1].args == (newline_request,)
        assert results[unicode_request] == (r"direct:\bकु\b",)
        assert results[newline_request] == ("direct:first\nsecond",)

    def test_non_ascii_content_uses_ripgrep_boundary_semantics(self):
        # NFD: "foo" + combining acute accent. Ripgrep's UTS#18 \b treats
        # the mark as a word character (no boundary, so no foo match); Python
        # re does not, so unadjudicated replay would credit foo with a line
        # ripgrep never matched for it.
        content = "pkg.foo\u0301 = 1; pkg.bar()"
        line = f"/repo/code.py:1:{content}"
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        foo_request = GrepRequest(pattern=r"\bpkg\.foo\b", **common)
        bar_request = GrepRequest(pattern=r"\bpkg\.bar\b", **common)
        literal_request = GrepRequest(pattern=r"pkg\.literal", **common)

        batch_result = Mock(
            returncode=0,
            stdout=_rg_json_output(
                ("/repo/code.py", 1, f"{content}\n"),
                ("/repo/other.py", 2, "pkg.literalé()\n"),
            ),
            stderr="",
        )

        def fake_run(cmd, **kwargs):
            if "--json" in cmd:
                return batch_result
            pattern = cmd[-2]
            if pattern == foo_request.pattern:
                return Mock(returncode=1, stdout="", stderr="")
            return Mock(returncode=0, stdout=f"1:{content}\n", stderr="")

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                side_effect=fake_run,
            ) as mock_run,
        ):
            results = execute_grep_batch(
                [foo_request, bar_request, literal_request]
            )

        adjudication_calls = [
            call for call in mock_run.call_args_list if "--json" not in call.args[0]
        ]
        assert len(adjudication_calls) == 2
        assert results[foo_request] == ()
        assert results[bar_request] == (line,)
        assert results[literal_request] == ("/repo/other.py:2:pkg.literalé()",)

    def test_engine_sensitive_space_patterns_are_batched(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        space_request = GrepRequest(pattern=r"alpha\somega", **common)
        negated_request = GrepRequest(pattern=r"alpha\Somega", **common)
        process_result = Mock(
            returncode=0,
            stdout=_rg_json_output(("/repo/a.py", 1, "alpha omega\n")),
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ) as mock_run,
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                side_effect=AssertionError("space patterns must stay batched"),
            ),
        ):
            results = execute_grep_batch([space_request, negated_request])

        assert mock_run.call_count == 1
        assert mock_run.call_args.kwargs["input_text"] == (
            "alpha\\somega\nalpha\\Somega\n"
        )
        assert results[space_request] == ("/repo/a.py:1:alpha omega",)
        assert results[negated_request] == ()

    @pytest.mark.parametrize(
        ("pattern", "adjudication_matches"),
        [(r"alpha\somega", False), (r"alpha\Somega", True)],
    )
    def test_ascii_separator_content_uses_ripgrep_space_semantics(
        self,
        pattern,
        adjudication_matches,
    ):
        # U+001C-U+001F are the complete divergence between Python re \s and
        # ripgrep's Unicode White_Space \s. The inverse difference applies to
        # \S. They are ASCII, so the non-ASCII sensitivity check never sees
        # them and unadjudicated replay would produce the wrong verdict.
        content = "alpha\x1comega = 1"
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        space_request = GrepRequest(pattern=pattern, **common)
        companion_request = GrepRequest(pattern=r"alpha", **common)

        batch_result = Mock(
            returncode=0,
            stdout=_rg_json_output(("/repo/code.py", 1, f"{content}\n")),
            stderr="",
        )

        def fake_run(cmd, **kwargs):
            if "--json" in cmd:
                return batch_result
            assert cmd[-2] == space_request.pattern
            return Mock(
                returncode=0 if adjudication_matches else 1,
                stdout=f"1:{content}\n" if adjudication_matches else "",
                stderr="",
            )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                side_effect=fake_run,
            ) as mock_run,
        ):
            results = execute_grep_batch([space_request, companion_request])

        adjudication_calls = [
            call for call in mock_run.call_args_list if "--json" not in call.args[0]
        ]
        assert len(adjudication_calls) == 1
        expected = (f"/repo/code.py:1:{content}",) if adjudication_matches else ()
        assert results[space_request] == expected
        assert results[companion_request] == (f"/repo/code.py:1:{content}",)

    def test_large_space_adjudication_payload_is_chunked(self):
        # Adjudication stdin is capped. A repository with more divergent
        # candidate lines than that cap must still be adjudicated, because a
        # direct per-pattern search would have completed. Alternating lines
        # match under ripgrep semantics and do not, so a chunked adjudication
        # that mismapped positions would surface here as wrong evidence.
        padding = "p" * 190
        contents = [
            f"alpha omega\x1c{padding}"
            if index % 2 == 0
            else f"alpha\x1comega{padding}"
            for index in range(40)
        ]
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 100,
        }
        space_request = GrepRequest(pattern=r"alpha\somega", **common)

        batch_result = Mock(
            returncode=0,
            stdout=_rg_json_output(
                *(
                    (f"/repo/code{index:02d}.py", 1, f"{content}\n")
                    for index, content in enumerate(contents)
                )
            ),
            stderr="",
        )

        def fake_run(cmd, **kwargs):
            if "--json" in cmd:
                return batch_result
            payload = kwargs["input_text"]
            if len(payload.encode("utf-8")) > kwargs["input_limit"]:
                raise _GrepInputLimitExceeded("grep subprocess input is too large")
            # Ripgrep's \s excludes U+001C, so only the space lines match.
            matched = [
                f"{position}:{line}"
                for position, line in enumerate(payload.split("\n")[:-1], start=1)
                if "alpha omega" in line
            ]
            return Mock(
                returncode=0 if matched else 1,
                stdout="".join(f"{line}\n" for line in matched),
                stderr="",
            )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_UNICODE_MAX_INPUT_BYTES",
                4096,
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                side_effect=fake_run,
            ) as mock_run,
        ):
            results = execute_grep_batch([space_request])

        adjudication_calls = [
            call for call in mock_run.call_args_list if "--json" not in call.args[0]
        ]
        assert len(adjudication_calls) > 1
        for call in adjudication_calls:
            assert (
                len(call.kwargs["input_text"].encode("utf-8"))
                <= call.kwargs["input_limit"]
            )
        # Sorted by path, so the fixture names are zero-padded to keep
        # lexicographic and numeric order the same.
        assert results[space_request] == tuple(
            f"/repo/code{index:02d}.py:1:{content}"
            for index, content in enumerate(contents)
            if index % 2 == 0
        )

    def test_grep_stdin_chunks_use_exact_utf8_byte_limit(self):
        assert list(grep_verify_common_module._grep_stdin_chunks(["é", "x"], 3)) == [
            (0, ["é"]),
            (1, ["x"]),
        ]

        with pytest.raises(_GrepInputLimitExceeded):
            list(grep_verify_common_module._grep_stdin_chunks(["éé"], 4))

    def test_single_oversized_space_adjudication_is_incomplete(self):
        content = "alpha\x1comega"
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        sensitive = GrepRequest(pattern=r"alpha\somega", **common)
        companion = GrepRequest(pattern="alpha", **common)
        batch_result = Mock(
            returncode=0,
            stdout=_rg_json_output(("/repo/code.py", 1, f"{content}\n")),
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_UNICODE_MAX_INPUT_BYTES",
                4,
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=batch_result,
            ) as mock_run,
        ):
            results = execute_grep_batch([sensitive, companion])

        assert results[sensitive] == ()
        assert sensitive in results.incomplete_requests
        assert results[companion] == (f"/repo/code.py:1:{content}",)
        mock_run.assert_called_once()

    def test_later_space_adjudication_chunk_failure_discards_partial_matches(self):
        content = "alpha\x1comega"
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        sensitive = GrepRequest(pattern=r"alpha\Somega", **common)
        companion = GrepRequest(pattern="alpha", **common)
        batch_result = Mock(
            returncode=0,
            stdout=_rg_json_output(
                ("/repo/a.py", 1, f"{content}\n"),
                ("/repo/b.py", 1, f"{content}\n"),
            ),
            stderr="",
        )
        adjudication_calls = 0

        def fake_run(cmd, **kwargs):
            nonlocal adjudication_calls
            if "--json" in cmd:
                return batch_result
            adjudication_calls += 1
            if adjudication_calls == 1:
                return Mock(returncode=0, stdout=f"1:{content}\n", stderr="")
            raise _GrepDeadlineExceeded("forced later-chunk deadline")

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_UNICODE_MAX_INPUT_BYTES",
                len(content.encode("utf-8")) + 1,
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                side_effect=fake_run,
            ),
        ):
            results = execute_grep_batch([sensitive, companion])

        assert adjudication_calls == 2
        assert results[sensitive] == ()
        assert sensitive in results.incomplete_requests
        assert results[companion] == (
            f"/repo/a.py:1:{content}",
            f"/repo/b.py:1:{content}",
        )

    def test_batched_and_legacy_verdicts_match_on_non_ascii_content(self, tmp_path):
        package = tmp_path / "pkg.py"
        package.write_text(
            "def foo():\n    return 1\n\ndef bar():\n    return 2\n",
            encoding="utf-8",
        )
        (tmp_path / "other.py").write_text(
            "pkg.foo\u0301 = 1; pkg.bar()\n", encoding="utf-8"
        )
        findings = [
            {
                "name": name,
                "full_name": f"pkg.{name}",
                "simple_name": name,
                "type": "function",
                "file": str(package),
                "line": line,
                "confidence": 80,
            }
            for name, line in (("foo", 1), ("bar", 4))
        ]

        batched = grep_verify_findings(findings, str(tmp_path))
        legacy = grep_verify_findings(
            findings, str(tmp_path), parallel=True, max_workers=2
        )

        # Batched replay must agree with the per-pattern engine either way;
        # only ripgrep's UTS#18 \b excludes the NFD line from the foo pattern,
        # so the strict set is asserted only when ripgrep does the searching.
        assert set(batched) == set(legacy)
        if shutil.which("rg"):
            assert set(batched) == {"pkg.bar"}

    def test_batch_decode_failure_falls_back_to_legacy_results(self):
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root="/repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        decode_error = UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid")

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=decode_error,
            ),
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                return_value=["/repo/main.py:1:helper()"],
            ) as mock_direct,
        ):
            results = execute_grep_batch([request])

        assert results == {request: ("/repo/main.py:1:helper()",)}
        mock_direct.assert_called_once_with(
            request, deadline=None, require_complete=True
        )

    def test_structured_bytes_match_falls_back_to_legacy_results(self):
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root="/repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        process_result = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "type": "match",
                    "data": {
                        "path": {"bytes": "L3JlcG8vaW52YWxpZC5weQ=="},
                        "lines": {"text": "helper()\n"},
                        "line_number": 1,
                    },
                }
            )
            + "\n",
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ),
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                return_value=["/repo/main.py:1:helper()"],
            ) as mock_direct,
        ):
            results = execute_grep_batch([request])

        assert results == {request: ("/repo/main.py:1:helper()",)}
        mock_direct.assert_called_once_with(
            request, deadline=None, require_complete=True
        )

    def test_batch_timeout_never_retries_every_request_serially(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        requests = [
            GrepRequest(pattern=rf"\bsymbol_{index}\b", **common)
            for index in range(4)
        ]

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=subprocess.TimeoutExpired("rg", 0.01),
            ),
            patch(
                "skylos.core.grep_verify_common._run_grep_request"
            ) as mock_direct,
        ):
            results = execute_grep_batch(requests, deadline=time.monotonic() + 1)

        assert results == {}
        mock_direct.assert_not_called()

    def test_serial_fallback_stops_at_the_shared_deadline(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        first = GrepRequest(pattern=r"\bfirst\b", **common)
        second = GrepRequest(pattern=r"\bsecond\b", **common)
        now = [0.0]

        def finish_first(*_args, **_kwargs):
            now[0] = 2.0
            return ["/repo/main.py:1:first()"]

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=RuntimeError("combined pattern rejected"),
            ),
            patch(
                "skylos.core.grep_verify_common.time.monotonic",
                side_effect=lambda: now[0],
            ),
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                side_effect=finish_first,
            ) as mock_direct,
        ):
            results = execute_grep_batch([first, second], deadline=1.0)

        assert results == {first: ("/repo/main.py:1:first()",)}
        mock_direct.assert_called_once_with(
            first, deadline=1.0, require_complete=True
        )

    def test_large_request_sets_are_split_into_bounded_chunks(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        requests = [
            GrepRequest(pattern=rf"\bsymbol_{index}\b", **common)
            for index in range(129)
        ]

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=lambda chunk, _rg, **_kwargs: {
                    request: () for request in chunk
                },
            ) as mock_batch,
        ):
            results = execute_grep_batch(requests)

        assert len(results) == 129
        assert [len(call.args[0]) for call in mock_batch.call_args_list] == [128, 1]

    def test_output_limit_splits_batch_without_losing_quiet_requests(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        requests = [
            GrepRequest(pattern=rf"\bsymbol_{index}\b", **common)
            for index in range(2)
        ]

        def limited_batch(chunk, _rg, **_kwargs):
            if len(chunk) > 1:
                raise _GrepOutputLimitExceeded("forced output cap")
            return {chunk[0]: ()}

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=limited_batch,
            ) as mock_batch,
        ):
            results = execute_grep_batch(requests)

        assert results == {request: () for request in requests}
        assert mock_batch.call_count == 3

    @requires_ripgrep
    def test_fixed_singleton_output_overflow_streams_canonical_prefix(
        self, tmp_path
    ):
        earlier = tmp_path / "release.py"
        earlier.write_text("needle earlier\n" * 10, encoding="utf-8")
        later_dir = tmp_path / "release"
        later_dir.mkdir()
        later = later_dir / "template.py"
        later.write_text("needle later\n" * 30, encoding="utf-8")
        request = GrepRequest(
            pattern="needle",
            project_root=str(tmp_path),
            use_regex=False,
            include_globs=("*.py",),
            fixed_string=True,
            max_results=5,
        )

        with (
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_OUTPUT_BYTES",
                4_096,
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_RESULT_FLOOR",
                5,
            ),
            patch(
                "skylos.core.grep_verify_common._run_streamed_grep_batch",
                wraps=grep_verify_common_module._run_streamed_grep_batch,
            ) as streamed_retry,
        ):
            results = execute_grep_batch([request])

        assert streamed_retry.called
        assert results[request] == tuple(
            f"{earlier}:{line}:needle earlier" for line in range(1, 6)
        )

    @requires_ripgrep
    def test_dead_candidate_completes_after_real_regex_overflow(
        self, tmp_path
    ):
        definition = tmp_path / "lib.py"
        definition.write_text(
            "def _hot_symbol():\n    return 1\n",
            encoding="utf-8",
        )
        (tmp_path / "hot.py").write_text(
            "# _hot_symbol\n" * 100,
            encoding="utf-8",
        )
        finding = {
            "name": "_hot_symbol",
            "full_name": "lib._hot_symbol",
            "simple_name": "_hot_symbol",
            "type": "function",
            "file": str(definition),
            "line": 1,
            "confidence": 80,
        }

        with (
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_OUTPUT_BYTES",
                4_096,
            ),
            patch(
                "skylos.core.grep_verify_common._run_streamed_grep_batch",
                wraps=grep_verify_common_module._run_streamed_grep_batch,
            ) as streamed_retry,
        ):
            result = grep_verify_findings(
                [finding],
                str(tmp_path),
                time_budget=5.0,
            )

        assert streamed_retry.called
        assert result.complete is True
        assert result.incomplete_reason is None
        assert result.verified_count == 1
        assert result == {}

    @requires_ripgrep
    def test_streamed_retry_keeps_searching_for_quiet_requests(self, tmp_path):
        early = tmp_path / "a.py"
        early.write_text("hot value\n" * 80, encoding="utf-8")
        late = tmp_path / "z.py"
        late.write_text("quiet value\n", encoding="utf-8")
        common = {
            "project_root": str(tmp_path),
            "use_regex": False,
            "include_globs": ("*.py",),
            "fixed_string": True,
            "max_results": 3,
        }
        hot = GrepRequest(pattern="hot", **common)
        quiet = GrepRequest(pattern="quiet", **common)

        with (
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_OUTPUT_BYTES",
                4_096,
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_RESULT_FLOOR",
                3,
            ),
            patch(
                "skylos.core.grep_verify_common._run_streamed_grep_batch",
                wraps=grep_verify_common_module._run_streamed_grep_batch,
            ) as streamed_retry,
        ):
            results = execute_grep_batch([hot, quiet])

        assert streamed_retry.called
        assert results[hot] == tuple(
            f"{early}:{line}:hot value" for line in range(1, 4)
        )
        assert results[quiet] == (f"{late}:1:quiet value",)

    @requires_ripgrep
    @pytest.mark.parametrize(
        ("fixed_string", "patterns"),
        [
            (True, ("alpha", "alpha.beta")),
            (False, (r"\balpha\b", r"\bbeta\b")),
        ],
    )
    def test_streamed_retry_matches_canonical_batch_results(
        self,
        tmp_path,
        fixed_string,
        patterns,
    ):
        (tmp_path / "release.py").write_text(
            "alpha.beta()\nbeta(alpha)\n" * 20,
            encoding="utf-8",
        )
        nested = tmp_path / "release"
        nested.mkdir()
        (nested / "template.py").write_text(
            "alpha()\nbeta()\nalpha\u0301 beta\nalpha² beta\n" * 20,
            encoding="utf-8",
        )
        requests = [
            GrepRequest(
                pattern=pattern,
                project_root=str(tmp_path),
                use_regex=not fixed_string,
                include_globs=("*.py",),
                fixed_string=fixed_string,
                max_results=5,
            )
            for pattern in patterns
        ]

        with patch(
            "skylos.core.grep_verify_common._GREP_BATCH_RESULT_FLOOR",
            5,
        ):
            canonical = execute_grep_batch(requests)
            with patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_OUTPUT_BYTES",
                4_096,
            ), patch(
                "skylos.core.grep_verify_common._run_streamed_grep_batch",
                wraps=grep_verify_common_module._run_streamed_grep_batch,
            ) as streamed_retry:
                streamed = execute_grep_batch(requests)

        assert streamed_retry.called
        assert streamed == canonical
        assert streamed.incomplete_requests == set()

    @requires_ripgrep
    def test_streamed_retry_keeps_recursive_symlink_behavior(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        hot_source = root / "hot.py"
        hot_source.write_text("hot value\n" * 80, encoding="utf-8")
        outside = tmp_path / "outside.py"
        outside.write_text("outside_secret\n", encoding="utf-8")
        (root / "escape.py").symlink_to(outside)

        common = {
            "project_root": str(root),
            "use_regex": False,
            "include_globs": ("*.py",),
            "fixed_string": True,
            "max_results": 3,
        }
        hot = GrepRequest(pattern="hot", **common)
        escaped = GrepRequest(pattern="outside_secret", **common)

        with (
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_OUTPUT_BYTES",
                4_096,
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_RESULT_FLOOR",
                3,
            ),
        ):
            results = execute_grep_batch([hot, escaped])

        assert len(results[hot]) == 3
        assert results[escaped] == ()

    @pytest.mark.parametrize(
        "output",
        (
            "not-json\n",
            _rg_json_match("/repo/source.py", 1, "needle\n"),
        ),
    )
    def test_streamed_retry_rejects_malformed_or_unterminated_output(
        self,
        output,
    ):
        request = _fixed_grep_request()

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(output),
            ),
        ):
            results = execute_grep_batch([request])

        assert request not in results

    def test_streamed_retry_bounds_retained_evidence(self):
        request = _fixed_grep_request()
        output = _rg_json_output(
            ("/repo/source.py", 1, f"needle {'x' * 200}\n")
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(output),
            ),
            patch(
                "skylos.core.grep_verify_common."
                "_GREP_STREAM_MAX_RETAINED_BYTES",
                32,
            ),
        ):
            results = execute_grep_batch([request])

        assert request not in results

    def test_stderr_overflow_does_not_trigger_streamed_stdout_retry(self):
        request = _fixed_grep_request()

        def stderr_overflow_batch(_requests, _rg, **_kwargs):
            return _run_bounded_subprocess(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write('x' * 10000)",
                ],
                input_text="",
                timeout=2.0,
            )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_STDERR_BYTES",
                64,
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=stderr_overflow_batch,
            ),
            patch(
                "skylos.core.grep_verify_common._run_streamed_grep_batch",
            ) as streamed_retry,
        ):
            results = execute_grep_batch([request])

        assert request not in results
        streamed_retry.assert_not_called()

    def test_streamed_retry_resolves_ambiguous_unicode_regex(self):
        ambiguous = _regex_grep_request(r"\bfoo\b")
        unambiguous = _regex_grep_request("bar")
        output = _rg_json_output(
            ("/repo/source.py", 1, "pkg.foo\u0301 = bar()\n")
        )
        process_outputs = iter((output, ""))

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(next(process_outputs)),
            ) as open_process,
        ):
            results = execute_grep_batch([ambiguous, unambiguous])

        assert results[ambiguous] == ()
        assert results[unambiguous] == (
            "/repo/source.py:1:pkg.foo\u0301 = bar()",
        )
        assert results.incomplete_requests == set()
        assert open_process.call_count == 2

    @pytest.mark.parametrize(
        ("pattern", "exact_output", "expected"),
        [
            (r"alpha\somega", "", ()),
            (
                r"alpha\Somega",
                _rg_json_output(("/repo/source.py", 1, "alpha\x1comega\n")),
                ("/repo/source.py:1:alpha\x1comega",),
            ),
        ],
    )
    def test_streamed_retry_uses_ripgrep_space_semantics(
        self,
        pattern,
        exact_output,
        expected,
    ):
        sensitive = _regex_grep_request(pattern)
        companion = _regex_grep_request("alpha")
        union_output = _rg_json_output(("/repo/source.py", 1, "alpha\x1comega\n"))
        process_outputs = iter((union_output, exact_output))

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(next(process_outputs)),
            ) as open_process,
        ):
            results = execute_grep_batch([sensitive, companion])

        assert results[sensitive] == expected
        assert results[companion] == ("/repo/source.py:1:alpha\x1comega",)
        assert results.incomplete_requests == set()
        assert open_process.call_count == 2

    def test_streamed_space_exact_search_failure_is_incomplete(self):
        sensitive = _regex_grep_request(r"alpha\somega")
        companion = _regex_grep_request("alpha")
        union_output = _rg_json_output(("/repo/source.py", 1, "alpha\x1comega\n"))
        process_outputs = iter((union_output, "not-json\n"))

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(next(process_outputs)),
            ),
        ):
            results = execute_grep_batch([sensitive, companion])

        assert results[sensitive] == ()
        assert sensitive in results.incomplete_requests
        assert companion not in results.incomplete_requests

    def test_streamed_retry_marks_failed_exact_search_incomplete(self):
        ambiguous = _regex_grep_request(r"\bfoo\b")
        unambiguous = _regex_grep_request("bar")
        output = _rg_json_output(
            ("/repo/source.py", 1, "pkg.foo\u0301 = bar()\n")
        )
        process_outputs = iter((output, "not-json\n"))

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(next(process_outputs)),
            ),
        ):
            results = execute_grep_batch([ambiguous, unambiguous])

        assert results[ambiguous] == ()
        assert ambiguous in results.incomplete_requests
        assert unambiguous not in results.incomplete_requests

    def test_streamed_retry_ignores_unrelated_unicode_union_line(self):
        quiet = _regex_grep_request(r"\bnumpy\b")
        import_quiet = _regex_grep_request(r"import.*\bnumpy\b")
        hot = _regex_grep_request("bar")
        output = _rg_json_output(
            ("/repo/source.py", 1, "bar = value\u0301\n")
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(output),
            ) as open_process,
        ):
            results = execute_grep_batch([quiet, import_quiet, hot])

        assert results[quiet] == ()
        assert results[import_quiet] == ()
        assert results[hot] == ("/repo/source.py:1:bar = value\u0301",)
        assert results.incomplete_requests == set()
        open_process.assert_called_once()

    def test_streamed_retry_skips_late_ambiguous_line_outside_window(self):
        numpy = _regex_grep_request(r"\bnumpy\b", max_results=2)
        late = _regex_grep_request("late", max_results=2)
        output = _rg_json_output(
            ("/repo/a.py", 1, "numpy()\n"),
            ("/repo/a.py", 2, "numpy()\n"),
            ("/repo/z.py", 1, "numpy\u0301 late\n"),
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=lambda _cmd: _stdout_process(output),
            ) as open_process,
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_RESULT_FLOOR",
                2,
            ),
        ):
            results = execute_grep_batch([numpy, late])

        assert results[numpy] == (
            "/repo/a.py:1:numpy()",
            "/repo/a.py:2:numpy()",
        )
        assert results.incomplete_requests == set()
        open_process.assert_called_once()

    def test_streamed_retry_allows_reader_to_drain_after_process_exit(self):
        request = _fixed_grep_request()
        output = _rg_json_output(("/repo/source.py", 1, "needle\n"))
        original_reader = grep_verify_common_module._read_streamed_grep_output
        process_exited = threading.Event()

        def signaling_process(_cmd):
            process = _stdout_process(output)
            original_wait = process.wait

            def wait_and_signal(*args, **kwargs):
                result = original_wait(*args, **kwargs)
                process_exited.set()
                return result

            process.wait = wait_and_signal
            return process

        def delayed_reader(*args):
            assert process_exited.wait(timeout=1.0)
            original_reader(*args)

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_ripgrep_batch",
                side_effect=_GrepOutputLimitExceeded("forced output cap"),
            ),
            patch(
                "skylos.core.grep_verify_common._open_grep_process",
                side_effect=signaling_process,
            ),
            patch(
                "skylos.core.grep_verify_common._read_streamed_grep_output",
                side_effect=delayed_reader,
            ),
        ):
            results = execute_grep_batch(
                [request],
                deadline=time.monotonic() + 2.0,
            )

        assert results[request] == ("/repo/source.py:1:needle",)

    def test_unicode_adjudication_covers_every_request_in_a_bounded_batch(self):
        common = {
            "project_root": "/repo",
            "use_regex": True,
            "include_globs": ("*.py",),
            "fixed_string": False,
            "max_results": 5,
        }
        requests = [
            GrepRequest(pattern=rf"\bsymbol_{index}\b", **common)
            for index in range(_GREP_BATCH_SIZE)
        ]
        matches = [("/repo/nfd.py", 1, "unrelated\u0301\n")]
        matches.extend(
            (f"/repo/use_{index}.py", 1, f"symbol_{index}()\n")
            for index in range(_GREP_BATCH_SIZE)
        )
        batch_result = Mock(
            returncode=0,
            stdout=_rg_json_output(*matches),
            stderr="",
        )

        def fake_run(cmd, **_kwargs):
            if "--json" in cmd:
                return batch_result
            return Mock(returncode=1, stdout="", stderr="")

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                side_effect=fake_run,
            ) as mock_run,
        ):
            results = execute_grep_batch(requests)

        assert set(results) == set(requests)
        for index, request in enumerate(requests):
            assert results[request] == (
                f"/repo/use_{index}.py:1:symbol_{index}()",
            )
        assert mock_run.call_count == len(requests) + 1
        assert results.incomplete_requests == set()

    def test_bounded_subprocess_rejects_oversized_output(self):
        with (
            patch(
                "skylos.core.grep_verify_common._GREP_BATCH_MAX_OUTPUT_BYTES",
                64,
            ),
            pytest.raises(_GrepOutputLimitExceeded),
        ):
            _run_bounded_subprocess(
                [sys.executable, "-c", "print('x' * 10000)"],
                input_text="",
                timeout=2.0,
            )

    def test_thread_start_failure_leaves_request_incomplete(self):
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root="/repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value=sys.executable,
            ),
            patch(
                "skylos.core.grep_verify_common.threading.Thread.start",
                side_effect=RuntimeError("cannot start thread"),
            ),
        ):
            results = execute_grep_batch([request])

        assert request not in results

    def test_repo_planted_search_backends_are_never_executed(self, tmp_path):
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root=str(tmp_path),
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        planted = {
            "rg": str(tmp_path / "rg.exe"),
            "grep": str(tmp_path / "grep.exe"),
        }

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                side_effect=lambda executable: planted[executable],
            ),
            patch("skylos.core.grep_verify_common.subprocess.Popen") as popen,
        ):
            results = execute_grep_batch([request])

        assert request not in results
        popen.assert_not_called()

    def test_single_file_scan_rejects_sibling_search_backends(self, tmp_path):
        target = tmp_path / "target.py"
        target.write_text("helper()\n", encoding="utf-8")
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root=str(target),
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        planted = {
            "rg": str(tmp_path / "rg.exe"),
            "grep": str(tmp_path / "grep.exe"),
        }

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                side_effect=lambda executable: planted[executable],
            ),
            patch("skylos.core.grep_verify_common.subprocess.Popen") as popen,
        ):
            results = execute_grep_batch([request])

        assert request not in results
        popen.assert_not_called()

    def test_deleted_single_file_still_rejects_sibling_search_backends(
        self, tmp_path
    ):
        target = tmp_path / "target.py"
        target.write_text("helper()\n", encoding="utf-8")
        request = GrepRequest(
            pattern=r"\bhelper\b",
            project_root=str(target),
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        target.unlink()
        planted = {
            "rg": str(tmp_path / "rg.exe"),
            "grep": str(tmp_path / "grep.exe"),
        }

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                side_effect=lambda executable: planted[executable],
            ),
            patch("skylos.core.grep_verify_common.subprocess.Popen") as popen,
        ):
            results = execute_grep_batch([request])

        assert request not in results
        popen.assert_not_called()

    def test_filesystem_root_cwd_does_not_reject_system_backend(self):
        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common.Path.cwd",
                return_value=Path("/"),
            ),
        ):
            resolved = _trusted_which("rg", ("/workspace/repo",))

        assert resolved == "/usr/bin/rg"

    def test_home_cwd_does_not_reject_user_installed_backend(self):
        expected = str(Path("/home/alice/.local/bin/rg").resolve())
        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/home/alice/.local/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common.Path.cwd",
                return_value=Path("/home/alice"),
            ),
        ):
            resolved = _trusted_which("rg", ("/workspace/repo",))

        assert resolved == expected

    def test_unrelated_cwd_backend_is_rejected(self):
        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/untrusted/rg.exe",
            ),
            patch(
                "skylos.core.grep_verify_common.Path.cwd",
                return_value=Path("/untrusted"),
            ),
        ):
            resolved = _trusted_which("rg", ("/workspace/repo",))

        assert resolved is None

    def test_missing_search_executables_leave_request_incomplete(self):
        request = GrepRequest(
            pattern="helper",
            project_root="/repo",
            use_regex=False,
            include_globs=("*.py",),
            fixed_string=True,
            max_results=5,
        )

        with patch(
            "skylos.core.grep_verify_common.shutil.which", return_value=None
        ):
            results = execute_grep_batch([request])

        assert request not in results

    def test_grep_fallback_treats_pattern_and_root_as_operands(self):
        request = GrepRequest(
            pattern="--include=*",
            project_root="-repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        process_result = Mock(returncode=1, stdout="", stderr="")

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                side_effect=lambda executable: (
                    None if executable == "rg" else "/usr/bin/grep"
                ),
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ) as mock_run,
        ):
            assert _run_grep_request(request, require_complete=True) == []

        assert mock_run.call_args.args[0][-4:] == [
            "-e",
            "--include=*",
            "--",
            os.path.abspath("-repo"),
        ]

    def test_direct_ripgrep_preserves_colon_path(self):
        request = GrepRequest(
            pattern=r"helper\s*\(",
            project_root="/repo",
            use_regex=True,
            include_globs=("*.py",),
            fixed_string=False,
            max_results=5,
        )
        path = "/repo/release.v1:123/pkg/lib.py"
        process_result = Mock(
            returncode=0,
            stdout=_rg_json_output((path, 7, "helper()\n")),
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ) as mock_run,
        ):
            evidence = _run_grep_request(request, require_complete=True)[0]

        assert evidence == f"{path}:7:helper()"
        assert isinstance(evidence, _GrepEvidence)
        assert evidence.path == path
        assert "--json" in mock_run.call_args.args[0]

    def test_grep_fallback_preserves_colon_path(self):
        request = GrepRequest(
            pattern="helper",
            project_root="/repo",
            use_regex=False,
            include_globs=("*.py",),
            fixed_string=True,
            max_results=5,
        )
        path = "/repo/release.v1:123/pkg/lib.py"
        process_result = Mock(
            returncode=0,
            stdout=f"{path}\0" "7:helper()\n",
            stderr="",
        )

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                side_effect=lambda executable: (
                    None if executable == "rg" else "/usr/bin/grep"
                ),
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ),
        ):
            evidence = _run_grep_request(request, require_complete=True)[0]

        assert evidence == f"{path}:7:helper()"
        assert isinstance(evidence, _GrepEvidence)
        assert evidence.path == path

    def test_incomplete_batch_is_not_replayed_or_cached(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }
        cache = GrepCache()

        with patch(
            "skylos.core.grep_verify.execute_grep_batch", return_value={}
        ):
            verdicts = grep_verify_findings(
                [finding], str(tmp_path), cache=cache, time_budget=1.0
            )

        assert verdicts == {}
        assert verdicts.complete is False
        assert verdicts.incomplete_reason == "verification_incomplete"
        assert cache.size == 0

    def test_conservative_partial_match_can_rescue_but_is_not_cached(
        self, tmp_path
    ):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        usage = tmp_path / "usage.py"
        usage.write_text("helper()\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }
        cache = GrepCache()

        def partial_results(requests, **_kwargs):
            results = _GrepBatchResults()
            evidence = _GrepEvidence(str(usage), 1, "helper()")
            for request in requests:
                results[request] = (evidence,)
            results.incomplete_requests.add(requests[0])
            return results

        with patch(
            "skylos.core.grep_verify.execute_grep_batch",
            side_effect=partial_results,
        ):
            verdicts = grep_verify_findings(
                [finding], str(tmp_path), cache=cache, time_budget=1.0
            )

        assert set(verdicts) == {"library.helper"}
        assert verdicts.complete is True
        assert cache.size == 0

    def test_incomplete_request_without_alive_evidence_fails_closed(
        self, tmp_path
    ):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }
        cache = GrepCache()

        def incomplete_negative_results(requests, **_kwargs):
            results = _GrepBatchResults()
            for request in requests:
                results[request] = ()
            results.incomplete_requests.add(requests[0])
            return results

        with patch(
            "skylos.core.grep_verify.execute_grep_batch",
            side_effect=incomplete_negative_results,
        ):
            verdicts = grep_verify_findings(
                [finding], str(tmp_path), cache=cache, time_budget=1.0
            )

        assert verdicts == {}
        assert verdicts.complete is False
        assert verdicts.incomplete_reason == "verification_incomplete"
        assert cache.size == 0

    def test_malformed_cached_group_is_treated_as_a_cache_miss(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }
        cache = GrepCache()

        with (
            patch.object(cache, "get", return_value=["[]"]),
            patch(
                "skylos.core.grep_verify.execute_grep_batch", return_value={}
            ) as mock_batch,
        ):
            verdicts = grep_verify_findings(
                [finding], str(tmp_path), cache=cache, time_budget=1.0
            )

        assert verdicts == {}
        mock_batch.assert_called_once()

    def test_oversized_group_result_is_not_stored(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
        }
        cache = GrepCache()
        cache.bind_repository(tmp_path)

        _store_cached_group_results(
            cache,
            "python_core",
            finding,
            {"references": ["x" * 1_000_001]},
        )

        assert cache.size == 0

    def test_no_ripgrep_uses_legacy_requests(self):
        request = GrepRequest(
            pattern="helper",
            project_root="/repo",
            use_regex=False,
            include_globs=("*.py",),
            fixed_string=True,
            max_results=5,
        )

        with (
            patch("skylos.core.grep_verify_common.shutil.which", return_value=None),
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                return_value=["/repo/main.py:1:helper()"],
            ) as mock_direct,
        ):
            results = execute_grep_batch([request])

        assert results == {request: ("/repo/main.py:1:helper()",)}
        mock_direct.assert_called_once_with(
            request, deadline=None, require_complete=True
        )

    def test_replay_miss_executes_legacy_request(self):
        with (
            replay_grep_results({}),
            patch(
                "skylos.core.grep_verify_common._run_grep_request",
                return_value=["/repo/main.py:1:helper()"],
            ) as mock_direct,
        ):
            results = _run_grep(
                "helper",
                "/repo",
                include_globs=["*.py"],
                fixed_string=True,
                max_results=5,
            )

        assert results == ["/repo/main.py:1:helper()"]
        mock_direct.assert_called_once()

    def test_non_utf8_matching_line_does_not_abort_verification(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        invalid = tmp_path / "invalid.py"
        invalid.write_bytes(b"helper()  # \xe9\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }

        with patch(
            "skylos.core.grep_verify_common._run_ripgrep_batch",
            side_effect=_invalid_utf8_decode_error(),
        ):
            batched = grep_verify_findings([finding], str(tmp_path))
        legacy = grep_verify_findings([finding], str(tmp_path), parallel=True)

        assert batched == legacy == {}

    def test_sorted_over_cap_definitions_do_not_hide_late_usage(self, tmp_path):
        for index in range(30):
            (tmp_path / f"a{index:02}.py").write_text(
                "def helper():\n    return None\n"
            )
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        usage = tmp_path / "z_usage.py"
        usage.write_text("helper()\n")
        output_matches = [
            (str(tmp_path / f"a{index:02}.py"), 1, "def helper():\n")
            for index in range(30)
        ]
        output_matches.extend(
            ((str(library), 1, "def helper():\n"), (str(usage), 1, "helper()\n"))
        )
        process_result = Mock(
            returncode=0,
            stdout=_rg_json_output(*output_matches),
            stderr="",
        )
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }

        with (
            patch(
                "skylos.core.grep_verify_common.shutil.which",
                return_value="/usr/bin/rg",
            ),
            patch(
                "skylos.core.grep_verify_common._run_bounded_subprocess",
                return_value=process_result,
            ),
        ):
            verdicts = grep_verify_findings([finding], str(tmp_path))

        assert set(verdicts) == {"library.helper"}

    def test_final_finding_batch_is_not_started_after_deadline(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        (tmp_path / "main.py").write_text("helper()\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }
        now = [0.0]
        original_plan = grep_verify_module._plan_batched_finding

        def plan_then_expire(*args, **kwargs):
            planned = original_plan(*args, **kwargs)
            now[0] = 1.0
            return planned

        with (
            patch(
                "skylos.core.grep_verify.time.monotonic",
                side_effect=lambda: now[0],
            ),
            patch(
                "skylos.core.grep_verify._plan_batched_finding",
                side_effect=plan_then_expire,
            ),
            patch("skylos.core.grep_verify.execute_grep_batch") as mock_batch,
        ):
            verdicts = grep_verify_findings([finding], str(tmp_path), time_budget=0.5)

        assert verdicts == {}
        assert verdicts.complete is False
        assert verdicts.budget_exhausted is True
        mock_batch.assert_not_called()

    def test_batched_and_legacy_verdicts_match(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text(
            "def helper():\n    return 1\n\ndef orphan():\n    return 2\n"
        )
        (tmp_path / "main.py").write_text("from library import helper\nhelper()\n")
        findings = [
            {
                "name": name,
                "full_name": f"library.{name}",
                "simple_name": name,
                "type": "function",
                "file": str(library),
                "line": line,
                "confidence": 80,
            }
            for name, line in (("helper", 1), ("orphan", 4))
        ]

        batched = grep_verify_findings(findings, str(tmp_path))
        legacy = grep_verify_findings(
            findings, str(tmp_path), parallel=True, max_workers=2
        )

        assert set(batched) == set(legacy) == {"library.helper"}
        assert (
            batched["library.helper"].suppression_code
            == legacy["library.helper"].suppression_code
        )

    def test_warm_cache_skips_batch_execution(self, tmp_path):
        library = tmp_path / "library.py"
        library.write_text("def helper():\n    return 1\n")
        (tmp_path / "main.py").write_text("from library import helper\nhelper()\n")
        finding = {
            "name": "helper",
            "full_name": "library.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(library),
            "line": 1,
            "confidence": 80,
        }
        cache = GrepCache()

        with patch(
            "skylos.core.grep_verify.execute_grep_batch", wraps=execute_grep_batch
        ) as mock_batch:
            first = grep_verify_findings([finding], str(tmp_path), cache=cache)
            second = grep_verify_findings([finding], str(tmp_path), cache=cache)

        assert set(first) == set(second) == {"library.helper"}
        assert mock_batch.call_count == 1


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

        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert verdicts["foo.bar"].alive

    def test_qualified_ref_in_markdown_does_not_rescue(self, tmp_path):
        (tmp_path / "mod.py").write_text("def bar():\n    pass\n")
        (tmp_path / "NOTES.md").write_text("foo.bar\n")

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

        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "foo.bar" not in verdicts

    @pytest.mark.parametrize("reference", ['value = "foo.bar"\n', "# foo.bar\n"])
    def test_qualified_ref_in_python_non_code_does_not_rescue(
        self, tmp_path, reference
    ):
        (tmp_path / "mod.py").write_text("def bar():\n    pass\n")
        (tmp_path / "other.py").write_text(reference)

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

        verdicts = grep_verify_findings(findings, str(tmp_path))
        assert "foo.bar" not in verdicts


class TestAnalyzerIntegration:
    def test_exhausted_budget_withholds_candidates_and_marks_scan_incomplete(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "app.py").write_text(
            "import os\n\ndef orphan(unused_arg):\n    return 1\n",
            encoding="utf-8",
        )
        (tmp_path / "utils.py").write_text(
            "def another_orphan():\n    return 2\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("SKYLOS_GREP_BUDGET", "0")

        from skylos import cli
        from skylos.analyzer import analyze

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))

        assert result["analysis_errors"][0]["rule_id"] == (
            "SKY-ANALYSIS-INCOMPLETE"
        )
        assert result["analysis_errors"][0]["kind"] == "grep_budget_exhausted"
        assert result["analysis_summary"]["grep_verify"] == {
            "enabled": True,
            "rescued_count": 0,
            "project_cache_enabled": True,
            "complete": False,
            "status": "incomplete",
            "candidate_count": 4,
            "candidate_file_count": 2,
            "time_budget_seconds": 0.0,
            "incomplete_reason": "budget_exhausted",
        }
        assert result["analysis_errors"][0]["file"] == str(tmp_path / "app.py")
        assert result["analysis_errors"][0]["affected_file_count"] == 2
        assert "grade" not in result
        assert result["analysis_summary"]["grade_unavailable_reason"] == (
            "analysis_incomplete"
        )
        assert cli._analysis_incomplete_exit_code(result) == 2

        assert result["unused_functions"] == []
        assert result["unused_imports"] == []
        assert result["unused_parameters"] == []
        abstentions = result["dead_code_abstentions"]
        assert {finding["type"] for finding in abstentions} >= {
            "function",
            "import",
            "parameter",
        }
        grep_uncertainty = [
            evidence
            for finding in abstentions
            for evidence in finding.get("dead_code_evidence", [])
            if evidence.get("source") == "grep_verify"
        ]
        assert grep_uncertainty
        assert all(
            evidence["kind"] == "uncertainty" for evidence in grep_uncertainty
        )

    def test_incomplete_grep_state_is_reset_between_analyzer_runs(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "app.py").write_text(
            "def orphan():\n    return 1\n",
            encoding="utf-8",
        )

        from skylos.analyzer import Skylos

        analyzer = Skylos()
        monkeypatch.setenv("SKYLOS_GREP_BUDGET", "0")
        incomplete = json.loads(
            analyzer.analyze(str(tmp_path), thr=0, grep_verify=True)
        )
        complete = json.loads(
            analyzer.analyze(str(tmp_path), thr=0, grep_verify=False)
        )

        assert incomplete["unused_functions"] == []
        assert incomplete["dead_code_abstentions"]
        assert complete["analysis_errors"] == []
        assert complete["dead_code_abstentions"] == []
        assert {item["simple_name"] for item in complete["unused_functions"]} == {
            "orphan"
        }

    def test_grep_cache_invalidates_when_repository_evidence_changes(self, tmp_path):
        target = tmp_path / "target.py"
        evidence = tmp_path / "evidence.py"
        target.write_text("def _cached_helper() -> None:\n    pass\n")
        evidence.write_text("from target import _cached_helper\n\n_cached_helper()\n")

        import json

        from skylos.analyzer import analyze

        def unused_functions():
            result = json.loads(analyze(str(target), conf=0, grep_verify=True))
            return {finding["full_name"] for finding in result["unused_functions"]}

        assert "target._cached_helper" not in unused_functions()

        evidence.write_text("value = 1\n")
        assert "target._cached_helper" in unused_functions()

        evidence.write_text("from target import _cached_helper\n\n_cached_helper()\n")
        assert "target._cached_helper" not in unused_functions()

    def test_grep_verify_matches_static_analysis_for_unrelated_parameters(
        self, tmp_path
    ):
        (tmp_path / "first.py").write_text(
            'def target(unused_value: str) -> None:\n    pass\n\ntarget("x")\n'
        )
        (tmp_path / "second.py").write_text(
            'def unrelated(unused_value: str) -> None:\n    pass\n\nunrelated("x")\n'
        )

        import json

        from skylos.analyzer import analyze

        result_on = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
        result_off = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

        def unused_parameter_locations(result):
            return {
                (finding["file"], finding["full_name"])
                for finding in result["unused_parameters"]
            }

        assert unused_parameter_locations(result_on) == unused_parameter_locations(
            result_off
        )
        assert len(result_on["unused_parameters"]) == 2
        assert result_on["analysis_summary"]["grep_verify"]["rescued_count"] == 0

    def test_grep_verify_rescues_dynamic_dispatch(self, tmp_path):
        (tmp_path / "plugin.py").write_text(
            'def handle_event():\n    return "handled"\n'
        )
        (tmp_path / "dispatcher.py").write_text(
            'import plugin\ngetattr(plugin, "handle_event")()\n'
        )

        import json

        from skylos.analyzer import analyze

        result_on = json.loads(analyze(str(tmp_path), conf=60, grep_verify=True))
        result_off = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))

        unused_names_on = {
            f.get("simple_name") for f in result_on.get("unused_functions", [])
        }
        unused_names_off = {
            f.get("simple_name") for f in result_off.get("unused_functions", [])
        }

        assert len(unused_names_on) <= len(unused_names_off)
        assert result_on["analysis_summary"]["grep_verify"]["enabled"] is True
        assert (
            result_on["analysis_summary"]["grep_verify"]["project_cache_enabled"]
            is True
        )
        assert isinstance(
            result_on["analysis_summary"]["grep_verify"]["rescued_count"], int
        )
        assert result_off["analysis_summary"]["grep_verify"] == {
            "enabled": False,
            "rescued_count": 0,
        }

    def test_grep_verify_keeps_same_name_wrapper_dead(self, tmp_path):
        (tmp_path / "app.py").write_text(
            """
class InternalClass:
    @staticmethod
    def same_name_method():
        return "internal"

class PublicClass:
    @staticmethod
    def same_name_method():
        return InternalClass.same_name_method()

    @staticmethod
    def different_name_wrapper():
        return InternalClass.same_name_method()

    @staticmethod
    def used_method():
        return "used"

result = PublicClass.used_method()
""",
            encoding="utf-8",
        )

        import json

        from skylos.analyzer import analyze

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
        unused_methods = {
            finding.get("full_name") for finding in result.get("unused_functions", [])
        }

        assert "app.PublicClass.same_name_method" in unused_methods
        assert "app.PublicClass.different_name_wrapper" in unused_methods


class TestAnalyzerGrepVerifyOrdering:
    @pytest.mark.parametrize("changed_file_style", ["absolute", "relative"])
    def test_changed_file_scan_only_verifies_reportable_definitions(
        self, tmp_path, changed_file_style
    ):
        from skylos.analyzer import analyze

        changed = tmp_path / "changed.py"
        unchanged = tmp_path / "unchanged.py"
        changed.write_text("def _changed_dead():\n    return 1\n", encoding="utf-8")
        unchanged.write_text(
            "def _unchanged_dead():\n    return 2\n", encoding="utf-8"
        )
        selected = (
            str(changed.resolve())
            if changed_file_style == "absolute"
            else changed.name
        )

        with patch(
            "skylos.core.grep_verify.grep_verify_findings", return_value={}
        ) as mock_grep:
            result = json.loads(
                analyze(
                    str(tmp_path),
                    conf=0,
                    changed_files={selected},
                    grep_verify=True,
                )
            )

        candidates = mock_grep.call_args.args[0]
        assert {Path(item["file"]).resolve() for item in candidates} == {
            changed.resolve()
        }
        assert Path(mock_grep.call_args.args[1]).resolve() == tmp_path.resolve()
        assert {
            Path(item["file"]).resolve()
            for item in result["unused_functions"]
        } == {changed.resolve()}

    def test_changed_definition_can_be_rescued_from_unchanged_repository_file(
        self, tmp_path
    ):
        from skylos.analyzer import analyze

        changed = tmp_path / "handlers.py"
        changed.write_text(
            "def payment_webhook():\n    return 'ok'\n", encoding="utf-8"
        )
        (tmp_path / "routes.yaml").write_text(
            "handler_module: handlers.py\n", encoding="utf-8"
        )

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                changed_files={str(changed)},
                grep_verify=True,
                grep_cache=False,
            )
        )

        assert not result["unused_functions"]
        assert result["analysis_summary"]["grep_verify"]["rescued_count"] == 1

    def test_empty_changed_file_scope_skips_dead_code_verification(self, tmp_path):
        from skylos.analyzer import analyze

        (tmp_path / "unchanged.py").write_text(
            "def _unchanged_dead():\n    return 1\n", encoding="utf-8"
        )

        with patch(
            "skylos.core.grep_verify.grep_verify_findings"
        ) as mock_grep:
            result = json.loads(
                analyze(
                    str(tmp_path),
                    conf=0,
                    changed_files=set(),
                    grep_verify=True,
                )
            )

        mock_grep.assert_not_called()
        assert result["unused_functions"] == []
        assert result["analysis_errors"] == []

    def test_full_scan_keeps_all_dead_code_candidates(self, tmp_path):
        from skylos.analyzer import Skylos

        first = tmp_path / "first.py"
        second = tmp_path / "second.py"
        first.write_text("def _first_dead():\n    return 1\n", encoding="utf-8")
        second.write_text("def _second_dead():\n    return 2\n", encoding="utf-8")

        analyzer = Skylos()
        scoped = json.loads(
            analyzer.analyze(
                str(tmp_path),
                thr=0,
                changed_files={str(first)},
                grep_verify=False,
            )
        )
        result = json.loads(
            analyzer.analyze(str(tmp_path), thr=0, grep_verify=False)
        )

        assert {
            Path(item["file"]).resolve()
            for item in scoped["unused_functions"]
        } == {first.resolve()}
        assert {
            Path(item["file"]).resolve()
            for item in result["unused_functions"]
        } == {first.resolve(), second.resolve()}

    def test_incomplete_result_does_not_apply_partial_rescues(
        self, tmp_path, monkeypatch
    ):
        from skylos.analyzer import Skylos
        from skylos.visitors.base import Definition

        source = tmp_path / "mod.py"
        source.write_text("def helper():\n    return 1\n")
        analyzer = Skylos()
        analyzer._project_root = tmp_path
        definition = Definition("mod.helper", "function", source, 1)
        definition.confidence = 80
        analyzer.defs = {"mod.helper": definition}
        incomplete = GrepVerificationResult(
            {"mod.helper": GrepVerdict(alive=True)},
            candidate_count=1,
            verified_count=0,
            time_budget=0.0,
            incomplete_reason="budget_exhausted",
        )
        monkeypatch.setenv("SKYLOS_GREP_BUDGET", "0")

        with patch(
            "skylos.core.grep_verify.grep_verify_findings",
            return_value=incomplete,
        ):
            rescued = analyzer._grep_verify()

        assert rescued == 0
        assert definition.references == 0
        assert definition.heuristic_refs.get("grep_verify") is None
        assert analyzer._grep_verify_report["complete"] is False
        assert analyzer._grep_verify_incomplete_candidates[0]["full_name"] == (
            "mod.helper"
        )

        with patch(
            "skylos.core.grep_verify.grep_verify_findings",
            return_value={},
        ):
            analyzer._grep_verify()

        assert not hasattr(analyzer, "_grep_verify_incomplete_candidates")
        assert "complete" not in analyzer._grep_verify_report

    def test_candidates_are_sorted_by_rescue_priority(self, tmp_path):
        from skylos.analyzer import Skylos
        from skylos.visitors.base import Definition

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

        with patch(
            "skylos.core.grep_verify.grep_verify_findings", return_value={}
        ) as mock_grep:
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


class TestAnalyzerGrepVerifyCache:
    def test_grep_verify_loads_and_saves_cache(self, tmp_path):
        from skylos.analyzer import Skylos
        from skylos.visitors.base import Definition

        project_root = tmp_path / "repo"
        project_root.mkdir()
        source = project_root / "mod.py"
        source.write_text("def helper():\n    return 1\n")

        analyzer = Skylos()
        analyzer._project_root = project_root

        definition = Definition("mod.helper", "function", source, 1)
        definition.confidence = 80
        analyzer.defs = {"mod.helper": definition}

        with (
            patch(
                "skylos.analyzer.find_git_root", return_value=project_root
            ) as mock_root,
            patch("skylos.core.grep_cache.GrepCache") as mock_cache_cls,
            patch(
                "skylos.core.grep_verify.grep_verify_findings", return_value={}
            ) as mock_grep,
        ):
            cache = mock_cache_cls.return_value
            analyzer._grep_verify()

        mock_root.assert_called_once_with(str(project_root))
        cache.load.assert_called_once_with(project_root)
        cache.save.assert_called_once_with(project_root)
        assert mock_grep.call_args.kwargs["cache"] is cache


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

    def test_php(self):
        assert detect_language("index.php") == "php"

    def test_rust(self):
        assert detect_language("lib.rs") == "rust"

    def test_kotlin(self):
        assert detect_language("Main.kt") == "kotlin"
        assert detect_language("build.gradle.kts") == "kotlin"

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

    def test_php_module(self, tmp_path):
        f = tmp_path / "src" / "Controller" / "UserController.php"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.touch()
        candidates = module_candidates(str(f), str(tmp_path))
        assert "Controller.UserController" in candidates


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

    def test_php_method(self):
        finding = {"file": "/repo/App.php", "line": 7, "simple_name": "helper"}
        assert is_definition_line(
            "/repo/App.php:7:    private function helper($x) {", finding
        )


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

    def test_kotlin_test_annotation(self):
        finding = {
            "file": "UserTest.kt",
            "simple_name": "loadsUser",
            "type": "function",
            "decorators": ["@Test"],
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

    def test_php_globs(self):
        globs = source_globs_for_language("php")
        assert "*.php" in globs

    def test_kotlin_globs(self):
        globs = source_globs_for_language("kotlin")
        assert "*.kt" in globs
        assert "*.kts" in globs

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

    def test_parallel_logs_and_ignores_strategy_group_failures(self, tmp_path):
        finding = {
            "name": "helper",
            "full_name": "lib.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "lib.py"),
            "line": 1,
        }

        with (
            patch(
                "skylos.core.grep_verify._cached_group_results",
                side_effect=RuntimeError("boom"),
            ),
            patch("skylos.core.grep_verify.logger.debug") as mock_debug,
        ):
            results = parallel_multi_strategy_search(
                finding, str(tmp_path), max_workers=2
            )

        assert results == {}
        mock_debug.assert_called()

    def test_parallel_cache_group_names_for_typescript(self, tmp_path):
        finding = {
            "name": "helper",
            "full_name": "util.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "util.ts"),
            "line": 1,
        }
        cache = GrepCache()

        with patch(
            "skylos.core.grep_verify._cached_group_results", return_value={}
        ) as mock_cached_group:
            parallel_multi_strategy_search(
                finding, str(tmp_path), max_workers=2, cache=cache
            )

        group_names = {call.args[1] for call in mock_cached_group.call_args_list}
        assert group_names == {"general_refs", "typescript"}


class TestGrepVerifyParallel:
    def test_parallel_incomplete_operation_at_deadline_is_budget_exhaustion(self):
        incomplete = grep_verify_module.concurrent.futures.Future()
        incomplete.set_exception(_GrepExecutionIncomplete("request timed out"))

        with patch("skylos.core.grep_verify.time.monotonic", return_value=1.0):
            verified_count, reason = (
                grep_verify_module._collect_finished_findings(
                    {incomplete}, {}, deadline=1.0
                )
            )

        assert verified_count == 0
        assert reason == "budget_exhausted"

    def test_parallel_completion_reason_is_order_independent(self):
        success = grep_verify_module.concurrent.futures.Future()
        success.set_result(("lib.helper", GrepVerdict(alive=True)))
        deadline = grep_verify_module.concurrent.futures.Future()
        deadline.set_exception(_GrepDeadlineExceeded("budget"))
        failure = grep_verify_module.concurrent.futures.Future()
        failure.set_exception(RuntimeError("backend failed"))
        verdicts = {}

        verified_count, reason = grep_verify_module._collect_finished_findings(
            {deadline, success, failure}, verdicts
        )

        assert verified_count == 1
        assert reason == "verification_incomplete"
        assert set(verdicts) == {"lib.helper"}

    def test_parallel_budget_exhaustion_discards_partial_results(self, tmp_path):
        finding = {
            "name": "helper",
            "full_name": "lib.helper",
            "simple_name": "helper",
            "type": "function",
            "file": str(tmp_path / "lib.py"),
            "line": 1,
            "confidence": 80,
        }

        verdicts = grep_verify_findings(
            [finding],
            str(tmp_path),
            time_budget=0.0,
            parallel=True,
            max_workers=1,
        )

        assert verdicts == {}
        assert verdicts.complete is False
        assert verdicts.budget_exhausted is True

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
