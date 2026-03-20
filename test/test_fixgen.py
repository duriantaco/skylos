from __future__ import annotations

from skylos.fixgen import (
    RemovalPatch,
    _build_dependency_dag,
    _compute_safety_score,
    _find_block_end,
    _find_import_range,
    _topological_sort,
    apply_patches,
    generate_fix_summary,
    generate_removal_plan,
    generate_unified_diff,
    validate_patches,
)


class TestRemovalPatch:
    def test_line_count_single(self):
        p = RemovalPatch("f.py", (5, 5), "", "foo", "function")
        assert p.line_count == 1

    def test_line_count_multi(self):
        p = RemovalPatch("f.py", (3, 10), "", "bar", "class")
        assert p.line_count == 8


class TestBuildDependencyDag:
    def test_no_findings(self):
        assert _build_dependency_dag([], {}) == {}

    def test_simple_deps(self):
        findings = [
            {"full_name": "a", "name": "a"},
            {"full_name": "b", "name": "b"},
        ]
        defs_map = {
            "a": {"calls": ["b"]},
            "b": {"calls": []},
        }
        dag = _build_dependency_dag(findings, defs_map)
        assert dag == {"a": ["b"], "b": []}

    def test_ignores_external_calls(self):
        findings = [{"full_name": "a"}]
        defs_map = {"a": {"calls": ["external_func"]}}
        dag = _build_dependency_dag(findings, defs_map)
        assert dag == {"a": []}

    def test_ignores_self_calls(self):
        findings = [{"full_name": "a"}]
        defs_map = {"a": {"calls": ["a"]}}
        dag = _build_dependency_dag(findings, defs_map)
        assert dag == {"a": []}

    def test_falls_back_to_name(self):
        findings = [{"name": "x"}]
        defs_map = {"x": {"calls": []}}
        dag = _build_dependency_dag(findings, defs_map)
        assert dag == {"x": []}

    def test_skips_empty_names(self):
        findings = [{}]
        dag = _build_dependency_dag(findings, {})
        assert dag == {}

    def test_non_dict_info(self):
        findings = [{"full_name": "a"}]
        defs_map = {"a": "not_a_dict"}
        dag = _build_dependency_dag(findings, defs_map)
        assert dag == {"a": []}


class TestTopologicalSort:
    def test_empty(self):
        assert _topological_sort({}) == []

    def test_single_node(self):
        assert _topological_sort({"a": []}) == ["a"]

    def test_linear_chain(self):
        dag = {"a": ["b"], "b": ["c"], "c": []}
        result = _topological_sort(dag)
        assert result.index("a") < result.index("b") < result.index("c")

    def test_independent_nodes(self):
        dag = {"a": [], "b": [], "c": []}
        result = _topological_sort(dag)
        assert set(result) == {"a", "b", "c"}

    def test_cycle_still_included(self):
        dag = {"a": ["b"], "b": ["a"]}
        result = _topological_sort(dag)
        assert set(result) == {"a", "b"}

    def test_diamond(self):
        dag = {"d": ["b", "c"], "b": ["a"], "c": ["a"], "a": []}
        result = _topological_sort(dag)
        assert result.index("d") < result.index("b")
        assert result.index("d") < result.index("c")
        assert result.index("b") < result.index("a")
        assert result.index("c") < result.index("a")


class TestComputeSafetyScore:
    def test_import(self):
        assert _compute_safety_score({"type": "import"}) == 0.95

    def test_function(self):
        assert _compute_safety_score({"type": "function"}) == 0.9

    def test_variable(self):
        assert _compute_safety_score({"type": "variable"}) == 0.85

    def test_class(self):
        assert _compute_safety_score({"type": "class"}) == 0.7

    def test_method(self):
        assert _compute_safety_score({"type": "method"}) == 0.6

    def test_unknown_type(self):
        assert _compute_safety_score({"type": "other"}) == 1.0

    def test_no_type(self):
        assert _compute_safety_score({}) == 1.0

    def test_llm_verified_boost(self):
        score = _compute_safety_score(
            {"type": "function", "_llm_verdict": "TRUE_POSITIVE"}
        )
        assert score == 0.95

    def test_high_confidence_boost(self):
        score = _compute_safety_score({"type": "function", "confidence": 95})
        assert score == 0.95

    def test_both_boosts(self):
        score = _compute_safety_score(
            {
                "type": "import",
                "_llm_verdict": "TRUE_POSITIVE",
                "confidence": 95,
            }
        )
        assert score == 1.0

    def test_low_confidence_no_boost(self):
        score = _compute_safety_score({"type": "function", "confidence": 60})
        assert score == 0.9

    def test_non_numeric_confidence(self):
        score = _compute_safety_score({"type": "function", "confidence": "high"})
        assert score == 0.9


class TestFindBlockEnd:
    def test_simple_function(self):
        lines = [
            "def foo():",
            "    return 1",
            "",
            "x = 10",
        ]
        assert _find_block_end(lines, 0) == 2

    def test_nested_function(self):
        lines = [
            "def foo():",
            "    x = 1",
            "    def bar():",
            "        return x",
            "    return bar",
            "other = 1",
        ]
        assert _find_block_end(lines, 0) == 4

    def test_class_block(self):
        lines = [
            "class Foo:",
            "    x = 1",
            "    def method(self):",
            "        pass",
            "",
            "y = 2",
        ]
        assert _find_block_end(lines, 0) == 4

    def test_start_beyond_file(self):
        lines = ["x = 1"]
        assert _find_block_end(lines, 5) == 5

    def test_indented_block(self):
        lines = [
            "class Outer:",
            "    def inner(self):",
            "        x = 1",
            "        y = 2",
            "    other = 3",
        ]
        assert _find_block_end(lines, 1) == 3

    def test_block_with_comments(self):
        lines = [
            "def foo():",
            "    x = 1",
            "    # comment",
            "    y = 2",
            "z = 3",
        ]
        assert _find_block_end(lines, 0) == 3

    def test_single_line_at_eof(self):
        lines = ["def foo():", "    pass"]
        assert _find_block_end(lines, 0) == 1


class TestFindImportRange:
    def test_single_line_import(self):
        lines = ["import os", "x = 1"]
        assert _find_import_range(lines, 0) == 0

    def test_multi_line_parens(self):
        lines = [
            "from os import (",
            "    path,",
            "    getcwd,",
            ")",
            "x = 1",
        ]
        assert _find_import_range(lines, 0) == 3

    def test_backslash_continuation(self):
        lines = [
            "from os import path, \\",
            "    getcwd",
            "x = 1",
        ]
        assert _find_import_range(lines, 0) == 1

    def test_start_beyond_file(self):
        lines = ["import os"]
        assert _find_import_range(lines, 5) == 5

    def test_single_line_from_import(self):
        lines = ["from os import path"]
        assert _find_import_range(lines, 0) == 0

    def test_parens_same_line(self):
        lines = ["from os import (path, getcwd)", "x = 1"]
        assert _find_import_range(lines, 0) == 0


class TestGenerateRemovalPlan:
    def test_basic_plan(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("def dead():\n    pass\n\nx = 1\n")
        findings = [
            {
                "full_name": "dead",
                "name": "dead",
                "type": "function",
                "file": str(src),
                "line": 1,
                "confidence": 95,
            }
        ]
        patches = generate_removal_plan(findings, {"dead": {"calls": []}}, tmp_path)
        assert len(patches) == 1
        p = patches[0]
        assert p.finding_name == "dead"
        assert p.finding_type == "function"
        assert p.line_range == (1, 3)
        assert p.replacement == ""

    def test_comment_mode(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\n\nx = 1\n")
        findings = [{"full_name": "os", "type": "import", "file": str(src), "line": 1}]
        patches = generate_removal_plan(
            findings, {"os": {"calls": []}}, tmp_path, mode="comment"
        )
        assert len(patches) == 1
        assert "# DEAD CODE:" in patches[0].replacement

    def test_min_safety_filters(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("def f():\n    pass\n")
        findings = [{"full_name": "f", "type": "method", "file": str(src), "line": 1}]
        patches = generate_removal_plan(
            findings, {"f": {"calls": []}}, tmp_path, min_safety=0.8
        )
        assert len(patches) == 0

    def test_ordering_deps(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("def a():\n    b()\n\ndef b():\n    pass\n")
        findings = [
            {"full_name": "a", "type": "function", "file": str(src), "line": 1},
            {"full_name": "b", "type": "function", "file": str(src), "line": 4},
        ]
        defs_map = {"a": {"calls": ["b"]}, "b": {"calls": []}}
        patches = generate_removal_plan(findings, defs_map, tmp_path)
        assert len(patches) == 2
        assert patches[0].finding_name == "b"
        assert patches[1].finding_name == "a"

    def test_decorator_inclusion(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("@decorator\n@another\ndef f():\n    pass\n\nx = 1\n")
        findings = [{"full_name": "f", "type": "function", "file": str(src), "line": 3}]
        patches = generate_removal_plan(findings, {"f": {"calls": []}}, tmp_path)
        assert len(patches) == 1
        assert patches[0].line_range[0] == 1

    def test_skips_missing_file(self, tmp_path):
        findings = [
            {
                "full_name": "f",
                "type": "function",
                "file": str(tmp_path / "nope.py"),
                "line": 1,
            }
        ]
        patches = generate_removal_plan(findings, {"f": {"calls": []}}, tmp_path)
        assert len(patches) == 0

    def test_skips_no_line(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("x = 1\n")
        findings = [{"full_name": "f", "type": "function", "file": str(src), "line": 0}]
        patches = generate_removal_plan(findings, {"f": {"calls": []}}, tmp_path)
        assert len(patches) == 0

    def test_variable_multiline(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("DEAD = 1 + \\\n    2 + \\\n    3\nother = 4\n")
        findings = [
            {"full_name": "DEAD", "type": "variable", "file": str(src), "line": 1}
        ]
        patches = generate_removal_plan(findings, {"DEAD": {"calls": []}}, tmp_path)
        assert len(patches) == 1
        assert patches[0].line_range == (1, 3)

    def test_import_multiline(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("from os import (\n    path,\n    getcwd,\n)\nx = 1\n")
        findings = [
            {"full_name": "os_import", "type": "import", "file": str(src), "line": 1}
        ]
        patches = generate_removal_plan(
            findings, {"os_import": {"calls": []}}, tmp_path
        )
        assert len(patches) == 1
        assert patches[0].line_range == (1, 4)

    def test_relative_file_path(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\n")
        findings = [{"full_name": "os", "type": "import", "file": "mod.py", "line": 1}]
        patches = generate_removal_plan(findings, {"os": {"calls": []}}, tmp_path)
        assert len(patches) == 1


class TestGenerateUnifiedDiff:
    def test_basic_diff(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("def dead():\n    pass\n\nx = 1\n")
        patch = RemovalPatch(
            file_path=str(src),
            line_range=(1, 2),
            replacement="",
            finding_name="dead",
            finding_type="function",
        )
        diff = generate_unified_diff([patch], tmp_path)
        assert "--- a/mod.py" in diff
        assert "+++ b/mod.py" in diff
        assert "-def dead():" in diff

    def test_comment_mode_diff(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nx = 1\n")
        patch = RemovalPatch(
            file_path=str(src),
            line_range=(1, 1),
            replacement="# DEAD CODE: import os",
            finding_name="os",
            finding_type="import",
        )
        diff = generate_unified_diff([patch], tmp_path)
        assert "+# DEAD CODE: import os" in diff

    def test_missing_file(self, tmp_path):
        patch = RemovalPatch(
            file_path=str(tmp_path / "nope.py"),
            line_range=(1, 1),
            replacement="",
            finding_name="x",
            finding_type="variable",
        )
        diff = generate_unified_diff([patch], tmp_path)
        assert diff == ""

    def test_empty_patches(self, tmp_path):
        diff = generate_unified_diff([], tmp_path)
        assert diff == ""


class TestApplyPatches:
    def test_dry_run(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nx = 1\n")
        original = src.read_text()
        patch = RemovalPatch(
            file_path=str(src),
            line_range=(1, 1),
            replacement="",
            finding_name="os",
            finding_type="import",
        )
        result = apply_patches([patch], tmp_path, dry_run=True)
        assert str(src) in result
        assert result[str(src)] == "x = 1\n"
        assert src.read_text() == original

    def test_actual_apply(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nx = 1\n")
        patch = RemovalPatch(
            file_path=str(src),
            line_range=(1, 1),
            replacement="",
            finding_name="os",
            finding_type="import",
        )
        apply_patches([patch], tmp_path, dry_run=False, backup=True)
        assert src.read_text() == "x = 1\n"
        assert (tmp_path / "mod.py.bak").exists()

    def test_apply_no_backup(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nx = 1\n")
        patch = RemovalPatch(
            file_path=str(src),
            line_range=(1, 1),
            replacement="",
            finding_name="os",
            finding_type="import",
        )
        apply_patches([patch], tmp_path, dry_run=False, backup=False)
        assert src.read_text() == "x = 1\n"
        assert not (tmp_path / "mod.py.bak").exists()

    def test_apply_with_replacement(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nx = 1\n")
        patch = RemovalPatch(
            file_path=str(src),
            line_range=(1, 1),
            replacement="# DEAD CODE: import os",
            finding_name="os",
            finding_type="import",
        )
        result = apply_patches([patch], tmp_path, dry_run=True)
        assert "# DEAD CODE: import os" in result[str(src)]

    def test_missing_file(self, tmp_path):
        patch = RemovalPatch(
            file_path=str(tmp_path / "nope.py"),
            line_range=(1, 1),
            replacement="",
            finding_name="x",
            finding_type="variable",
        )
        result = apply_patches([patch], tmp_path, dry_run=True)
        assert result == {}

    def test_multiple_patches_same_file(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nimport sys\nx = 1\n")
        p1 = RemovalPatch(str(src), (1, 1), "", "os", "import")
        p2 = RemovalPatch(str(src), (2, 2), "", "sys", "import")
        result = apply_patches([p1, p2], tmp_path, dry_run=True)
        assert result[str(src)] == "x = 1\n"


class TestValidatePatches:
    def test_valid_removal(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("import os\nx = 1\n")
        patch = RemovalPatch(str(src), (1, 1), "", "os", "import")
        errors = validate_patches([patch], tmp_path)
        assert errors == []

    def test_syntax_error_after_removal(self, tmp_path):
        src = tmp_path / "mod.py"
        src.write_text("if True:\n    pass\n")
        patch = RemovalPatch(str(src), (2, 2), "", "pass_stmt", "variable")
        errors = validate_patches([patch], tmp_path)
        assert len(errors) == 1
        assert "syntax error" in errors[0].lower()

    def test_non_python_file_skipped(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_text("hello\nworld\n")
        patch = RemovalPatch(str(src), (1, 1), "", "hello", "variable")
        errors = validate_patches([patch], tmp_path)
        assert errors == []

    def test_empty_patches(self, tmp_path):
        errors = validate_patches([], tmp_path)
        assert errors == []


class TestGenerateFixSummary:
    def test_empty(self):
        summary = generate_fix_summary([])
        assert summary == {
            "total_patches": 0,
            "files_affected": 0,
            "total_lines_removed": 0,
            "by_type": {},
            "avg_safety_score": 0.0,
        }

    def test_basic_summary(self):
        patches = [
            RemovalPatch("a.py", (1, 5), "", "f", "function", safety_score=0.9),
            RemovalPatch("a.py", (10, 12), "", "g", "function", safety_score=0.8),
            RemovalPatch("b.py", (1, 1), "", "os", "import", safety_score=0.95),
        ]
        summary = generate_fix_summary(patches)
        assert summary["total_patches"] == 3
        assert summary["files_affected"] == 2
        assert summary["total_lines_removed"] == 5 + 3 + 1  # 9
        assert summary["by_type"] == {"function": 2, "import": 1}
        expected_avg = round((0.9 + 0.8 + 0.95) / 3, 2)
        assert summary["avg_safety_score"] == expected_avg

    def test_single_patch(self):
        patches = [RemovalPatch("x.py", (3, 3), "", "v", "variable", safety_score=0.85)]
        summary = generate_fix_summary(patches)
        assert summary["total_patches"] == 1
        assert summary["files_affected"] == 1
        assert summary["total_lines_removed"] == 1
        assert summary["by_type"] == {"variable": 1}
        assert summary["avg_safety_score"] == 0.85
