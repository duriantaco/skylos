"""Cleanup must preserve the selected f-string field and observe replacements."""

import ast
from copy import deepcopy
from pathlib import Path
import shlex
import sys

import pytest

from skylos.cleanup import build_cleanup_plan
from skylos.cleanup_execution import apply_cleanup_edit, plan_cleanup_edit
from skylos.rules.quality.slop import FormattedConversionCallRule


def _report(root, rows=(), **sections):
    return {
        "quality": list(rows),
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "comparison_scope": {"scan_path": str(root), "excluded_folders": []},
            "ai_verification": {"state": "complete"},
        },
        **sections,
    }


def _rows(root, source, *, with_source=True):
    context = {"filename": str(root / "app.py"), "project_root": root}
    if with_source:
        context["source"] = source
    return FormattedConversionCallRule().visit_node(ast.parse(source), context) or []


def _edit(root, source):
    (root / "app.py").write_text(source, encoding="utf-8")
    report = _report(root, _rows(root, source))
    queue = build_cleanup_plan(report, project_root=root, all_advice=True, top=None)
    task = next(row for row in queue["advisories"] if row["rule_id"] == "SKY-L038")
    task["baseline_report"] = report
    return plan_cleanup_edit(task, root)


@pytest.mark.parametrize("prefix", ["aaaaaaaaaaaa", "é" * 12, "界" * 6])
def test_fstring_rewrite_binds_the_selected_call_after_unicode(tmp_path, prefix):
    source = (
        f'def render(label, code):\n    return f"{prefix}{{str(label)}}{{int(code)}}"\n'
    )
    edit = _edit(tmp_path, source)
    assert edit["_replacement"] == (
        f'def render(label, code):\n    return f"{prefix}{{label!s}}{{int(code)}}"\n'
    )
    assert (tmp_path / "app.py").read_text() == source


@pytest.mark.parametrize("expression", ["str(label)", "(str(label))", "((str(label)))"])
def test_ordinary_formatting_is_still_supported(tmp_path, expression):
    source = f'def render(label):\n    return f"str(label)={{{expression}:>8}}"\n'
    edit = _edit(tmp_path, source)
    assert "label!s:>8" in edit["_replacement"]
    assert 'f"str(label)=' in edit["_replacement"]


@pytest.mark.parametrize(
    "field", ["str(label)=:>8", "str(label)=:", "str(label) = :>8", "(str(label))=:>8"]
)
def test_debug_fields_are_not_claimed_equivalent(tmp_path, field):
    source = f'def render(label):\n    return f"{{{field}}}"\n'
    assert _rows(tmp_path, source) == []


def test_ast_only_fields_do_not_guess_whether_debug_output_is_present(tmp_path):
    source = 'def render(label):\n    return f"{str(label)=:>8}"\n'
    assert _rows(tmp_path, source, with_source=False) == []


def test_many_fields_share_source_lines_without_reparsing_the_ast(
    tmp_path, monkeypatch
):
    class CountedSource(str):
        splits = 0

        def splitlines(self, *args, **kwargs):
            self.splits += 1
            return super().splitlines(*args, **kwargs)

    source = CountedSource(
        "\n".join(f'value_{index} = f"{{str(item)}}"' for index in range(300)) + "\n"
    )
    module = ast.parse(source)

    def no_reparse(*args, **kwargs):
        raise AssertionError("The source AST must be reused")

    monkeypatch.setattr(ast, "parse", no_reparse)
    findings = (
        FormattedConversionCallRule().visit_node(
            module,
            {
                "filename": str(tmp_path / "app.py"),
                "project_root": tmp_path,
                "source": source,
            },
        )
        or []
    )
    assert len(findings) == 300
    assert source.splits == 1


def test_changed_call_identity_is_checked_before_cst_rewrite(tmp_path):
    import skylos.cleanup_execution as execution

    source = 'def render(label, code):\n    return f"{str(label)}{int(code)}"\n'
    target = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
    )
    target.args[0].id = "another_label"
    # A direct exact-target mismatch must refuse, even when coordinates agree.
    with pytest.raises(ValueError):
        execution._l038_edit(source, {}, tmp_path, Path("app.py"), target)


def _pytest_command(root, *, relevant):
    body = (
        "from app import render\n\ndef test_render():\n    assert render('tag') == 'tag'\n"
        if relevant
        else "def test_other():\n    value = 4\n    assert value == 4\n"
    )
    (root / "test_local.py").write_text(body, encoding="utf-8")
    return shlex.join([sys.executable, "-m", "pytest", "-q", "test_local.py"])


@pytest.mark.parametrize("relevant", [False, True])
def test_replacement_verification_requires_observed_change_evidence(tmp_path, relevant):
    edit = _edit(tmp_path, 'def render(label):\n    return f"{str(label)}"\n')
    receipt = apply_cleanup_edit(
        edit,
        tmp_path,
        test_cmd=_pytest_command(tmp_path, relevant=relevant),
        rescan=lambda: _report(tmp_path),
    )
    assert receipt["tests"]["status"] == "passed"
    assert receipt["tests"]["observed"] is True
    assert receipt["tests"]["exercised_change"] is relevant
    assert receipt["rescan"]["status"] == "passed"
    assert receipt["status"] == ("verified" if relevant else "applied_unverified")
    if not relevant:
        assert any("exercise" in item.lower() for item in receipt["limitations"])
        assert receipt["applied"] is True and receipt["rolled_back"] is False


def test_custom_junit_without_replacement_coverage_remains_unverified(tmp_path):
    edit = _edit(tmp_path, 'def render(label):\n    return f"{str(label)}"\n')
    writer = tmp_path / "write_junit.py"
    writer.write_text(
        "from pathlib import Path\n"
        "Path('tests.xml').write_text('<testsuite><testcase name=\"other\"/></testsuite>')\n",
        encoding="utf-8",
    )
    receipt = apply_cleanup_edit(
        edit,
        tmp_path,
        test_cmd=shlex.join([sys.executable, str(writer)]),
        junit_xml="tests.xml",
        rescan=lambda: _report(tmp_path),
    )
    assert receipt["tests"]["observed"] is True
    assert receipt["tests"]["exercised_change"] is None
    assert receipt["status"] == "applied_unverified"


def test_deletion_only_verification_explains_its_coverage_limit(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("import math\nanswer = 42\n", encoding="utf-8")
    finding = {"name": "math", "file": str(path), "line": 1, "confidence": 100}
    report = _report(tmp_path, unused_imports=[finding])
    queue = build_cleanup_plan(report, project_root=tmp_path, top=None)
    task = next(row for row in queue["tasks"] if row["rule_id"] == "SKY-U002")
    task["baseline_report"] = deepcopy(report)
    (tmp_path / "test_local.py").write_text(
        "from app import answer\n\ndef test_answer():\n    assert answer == 42\n",
        encoding="utf-8",
    )
    receipt = apply_cleanup_edit(
        plan_cleanup_edit(task, tmp_path),
        tmp_path,
        test_cmd=shlex.join([sys.executable, "-m", "pytest", "-q", "test_local.py"]),
        rescan=lambda: _report(tmp_path),
    )
    assert receipt["status"] == "verified"
    assert receipt["tests"]["exercised_change"] is None
    assert any("delet" in item.lower() for item in receipt["limitations"])
