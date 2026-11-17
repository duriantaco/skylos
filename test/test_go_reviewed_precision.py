"""Go identity and bounded test-receiver facts distilled from source review."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.engines.go_runner import GoEngineError, run_go_engine_for_module
from skylos.visitors.languages.go import clear_go_cache
from skylos.visitors.languages.go.go import _scoped_go_context


def test_legacy_project_scope_keeps_package_namespaces_and_admission(tmp_path):
    first, second = tmp_path / "root.go", tmp_path / "child" / "api.go"
    second.parent.mkdir()
    first.write_text("package root\n")
    second.write_text("package child\n")
    scope = (str(tmp_path), (str(first), str(second)))
    root, files = _scoped_go_context(second, second.parent, scope, legacy_project=True)
    assert root == tmp_path
    assert set(files) == {str(first), str(second)}


def _scan(root):
    try:
        run_go_engine_for_module(root)
    except GoEngineError as exc:
        pytest.skip(f"requires source-built Go engine: {exc}")
    clear_go_cache()
    result = json.loads(
        analyze(
            str(root),
            conf=60,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return result


def test_legacy_subpackages_and_build_variants_preserve_every_definition(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    (tmp_path / "one.go").write_text(
        "//go:build !alternative\n\npackage demo\nfunc API(){helper()}\nfunc helper(){}\nfunc stale(){}\n"
    )
    (tmp_path / "two.go").write_text(
        "//go:build alternative\n\npackage demo\nfunc API(){helper()}\nfunc helper(){}\n"
    )
    (tmp_path / "other").mkdir()
    (tmp_path / "other/api.go").write_text(
        "package other\nfunc API(){helper()}\nfunc helper(){}\nfunc abandoned(){}\n"
    )
    result = _scan(tmp_path)
    definitions = list(result["definitions"].values())
    for file, line in [
        ("one.go", 4),
        ("one.go", 5),
        ("two.go", 4),
        ("two.go", 5),
        ("other/api.go", 2),
        ("other/api.go", 3),
    ]:
        assert any(
            Path(d["file"]).relative_to(tmp_path).as_posix() == file
            and d["line"] == line
            for d in definitions
        )
    assert {f["full_name"] for f in result.get("unused_functions", [])} == {
        "stale",
        "other.abandoned",
    }


def test_only_uninstantiated_private_test_receiver_methods_are_reported(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    (tmp_path / "api.go").write_text("package demo\nfunc API(){}\n")
    (tmp_path / "api_test.go").write_text(
        'package demo\nimport "testing"\ntype retired struct{}\nfunc(retired) Match(){}\ntype active struct{}\nfunc(active) Match(){}\nfunc TestUse(t *testing.T){active{}.Match()}\n'
    )
    result = _scan(tmp_path)
    assert {f["full_name"] for f in result.get("unused_functions", [])} == {
        "retired.Match"
    }
