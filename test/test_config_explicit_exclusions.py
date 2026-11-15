import json
import subprocess
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.commands.scan_cmd import _config_scope_options


@pytest.fixture
def task_repo(tmp_path, monkeypatch):
    engine = pytest.importorskip("ca9.api")
    from skylos.rules.sca import supply_chain

    monkeypatch.setattr(supply_chain, "load_ca9_api", lambda: engine)
    task = {
        "version": "2.0.0",
        "tasks": [
            {
                "label": "watch",
                "command": "node tools/watch.js",
                "runOptions": {"runOn": "folderOpen"},
            }
        ],
    }
    (tmp_path / "app.py").write_text("print('ready')\n")
    for folder in (".vscode", "benchmarks/fixture/.vscode"):
        path = tmp_path / folder / "tasks.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(task))
    for args in (("init", "-q"), ("add", "-A"), ("commit", "-qm", "fixture")):
        subprocess.run(
            ["git", "-c", "user.email=test@example.com", "-c", "user.name=test", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
    return tmp_path


def _tasks(root, **options):
    result = json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, **options)
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return {
        item["file"]
        for item in result.get("danger", [])
        if item["rule_id"] == "SKY-D366"
    }


def test_default_source_exclusions_keep_active_editor_config(task_repo):
    assert str(task_repo / ".vscode/tasks.json") in _tasks(
        task_repo,
        exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
        config_exclude_folders=[],
    )


def test_explicit_config_exclusions_still_apply(task_repo):
    assert not _tasks(
        task_repo,
        exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
        config_exclude_folders=[".vscode"],
    )


def test_excluded_fixtures_do_not_hide_active_editor_config(task_repo):
    assert _tasks(
        task_repo,
        exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS | {"benchmarks"}),
        config_exclude_folders=["benchmarks"],
    ) == {str(task_repo / ".vscode/tasks.json")}


def test_direct_api_exclusions_remain_explicit(task_repo):
    assert not _tasks(task_repo, exclude_folders=[".vscode"])


def test_cli_config_scope_keeps_default_dependency_exclusions():
    folders = set(
        _config_scope_options(SimpleNamespace(), {})["config_exclude_folders"]
    )
    assert folders == DEFAULT_EXCLUDE_FOLDERS - {".vscode"}


def test_cli_config_scope_honours_explicit_editor_exclusion():
    folders = _config_scope_options(SimpleNamespace(exclude_folders=[".vscode"]), {})
    assert ".vscode" in folders["config_exclude_folders"]


def test_cli_config_scope_can_disable_defaults():
    folders = _config_scope_options(SimpleNamespace(no_default_excludes=True), {})
    assert folders["config_exclude_folders"] == []
