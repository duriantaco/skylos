"""Behavioral checks for incremental report builds; fixture code is only parsed."""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from uml import cache, runner


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-c", f"core.hooksPath={os.devnull}", "-c", "user.name=UML Test", "-c", "user.email=uml@example.invalid", *args], cwd=root, env=env, text=True, capture_output=True, check=True).stdout.strip()


def write(root, path, text):
    location = root / path
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_text(text)
    return location


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    write(root, ".gitignore", "/UML/\n")
    write(root, "skylos/__init__.py", "")
    write(root, "skylos/helper.py", "RATE = 1\n\ndef adjust(value):\n    return value + RATE\n\ndef untouched(value):\n    return value * 2\n")
    write(root, "skylos/app.py", "from skylos.helper import adjust\n\ndef main():\n    return adjust(2)\n")
    write(root, "test/test_flow.py", "from skylos.app import main\n\ndef test_flow():\n    assert main() == 3\n")
    git(root, "init", "-q")
    git(root, "add", ".gitignore", "skylos", "test")
    git(root, "commit", "-qm", "fixture baseline")
    return root


def build(root, **kwargs):
    return runner.build_report(root, root / "UML", **kwargs)


def data(root):
    return json.loads(gzip.decompress((root / "UML/call-map.json.gz").read_bytes()))


def detail(document, path, name):
    return next(document["details"][i] for i, node in enumerate(document["nodes"]) if document["files"][node[1]] == path and node[0] == name)


def test_unchanged_run_does_no_analysis_or_report_write(repository, monkeypatch):
    first = build(repository)
    assert first["function_facts_analyzed"] == 3
    index = repository / "UML/index.html"
    before = index.stat().st_mtime_ns
    monkeypatch.setattr(runner, "native_graph", lambda *args, **kwargs: pytest.fail("native graph must not run on a full cache hit"))
    second = build(repository)
    assert second["cache_hit"] is True
    assert second["function_facts_analyzed"] == second["python_files_parsed"] == 0
    assert second["test_roots_analyzed"] == 0
    assert index.stat().st_mtime_ns == before


def test_edit_reanalyzes_one_function_and_reuses_its_sibling(repository):
    build(repository)
    path = repository / "skylos/helper.py"
    path.write_text(path.read_text().replace("return value + RATE", "return value + RATE + 1"))
    update = build(repository)
    assert update["changed_files"] == ["skylos/helper.py"]
    assert update["native_files_parsed"] == update["relation_files_analyzed"] == 1
    assert update["function_facts_analyzed"] == 1
    assert update["function_facts_reused"] == 2
    assert "return value + RATE + 1" in data(repository)["source"][data(repository)["files"].index("skylos/helper.py")]


def test_same_size_edit_with_restored_mtime_is_detected(repository):
    build(repository)
    path = repository / "skylos/helper.py"
    prior = path.stat()
    path.write_text(path.read_text().replace("value + RATE", "value - RATE"))
    os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
    update = build(repository)
    assert update["native_files_parsed"] == update["function_facts_analyzed"] == 1
    assert update["changed_files"] == ["skylos/helper.py"]


def test_constant_change_invalidates_only_readers_and_dependent_notes(repository):
    write(repository, "UML/curation.json", json.dumps({"skylos.app.main": {"summary": "Returns the adjusted result."}}))
    build(repository)
    path = repository / "skylos/helper.py"
    path.write_text(path.read_text().replace("RATE = 1", "RATE = 2"))
    update = build(repository)
    assert update["function_facts_analyzed"] == 1
    assert update["function_facts_reused"] == 2
    assert detail(data(repository), "skylos/app.py", "main")["descriptionNeedsRefresh"] is True


def test_changed_call_refreshes_test_links_and_caller_context(repository):
    write(repository, "UML/curation.json", json.dumps({"skylos.app.main": {"summary": "Returns the adjusted result."}}))
    build(repository)
    path = repository / "skylos/helper.py"
    path.write_text(path.read_text().replace("return value + RATE", "return untouched(value)"))
    update = build(repository)
    assert update["function_facts_analyzed"] == 1
    assert update["test_roots_analyzed"] == 1
    assert update["affected_callers"] >= 1
    document = data(repository)
    assert detail(document, "skylos/app.py", "main")["descriptionNeedsRefresh"] is True
    assert detail(document, "skylos/helper.py", "untouched")["tests"]


def test_line_only_edits_rebase_source_facts_without_reanalysis(repository):
    path = repository / "skylos/helper.py"
    path.write_text(path.read_text().replace("    return value + RATE", "    if value:\n        return value + RATE\n    return 0"))
    build(repository)
    before = detail(data(repository), "skylos/helper.py", "adjust")["conditions"][0][0]
    path.write_text("\n\n" + path.read_text())
    update = build(repository)
    assert update.get("function_facts_analyzed", 0) == 0
    assert update["function_facts_reused"] == 3
    assert detail(data(repository), "skylos/helper.py", "adjust")["conditions"][0][0] == before + 2


def test_added_renamed_and_deleted_files_do_not_leave_stale_symbols(repository):
    build(repository)
    extra = write(repository, "skylos/extra.py", "def extra():\n    return 7\n")
    added = build(repository)
    assert added["native_files_parsed"] == 1
    assert "skylos/extra.py" in data(repository)["files"]
    renamed = extra.with_name("renamed.py")
    extra.rename(renamed)
    moved = build(repository)
    assert moved["native_files_parsed"] == 1
    assert moved["removed_files"] == ["skylos/extra.py"]
    assert "skylos/extra.py" not in data(repository)["files"]
    renamed.unlink()
    removed = build(repository)
    assert removed["removed_files"] == ["skylos/renamed.py"]
    assert removed.get("native_files_parsed", 0) == 0
    assert "skylos/renamed.py" not in data(repository)["files"]


def test_restored_ci_cache_reuses_identical_content_with_new_checkout_times(repository, tmp_path):
    build(repository)
    fresh = tmp_path / "fresh"
    shutil.copytree(repository, fresh)
    for path in fresh.rglob("*.py"):
        previous = path.stat()
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000_000))
    changed = fresh / "skylos/helper.py"
    changed.write_text(changed.read_text().replace("value + RATE", "value - RATE"))
    update = build(fresh)
    assert update["native_files_parsed"] == 1
    assert update["native_files_reused"] >= 3
    assert update["function_facts_analyzed"] == 1
    assert update["function_facts_reused"] == 2


def test_ui_only_changes_reuse_all_analysis(repository, tmp_path, monkeypatch):
    assets = tmp_path / "assets"
    shutil.copytree(runner.ASSETS, assets)
    monkeypatch.setattr(runner, "ASSETS", assets)
    build(repository)
    css = assets / "viewer.css"
    css.write_text(css.read_text() + "\n/* report theme updated */\n")
    update = build(repository)
    assert update["report_written"] is True
    assert update.get("function_facts_analyzed", 0) == 0
    assert update.get("python_files_parsed", 0) == 0
    assert "report theme updated" in (repository / "UML/index.html").read_text()


def test_damaged_file_cache_is_rebuilt_for_the_edited_file(repository):
    build(repository)
    cached = repository / "UML/.cache/files" / (cache.digest("skylos/helper.py")[:24] + ".json.gz")
    cached.write_bytes(b"invalid cache")
    path = repository / "skylos/helper.py"
    path.write_text(path.read_text().replace("value + RATE", "value - RATE"))
    update = build(repository)
    assert update["native_files_parsed"] == 1
    assert update["function_facts_analyzed"] == 2


def test_ci_uses_selected_base_and_does_not_read_personal_notes(repository):
    baseline = git(repository, "rev-parse", "HEAD")
    path = repository / "skylos/helper.py"
    path.write_text(path.read_text().replace("value + RATE", "value - RATE"))
    git(repository, "add", "skylos/helper.py")
    git(repository, "commit", "-qm", "fixture change")
    write(repository, "UML/curation.json", json.dumps({"skylos.app.main": {"summary": "PRIVATE NOTE MUST STAY LOCAL"}}))
    write(repository, "skylos/runner_generated.py", "def generated():\n    return 4\n")
    stats = build(repository, base=baseline, ci=True)
    report = data(repository)
    assert report["reviewMeta"]["baseCommit"] == baseline
    assert report["reviewMeta"]["changedFunctions"] == 1
    assert stats["native_files_parsed"] == 1
    assert report["files"] == ["skylos/helper.py"]
    assert report["overview"]["files"] == [{"path": "skylos/helper.py", "status": "M", "previous": None}]
    (change,) = report["overview"]["symbols"]
    assert change["name"] == "adjust"
    assert "Changes the returned value from value plus RATE to value minus RATE." in change["explanation"]
    assert "Used by main." in change["explanation"]
    assert "PRIVATE NOTE MUST STAY LOCAL" not in json.dumps(report)


def test_ci_workflow_change_uses_only_the_changed_workflow(repository):
    workflow = write(repository, ".github/workflows/example.yml", "jobs:\n  scan:\n    steps:\n      - name: Scan\n        run: python scripts/run.py\n")
    write(repository, "scripts/run.py", "def main():\n    return 0\n")
    git(repository, "add", ".github/workflows/example.yml", "scripts/run.py")
    git(repository, "commit", "-qm", "add workflow")
    workflow.write_text(workflow.read_text() + "      - name: Upload report\n        run: python scripts/run.py\n")
    git(repository, "add", ".github/workflows/example.yml")
    git(repository, "commit", "-qm", "add step")

    stats = build(repository, base="HEAD^", ci=True)
    report = data(repository)
    assert not stats.get("native_files_parsed")
    assert report["files"] == [".github/workflows/example.yml"]
    assert report["overview"]["workflows"] == [{
        "file": ".github/workflows/example.yml",
        "explanation": ["Adds the Upload report step to scan."],
    }]


def test_ci_reports_removal_and_rename_with_no_live_nodes(repository):
    write(repository, "guide.md", "Reading guide\n")
    git(repository, "add", "guide.md")
    git(repository, "commit", "-qm", "add guide")
    git(repository, "mv", "guide.md", "review guide.md")
    git(repository, "rm", "skylos/app.py")
    git(repository, "commit", "-qm", "rename guide and remove app")

    build(repository, base="HEAD^", ci=True)
    report = data(repository)
    assert report["nodes"] == []
    assert report["overview"]["files"] == [
        {"path": "review guide.md", "status": "R", "previous": "guide.md"},
        {"path": "skylos/app.py", "status": "D", "previous": None},
    ]
    (change,) = report["overview"]["symbols"]
    assert change["name"] == "main" and change["status"] == "deleted"
    assert change["inUml"] is False


def test_missing_ci_predecessor_is_an_explicit_initial_snapshot(repository):
    stats = build(repository, base="a" * 40, ci=True)
    assert data(repository)["reviewMeta"]["available"] is False
    assert "Initial snapshot" in data(repository)["reviewMeta"]["scope"]
    assert not stats.get("native_files_parsed")
    assert data(repository)["nodes"] == []


def test_workflow_script_startup_resolves_its_local_import(repository):
    write(repository, "scripts/helper.py", "def main():\n    return 0\n")
    write(repository, "scripts/run.py", "from helper import main\n\nif __name__ == '__main__':\n    raise SystemExit(main())\n")
    write(repository, ".github/workflows/example.yml", "jobs:\n  report:\n    steps:\n      - run: python scripts/run.py\n")
    build(repository)
    report = data(repository)
    lookup = {(report["files"][n[1]], n[0]): i for i, n in enumerate(report["nodes"])}
    script = lookup["scripts/run.py", "run.py"]
    target = lookup["scripts/helper.py", "main"]
    starts = report["linkKinds"].index("starts")
    assert [script, target, starts] in report["edges"]


def test_workflow_only_edit_updates_input_counts_without_reparsing_sources(repository):
    write(repository, "scripts/run.py", "def main():\n    return 0\n\nif __name__ == '__main__':\n    main()\n")
    workflow = write(repository, ".github/workflows/example.yml", "name: Original\njobs:\n  report:\n    steps:\n      - run: python scripts/run.py\n")
    build(repository)
    workflow.write_text(workflow.read_text().replace("Original", "Updated"))
    update = build(repository)
    assert update["changed_files"] == [".github/workflows/example.yml"]
    assert update.get("native_files_parsed", 0) == 0
    assert update.get("python_files_parsed", 0) == 0
    report = data(repository)
    assert "name: Updated" in report["source"][report["files"].index(".github/workflows/example.yml")]


def test_skylos_workflow_builds_and_links_a_read_only_uml_diff():
    workflow = yaml.safe_load((SCRIPTS.parent / ".github/workflows/skylos.yaml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request", "push", "workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    steps = workflow["jobs"]["scan"]["steps"]
    for step in steps:
        if "uses" in step:
            assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    builder = next(step for step in steps if step.get("id") == "uml")
    assert builder["env"]["DIFF_BASE"] == "${{ steps.diff.outputs.base }}"
    assert builder["continue-on-error"] is True
    assert "!cancelled()" in builder["if"] and "steps.scan.outcome == 'success'" in builder["if"]
    assert '--ci --base "$DIFF_BASE"' in builder["run"]
    assert 'git archive "$DIFF_BASE" -- scripts/build_uml.py scripts/uml' in builder["run"]
    assert 'python -I "$TOOL"' in builder["run"]
    assert "${{" not in builder["run"] and "secrets." not in str(builder)
    upload = next(step for step in steps if step.get("id") == "uml_artifact")
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert "steps.uml.outputs.ready == 'true'" in upload["if"]
    assert upload["with"]["path"].splitlines() == [
        "${{ runner.temp }}/skylos-uml/index.html",
        "${{ runner.temp }}/skylos-uml/update-stats.json",
    ]
    link = next(step for step in steps if step.get("name") == "Link the UML report in the run summary")
    assert link["env"]["ARTIFACT_URL"] == "${{ steps.uml_artifact.outputs.artifact-url }}"
    assert '>> "$GITHUB_STEP_SUMMARY"' in link["run"]
