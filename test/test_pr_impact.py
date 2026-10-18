"""A removed caller must remain visible even when definition lines are unchanged."""

import json
import subprocess
import sys

import pytest

import skylos.cli as cli
from skylos.core.pr_impact import annotate_dead_code_impact


def git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Skylos Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.strip()


def baseline(root, source, *, path="app.py"):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)  # skylos: ignore[SKY-D324] all callers use fresh pytest tmp_path roots and fixed paths
    git(root, "init", "-q")
    git(root, "add", path)
    git(root, "commit", "-q", "-m", "Static baseline")
    return target


def scan(monkeypatch, capsys, root, *args):
    monkeypatch.chdir(root)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.setattr("skylos.cloud.sync.load_custom_rules", lambda: {
        "rules": [], "status": "not_connected", "reason": "no_token",
    })
    monkeypatch.setattr(sys, "argv", [
        "skylos", str(root), "--format", "json", "--no-upload",
        "--no-provenance", "--no-grep-verify", *args,
    ])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def test_removed_caller_is_introduced_outside_changed_lines(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, "def legacy():\n    return 7\n\ndef already_dead():\n    return 8\n\nlegacy()\n")
    source.write_text("def legacy():\n    return 7\n\ndef already_dead():\n    return 8\n\nprint('done')\n")
    code, lines = scan(monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--strict")
    assert code == 0
    assert not lines["unused_functions"]
    code, impact = scan(monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact", "--strict")
    assert code == 1
    assert [item["name"] for item in impact["unused_functions"]] == ["legacy"]
    assert impact["unused_functions"][0]["report_scope"] == "dependency_impact"
    assert impact["unused_functions"][0]["change_status"] == "introduced"
    assert impact["analysis_summary"]["pr_impact"]["status"] == "complete"


def test_line_shift_does_not_reintroduce_existing_dead_code(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, "def existing_dead():\n    return 1\n\nprint('base')\n")
    source.write_text("# unrelated header\n\n" + source.read_text())
    code, report = scan(monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact", "--strict")
    assert code == 0
    assert not report["unused_functions"]
    assert report["analysis_summary"]["pr_impact"]["introduced_count"] == 0


def test_incomplete_base_blocks_instead_of_claiming_all_findings_new(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, "def broken(\n")
    source.write_text("def new_dead():\n    return 1\n")
    code, report = scan(monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact")
    assert code == 2
    assert report["analysis_summary"]["pr_impact"]["reason"] == "base_analysis_incomplete"
    assert any(item["kind"] == "pr_impact_incomplete" for item in report["analysis_errors"])
    assert all("change_status" not in item for item in report["unused_functions"])


def test_incomplete_head_caller_does_not_claim_dependency_impact(tmp_path, monkeypatch, capsys):
    baseline(tmp_path, "def helper():\n    return 1\n")
    caller = tmp_path / "caller.py"
    caller.write_text("from app import helper\nhelper()\n")
    git(tmp_path, "add", "caller.py")
    git(tmp_path, "commit", "-q", "-m", "Live caller")
    caller.write_text("from app import helper\nhelper(\n")

    code, report = scan(
        monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact",
    )

    assert code == 2
    assert report["analysis_summary"]["pr_impact"]["status"] == "incomplete"
    assert report["analysis_summary"]["pr_impact"]["reason"] == "head_analysis_incomplete"
    assert all("change_status" not in item for item in report["unused_functions"])


def test_subdirectory_qualified_identity_is_stable(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, "def legacy():\n    return 7\n\nlegacy()\n", path="service/app.py")
    source.write_text("def legacy():\n    return 7\n\nprint('done')\n")
    code, report = scan(monkeypatch, capsys, tmp_path / "service", "--diff", "HEAD", "--diff-mode", "impact", "--strict")
    assert code == 1
    assert [item["name"] for item in report["unused_functions"]] == ["legacy"]
    assert report["analysis_summary"]["pr_impact"]["status"] == "complete"


def test_explicit_operator_config_applies_to_baseline_file_processing(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repository"
    root.mkdir()
    source = baseline(root, "def existing_dead():\n    return 1\n\nprint('base')\n")
    (root / "pyproject.toml").write_text(
        '[tool.skylos]\nwhitelist = ["existing_dead"]\n'
    )
    git(root, "add", "pyproject.toml")
    git(root, "commit", "-q", "-m", "Repository policy")
    operator_config = tmp_path / "operator.toml"
    operator_config.write_text("[tool.skylos]\n")
    source.write_text(source.read_text() + "# unrelated comment\n")

    code, report = scan(
        monkeypatch, capsys, root, "--diff", "HEAD", "--diff-mode", "impact",
        "--strict", "--config-file", str(operator_config),
    )

    assert code == 0
    assert not report["unused_functions"]
    assert report["analysis_summary"]["pr_impact"]["status"] == "complete"
    assert report["analysis_summary"]["pr_impact"]["introduced_count"] == 0


def test_nongated_impact_uses_the_same_base_policy_for_head_and_baseline(tmp_path, monkeypatch, capsys):
    baseline(tmp_path, "def existing_dead():\n    return 1\n\nprint('base')\n")
    policy = tmp_path / "pyproject.toml"
    policy.write_text('[tool.skylos]\nwhitelist = ["existing_dead"]\n')
    git(tmp_path, "add", "pyproject.toml")
    git(tmp_path, "commit", "-q", "-m", "Base whitelist")
    policy.write_text('[tool.skylos]\nwhitelist = []\n')

    code, report = scan(
        monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact",
        "--strict",
    )

    assert code == 0
    assert not report["unused_functions"]
    assert report["analysis_summary"]["pr_impact"]["status"] == "complete"
    assert report["analysis_summary"]["pr_impact"]["introduced_count"] == 0


def test_csharp_application_scope_and_metadata_preserve_existing_dead_class(tmp_path, monkeypatch, capsys):
    source = baseline(
        tmp_path,
        "namespace Demo;\n"
        "internal static class Program { static void Main() {} }\n"
        "public static class Dead { public static int Unused() { return 1; } }\n",
        path="Program.cs",
    )
    (tmp_path / "app.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<OutputType>Exe</OutputType></PropertyGroup></Project>"
    )
    git(tmp_path, "add", "app.csproj")
    git(tmp_path, "commit", "-q", "-m", "Application metadata")
    source.write_text(source.read_text() + "// unrelated comment\n")

    _, full = scan(monkeypatch, capsys, tmp_path)
    assert "Dead" in {item["name"] for item in full["unused_classes"]}
    code, report = scan(
        monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact",
        "--strict",
    )

    assert code == 0
    assert not report["unused_classes"]
    assert report["analysis_summary"]["pr_impact"]["introduced_count"] == 0


def test_removed_html_handler_is_introduced_outside_javascript_lines(tmp_path, monkeypatch, capsys):
    baseline(tmp_path, "function browserHandler() { return 1; }\n", path="app.js")
    template = tmp_path / "index.html"
    template.write_text('<button onclick="browserHandler()">Go</button>\n')
    git(tmp_path, "add", "index.html")
    git(tmp_path, "commit", "-q", "-m", "Template caller")
    template.write_text("<button>Go</button>\n")

    code, report = scan(
        monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact",
        "--strict", "--confidence", "0",
    )

    assert code == 1, report.get("analysis_summary", {}).get("pr_impact")
    handler = next(item for item in report["unused_functions"] if item["name"] == "browserHandler")
    assert handler["change_status"] == "introduced"
    assert handler["report_scope"] == "dependency_impact"
    assert report["analysis_summary"]["pr_impact"]["status"] == "complete"


def test_unnamed_existing_unused_javascript_file_has_stable_identity(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, "function existingDead() { return 1; }\n", path="legacy.js")
    source.write_text(source.read_text() + "// unrelated comment\n")

    code, report = scan(
        monkeypatch, capsys, tmp_path, "--diff", "HEAD", "--diff-mode", "impact",
        "--strict", "--confidence", "0",
    )

    assert code == 0
    assert not report["unused_files"]
    assert not report["unused_functions"]
    assert report["analysis_summary"]["pr_impact"]["status"] == "complete"
    assert report["analysis_summary"]["pr_impact"]["introduced_count"] == 0


def test_new_scan_directory_has_an_empty_baseline(tmp_path, monkeypatch, capsys):
    baseline(tmp_path, "print('existing')\n")
    root = tmp_path / "new_service"
    root.mkdir()
    (root / "app.py").write_text("def new_dead():\n    return 1\n")

    code, report = scan(
        monkeypatch, capsys, root, "--diff", "HEAD", "--diff-mode", "impact",
        "--strict",
    )

    assert code == 1
    assert [item["name"] for item in report["unused_functions"]] == ["new_dead"]
    assert report["unused_functions"][0]["change_status"] == "introduced"
    assert report["analysis_summary"]["pr_impact"]["status"] == "complete"


def test_baseline_retains_arbitrary_liveness_inputs_and_supported_source_suffixes(tmp_path):
    from skylos.analyzer import ANALYZED_SOURCE_SUFFIXES
    from skylos.core.git_context import GitContext
    from skylos.core.pr_impact import _snapshot_entries

    baseline(tmp_path, "print('existing')\n")
    names = [
        "view.custom-template", "README", "app.csproj", "view.fxml", "page.mdx",
        "go.mod", "module.pyw", "app.cxx", "app.hxx", "app.zsh", "data.bin",
    ]
    for name in names:
        (tmp_path / name).write_bytes(b"bounded raw fixture\n")
    git(tmp_path, "add", "--", *names)
    git(tmp_path, "commit", "-q", "-m", "Liveness inputs")
    commit = git(tmp_path, "rev-parse", "HEAD")

    snapshot = _snapshot_entries(
        GitContext.from_path(tmp_path), commit, ANALYZED_SOURCE_SUFFIXES
    )

    assert {name for name, _, _ in snapshot.files} == {"app.py", *names}
    assert not snapshot.omitted


def test_oversized_non_source_blob_is_left_out_of_the_baseline(tmp_path, monkeypatch):
    # A large binary defines nothing: leaving it out only removes references
    # from the baseline, which can hide a newly unused finding, never invent one.
    baseline(tmp_path, "print('existing')\n")
    (tmp_path / "asset.bin").write_bytes(b"a" * 129)
    git(tmp_path, "add", "asset.bin")
    git(tmp_path, "commit", "-q", "-m", "Large artifact")
    monkeypatch.setattr("skylos.core.pr_impact.MAX_BLOB_BYTES", 128)
    report = {}

    receipt = annotate_dead_code_impact(
        report, str(tmp_path), project_root=tmp_path, base_ref="HEAD",
        config={}, grep_verify=False,
    )

    assert receipt["status"] == "complete"
    assert receipt["omitted"] == {"oversize_non_source": 1}
    assert not report.get("analysis_errors")


def test_symlinked_base_source_is_recreated_in_the_baseline(tmp_path):
    # Source discovery never reads a symlinked file in either tree, so the
    # same link in the baseline keeps the two scans alike.
    target = baseline(tmp_path, "print('ok')\n")
    (tmp_path / "linked.py").symlink_to(target.name)
    git(tmp_path, "add", "linked.py")
    git(tmp_path, "commit", "-q", "-m", "Source link")
    report = {}
    receipt = annotate_dead_code_impact(report, str(tmp_path), project_root=tmp_path,
                                       base_ref="HEAD", config={}, grep_verify=False)
    assert receipt["status"] == "complete"
    assert "omitted" not in receipt
    assert receipt["snapshot_file_count"] == 2


def test_snapshot_reads_raw_blobs_without_filters_or_target_execution(tmp_path):
    baseline(tmp_path, "def unused():\n    return 1\n\nraise RuntimeError('DO_NOT_EXECUTE_TARGET')\n")
    marker = tmp_path / "filter-executed"
    (tmp_path / ".gitattributes").write_text("*.py filter=untrusted\n")
    git(tmp_path, "add", ".gitattributes")
    git(tmp_path, "commit", "-q", "-m", "Source filter selection")
    git(tmp_path, "config", "filter.untrusted.smudge", f"touch {marker}")
    git(tmp_path, "config", "filter.untrusted.clean", f"touch {marker}")
    report = {"unused_functions": [{"file": str(tmp_path / "app.py"), "full_name": "app.unused", "type": "function"}]}
    receipt = annotate_dead_code_impact(report, str(tmp_path), project_root=tmp_path,
                                       base_ref="HEAD", config={}, grep_verify=False)
    assert receipt["status"] == "complete"
    assert receipt["introduced_count"] == 0
    assert not marker.exists()


@pytest.mark.parametrize("extra", [[], ["--diff", "HEAD", "--diff-base", "HEAD"]])
def test_impact_rejects_missing_diff_or_partial_head(tmp_path, monkeypatch, capsys, extra):
    baseline(tmp_path, "print('ok')\n")
    monkeypatch.setattr(sys, "argv", ["skylos", str(tmp_path), "--diff-mode", "impact", *extra])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
