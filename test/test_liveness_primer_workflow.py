import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from skylos.rules.config.cicd.github_actions import scan_github_actions_file

WORKFLOW_PATH = Path(".github/workflows/liveness-primer.yml")


def _workflow():
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _comparison_step(workflow):
    return next(
        step
        for step in workflow["jobs"]["blast-radius"]["steps"]
        if step.get("name") == "Compare base with the pull request merge result"
    )


def test_liveness_primer_workflow_covers_all_prs_read_only_and_advisory():
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))

    assert set(triggers) == {"pull_request"}
    pull_request = triggers["pull_request"]
    assert pull_request["types"] == [
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
    ]
    # Docs-only, packaging, tests, and fork PRs all need the same check.
    assert set(pull_request) == {"types"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "liveness-primer-${{ github.event.pull_request.number }}",
        "cancel-in-progress": True,
    }

    job = workflow["jobs"]["blast-radius"]
    assert job["name"] == "Skylos analyzer blast radius"
    assert "if" not in job  # Draft PRs get evidence too.
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 45

    comparison = _comparison_step(workflow)
    assert "--all" in comparison["run"]
    assert "--fail-on" not in comparison["run"]
    assert "continue-on-error" not in comparison
    assert "continue-on-error" not in job


def test_liveness_primer_workflow_pins_actions_and_toolchain():
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]
    action_steps = [step for step in steps if "uses" in step]

    assert {step["uses"] for step in action_steps} == {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
    }
    for step in action_steps:
        action_ref = step["uses"].split("@", 1)[1]
        assert len(action_ref) == 40
        assert all(character in "0123456789abcdef" for character in action_ref)

    assert workflow["env"] == {
        "LIVENESS_PRIMER_REF": "1438a928dd00cbb3b1098a9edc82480f43daabdb"
    }

    trusted_checkout = next(
        step for step in steps if step.get("name") == "Check out trusted Skylos base"
    )
    assert trusted_checkout["with"] == {
        "ref": "${{ github.event.pull_request.base.sha }}",
        "path": "_trusted_skylos",
        "persist-credentials": False,
    }

    primer_checkout = next(
        step for step in steps if step.get("name") == "Check out pinned liveness_primer"
    )
    assert primer_checkout["with"] == {
        "repository": "mcdigman/liveness_primer",
        "ref": "${{ env.LIVENESS_PRIMER_REF }}",
        "path": "_liveness_primer",
        "persist-credentials": False,
    }

    setup_go = next(step for step in steps if step.get("name") == "Install Go")
    assert setup_go["with"] == {"go-version": "1.22", "cache": False}

    setup_uv = next(step for step in steps if step.get("name") == "Install uv")
    assert setup_uv["with"] == {
        "version": "0.12.5",
        "python-version": "3.13",
        "enable-cache": False,
    }


def test_liveness_primer_workflow_builds_trusted_base_go_engine():
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]
    build = next(
        step for step in steps if step.get("name") == "Build trusted base Go engine"
    )

    assert build["env"] == {
        "TRUSTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}"
    }
    assert build["shell"] == "bash"
    script = build["run"]
    assert '[[ ! "$TRUSTED_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]' in script
    assert "git -C _trusted_skylos rev-parse HEAD" in script
    assert '[[ "$trusted_checkout_sha" != "$TRUSTED_BASE_SHA" ]]' in script
    assert "cd _trusted_skylos/skylos/engines/go" in script
    assert 'go build -trimpath -o "$engine_dir/skylos-go" ./cmd/skylos-go' in script
    assert 'engine_dir="$RUNNER_TEMP/skylos-go-engine"' in script
    assert '"$engine_dir/skylos-go" --version' in script
    # The comparison step must hand skylos the engine this step built.
    comparison = _comparison_step(workflow)
    assert comparison["env"]["SKYLOS_GO_BIN"] == (
        "${{ format('{0}/skylos-go-engine/skylos-go', runner.temp) }}"
    )


def test_liveness_primer_workflow_discloses_go_engine_coverage_boundary():
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]
    boundary = next(
        step
        for step in steps
        if step.get("name") == "Record Go engine coverage boundary"
    )

    assert boundary["env"] == {
        "TRUSTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}"
    }
    assert boundary["shell"] == "bash"
    script = boundary["run"]
    assert '[[ ! "$TRUSTED_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]' in script
    assert '>> "$GITHUB_STEP_SUMMARY"' in script
    assert "uses the Go engine built from base commit" in script
    assert "Changes under \\`skylos/engines/go/\\` are outside" in script
    assert "::notice title=Go engine coverage boundary::" in script


def test_liveness_primer_workflow_uses_locked_comparison_contract():
    workflow = _workflow()
    comparison = _comparison_step(workflow)
    assert comparison["env"] == {
        "SKYLOS_REPOSITORY": "${{ github.server_url }}/${{ github.repository }}",
        "SKYLOS_GO_BIN": (
            "${{ format('{0}/skylos-go-engine/skylos-go', runner.temp) }}"
        ),
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "MERGE_SHA": "${{ github.sha }}",
        "REPORT_JSON": "liveness-primer-report.json",
        "REPORT_MARKDOWN": "liveness-primer-report.md",
    }
    script = comparison["run"]
    assert "${{" not in script
    assert '[[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]' in script
    assert "uv run --project _liveness_primer --locked liveness-primer run" in script
    assert "--tool skylos" in script
    assert '--repo "$SKYLOS_REPOSITORY"' in script
    assert '--old "$BASE_SHA"' in script
    assert '--new "$MERGE_SHA"' in script
    assert "--container" in script
    assert "--output github" in script
    assert '--json-out "$REPORT_JSON"' in script
    assert "--jobs 2" in script
    assert "--timeout 300" in script
    assert "set -euo pipefail" in script
    assert '| tee "$REPORT_MARKDOWN" >> "$GITHUB_STEP_SUMMARY"' in script
    assert 'test -s "$REPORT_JSON"' in script


def test_liveness_primer_workflow_preserves_evidence_without_write_access():
    workflow_source = WORKFLOW_PATH.read_text(encoding="utf-8")
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]

    artifact = next(
        step for step in steps if step.get("name") == "Upload blast-radius evidence"
    )
    assert artifact["if"] == "always()"
    assert artifact["with"]["name"] == "liveness-primer-report"
    assert artifact["with"]["if-no-files-found"] == "error"
    assert artifact["with"]["retention-days"] == 14
    assert set(artifact["with"]["path"].splitlines()) == {
        "liveness-primer-report.md",
        "liveness-primer-report.json",
    }

    assert "pull_request_target" not in workflow_source
    assert "secrets." not in workflow_source
    assert "pull-requests: write" not in workflow_source
    assert "gh pr comment" not in workflow_source
    assert scan_github_actions_file(WORKFLOW_PATH, root=".") == []


def _run_comparison(
    tmp_path,
    *,
    exit_code=0,
    report_state="present",
    base_sha="a" * 40,
    merge_sha="b" * 40,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow shell checks require bash")

    # A shell function intercepts uv in the real workflow command. No primer,
    # detector revisions, network requests, or corpus code are executed, and
    # no executable fixture needs to be created on disk.
    stub = """uv() {
  "$PRIMER_STUB_PYTHON" - "$@" <<'PY'
import json, os, sys
with open('invocation.json', 'x', encoding='utf-8') as out:
    json.dump(sys.argv[1:], out)
if os.environ['PRIMER_STUB_REPORT'] != 'missing':
    with open(os.environ['REPORT_JSON'], 'x', encoding='utf-8') as out:
        if os.environ['PRIMER_STUB_REPORT'] == 'present':
            json.dump({'fixture': 'offline workflow test'}, out)
print('# Offline primer report')
sys.exit(int(os.environ['PRIMER_STUB_EXIT']))
PY
}
"""
    env = {
        "PATH": os.defpath,
        "SKYLOS_REPOSITORY": "https://github.com/duriantaco/skylos",
        "BASE_SHA": base_sha,
        "MERGE_SHA": merge_sha,
        # Spaces exercise quoting of the report destinations.
        "REPORT_JSON": str(tmp_path / "report data.json"),
        "REPORT_MARKDOWN": str(tmp_path / "report summary.md"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "step summary.md"),
        "PRIMER_STUB_EXIT": str(exit_code),
        "PRIMER_STUB_REPORT": report_state,
        "PRIMER_STUB_PYTHON": sys.executable,
    }
    return subprocess.run(
        [bash, "-c", stub + _comparison_step(_workflow())["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_comparison_shell_passes_exact_revisions_and_keeps_both_reports(tmp_path):
    result = _run_comparison(tmp_path)

    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / "invocation.json").read_text()) == [
        "run",
        "--project",
        "_liveness_primer",
        "--locked",
        "liveness-primer",
        "run",
        "--tool",
        "skylos",
        "--repo",
        "https://github.com/duriantaco/skylos",
        "--old",
        "a" * 40,
        "--new",
        "b" * 40,
        "--all",
        "--container",
        "--output",
        "github",
        "--json-out",
        str(tmp_path / "report data.json"),
        "--jobs",
        "2",
        "--timeout",
        "300",
    ]
    assert json.loads((tmp_path / "report data.json").read_text()) == {
        "fixture": "offline workflow test"
    }
    assert (tmp_path / "report summary.md").read_text() == "# Offline primer report\n"
    assert (tmp_path / "step summary.md").read_text() == "# Offline primer report\n"


@pytest.mark.parametrize("exit_code", [1, 2, 3])
def test_comparison_shell_does_not_hide_primer_failure_behind_tee(tmp_path, exit_code):
    result = _run_comparison(tmp_path, exit_code=exit_code)

    assert result.returncode == exit_code
    assert (tmp_path / "report data.json").is_file()
    assert (tmp_path / "report summary.md").read_text() == "# Offline primer report\n"


@pytest.mark.parametrize("report_state", ["missing", "empty"])
def test_comparison_shell_rejects_success_without_report_data(tmp_path, report_state):
    result = _run_comparison(tmp_path, report_state=report_state)

    assert result.returncode != 0
    assert (tmp_path / "invocation.json").is_file()


@pytest.mark.parametrize("revision", ["base_sha", "merge_sha"])
def test_comparison_shell_rejects_non_commit_refs_before_running(tmp_path, revision):
    result = _run_comparison(tmp_path, **{revision: "main"})

    assert result.returncode != 0
    assert "Invalid comparison revision" in result.stderr
    assert not (tmp_path / "invocation.json").exists()


_WORKFLOW_STUBS = r"""
record() {
  "$WORKFLOW_TEST_PYTHON" -c '
import json, os, sys
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
' "$@"
}
git() {
  record git "$@"
  printf '%s\n' "$CHECKOUT_SHA"
  return "$GIT_EXIT"
}
go() {
  record go "$@"
  if [[ "$GO_EXIT" != 0 ]]; then return "$GO_EXIT"; fi
  "$WORKFLOW_TEST_PYTHON" - "$RUNNER_TEMP/skylos-go-engine/skylos-go" <<'STUB'
import os, pathlib, sys
engine = pathlib.Path(sys.argv[1])
engine.write_text("#!/bin/sh\nprintf '%s\\n' 'engine-version-probed' > \"$VERSION_PROBE\"\nexit \"$ENGINE_EXIT\"\n")
engine.chmod(0o700)
STUB
}
"""


def _run_workflow_step(
    tmp_path: Path, name: str, overrides: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow shell checks require bash")
    step = next(
        step
        for step in _workflow()["jobs"]["blast-radius"]["steps"]
        if step.get("name") == name
    )
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "WORKFLOW_TEST_PYTHON": sys.executable,
        "CALL_LOG": str(tmp_path / "calls.jsonl"),
        "RUNNER_TEMP": str(tmp_path / "runner temp"),
        "VERSION_PROBE": str(tmp_path / "version probe"),
        "TRUSTED_BASE_SHA": "a" * 40,
        "CHECKOUT_SHA": "a" * 40,
        "GIT_EXIT": "0",
        "GO_EXIT": "0",
        "ENGINE_EXIT": "0",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "step summary.md"),
        **(overrides or {}),
    }
    (tmp_path / "_trusted_skylos/skylos/engines/go").mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [bash, "-c", _WORKFLOW_STUBS + step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _workflow_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / "calls.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_trusted_go_build_executes_and_probes_engine(tmp_path: Path) -> None:
    result = _run_workflow_step(tmp_path, "Build trusted base Go engine")
    assert result.returncode == 0, result.stderr
    assert _workflow_calls(tmp_path) == [
        ["git", "-C", "_trusted_skylos", "rev-parse", "HEAD"],
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(tmp_path / "runner temp/skylos-go-engine/skylos-go"),
            "./cmd/skylos-go",
        ],
    ]
    assert (tmp_path / "version probe").read_text() == "engine-version-probed\n"


def test_go_engine_coverage_boundary_is_emitted(tmp_path: Path) -> None:
    result = _run_workflow_step(tmp_path, "Record Go engine coverage boundary")

    assert result.returncode == 0, result.stderr
    summary = (tmp_path / "step summary.md").read_text()
    assert "## Go engine coverage boundary" in summary
    assert "base commit `" + ("a" * 40) + "`" in summary
    assert "Changes under `skylos/engines/go/` are outside" in summary
    assert "::notice title=Go engine coverage boundary::" in result.stdout


def test_go_engine_coverage_boundary_rejects_non_commit_ref(tmp_path: Path) -> None:
    result = _run_workflow_step(
        tmp_path,
        "Record Go engine coverage boundary",
        {"TRUSTED_BASE_SHA": "main"},
    )

    assert result.returncode == 1
    assert "Invalid pull request base SHA" in result.stderr
    assert not (tmp_path / "step summary.md").exists()


@pytest.mark.parametrize(
    "overrides,expected_exit,expected_commands",
    [
        ({"TRUSTED_BASE_SHA": "main"}, 1, []),
        ({"CHECKOUT_SHA": "c" * 40}, 1, ["git"]),
        ({"GIT_EXIT": "7"}, 7, ["git"]),
        ({"GO_EXIT": "8"}, 8, ["git", "go"]),
        ({"ENGINE_EXIT": "9"}, 9, ["git", "go"]),
    ],
)
def test_trusted_go_build_stops_on_failure(
    tmp_path: Path,
    overrides: dict[str, str],
    expected_exit: int,
    expected_commands: list[str],
) -> None:
    result = _run_workflow_step(tmp_path, "Build trusted base Go engine", overrides)
    assert result.returncode == expected_exit, result.stderr
    assert [call[0] for call in _workflow_calls(tmp_path)] == expected_commands
    assert (tmp_path / "version probe").exists() == ("ENGINE_EXIT" in overrides)


# Test-owned snippets of the pinned primer's interface. The real overlay runs
# against these offline; no upstream imports, detector builds, or corpus code run.
_PRIMER_CONTAINER_INTERFACE = r'''
import hashlib
import json

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from liveness_primer.envcache import (
    fetch_records_for,
    parse_static_metadata,
    resolve_pair_refs,
    resolve_paired_delta,
)

_DOCKERFILE = """\
RUN uv pip install --quiet --compile-bytecode --no-index \
    --python /liveness/venv/bin/python \
    --find-links /liveness/wheelhouse /liveness/detector
"""

def container_fingerprint(adapter):
    material = json.dumps(
        {
            'recipe': adapter.build_recipe.digest(),
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode('utf-8')).hexdigest()

class ContainerEnvironments:
    def _side_requirements(self, repo: str, sha: str) -> tuple[str, ...]:
        """Fetch requirements from static metadata.

        Returns
        -------
        tuple[str, ...]
            Deduplicated declared dependencies and build requirements.
            Extras are deliberately left out, exactly as in the host-venv
            path: the offline install selects no extras (contract §3).
        """
        checkout = self._store.materialize(repo, sha, history=True)
        metadata = parse_static_metadata(checkout)
        return tuple(dict.fromkeys((*metadata.dependencies, *metadata.build_requires)))
'''


def _run_dart_overlay(tmp_path: Path, source: str):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow shell checks require bash")
    workspace = Path(tempfile.mkdtemp(dir=tmp_path))
    target = workspace / "_liveness_primer/liveness_primer/container.py"
    target.parent.mkdir(parents=True)
    if target.is_symlink():
        raise ValueError("overlay fixture must be a regular file")
    # Exclusive creation also rejects a symlink planted after the check.
    with target.open("x", encoding="utf-8") as fixture:
        fixture.write(source)
    step = next(
        step
        for step in _workflow()["jobs"]["blast-radius"]["steps"]
        if step.get("name") == "Enable Dart support for the full corpus"
    )
    result = subprocess.run(
        [bash, "-c", 'python() { "$OVERLAY_TEST_PYTHON" "$@"; }\n' + step["run"]],
        cwd=workspace,
        env={
            "PATH": os.defpath,
            "OVERLAY_TEST_PYTHON": sys.executable,
            "GITHUB_STEP_SUMMARY": str(tmp_path / "step summary.md"),
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result, target


def _overlay_interface(path: Path, monkeypatch: pytest.MonkeyPatch, **stubs):
    # Import the test-owned fixture as a normal module. The upstream package
    # is stubbed, so importing it never runs downloaded primer code.
    package = ModuleType("liveness_primer")
    package.__path__ = []
    envcache = ModuleType("liveness_primer.envcache")
    for name in (
        "fetch_records_for",
        "parse_static_metadata",
        "resolve_pair_refs",
        "resolve_paired_delta",
        "_read_pyproject_text",
    ):
        setattr(envcache, name, stubs.get(name))
    monkeypatch.setitem(sys.modules, "liveness_primer", package)
    monkeypatch.setitem(sys.modules, "liveness_primer.envcache", envcache)
    spec = importlib.util.spec_from_file_location("offline_primer_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dart_overlay_runs_before_full_corpus_comparison():
    steps = _workflow()["jobs"]["blast-radius"]["steps"]
    names = [step.get("name") for step in steps]
    name = "Enable Dart support for the full corpus"
    step = steps[names.index(name)]

    assert names.index("Install uv") < names.index(name)
    comparison_name = "Compare base with the pull request merge result"
    assert names.index(name) < names.index(comparison_name)
    assert step["shell"] == "bash"
    assert "set -euo pipefail" in step["run"]


@pytest.mark.parametrize("dart_in_core", [True, False], ids=["old-core", "new-extra"])
def test_dart_overlay_prefetches_selected_dart_without_other_extras(
    tmp_path, monkeypatch, dart_in_core
):
    result, target = _run_dart_overlay(tmp_path, _PRIMER_CONTAINER_INTERFACE)
    assert result.returncode == 0, result.stderr
    checkout = tmp_path / "detector"
    checkout.mkdir()
    grammar = "tree-sitter-dart-orchard>=0.3.2,<0.6"
    dependencies = ["requests", *([grammar] if dart_in_core else [])]
    optional = {} if dart_in_core else {"dart": [grammar]}
    optional["llm"] = ["unresolvable-llm-extra==999"]
    text = (
        "[project]\n"
        f"dependencies = {json.dumps(dependencies)}\n"
        "[project.optional-dependencies]\n"
        + "".join(
            f"{name} = {json.dumps(values)}\n" for name, values in optional.items()
        )
    )
    (checkout / "pyproject.toml").write_text(text, encoding="utf-8")
    events = []

    def validate(path):
        events.append("validate")
        assert path == checkout
        return SimpleNamespace(
            dependencies=tuple(dependencies), build_requires=("setuptools",)
        )

    def read_metadata(path):
        events.append("read")
        assert path == checkout / "pyproject.toml"
        return path.read_text(encoding="utf-8")

    patched = _overlay_interface(
        target,
        monkeypatch,
        parse_static_metadata=validate,
        _read_pyproject_text=read_metadata,
    )
    environment = patched.ContainerEnvironments()
    environment._store = SimpleNamespace(
        materialize=lambda *args, **kwargs: checkout
    )
    requirements = environment._side_requirements("fixture-repo", "a" * 40)

    assert set(requirements) == {"requests", "setuptools", grammar}
    assert requirements.count(grammar) == 1
    assert events == ["validate", "read"]
    assert '"/liveness/detector[dart]"' in target.read_text(encoding="utf-8")
    adapter = SimpleNamespace(build_recipe=SimpleNamespace(digest=lambda: "recipe"))
    original_fingerprint = hashlib.sha256(
        json.dumps({"recipe": "recipe"}, sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert patched.container_fingerprint(adapter) != original_fingerprint


def test_dart_overlay_propagates_metadata_validation_before_reading(
    tmp_path, monkeypatch
):
    result, target = _run_dart_overlay(tmp_path, _PRIMER_CONTAINER_INTERFACE)
    assert result.returncode == 0, result.stderr

    def invalid_metadata(_checkout):
        raise ValueError("invalid optional dependency metadata")

    def unexpected_read(_path):
        pytest.fail("overlay read metadata before existing validation completed")

    patched = _overlay_interface(
        target,
        monkeypatch,
        parse_static_metadata=invalid_metadata,
        _read_pyproject_text=unexpected_read,
    )
    environment = patched.ContainerEnvironments()
    environment._store = SimpleNamespace(
        materialize=lambda *args, **kwargs: tmp_path
    )
    with pytest.raises(ValueError, match="invalid optional dependency metadata"):
        environment._side_requirements("fixture-repo", "a" * 40)


@pytest.mark.parametrize("state", ["unknown", "duplicate", "already-patched"])
def test_dart_overlay_rejects_changed_interfaces_without_partial_writes(
    tmp_path, state
):
    source = _PRIMER_CONTAINER_INTERFACE
    anchor = "return tuple(dict.fromkeys((*metadata.dependencies, *metadata.build_requires)))"
    if state == "unknown":
        source = source.replace(anchor, "return metadata.dependencies")
    elif state == "duplicate":
        source += source
    else:
        result, target = _run_dart_overlay(tmp_path, source)
        assert result.returncode == 0, result.stderr
        source = target.read_text(encoding="utf-8")

    result, target = _run_dart_overlay(tmp_path, source)

    assert result.returncode != 0
    assert target.read_text(encoding="utf-8") == source
