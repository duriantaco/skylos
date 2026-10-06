import shlex

import pytest
import yaml
from skylos.cicd.init_setup import DoneSetup, detect_done_setup
from skylos.cicd.workflow import generate_workflow
from skylos.cli_core.main_parser import build_main_parser
from skylos.commands.done_cmd import build_parser as build_done_parser
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.github_actions import scan_github_actions


def test_default_workflow_valid_yaml():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    assert parsed["name"] == "Skylos Analysis"
    assert "on" in parsed or True in parsed
    assert "jobs" in parsed


def test_workflow_has_all_steps():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    step_names = [s.get("name", "") for s in steps]

    assert "Checkout" in step_names
    assert "Setup Python" in step_names
    assert "Install Skylos" in step_names
    assert "Run Skylos Analysis" in step_names
    assert "Quality Gate" in step_names
    assert "GitHub Annotations" in step_names
    assert "PR Review Comments" in step_names
    quality_gate = next(s for s in steps if s.get("name") == "Quality Gate")
    assert "--advisory" not in quality_gate["run"]
    pr_review = next(s for s in steps if s.get("name") == "PR Review Comments")
    assert "--evidence-cards" in pr_review["run"]


def test_workflow_can_generate_advisory_gate():
    content = generate_workflow(advisory_gate=True)
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    quality_gate = next(s for s in steps if s.get("name") == "Quality Gate")
    assert "--advisory" in quality_gate["run"]


def test_workflow_triggers():
    content = generate_workflow(triggers=["pull_request", "push"])
    parsed = yaml.safe_load(content)
    assert "pull_request" in parsed.get("on") or parsed.get(True)
    assert "push" in parsed.get("on") or parsed.get(True)


def test_workflow_custom_python_version():
    content = generate_workflow(python_version="3.11")
    assert "'3.11'" in content


def test_workflow_analysis_flags():
    content = generate_workflow(analysis_types=["security", "quality"])
    assert "--danger" in content
    assert "--quality" in content
    assert "--ai-defects" not in content
    assert "--secrets" not in content
    assert "--sca" not in content


def test_workflow_includes_ai_defects_by_default():
    content = generate_workflow()
    assert "--ai-defects" in content


def test_workflow_includes_dependency_scan_by_default():
    content = generate_workflow()
    assert "--sca" in content


def test_workflow_uses_baseline_by_default():
    content = generate_workflow()
    assert "--baseline" in content


def test_workflow_omits_baseline_when_disabled():
    content = generate_workflow(use_baseline=False)
    assert "--baseline" not in content


def test_workflow_pull_request_analysis_is_diff_aware():
    content = generate_workflow()
    assert 'pr_base_ref="origin/${GITHUB_BASE_REF:-main}"' in content
    assert '--diff-base "$pr_base_ref"' in content
    assert '--diff "$pr_base_ref"' in content
    assert "github.base_ref" not in content


def test_workflow_quotes_base_ref_in_pr_review_step():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    pr_review = next(s for s in steps if s.get("name") == "PR Review Comments")
    assert 'pr_base_ref="origin/${GITHUB_BASE_REF:-main}"' in pr_review["run"]
    assert '--diff-base "$pr_base_ref"' in pr_review["run"]
    assert "github.base_ref" not in pr_review["run"]


def test_workflow_no_llm_by_default():
    content = generate_workflow()
    assert "SKYLOS_API_KEY" not in content
    assert "agent review" not in content
    assert "agent scan" not in content


def test_workflow_with_llm():
    content = generate_workflow(use_llm=True, model="claude-sonnet-4-5-20250929")
    assert "agent scan" in content
    assert "--changed" in content
    assert "claude-sonnet-4-5-20250929" in content
    assert "SKYLOS_API_KEY" in content


def test_workflow_claude_model_adds_anthropic_key():
    content = generate_workflow(use_llm=True, model="claude-sonnet-4-20250514")
    assert "ANTHROPIC_API_KEY" in content


def test_workflow_non_claude_model_no_anthropic_key():
    content = generate_workflow(use_llm=True, model="gpt-4.1")
    assert "ANTHROPIC_API_KEY" not in content


def test_workflow_permissions():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    assert parsed["permissions"] == {"contents": "read"}
    jobs = parsed["jobs"]
    # Only the default-branch upload job may mint a GitHub OIDC token.
    assert jobs["skylos"]["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
    }
    assert jobs["done"]["permissions"] == {"contents": "read"}
    assert jobs["cloud-upload"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert jobs["skylos"]["timeout-minutes"] == 15


def test_generated_workflow_passes_skylos_actions_audit(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    _write(workflow, generate_workflow())

    assert scan_github_actions(tmp_path) == []


def test_generated_claude_workflow_passes_skylos_actions_audit(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    _write(
        workflow,
        generate_workflow(
            use_upload=True,
            use_llm=True,
            use_defend=True,
            use_claude_security=True,
            model="gpt-4.1",
        ),
    )

    assert scan_github_actions(tmp_path) == []


def test_workflow_schedule_trigger():
    content = generate_workflow(triggers=["schedule"])
    parsed = yaml.safe_load(content)
    assert "schedule" in parsed.get("on") or parsed.get(True)


def test_workflow_without_upload_has_no_cloud_job():
    content = generate_workflow(use_upload=False)
    parsed = yaml.safe_load(content)
    assert "cloud-upload" not in parsed["jobs"]
    assert "--upload" not in content
    assert "id-token" not in content
    assert "skylos sync pull" not in content
    assert "SKYLOS_TOKEN" not in content
    # Without the upload job, the gate job also scans default-branch pushes.
    assert "if" not in parsed["jobs"]["skylos"]


def test_workflow_uploads_through_oidc_by_default():
    content = generate_workflow()
    parsed = yaml.safe_load(content)
    assert "SKYLOS_TOKEN" not in content
    gate_job = parsed["jobs"]["skylos"]
    assert gate_job["if"] == "github.event_name != 'push'"
    analysis_step = next(
        s for s in gate_job["steps"] if s.get("name") == "Run Skylos Analysis"
    )
    assert "--upload" not in analysis_step["run"]
    assert "env" not in analysis_step

    job = parsed["jobs"]["cloud-upload"]
    assert job["if"] == (
        "github.event_name == 'push' && github.ref == "
        "format('refs/heads/{0}', github.event.repository.default_branch)"
    )
    steps = job["steps"]
    names = [s.get("name") for s in steps]
    assert names.index("Pull Skylos Cloud Policy") < names.index(
        "Scan and Upload to Skylos Cloud"
    )
    sync_step = steps[names.index("Pull Skylos Cloud Policy")]
    # Fail closed, but say what to do: the CLI's own error can be a traceback.
    sync_lines = sync_step["run"].splitlines()
    assert sync_lines[0] == "if ! skylos sync pull; then"
    assert sync_lines[1].startswith(
        '  echo "::error title=Skylos Cloud policy unavailable::'
    )
    assert "skylos cicd init --no-upload" in sync_lines[1]
    assert sync_lines[2:] == ["  exit 1", "fi"]
    assert "continue-on-error" not in sync_step
    upload_step = steps[names.index("Scan and Upload to Skylos Cloud")]
    args = build_main_parser(version="test").parse_args(
        shlex.split(upload_step["run"])[1:]
    )
    assert args.upload and not args.no_upload and not args.force
    assert not args.diff and not args.diff_base
    assert upload_step["env"] == {
        "SKYLOS_COMMIT": "${{ github.sha }}",
        "SKYLOS_BRANCH": "${{ github.ref_name }}",
    }


def test_workflow_upload_with_llm():
    content = generate_workflow(use_upload=True, use_llm=True, model="gpt-4.1")
    parsed = yaml.safe_load(content)
    steps = parsed["jobs"]["skylos"]["steps"]
    analysis_step = next(s for s in steps if s.get("name") == "Run Skylos Analysis")
    assert "--upload" not in analysis_step["run"]
    llm_step = next(s for s in steps if s.get("name") == "Skylos Agent Review (LLM)")
    assert "SKYLOS_API_KEY" in llm_step["env"]
    upload_steps = parsed["jobs"]["cloud-upload"]["steps"]
    assert any("--upload" in s.get("run", "") for s in upload_steps)
    assert all("SKYLOS_API_KEY" not in s.get("env", {}) for s in upload_steps)


def test_workflow_defend_uploads_only_from_upload_job():
    content = generate_workflow(use_defend=True)
    parsed = yaml.safe_load(content)
    gate_defend = next(
        s
        for s in parsed["jobs"]["skylos"]["steps"]
        if s.get("name") == "AI Defense Check"
    )
    assert "--upload" not in gate_defend["run"]
    upload_defend = next(
        s
        for s in parsed["jobs"]["cloud-upload"]["steps"]
        if s.get("name") == "AI Defense Check and Upload"
    )
    assert upload_defend["run"].endswith("--upload")
    assert upload_defend["env"]["SKYLOS_COMMIT"] == "${{ github.sha }}"


def test_workflow_scan_path_is_monorepo_aware():
    content = generate_workflow(scan_path="apps/api", use_upload=True, use_defend=True)
    assert "skylos apps/api" in content
    assert "skylos defend apps/api" in content
    assert '--json -o "$RUNNER_TEMP/defense-results.json"' in content
    assert '--defense-input "$RUNNER_TEMP/defense-results.json"' in content
    assert "--defense-input defense-results.json" not in content


def test_workflow_prefixes_leading_dash_scan_path():
    content = generate_workflow(scan_path="-service")
    assert "skylos ./-service" in content


@pytest.mark.parametrize("control_char", ["\n", "\r", "\t", "\x7f"])
def test_workflow_rejects_scan_path_control_characters(control_char):
    payload = f"apps/api{control_char}      - name: Injected Step"

    with pytest.raises(ValueError, match="scan_path"):
        generate_workflow(
            scan_path=payload,
            use_llm=True,
            use_defend=True,
        )


def test_workflow_pins_installed_skylos_version():
    content = generate_workflow(skylos_version="4.9.0")
    # -I keeps files from the checked-out pull request off pip's sys.path.
    assert "python -I -m pip install skylos==4.9.0" in content
    assert "python -m pip" not in content


def test_workflow_gates_every_pull_request_and_filters_pushes():
    parsed = yaml.safe_load(generate_workflow(default_branch="trunk"))
    on = parsed["on"]
    # No base-branch filter: a repository whose default branch is not main
    # still gets the gate.
    assert on["pull_request"] is None
    assert on["push"] == {"branches": ["trunk"]}


def test_workflow_push_filter_falls_back_to_main_and_master():
    parsed = yaml.safe_load(generate_workflow())
    assert parsed["on"]["push"] == {"branches": ["main", "master"]}


@pytest.mark.parametrize(
    "branch",
    ["", "-x", "a b", "main\n  - injected", "${{ github.head_ref }}", "a..b", "x*"],
)
def test_workflow_rejects_unsafe_default_branch(branch):
    with pytest.raises(ValueError, match="default_branch"):
        generate_workflow(default_branch=branch)


def test_done_job_runs_tests_on_pull_request_head_without_upload_authority():
    content = generate_workflow(
        done_install_commands=["python -I -m pip install -e . pytest", "npm ci"]
    )
    parsed = yaml.safe_load(content)
    job = parsed["jobs"]["done"]
    assert job["name"] == "Skylos Done"
    assert job["if"] == "github.event_name == 'pull_request'"
    assert job["permissions"] == {"contents": "read"}
    assert "environment" not in job
    checkout = job["steps"][0]
    assert checkout["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}",
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    names = [s.get("name") for s in job["steps"]]
    assert names == [
        "Checkout pull request head",
        "Setup Python",
        "Install Skylos",
        "Install project test dependencies",
        "Check the change is finished",
    ]
    install = job["steps"][3]["run"]
    assert install.splitlines() == ["python -I -m pip install -e . pytest", "npm ci"]
    done_run = job["steps"][4]["run"]
    assert done_run == 'skylos done --base "origin/$GITHUB_BASE_REF"'
    args = build_done_parser().parse_args(shlex.split(done_run)[2:])
    assert args.base == "origin/$GITHUB_BASE_REF" and not args.no_tests
    assert "SKYLOS_TOKEN" not in content and "github.base_ref" not in content


def test_done_job_can_be_left_out():
    parsed = yaml.safe_load(generate_workflow(use_done=False))
    assert "done" not in parsed["jobs"]
    parsed = yaml.safe_load(generate_workflow(triggers=["push"]))
    assert "done" not in parsed["jobs"]


def test_header_names_the_required_checks():
    content = generate_workflow()
    header = content.split("\nname:", 1)[0]
    assert all(line.startswith("#") for line in header.splitlines())
    assert '"Skylos Quality Gate"' in header
    assert '"Skylos Done"' in header
    assert "first-gated-pr.md" in header
    assert '"Skylos Done"' not in generate_workflow(use_done=False).split("\nname:")[0]


def test_generated_minimal_workflow_passes_skylos_actions_audit(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "skylos.yml"
    _write(workflow, generate_workflow(use_upload=False, use_done=False))

    assert scan_github_actions(tmp_path) == []


def _write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


def test_detect_done_setup_installs_package_with_test_extra(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\nversion = "0"\n'
        '[project.optional-dependencies]\ndev = ["ruff"]\ntest = ["pytest-cov"]\n'
        "[tool.pytest.ini_options]\n",
    )
    setup = detect_done_setup(tmp_path)
    assert setup == DoneSetup(
        True,
        "pytest project found",
        ('python -I -m pip install -e ".[test]" pytest',),
    )


def test_detect_done_setup_uses_requirements_files(tmp_path):
    _write(tmp_path / "tests" / "test_app.py", "def test_x():\n    assert True\n")
    _write(tmp_path / "requirements.txt", "flask\n")
    _write(tmp_path / "requirements" / "test.txt", "pytest-mock\n")
    setup = detect_done_setup(tmp_path)
    assert setup.enabled
    assert setup.install_commands == (
        "python -I -m pip install -r requirements.txt -r requirements/test.txt pytest",
    )


def test_detect_done_setup_skips_repositories_without_tests(tmp_path):
    _write(tmp_path / "lib.py", "x = 1\n")
    setup = detect_done_setup(tmp_path)
    assert not setup.enabled
    assert "test_command" in setup.reason


def test_detect_done_setup_honours_configured_test_command(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos.done]\ntest_command = "npx vitest run"\n',
    )
    _write(tmp_path / "package.json", "{}")
    _write(tmp_path / "package-lock.json", "{}")
    setup = detect_done_setup(tmp_path)
    assert setup.enabled
    assert setup.reason == "[tool.skylos.done] test_command is set"
    assert setup.install_commands[-1] == "npm ci"

    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos.done]\ntest_command = ["python", "-m", "pytest", "-q"]\n',
    )
    assert detect_done_setup(tmp_path).install_commands == (
        "python -I -m pip install pytest",
    )


def test_detect_done_setup_only_uses_known_test_extras(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        '[build-system]\nrequires = ["setuptools"]\n'
        '[project.optional-dependencies]\n"x; curl evil" = []\n',
    )
    _write(tmp_path / "conftest.py")
    assert detect_done_setup(tmp_path).install_commands == (
        "python -I -m pip install -e . pytest",
    )


def test_detect_done_setup_survives_invalid_pyproject(tmp_path):
    _write(tmp_path / "conftest.py")
    _write(tmp_path / "pyproject.toml", "not = [valid toml")
    assert detect_done_setup(tmp_path).install_commands == (
        "python -I -m pip install pytest",
    )


def _run_cicd_init(tmp_path, monkeypatch, *argv, git=None):
    from unittest.mock import Mock

    import skylos.commands.cicd_cmd as cicd_cmd

    git = git or {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cicd_cmd, "_git_output", lambda *args: git.get(args, ""))
    console = Mock()
    output = tmp_path / ".github" / "workflows" / "skylos.yml"
    exit_code = cicd_cmd.run_cicd_command(
        ["init", "--output", str(output), *argv],
        console_factory=lambda: console,
        load_config_func=lambda path: {},
        run_gate_interaction_func=Mock(),
        emit_github_annotations_func=Mock(),
    )
    printed = "\n".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    workflow = yaml.safe_load(output.read_text()) if output.exists() else None
    return exit_code, workflow, printed


def test_cicd_init_adds_done_for_pytest_projects(tmp_path, monkeypatch):
    _write(tmp_path / "tests" / "test_app.py", "def test_x():\n    assert True\n")
    _write(tmp_path / "requirements.txt", "requests\n")
    exit_code, workflow, printed = _run_cicd_init(tmp_path, monkeypatch)

    assert exit_code == 0
    assert set(workflow["jobs"]) == {"skylos", "done", "cloud-upload"}
    install = workflow["jobs"]["done"]["steps"][3]["run"]
    assert install.strip() == "python -I -m pip install -r requirements.txt pytest"
    assert "Skylos Done" in printed and "runs your tests" in printed
    assert "Wait for: Skylos Quality Gate, Skylos Done" in printed
    assert "first-gated-pr.md" in printed
    assert "git add .github/workflows/skylos.yml" in printed


def test_cicd_init_leaves_done_out_when_tests_cannot_run(tmp_path, monkeypatch):
    _write(tmp_path / "lib.py", "x = 1\n")
    exit_code, workflow, printed = _run_cicd_init(tmp_path, monkeypatch)

    assert exit_code == 0
    assert "done" not in workflow["jobs"]
    assert "not added" in printed and "--done" in printed
    assert "Wait for: Skylos Quality Gate\n" in printed + "\n"


def test_cicd_init_done_and_upload_flags(tmp_path, monkeypatch):
    _write(tmp_path / "lib.py", "x = 1\n")
    _, workflow, printed = _run_cicd_init(
        tmp_path, monkeypatch, "--done", "--no-upload"
    )
    assert set(workflow["jobs"]) == {"skylos", "done"}
    assert "added with --done" in printed
    assert "GitHub OIDC" not in printed

    _write(tmp_path / "conftest.py")
    _, workflow, _ = _run_cicd_init(tmp_path, monkeypatch, "--no-done", "--upload")
    assert set(workflow["jobs"]) == {"skylos", "cloud-upload"}


def test_cicd_init_uses_origin_head_as_default_branch(tmp_path, monkeypatch):
    git = {
        (
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
        ): "origin/trunk"
    }
    _, workflow, printed = _run_cicd_init(tmp_path, monkeypatch, git=git)
    assert workflow["on"]["push"] == {"branches": ["trunk"]}
    assert "Pushes to trunk" in printed
    assert "No origin/HEAD" not in printed

    _, workflow, printed = _run_cicd_init(tmp_path, monkeypatch)
    assert workflow["on"]["push"] == {"branches": ["main", "master"]}
    assert "No origin/HEAD" in printed

    _, workflow, _ = _run_cicd_init(
        tmp_path, monkeypatch, "--default-branch", "release/2026", git=git
    )
    assert workflow["on"]["push"] == {"branches": ["release/2026"]}


def test_cicd_init_rejects_unsafe_default_branch(tmp_path, monkeypatch):
    exit_code, workflow, printed = _run_cicd_init(
        tmp_path, monkeypatch, "--default-branch", "main\n  - injected"
    )
    assert exit_code == 1
    assert workflow is None
    assert "Invalid workflow option" in printed


def test_cicd_init_ignores_unsafe_origin_head(tmp_path, monkeypatch):
    git = {
        (
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
        ): "origin/$(id)"
    }
    exit_code, workflow, _ = _run_cicd_init(tmp_path, monkeypatch, git=git)
    assert exit_code == 0
    assert workflow["on"]["push"] == {"branches": ["main", "master"]}


def test_skylos_init_points_to_the_pull_request_gate(tmp_path, monkeypatch):
    from unittest.mock import Mock, patch

    from skylos.commands.init_cmd import run_init_command

    monkeypatch.chdir(tmp_path)
    console = Mock()
    with patch("skylos.commands.init_cmd.Console", return_value=console):
        assert run_init_command() == 0

    printed = [str(call.args[0]) for call in console.print.call_args_list]
    hint = printed[-1]
    assert "skylos cicd init" in hint
    # Escaped, so Rich prints the table name instead of treating it as markup.
    assert r"\[tool.skylos]" in hint
