import os
import shlex
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

import skylos.cli as cli
from skylos.cicd import platforms
from skylos.cicd.platforms import BY_KEY, OTHER, Settings
from skylos.commands import cicd_cmd, doctor_cmd
from skylos.core import ci_env
from skylos.reporting import provenance

_CI_PREFIXES = (
    "GITHUB_",
    "BITBUCKET_",
    "SYSTEM_",
    "BUILD_",
    "CI_",
    "CIRCLE",
    "GITLAB_",
    "SKYLOS_",
    "CHANGE_",
    "BUILDKITE",
    "TRAVIS",
    "DRONE",
    "TEAMCITY_",
)
_CI_NAMES = (
    "CI",
    "JENKINS_URL",
    "JENKINS_HOME",
    "TF_BUILD",
    "WORKSPACE",
    "WORKSPACE_TMP",
)

JENKINS_PR = {"JENKINS_URL": "http://ci/", "CHANGE_ID": "42", "CHANGE_TARGET": "develop"}
GITLAB_MR = {
    "GITLAB_CI": "true",
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "release/2",
}
BUILDKITE_PR = {
    "BUILDKITE": "true",
    "BUILDKITE_PULL_REQUEST": "17",
    "BUILDKITE_PULL_REQUEST_BASE_BRANCH": "develop",
}
TRAVIS_PR = {"TRAVIS": "true", "TRAVIS_PULL_REQUEST": "5", "TRAVIS_BRANCH": "develop"}
DRONE_PR = {
    "DRONE": "true",
    "DRONE_BUILD_EVENT": "pull_request",
    "DRONE_TARGET_BRANCH": "develop",
}
WOODPECKER_PR = {
    "CI": "woodpecker",
    "CI_PIPELINE_EVENT": "pull_request",
    "CI_COMMIT_TARGET_BRANCH": "develop",
}
SCAN = "skylos . --danger --quality --ai-defects --secrets --sca --baseline --gate --diff"


@pytest.fixture(autouse=True)
def clean_ci_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith(_CI_PREFIXES) or name in _CI_NAMES:
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _set(monkeypatch, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def _git(cwd, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=test",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def origin(tmp_path):
    bare = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    _git(tmp_path, "init", "-q", "--bare", str(bare))
    _git(tmp_path, "clone", "-q", str(bare), str(seed))
    for branch, value in (("main", 1), ("develop", 2), ("feature", 3)):
        (seed / "app.py").write_text(f"x = {value}\n", encoding="utf-8")
        _git(seed, "add", "app.py")
        _git(seed, "commit", "-qm", branch)
        _git(seed, "push", "-q", "origin", f"HEAD:{branch}")
    return bare


def _clone(origin, tmp_path, name, *args):
    target = tmp_path / name
    _git(tmp_path, "clone", "-q", *args, f"file://{origin}", str(target))
    return target


@pytest.mark.parametrize(
    "env,branch,name",
    [
        (JENKINS_PR, "develop", "Jenkins"),
        (
            {"JENKINS_HOME": "/var/jenkins_home", "CHANGE_ID": "7", "CHANGE_TARGET": "develop"},
            "develop",
            "Jenkins",
        ),
        (
            {"BUILD_TAG": "jenkins-api-PR-7-3", "CHANGE_ID": "7", "CHANGE_TARGET": "develop"},
            "develop",
            "Jenkins",
        ),
        (GITLAB_MR, "release/2", "GitLab CI"),
        (BUILDKITE_PR, "develop", "Buildkite"),
        (TRAVIS_PR, "develop", "Travis CI"),
        (DRONE_PR, "develop", "Drone"),
        (WOODPECKER_PR, "develop", "Woodpecker"),
    ],
)
def test_pr_build_target_is_the_diff_base(monkeypatch, env, branch, name):
    _set(monkeypatch, env)
    assert ci_env.auto_diff_base_ref() == f"origin/{branch}"
    assert ci_env.github_or_ci_base_ref() == branch
    assert ci_env.ci_name() == name


@pytest.mark.parametrize(
    "env,name",
    [
        ({"JENKINS_URL": "http://ci/", "CHANGE_TARGET": "develop"}, "Jenkins"),
        ({"CHANGE_ID": "42", "CHANGE_TARGET": "develop"}, None),
        (
            {"BUILD_TAG": "buildkite-api-7", "CHANGE_ID": "7", "CHANGE_TARGET": "develop"},
            None,
        ),
        ({"JENKINS_HOME": "/var/jenkins_home", "CHANGE_TARGET": "develop"}, "Jenkins"),
        ({"GITLAB_CI": "true"}, "GitLab CI"),
        ({"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "develop"}, None),
        (
            {
                "BUILDKITE": "true",
                "BUILDKITE_PULL_REQUEST": "false",
                "BUILDKITE_PULL_REQUEST_BASE_BRANCH": "develop",
            },
            "Buildkite",
        ),
        (
            {"TRAVIS": "true", "TRAVIS_PULL_REQUEST": "false", "TRAVIS_BRANCH": "feature"},
            "Travis CI",
        ),
        (
            {"DRONE": "true", "DRONE_BUILD_EVENT": "push", "DRONE_TARGET_BRANCH": "feature"},
            "Drone",
        ),
        (
            {
                "CI": "woodpecker",
                "CI_PIPELINE_EVENT": "push",
                "CI_COMMIT_TARGET_BRANCH": "feature",
            },
            "Woodpecker",
        ),
        (
            {
                "CI": "true",
                "CI_PIPELINE_EVENT": "pull_request",
                "CI_COMMIT_TARGET_BRANCH": "develop",
            },
            None,
        ),
        ({}, None),
    ],
)
def test_builds_that_are_not_pull_requests_keep_origin_main(monkeypatch, env, name):
    _set(monkeypatch, env)
    assert ci_env.auto_diff_base_ref() == "origin/main"
    assert ci_env.github_or_ci_base_ref() is None
    assert ci_env.ci_name() == name


@pytest.mark.parametrize(
    "env,variable",
    [
        (JENKINS_PR, "CHANGE_TARGET"),
        (GITLAB_MR, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
        (BUILDKITE_PR, "BUILDKITE_PULL_REQUEST_BASE_BRANCH"),
        (TRAVIS_PR, "TRAVIS_BRANCH"),
        (DRONE_PR, "DRONE_TARGET_BRANCH"),
        (WOODPECKER_PR, "CI_COMMIT_TARGET_BRANCH"),
    ],
)
@pytest.mark.parametrize("value", ["-x", "a..b", "$(id)", "refs/tags/v1", "main~1", "a b"])
def test_unsafe_target_branches_are_rejected(monkeypatch, env, variable, value):
    _set(monkeypatch, {**env, variable: value})
    assert ci_env.pr_target_branch() is None
    assert ci_env.auto_diff_base_ref() == "origin/main"


def test_github_base_ref_still_wins_over_other_ci_targets(monkeypatch):
    _set(monkeypatch, JENKINS_PR)
    monkeypatch.setenv("GITHUB_BASE_REF", "trunk")
    assert ci_env.auto_diff_base_ref() == "origin/trunk"
    assert ci_env.github_or_ci_base_ref() == "trunk"


def test_diff_base_callers_use_the_jenkins_target(monkeypatch):
    from skylos.cli import _dependency_bump_cli_diff_base

    _set(monkeypatch, JENKINS_PR)
    assert _dependency_bump_cli_diff_base(SimpleNamespace(diff_base=None, diff="auto")) == (
        "origin/develop"
    )
    assert provenance._resolve_base_ref() == "origin/develop"


def test_hint_names_the_ci_and_its_command_fetches_the_base(monkeypatch, origin, tmp_path):
    clone = _clone(origin, tmp_path, "pr", "--single-branch", "--branch", "feature")
    _set(monkeypatch, JENKINS_PR)

    hint = platforms.missing_base_hint("origin/develop", clone)

    command = "git fetch --no-tags origin +refs/heads/develop:refs/remotes/origin/develop"
    assert hint == f"On Jenkins, run this before the scan: {command}"
    _git(clone, *shlex.split(command)[1:])
    assert platforms.missing_base_hint("origin/develop", clone) is None


def test_hint_outside_ci_says_how_to_fetch(origin, tmp_path):
    clone = _clone(origin, tmp_path, "local", "--single-branch", "--branch", "feature")
    assert platforms.missing_base_hint("origin/main", clone) == (
        "To fetch it: git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main"
    )


def test_hint_unshallows_a_shallow_clone(origin, tmp_path):
    clone = _clone(origin, tmp_path, "shallow", "--depth", "1", "--no-single-branch")
    hint = platforms.missing_base_hint("origin/develop", clone)
    assert hint is not None
    assert "git fetch --no-tags --unshallow origin +refs/heads/develop:" in hint
    _git(clone, *shlex.split(hint.split(": ", 1)[1])[1:])
    assert platforms.missing_base_hint("origin/develop", clone) is None


@pytest.mark.parametrize("base", ["origin/develop", "HEAD~1", "a" * 40, "origin/a..b", "", None])
def test_no_hint_when_the_base_is_usable_or_not_a_branch(origin, tmp_path, base):
    clone = _clone(origin, tmp_path, "full")
    assert platforms.missing_base_hint(base, clone) is None


def _scan_in(monkeypatch, capsys, clone, *args):
    monkeypatch.chdir(clone)
    monkeypatch.setenv("HOME", str(clone.parent / "home"))
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)

    def no_upload(*_args, **_kwargs):
        pytest.fail("this test must not upload anything")

    monkeypatch.setattr(cli, "upload_report", no_upload)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", "--no-provenance", "--no-grep-verify", "--no-clipboard", *args],
    )
    capsys.readouterr()
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    return exit_code, capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ("--danger", "--gate", "--diff", "--format", "json"),
        ("--danger", "--diff", "--format", "json"),
    ],
)
def test_scan_with_missing_base_prints_the_fetch_line(
    monkeypatch, capsys, origin, tmp_path, args
):
    clone = _clone(origin, tmp_path, "jenkins", "--single-branch", "--branch", "feature")
    _set(monkeypatch, JENKINS_PR)

    exit_code, err = _scan_in(monkeypatch, capsys, clone, *args)

    assert exit_code == 2
    assert (
        "On Jenkins, run this before the scan: git fetch --no-tags origin "
        "+refs/heads/develop:refs/remotes/origin/develop"
    ) in err


def _render(key, **settings):
    platform = BY_KEY.get(key, OTHER)
    return platforms.render(platform, Settings(skylos_version="9.9.9", **settings))


@pytest.mark.parametrize("key", ["gitlab", "bitbucket", "azure", "circleci"])
def test_yaml_templates_parse_and_contain_their_snippet(key):
    rendered = _render(key)
    assert yaml.safe_load(rendered.full)
    for line in rendered.snippet.splitlines():
        assert line.strip() in rendered.full


def test_gitlab_job_runs_on_merge_requests_with_full_history():
    job = yaml.safe_load(_render("gitlab").full)["skylos"]
    assert job["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'}]
    assert job["variables"] == {"GIT_DEPTH": "0"}
    assert job["image"] == "python:3.12"
    assert job["script"] == [
        "python -I -m pip install 'skylos[dart]==9.9.9'",
        'git fetch --no-tags origin "+refs/heads/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME'
        ':refs/remotes/origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"',
        SCAN,
    ]


def test_bitbucket_step_runs_on_pull_requests_with_full_clone():
    data = yaml.safe_load(_render("bitbucket").full)
    assert data["clone"] == {"depth": "full"}
    step = data["pipelines"]["pull-requests"]["**"][0]["step"]
    assert step["script"][-1] == SCAN
    assert "$BITBUCKET_PR_DESTINATION_BRANCH" in step["script"][1]


def test_azure_pipeline_fetches_full_history_without_a_credentialed_fetch():
    rendered = _render("azure")
    data = yaml.safe_load(rendered.full)
    assert data["steps"][0] == {"checkout": "self", "fetchDepth": 0}
    assert data["steps"][-1]["script"] == SCAN
    assert "git fetch" not in rendered.full


def test_circleci_compares_with_the_default_branch_on_pull_requests_only():
    data = yaml.safe_load(_render("circleci", default_branch="trunk").full)
    command = data["jobs"]["skylos"]["steps"][2]["run"]["command"]
    assert 'if [ -z "$CIRCLE_PULL_REQUEST" ]; then' in command
    assert command.rstrip().endswith(f"{SCAN} origin/trunk")
    assert data["workflows"]["skylos"]["jobs"] == ["skylos"]


@pytest.mark.parametrize(
    "key,requirement",
    [
        ("gitlab", "'skylos[dart]==9.9.9'"),
        ("bitbucket", "'skylos[dart]==9.9.9'"),
        ("azure", "'skylos[dart]==9.9.9'"),
        ("circleci", "'skylos[dart]==9.9.9'"),
        ("jenkins", "skylos==9.9.9"),
        ("other", "skylos==9.9.9"),
    ],
)
def test_only_agents_with_a_known_compiler_install_the_dart_grammar(key, requirement):
    rendered = _render(key)
    text = rendered.full or rendered.snippet
    installs = [line for line in text.splitlines() if "pip install" in line]
    assert len(installs) == 1
    assert installs[0].rstrip().endswith(f"pip install {requirement}")


def _jenkins_shell(full):
    return full.split("sh '''\n", 1)[1].split("'''", 1)[0]


def test_jenkins_stage_installs_outside_the_workspace_and_fetches_only_when_missing():
    rendered = _render("jenkins")
    shell = _jenkins_shell(rendered.full)
    assert "when { changeRequest() }" in rendered.full
    assert '${WORKSPACE_TMP:-$WORKSPACE@tmp}/skylos-venv' in shell
    assert ".venv" not in shell
    assert 'if ! git rev-parse --verify --quiet "origin/$CHANGE_TARGET^{commit}"' in shell
    assert shell.strip().splitlines()[-1].strip() == SCAN.replace(
        "skylos", '"$SKYLOS_VENV/bin/skylos"', 1
    )


@pytest.mark.parametrize("path", ["apps/my api #1: x", "it's", "a'''b", "-weird", "$(id)"])
@pytest.mark.parametrize("key", ["gitlab", "bitbucket", "azure", "circleci", "jenkins", "other"])
def test_scan_path_reaches_the_shell_as_one_argument(key, path):
    rendered = _render(key, scan_path=path)
    text = rendered.full or rendered.snippet
    if key == "jenkins":
        text = _jenkins_shell(text)
    else:
        yaml.safe_load(rendered.full or "{}")
    scan_lines = [line for line in text.splitlines() if "--gate --diff" in line]
    assert len(scan_lines) == 1
    expected = path
    if path.startswith("-"):
        expected = f"./{path}"
    assert shlex.split(scan_lines[0])[1] == expected


@pytest.mark.parametrize(
    "key,settings",
    [
        ("gitlab", {"python_version": "3.12; id"}),
        ("circleci", {"default_branch": "main\n  - injected"}),
        ("jenkins", {"scan_path": "apps\\api"}),
        ("gitlab", {"scan_path": "apps\napi"}),
    ],
)
def test_render_rejects_unsafe_settings(key, settings):
    with pytest.raises(ValueError):
        _render(key, **settings)


def _tree(tmp_path, *files):
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("steps: []\n", encoding="utf-8")


@pytest.mark.parametrize(
    "files,remote,expected",
    [
        ((), "", "github"),
        (("Jenkinsfile",), "", "jenkins"),
        ((".gitlab-ci.yml",), "git@github.com:a/b.git", "gitlab"),
        ((".github/workflows/ci.yml", "Jenkinsfile"), "", "github"),
        ((".travis.yml",), "", "other"),
        ((), "git@gitlab.com:acme/api.git", "gitlab"),
        ((), "https://acme@dev.azure.com/acme/p/_git/r", "azure"),
        ((), "ssh://git@bitbucket.org/acme/api.git", "bitbucket"),
        ((), "https://evilgitlab.com/acme/api.git", "github"),
    ],
)
def test_choose_platform(tmp_path, files, remote, expected):
    _tree(tmp_path, *files)
    choice = platforms.choose_platform(tmp_path, remote)
    assert choice.platform.key == expected


def test_choose_platform_refuses_to_guess_between_two_cis(tmp_path):
    _tree(tmp_path, "Jenkinsfile", ".gitlab-ci.yml")
    choice = platforms.choose_platform(tmp_path, "")
    assert choice.platform is None
    assert {f.platform.key for f in choice.found} == {"jenkins", "gitlab"}


@pytest.mark.parametrize(
    "output,expected",
    [
        ("Jenkinsfile", "jenkins"),
        ("ci/.gitlab-ci.yml", "gitlab"),
        ("/repo/.circleci/config.yml", "circleci"),
        (".github/workflows/skylos.yml", "github"),
        ("custom.yml", "github"),
    ],
)
def test_platform_from_output(output, expected):
    assert platforms.platform_from_output(output).key == expected


def _init(tmp_path, monkeypatch, *argv, git=None):
    git = git or {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cicd_cmd, "_git_output", lambda *args: git.get(args, ""))
    console = Mock()
    exit_code = cicd_cmd.run_cicd_command(
        ["init", *argv],
        console_factory=lambda: console,
        load_config_func=lambda path: {},
        run_gate_interaction_func=Mock(),
        emit_github_annotations_func=Mock(),
    )
    printed = "\n".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    return exit_code, printed


def test_init_without_ci_files_still_writes_the_github_workflow(tmp_path, monkeypatch):
    exit_code, printed = _init(tmp_path, monkeypatch, "--no-upload")
    assert exit_code == 0
    assert (tmp_path / ".github" / "workflows" / "skylos.yml").is_file()
    assert "Setting up" not in printed


def test_init_writes_the_jenkinsfile_it_renders(tmp_path, monkeypatch):
    exit_code, printed = _init(tmp_path, monkeypatch, "--ci", "jenkins")
    expected = platforms.render(BY_KEY["jenkins"], Settings())
    assert exit_code == 0
    assert (tmp_path / "Jenkinsfile").read_text(encoding="utf-8") == expected.full
    assert "Commit Jenkinsfile on a new branch" in printed
    assert "docs/ci-platforms.md#jenkins" in printed
    assert not (tmp_path / ".github").exists()


def test_init_never_edits_an_existing_ci_file(tmp_path, monkeypatch):
    jenkinsfile = tmp_path / "Jenkinsfile"
    jenkinsfile.write_text("pipeline { }\n", encoding="utf-8")

    exit_code, printed = _init(tmp_path, monkeypatch)

    assert exit_code == 0
    assert jenkinsfile.read_text(encoding="utf-8") == "pipeline { }\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Jenkinsfile"]
    assert "Setting up Jenkins (found Jenkinsfile)." in printed
    assert "Jenkinsfile already exists. Skylos does not edit it." in printed
    assert "Add this stage inside stages { } in your Jenkinsfile:" in printed
    assert "stage('Skylos') {" in printed


def test_init_says_when_the_file_is_already_up_to_date(tmp_path, monkeypatch):
    _init(tmp_path, monkeypatch, "--ci", "gitlab")
    exit_code, printed = _init(tmp_path, monkeypatch, "--ci", "gitlab")
    assert exit_code == 0
    assert "Already up to date: .gitlab-ci.yml" in printed
    assert "Add this job" not in printed


def test_init_asks_for_ci_when_the_repository_has_several(tmp_path, monkeypatch):
    _tree(tmp_path, "Jenkinsfile", ".gitlab-ci.yml")
    exit_code, printed = _init(tmp_path, monkeypatch)
    assert exit_code == 1
    assert "Found more than one CI" in printed
    assert "Nothing was written" in printed
    assert (tmp_path / "Jenkinsfile").read_text(encoding="utf-8") == "steps: []\n"
    assert not (tmp_path / ".github").exists()


def test_init_keeps_github_and_points_at_the_other_ci(tmp_path, monkeypatch):
    _tree(tmp_path, ".github/workflows/ci.yml", "Jenkinsfile")
    exit_code, printed = _init(tmp_path, monkeypatch, "--no-upload")
    assert exit_code == 0
    assert (tmp_path / ".github" / "workflows" / "skylos.yml").is_file()
    assert (
        "Also found Jenkinsfile (Jenkins); for it run: skylos cicd init --ci jenkins"
        in printed
    )


def test_init_follows_the_origin_host_when_no_ci_file_exists(tmp_path, monkeypatch):
    git = {("remote", "get-url", "origin"): "git@gitlab.com:acme/api.git"}
    exit_code, printed = _init(tmp_path, monkeypatch, git=git)
    assert exit_code == 0
    assert yaml.safe_load((tmp_path / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    assert "Setting up GitLab CI (origin is on that code host)." in printed


def test_init_for_a_ci_without_a_template_prints_the_commands(tmp_path, monkeypatch):
    _tree(tmp_path, ".travis.yml")
    git = {
        ("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"): "origin/trunk"
    }
    exit_code, printed = _init(tmp_path, monkeypatch, git=git)
    assert exit_code == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == [".travis.yml"]
    assert "Setting up Travis CI (found .travis.yml)." in printed
    assert 'git fetch --no-tags origin "+refs/heads/trunk:refs/remotes/origin/trunk"' in printed
    assert "--gate --diff origin/trunk" in printed
    assert "Add the commands above to a pull request step in Travis CI" in printed


def test_init_names_flags_it_does_not_use(tmp_path, monkeypatch):
    exit_code, printed = _init(
        tmp_path, monkeypatch, "--ci", "jenkins", "--llm", "--risk-review", "--upload"
    )
    assert exit_code == 0
    assert "Not used for Jenkins (GitHub Actions only): --llm, --risk-review" in printed
    assert "Skylos Cloud uploads are not generated for Jenkins" in printed


@pytest.mark.parametrize(
    "argv",
    [
        ("--ci", "circleci", "--default-branch", "main\n  - injected"),
        ("--ci", "gitlab", "--python-version", "3.12; id"),
    ],
)
def test_init_rejects_bad_options_without_writing(tmp_path, monkeypatch, argv):
    exit_code, printed = _init(tmp_path, monkeypatch, *argv)
    assert exit_code == 1
    assert "Invalid workflow option" in printed
    assert list(tmp_path.iterdir()) == []


def test_other_has_no_file_to_write():
    assert OTHER.config is None
    assert "other" in platforms.CI_CHOICES


def _doctor_lines(cwd):
    console = Mock()
    doctor_cmd._print_workflow_status(console, cwd)
    return [str(call.args[0]) for call in console.print.call_args_list if call.args]


def test_doctor_keeps_its_messages_without_other_ci(tmp_path):
    assert _doctor_lines(tmp_path) == [
        "  [yellow]--[/yellow]  No CI/CD workflow [dim](run: skylos cicd init)[/dim]"
    ]
    _tree(tmp_path, ".github/workflows/skylos.yml")
    assert _doctor_lines(tmp_path) == ["  [green]OK[/green]  GitHub Actions workflow found"]


def test_doctor_says_which_ci_does_not_run_skylos(tmp_path):
    _tree(tmp_path, "Jenkinsfile", ".travis.yml")
    lines = _doctor_lines(tmp_path)
    assert lines == [
        "  [yellow]--[/yellow]  Jenkins (Jenkinsfile) does not run Skylos "
        "[dim](run: skylos cicd init --ci jenkins)[/dim]",
        "  [yellow]--[/yellow]  Travis CI (.travis.yml) does not run Skylos "
        "[dim](run: skylos cicd init --ci other)[/dim]",
    ]


def test_doctor_finds_skylos_in_any_ci_file(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "steps:\n  - run: skylos . --gate\n", encoding="utf-8"
    )
    (tmp_path / "Jenkinsfile").write_text("sh 'skylos . --gate'\n", encoding="utf-8")
    assert _doctor_lines(tmp_path) == [
        "  [green]OK[/green]  GitHub Actions runs Skylos (.github/workflows/ci.yml)",
        "  [green]OK[/green]  Jenkins runs Skylos (Jenkinsfile)",
    ]
    report = doctor_cmd._ci_report(tmp_path)
    assert report["status"] == "ok"
    assert report["runtime"] is None
    assert [p["key"] for p in report["platforms"]] == ["github", "jenkins"]


def test_doctor_in_a_jenkins_pull_request_shows_the_base_and_fetch(
    monkeypatch, origin, tmp_path
):
    clone = _clone(origin, tmp_path, "pr", "--single-branch", "--branch", "feature")
    _set(monkeypatch, JENKINS_PR)
    lines = _doctor_lines(clone)
    assert "  [green]OK[/green]  Jenkins pull request: --diff compares with origin/develop" in lines
    assert any("On Jenkins, run this before the scan: git fetch" in line for line in lines)
    runtime = doctor_cmd._ci_report(clone)["runtime"]
    assert runtime["name"] == "Jenkins"
    assert runtime["pull_request"] is True
    assert runtime["diff_base"] == "origin/develop"
