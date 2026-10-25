"""CI platforms that `skylos cicd init` and `skylos doctor` recognize.

GitHub Actions keeps its own generator in skylos/cicd/workflow.py. The other
platforms get a pull request gate built around one scan command,
`skylos <path> <checks> --gate --diff`, wrapped in each CI's own syntax.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.cicd.workflow import (
    ANALYSIS_FLAG_MAP,
    _shell_path,
    is_valid_branch_name,
    skylos_requirement,
)

CI_PLATFORMS_GUIDE_URL = (
    "https://github.com/duriantaco/skylos/blob/main/docs/ci-platforms.md"
)
DEFAULT_ANALYSIS = (
    "dead-code",
    "security",
    "quality",
    "ai-defects",
    "secrets",
    "dependency",
)
_PYTHON_VERSION_RE = re.compile(r"3\.[0-9]{1,2}(\.[0-9]{1,3})?")
_MAX_CONFIG_BYTES = 512 * 1024
_MAX_CONFIG_FILES = 50
_REMOTE_HOST_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/]+@)?([^/:]+)")


@dataclass(frozen=True)
class Platform:
    key: str
    name: str
    markers: tuple[str, ...]
    config: str | None = None
    anchor: str = "other-ci"


PLATFORMS = (
    Platform(
        "github",
        "GitHub Actions",
        (".github/workflows",),
        ".github/workflows/skylos.yml",
        "github-actions",
    ),
    Platform("gitlab", "GitLab CI", (".gitlab-ci.yml",), ".gitlab-ci.yml", "gitlab-ci"),
    Platform("jenkins", "Jenkins", ("Jenkinsfile",), "Jenkinsfile", "jenkins"),
    Platform(
        "bitbucket",
        "Bitbucket Pipelines",
        ("bitbucket-pipelines.yml",),
        "bitbucket-pipelines.yml",
        "bitbucket-pipelines",
    ),
    Platform(
        "azure",
        "Azure Pipelines",
        ("azure-pipelines.yml", "azure-pipelines.yaml"),
        "azure-pipelines.yml",
        "azure-pipelines",
    ),
    Platform(
        "circleci",
        "CircleCI",
        (".circleci/config.yml", ".circleci/config.yaml"),
        ".circleci/config.yml",
        "circleci",
    ),
    Platform("buildkite", "Buildkite", (".buildkite",)),
    Platform("travis", "Travis CI", (".travis.yml",)),
    Platform("drone", "Drone", (".drone.yml",)),
    Platform(
        "woodpecker",
        "Woodpecker",
        (".woodpecker.yml", ".woodpecker.yaml", ".woodpecker"),
    ),
    Platform("teamcity", "TeamCity", (".teamcity",)),
)
OTHER = Platform("other", "your CI", ())
BY_KEY = {platform.key: platform for platform in PLATFORMS}
CI_CHOICES = tuple(p.key for p in PLATFORMS if p.config) + (OTHER.key,)
_REMOTE_HOSTS = (
    ("github.com", "github"),
    ("gitlab.com", "gitlab"),
    ("bitbucket.org", "bitbucket"),
    ("dev.azure.com", "azure"),
    ("visualstudio.com", "azure"),
)


@dataclass(frozen=True)
class Found:
    platform: Platform
    path: Path
    runs_skylos: Path | None = None


@dataclass(frozen=True)
class Choice:
    platform: Platform | None
    found: tuple[Found, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class Settings:
    python_version: str = "3.12"
    analysis_types: tuple[str, ...] = DEFAULT_ANALYSIS
    use_baseline: bool = True
    scan_path: str = "."
    default_branch: str | None = None
    skylos_version: str | None = None


@dataclass(frozen=True)
class Rendered:
    full: str
    snippet: str
    where: str
    notes: tuple[str, ...] = field(default_factory=tuple)


def _config_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    files = sorted(child for child in path.iterdir() if child.is_file())
    return files[:_MAX_CONFIG_FILES]


def _mentions_skylos(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            data = handle.read(_MAX_CONFIG_BYTES)
    except OSError:
        return False
    return b"skylos" in data.lower()


def detect_repo_platforms(root: Path) -> list[Found]:
    """CI platforms whose config files are in this repository."""
    found = []
    for platform in PLATFORMS:
        for marker in platform.markers:
            path = root / marker
            if not (path.is_file() or path.is_dir()):
                continue
            runs = next((f for f in _config_files(path) if _mentions_skylos(f)), None)
            found.append(Found(platform, path, runs))
            break
    return found


def platform_from_remote(url: str | None) -> Platform | None:
    match = _REMOTE_HOST_RE.match((url or "").strip())
    if not match:
        return None
    host = match.group(1).lower()
    for suffix, key in _REMOTE_HOSTS:
        if host == suffix or host.endswith(f".{suffix}"):
            return BY_KEY[key]
    return None


def platform_from_output(output: str) -> Platform:
    path = PurePosixPath(str(output).replace("\\", "/"))
    for platform in PLATFORMS:
        if not platform.config or platform.key == "github":
            continue
        config = PurePosixPath(platform.config)
        if path.parts[-len(config.parts) :] == config.parts:
            return platform
    return BY_KEY["github"]


def choose_platform(root: Path, remote_url: str | None) -> Choice:
    """Pick the platform `skylos cicd init` sets up when --ci is not given.

    A repository with GitHub workflows keeps getting the GitHub workflow. Any
    other single CI found by its config file wins next, then the code host of
    origin, then GitHub Actions as before.
    """
    found = tuple(detect_repo_platforms(root))
    keys = [f.platform.key for f in found]
    if "github" in keys:
        return Choice(BY_KEY["github"], found, "found .github/workflows")
    templated = [f for f in found if f.platform.config]
    if len(templated) == 1:
        only = templated[0]
        return Choice(only.platform, found, f"found {only.path.name}")
    if len(templated) > 1:
        return Choice(None, found, "found more than one CI")
    if found:
        return Choice(OTHER, found, f"found {found[0].path.name}")
    remote = platform_from_remote(remote_url)
    if remote:
        return Choice(remote, found, "origin is on that code host")
    return Choice(BY_KEY["github"], found, "")


def _validate(settings: Settings, platform: Platform) -> None:
    if not _PYTHON_VERSION_RE.fullmatch(str(settings.python_version)):
        raise ValueError("python_version must look like 3.12")
    if settings.default_branch is not None and not is_valid_branch_name(
        settings.default_branch
    ):
        raise ValueError("default_branch may only contain letters, digits and . _ / -")
    if platform.key == "jenkins" and "\\" in str(settings.scan_path):
        raise ValueError("scan_path must not contain backslashes in a Jenkinsfile")


def _scan_command(
    settings: Settings, *, skylos: str = "skylos", base: str | None = None
) -> str:
    parts = [skylos, _shell_path(settings.scan_path)]
    for kind in settings.analysis_types:
        flag = ANALYSIS_FLAG_MAP.get(kind)
        if flag and flag not in parts:
            parts.append(flag)
    if settings.use_baseline:
        parts.append("--baseline")
    parts += ["--gate", "--diff"]
    if base:
        parts.append(shlex.quote(base))
    return " ".join(parts)


def _fetch_command(branch: str) -> str:
    return f'git fetch --no-tags origin "+refs/heads/{branch}:refs/remotes/origin/{branch}"'


def _indent(lines: list[str], spaces: int) -> list[str]:
    pad = " " * spaces
    return [f"{pad}{line}" for line in lines]


def _header(prefix: str, key: str, lines: tuple[str, ...]) -> list[str]:
    first = (
        f"{prefix} Skylos pull request gate, written by `skylos cicd init --ci {key}`."
    )
    return [first, *(f"{prefix} {line}" for line in lines)]


def _gitlab(settings: Settings, requirement: str) -> Rendered:
    job = [
        "skylos:",
        "  stage: test",
        f"  image: python:{settings.python_version}",
        "  variables:",
        '    GIT_DEPTH: "0"',
        "  rules:",
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'",
        "  script:",
        f"    - python -I -m pip install {requirement}",
        f"    - {_fetch_command('$CI_MERGE_REQUEST_TARGET_BRANCH_NAME')}",
        "    - >-",
        f"      {_scan_command(settings)}",
    ]
    header = _header(
        "#",
        "gitlab",
        (
            "Merge request pipelines scan the lines the merge request changes and",
            "fail when the Skylos gate fails.",
        ),
    )
    return Rendered(
        full="\n".join([*header, *job]) + "\n",
        snippet="\n".join(job),
        where="Add this job to .gitlab-ci.yml (it runs in the test stage):",
        notes=("runs in merge request pipelines",),
    )


def _jenkins(settings: Settings, requirement: str) -> Rendered:
    scan = _scan_command(settings, skylos='"$SKYLOS_VENV/bin/skylos"')
    stage = [
        "stage('Skylos') {",
        "    when { changeRequest() }",
        "    steps {",
        "        sh '''",
        '            SKYLOS_VENV="${WORKSPACE_TMP:-$WORKSPACE@tmp}/skylos-venv"',
        '            python3 -m venv "$SKYLOS_VENV"',
        f'            "$SKYLOS_VENV/bin/python" -I -m pip install {requirement}',
        '            if ! git rev-parse --verify --quiet "origin/$CHANGE_TARGET^{commit}" >/dev/null; then',
        f"                {_fetch_command('$CHANGE_TARGET')}",
        "            fi",
        f"            {scan}",
        "        '''",
        "    }",
        "}",
    ]
    header = _header(
        "//",
        "jenkins",
        (
            "Multibranch Pipeline pull request builds scan the lines the pull",
            "request changes and fail when the Skylos gate fails.",
            "The agent needs Python 3.10 or newer as python3. To scan Dart",
            "files, install 'skylos[dart]' instead; it needs a C compiler.",
        ),
    )
    full = [
        *header,
        "pipeline {",
        "    agent any",
        "    stages {",
        *_indent(stage, 8),
        "    }",
        "}",
    ]
    return Rendered(
        full="\n".join(full) + "\n",
        snippet="\n".join(stage),
        where="Add this stage inside stages { } in your Jenkinsfile:",
        notes=(
            "runs in Multibranch Pipeline pull request builds",
            "the agent needs python3 (3.10 or newer)",
            "Dart files: install 'skylos[dart]' instead (needs a C compiler)",
            "private repository and the fetch fails: give the step Git credentials",
        ),
    )


def _bitbucket(settings: Settings, requirement: str) -> Rendered:
    step = [
        "- step:",
        "    name: Skylos quality gate",
        "    script:",
        f"      - python -I -m pip install {requirement}",
        f"      - {_fetch_command('$BITBUCKET_PR_DESTINATION_BRANCH')}",
        "      - >-",
        f"        {_scan_command(settings)}",
    ]
    header = _header(
        "#",
        "bitbucket",
        (
            "Pull request pipelines scan the lines the pull request changes and",
            "fail when the Skylos gate fails.",
        ),
    )
    full = [
        *header,
        f"image: python:{settings.python_version}",
        "",
        "clone:",
        "  depth: full",
        "",
        "pipelines:",
        "  pull-requests:",
        "    '**':",
        *_indent(step, 6),
    ]
    return Rendered(
        full="\n".join(full) + "\n",
        snippet="\n".join(step),
        where=(
            "Add this step under pipelines: pull-requests: '**': in "
            "bitbucket-pipelines.yml, and set clone: depth: full:"
        ),
        notes=("runs in pull request pipelines",),
    )


def _azure(settings: Settings, requirement: str) -> Rendered:
    steps = [
        "- task: UsePythonVersion@0",
        "  inputs:",
        f"    versionSpec: '{settings.python_version}'",
        f"- script: python -I -m pip install {requirement}",
        "  displayName: Install Skylos",
        "- script: >-",
        f"    {_scan_command(settings)}",
        "  displayName: Skylos quality gate",
    ]
    header = _header(
        "#",
        "azure",
        (
            "Pull request builds scan the lines the pull request changes and fail",
            "when the Skylos gate fails.",
        ),
    )
    full = [
        *header,
        "trigger: none",
        "",
        "pool:",
        "  vmImage: ubuntu-latest",
        "",
        "steps:",
        "  - checkout: self",
        "    fetchDepth: 0",
        *_indent(steps, 2),
    ]
    return Rendered(
        full="\n".join(full) + "\n",
        snippet="\n".join(steps),
        where=(
            "Set fetchDepth: 0 on your checkout: self step, then add these "
            "steps to azure-pipelines.yml:"
        ),
        notes=(
            "runs on pull request builds",
            "Azure Repos: add the pipeline as the target branch's Build validation policy",
        ),
    )


def _circleci(settings: Settings, requirement: str) -> Rendered:
    branch = settings.default_branch or "main"
    job = [
        "skylos:",
        "  docker:",
        f"    - image: python:{settings.python_version}",
        "  steps:",
        "    - checkout",
        "    - run:",
        "        name: Install Skylos",
        f"        command: python -I -m pip install {requirement}",
        "    - run:",
        "        name: Skylos quality gate",
        "        command: |",
        '          if [ -z "$CIRCLE_PULL_REQUEST" ]; then',
        '            echo "No pull request for this build; Skylos gate skipped."',
        "            exit 0",
        "          fi",
        f"          {_fetch_command(branch)}",
        f"          {_scan_command(settings, base=f'origin/{branch}')}",
    ]
    header = _header(
        "#",
        "circleci",
        (
            f"Builds with an open pull request scan the lines it changes since {branch}",
            "and fail when the Skylos gate fails.",
        ),
    )
    full = [
        *header,
        "version: 2.1",
        "",
        "jobs:",
        *_indent(job, 2),
        "",
        "workflows:",
        "  skylos:",
        "    jobs:",
        "      - skylos",
    ]
    return Rendered(
        full="\n".join(full) + "\n",
        snippet="\n".join(job),
        where=(
            "Add this job under jobs: in .circleci/config.yml, and add "
            "- skylos to a workflow's jobs:"
        ),
        notes=(
            f"runs on builds with an open pull request; compares with origin/{branch}",
            f"pull requests into another branch: change {branch} in the file",
        ),
    )


def _other(settings: Settings, requirement: str) -> Rendered:
    branch = settings.default_branch or "main"
    commands = [
        f"python -I -m pip install {requirement}",
        _fetch_command(branch),
        _scan_command(settings, base=f"origin/{branch}"),
    ]
    return Rendered(
        full="",
        snippet="\n".join(commands),
        where="Run these in a pull request build step (Python 3.10 or newer):",
        notes=(
            f"compares with origin/{branch}; change {branch} if the pull request targets another branch",
            "the scan exits non-zero when the gate fails, which fails the step",
            "Dart files: install 'skylos[dart]' instead (needs a C compiler)",
        ),
    )


_RENDERERS = {
    "gitlab": _gitlab,
    "jenkins": _jenkins,
    "bitbucket": _bitbucket,
    "azure": _azure,
    "circleci": _circleci,
    "other": _other,
}
_UNKNOWN_AGENT_KEYS = frozenset({"jenkins", "other"})


def render(platform: Platform, settings: Settings) -> Rendered:
    """The CI config for a non-GitHub platform; raises ValueError on bad input.

    Image-based templates run on python images that ship a C compiler, so they
    install the Dart grammar like the GitHub workflow. Jenkins agents and
    unknown CIs may have no compiler, so they install plain skylos.
    """
    _validate(settings, platform)
    renderer = _RENDERERS.get(platform.key, _other)
    dart = platform.key not in _UNKNOWN_AGENT_KEYS
    requirement = skylos_requirement(settings.skylos_version, dart=dart)
    return renderer(settings, requirement)


def print_platform_next_steps(
    console,
    *,
    platform: Platform,
    name: str,
    rendered: Rendered,
    written: str | None,
    upload_requested: bool = False,
) -> None:
    """Say what the generated gate does and how to get it on a pull request."""
    from rich.markup import escape

    from skylos.cicd.workflow import display_path

    label = "Skylos gate"
    indent = " " * (len(label) + 4)
    console.print()
    console.print("[bold]Pull requests[/bold]")
    console.print(
        f"  {label}  scans the changed lines; fails when the gate fails",
        soft_wrap=True,
    )
    for note in rendered.notes:
        console.print(f"{indent}{escape(note)}", soft_wrap=True)
    if upload_requested:
        console.print(
            f"[yellow]Skylos Cloud uploads are not generated for {escape(name)}; "
            "the guide shows the upload step.[/yellow]",
            soft_wrap=True,
        )
    console.print()
    console.print("[bold]Next[/bold]")
    if written:
        console.print(
            f"  1. Commit {escape(display_path(written))} on a new branch and "
            "open a pull request.",
            soft_wrap=True,
        )
    elif platform.config:
        console.print(
            f"  1. Add the block above to {escape(platform.config)} on a new "
            "branch and open a pull request.",
            soft_wrap=True,
        )
    else:
        console.print(
            f"  1. Add the commands above to a pull request step in {escape(name)} "
            "and open a pull request.",
            soft_wrap=True,
        )
    console.print(
        "  2. Check that the Skylos gate runs on it and passes or fails as expected."
    )
    console.print(
        "  3. Require that check before merging, in your code host's branch protection."
    )
    console.print(
        f"  Guide: {CI_PLATFORMS_GUIDE_URL}#{platform.anchor}", soft_wrap=True
    )


def missing_base_hint(base_ref: str | None, root: str | Path) -> str | None:
    """A git command that makes ``origin/<branch>`` usable as a diff base.

    None when the base is not a remote branch, or it is already there with
    full history.
    """
    if not base_ref or not str(base_ref).startswith("origin/"):
        return None
    from skylos.core.ci_env import ci_name, safe_branch_name
    from skylos.core.git_context import GitContext

    branch = safe_branch_name(str(base_ref)[len("origin/") :])
    if not branch:
        return None
    context = GitContext.from_path(root)
    present = context.run("rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}")
    shallow = context.run("rev-parse", "--is-shallow-repository")
    is_shallow = shallow.returncode == 0 and shallow.stdout.strip() == "true"
    if present.returncode == 0 and not is_shallow:
        return None
    command = ["git", "fetch", "--no-tags"]
    if is_shallow:
        command.append("--unshallow")
    command += ["origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}"]
    name = ci_name()
    if name:
        return f"On {name}, run this before the scan: {' '.join(command)}"
    return f"To fetch it: {' '.join(command)}"
