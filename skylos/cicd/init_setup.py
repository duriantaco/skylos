"""Repository checks and console guidance for `skylos cicd init`.

Detection decides whether the generated workflow can run `skylos done` and
how its job installs the project's tests; workflow.py renders the YAML.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shlex
from typing import Any

from rich.console import Console
from rich.markup import escape

from skylos.cicd.workflow import (
    DONE_JOB_NAME,
    FIRST_GATED_PR_GUIDE_URL,
    GATE_JOB_NAME,
    PR_PUBLISH_JOB_NAME,
    RISK_REVIEW_JOB_NAME,
    UPLOAD_JOB_NAME,
)

_REQUIREMENTS_FILES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "dev-requirements.txt",
    "requirements-test.txt",
    "requirements_test.txt",
    "test-requirements.txt",
    "requirements/dev.txt",
    "requirements/test.txt",
)
_TEST_EXTRAS = ("test", "tests", "testing", "dev")
_NODE_TEST_PROGRAMS = {"npm", "npx", "yarn", "pnpm", "node", "jest", "vitest", "bun"}
_VITEST_JUNIT = "reports/junit.xml"


@dataclass(frozen=True)
class DoneSetup:
    """Whether `skylos done` can run this repository's tests in CI, and how
    the generated job installs what those tests need."""

    enabled: bool
    reason: str
    install_commands: tuple[str, ...]
    # Done does not start JavaScript runners on its own. When a Vitest or
    # Jest project has no test_command, these are the [tool.skylos.done]
    # lines that make Done run its tests, and what to install first.
    suggested_settings: tuple[str, ...] = ()
    suggested_install: str = ""


def _read_pyproject(root: Path) -> dict[str, Any]:
    path = root / "pyproject.toml"
    if not path.is_file():
        return {}
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        import tomli as tomllib
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _table(data: Any, *keys: str) -> dict[str, Any]:
    for key in keys:
        data = data.get(key) if isinstance(data, dict) else None
    return data if isinstance(data, dict) else {}


def _looks_like_pytest_project(root: Path) -> bool:
    """The same test as `skylos done` uses to run pytest automatically."""
    from skylos.done.runner import has_pytest_config

    return has_pytest_config(root) or any(
        (root / name).is_dir() for name in ("tests", "test")
    )


def _is_installable_python_project(root: Path, pyproject: dict[str, Any]) -> bool:
    if (root / "setup.py").is_file():
        return True
    if "build-system" in pyproject or "project" in pyproject:
        return True
    setup_cfg = root / "setup.cfg"
    try:
        return setup_cfg.is_file() and "[metadata]" in setup_cfg.read_text("utf-8")
    except (OSError, UnicodeError):
        return False


def _done_install_commands(
    root: Path, pyproject: dict[str, Any], *, node: bool
) -> tuple[str, ...]:
    pip_args: list[str] = []
    if _is_installable_python_project(root, pyproject):
        extras = _table(pyproject, "project", "optional-dependencies")
        extra = next((name for name in _TEST_EXTRAS if name in extras), None)
        if extra:  # one of the fixed names above, so safe to quote
            pip_args.append(f'-e ".[{extra}]"')
        else:
            pip_args.append("-e .")
    for requirements in _REQUIREMENTS_FILES:
        if (root / requirements).is_file():
            pip_args.extend(["-r", requirements])
    pip_args.append("pytest")
    commands = ["python -I -m pip install " + " ".join(pip_args)]
    if node and (root / "package.json").is_file():
        commands.append(
            "npm ci" if (root / "package-lock.json").is_file() else "npm install"
        )
    return tuple(commands)


def _runs_node_tests(test_command: Any) -> bool:
    if isinstance(test_command, str):
        try:
            argv = shlex.split(test_command)
        except ValueError:
            return False
    elif isinstance(test_command, list):
        argv = [str(part) for part in test_command]
    else:
        return False
    return bool(argv) and Path(argv[0]).name in _NODE_TEST_PROGRAMS


def _read_package_json(root: Path) -> dict[str, Any]:
    try:
        data = json.loads((root / "package.json").read_text("utf-8"))
    except (OSError, UnicodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _jest_junit_path(package: dict[str, Any]) -> str:
    """Where jest-junit writes, from its package.json settings."""
    settings = package.get("jest-junit")
    settings = settings if isinstance(settings, dict) else {}
    directory = str(settings.get("outputDirectory") or ".")
    name = str(settings.get("outputName") or "junit.xml")
    directory = directory.replace("<rootDir>", ".").strip("/") or "."
    return (
        name if directory in {".", "./"} else f"{directory.removeprefix('./')}/{name}"
    )


def _js_runner_settings(root: Path) -> tuple[str, tuple[str, ...], str] | None:
    """(runner, [tool.skylos.done] lines, install hint) for a root
    package.json that depends on Vitest or Jest."""
    package = _read_package_json(root)
    dependencies: dict[str, Any] = {}
    for key in ("devDependencies", "dependencies"):
        if isinstance(package.get(key), dict):
            dependencies.update(package[key])
    if "vitest" in dependencies:
        return (
            "Vitest",
            (
                'test_command = "npx vitest run --reporter=default '
                f'--reporter=junit --outputFile.junit={_VITEST_JUNIT}"',
                f'junit_xml = "{_VITEST_JUNIT}"',
            ),
            "",
        )
    if "jest" in dependencies:
        install = (
            "" if "jest-junit" in dependencies else "npm install --save-dev jest-junit"
        )
        return (
            "Jest",
            (
                'test_command = "npx jest --ci --reporters=default --reporters=jest-junit"',
                f'junit_xml = "{_jest_junit_path(package)}"',
            ),
            install,
        )
    return None


def detect_done_setup(repo_root: str | Path) -> DoneSetup:
    """Decide whether the generated workflow should include `skylos done`.

    Done blocks a pull request whose tests it cannot run, so the job is only
    added when Done will find tests: a pytest project (the same detection
    Done uses) or a configured [tool.skylos.done] test_command.
    """
    root = Path(repo_root)
    pyproject = _read_pyproject(root)
    test_command = _table(pyproject, "tool", "skylos", "done").get("test_command")
    pytest_project = _looks_like_pytest_project(root)
    install = _done_install_commands(
        root, pyproject, node=_runs_node_tests(test_command)
    )
    if test_command:
        return DoneSetup(True, "[tool.skylos.done] test_command is set", install)
    if pytest_project:
        return DoneSetup(True, "pytest project found", install)
    js_runner = _js_runner_settings(root)
    if js_runner is not None:
        runner, settings, js_install = js_runner
        return DoneSetup(
            False,
            f"{runner} found, but Done needs a test_command that writes JUnit XML",
            install,
            suggested_settings=settings,
            suggested_install=js_install,
        )
    return DoneSetup(
        False,
        "no pytest project or [tool.skylos.done] test_command found",
        install,
    )


def _display_path(path: str) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def print_init_next_steps(
    console: Console,
    *,
    output_path: str,
    triggers: list[str],
    upload: bool,
    done_requested: bool | None,
    done_setup: DoneSetup,
    push_branches: tuple[str, ...],
    branch_detected: bool,
    risk_review: bool = False,
    pr_upload: bool = False,
) -> None:
    """Say what each generated job does and how to open the first gated PR."""
    pr = "pull_request" in triggers
    done = pr and done_setup.enabled
    branch_text = escape(" or ".join(push_branches))
    width = len(PR_PUBLISH_JOB_NAME) + 2
    indent = " " * (width + 2)

    def row(name: str, *lines: str) -> None:
        console.print(f"  {name:<{width}}{lines[0]}", soft_wrap=True)
        for line in lines[1:]:
            console.print(f"{indent}{line}", soft_wrap=True)

    console.print()
    if pr:
        console.print("[bold]Pull requests[/bold]")
        row(GATE_JOB_NAME, "scans the changed lines; fails when the gate fails")
        if done:
            row(
                DONE_JOB_NAME,
                f"runs your tests ({escape(done_setup.reason)})",
                "installs: " + escape(" && ".join(done_setup.install_commands)),
                "edit that step in the workflow if your tests need more",
            )
        elif done_requested is None and done_setup.suggested_settings:
            steps = []
            if done_setup.suggested_install:
                steps.append(f"first: {done_setup.suggested_install}")
            steps.append(
                "add to pyproject.toml (create it if needed) and commit it to "
                "your default branch: Done reads settings from there"
            )
            steps += ["  [tool.skylos.done]"]
            steps += [f"  {line}" for line in done_setup.suggested_settings]
            steps.append("then rerun: skylos cicd init --done")
            row(
                DONE_JOB_NAME,
                f"not added: {escape(done_setup.reason)}",
                *(escape(step) for step in steps),
            )
        elif done_requested is None:
            row(
                DONE_JOB_NAME,
                f"not added: {escape(done_setup.reason)}",
                escape(
                    "set test_command in [tool.skylos.done], then rerun with --done"
                ),
            )
        if risk_review:
            row(
                RISK_REVIEW_JOB_NAME,
                "fails while the PR has risks no person with write access approved",
                "(deleted tests, removed auth, new dependencies, weakened CI, ...);",
                "bot approvals do not count; reruns when a review is submitted",
            )
    if upload and "push" in triggers:
        console.print(f"[bold]Pushes to {branch_text}[/bold]")
        row(
            UPLOAD_JOB_NAME,
            "full scan to Skylos Cloud with GitHub OIDC; no API key secret",
            "needs the Skylos GitHub App on this repository",
            "(without Cloud: rerun with --no-upload)",
        )
        if pr and pr_upload:
            console.print(f"[bold]Pull requests to {branch_text}[/bold]")
            row(
                PR_PUBLISH_JOB_NAME,
                "scans the PR head as data with no credentials; a job that",
                "never checks it out uploads it with GitHub OIDC",
                "starts with PRs opened or updated after this file is merged",
            )
    if "push" in triggers and not branch_detected:
        console.print(
            f"[yellow]No origin/HEAD, so pushes to {branch_text} trigger it; "
            "use --default-branch to change.[/yellow]",
            soft_wrap=True,
        )

    required = (
        [GATE_JOB_NAME]
        + ([DONE_JOB_NAME] if done else [])
        + ([RISK_REVIEW_JOB_NAME] if pr and risk_review else [])
    )
    console.print()
    console.print("[bold]Next[/bold]")
    console.print("  1. Open a pull request that adds the workflow:")
    console.print("     git checkout -b add-skylos-gate")
    console.print(f"     git add {escape(_display_path(output_path))}", soft_wrap=True)
    console.print('     git commit -m "Add Skylos pull request gate"')
    console.print("     git push -u origin add-skylos-gate")
    console.print("     gh pr create --fill")
    console.print("  2. Wait for: " + ", ".join(required))
    console.print(
        "  3. Make those checks required on your default branch "
        "(the guide has a one-line gh command)."
    )
    console.print(f"  Guide: {FIRST_GATED_PR_GUIDE_URL}", soft_wrap=True)
