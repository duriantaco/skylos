"""Were the failing tests already failing on the base? (``skylos done``)

When tests fail, coding agents often call the failures "pre-existing" and
stop. Skylos checks the claim instead of trusting it. After a test run with
failures, it checks the base commit out into a temporary Git worktree outside
the repository (the user's working tree, index, HEAD and refs are never
touched), runs only the failing tests there with the same command and the
same installed environment, and labels each failure:

* ``preexisting``: it fails on the base too;
* ``introduced``: it passes on the base, so this change broke it;
* ``new_test``: it does not exist on the base (counts as introduced);
* ``undetermined``: the base run could not tell (it errored or ran out of
  time, a dependency manifest or lockfile changed, the base checkout imported
  code from the working tree, a control test that passes in the working tree
  failed in the base checkout, or the command cannot run there without
  installing anything).

Nothing is installed. pytest runs with the same interpreter or command and
the base checkout first on the import path; JavaScript runners reuse the
repository's node_modules through symlinks, with workspace package links
pointed at the base checkout's copies.

The labels never loosen the gate on their own: every failing test still
fails ``tests_pass`` unless a person sets ``allow_preexisting_failures =
true`` in the base's ``[tool.skylos.done]``. Then failures verified as
preexisting stop blocking; introduced, new and undetermined ones still
block. The setting applies only when the base is a pull request's merge base
or an agent session's starting point, never to plain ``skylos done`` (base
HEAD), where an agent's own commits would count as "the base".
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from skylos.core.git_safety import read_only_git_command
from skylos.done.base import Comparison, DoneError

if TYPE_CHECKING:
    from skylos.done.checks import CheckContext
    from skylos.done.runner import CaseResult, TestRunResult

ORIGINS = ("preexisting", "introduced", "new_test", "undetermined")
# Origins that count against the change.
INTRODUCED = frozenset({"introduced", "new_test"})
# Bases a change cannot have written itself: a pull request's merge base and
# an agent session's starting point. HEAD can hold the agent's own commits.
TRUSTED_BASES = frozenset({"merge_base", "session"})

MAX_VERIFIED_TESTS = 100
MAX_CONTROL_TESTS = 3
MAX_DETAIL_CHARS = 160
_MIN_CONFIRM_SECONDS = 5.0
_WORKTREE_PREFIX = "skylos-done-base-"
_GIT_TIMEOUT_SECONDS = 120
_MAX_NODE_MODULES_DIRS = 200
_MAX_WALK_DIRS = 20000
_MAX_WALK_DEPTH = 6
# Caches a runner writes under node_modules: never shared with the base run.
_UNSHARED_NODE_MODULES = frozenset({".cache", ".vite", ".vitest", ".jest-cache"})
_SKIP_WALK = frozenset(
    {".git", ".hg", ".svn", ".venv", "venv", ".tox", ".nox", "__pycache__"}
)

# Changes to these mean the installed packages match only one side, so a
# base run with them proves nothing.
_DEPENDENCY_FILES = frozenset(
    {
        # Python
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "environment.yml",
        "environment.yaml",
        # JavaScript
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "bun.lock",
        "bun.lockb",
        ".pnp.cjs",
        # Go, Rust, Ruby, PHP, JVM
        "go.mod",
        "go.sum",
        "go.work",
        "go.work.sum",
        "Cargo.toml",
        "Cargo.lock",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
    }
)
_REQUIREMENTS_RE = re.compile(
    r"^(?:requirements|constraints)[\w.-]*\.(?:txt|in)$|^pylock\.[\w.-]*toml$"
)
_PACKAGE_JSON_KEYS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundleDependencies",
    "bundledDependencies",
    "overrides",
    "resolutions",
    "pnpm",
    "workspaces",
    "packageManager",
)
# Commands that create or sync their own environment: running them in the
# base checkout would install packages there.
_ENVIRONMENT_MANAGERS = frozenset(
    {
        "uv",
        "uvx",
        "poetry",
        "pdm",
        "hatch",
        "pipenv",
        "rye",
        "tox",
        "nox",
        "pixi",
        "conda",
        "mamba",
        "micromamba",
    }
)
_JS_TEST_FILE_RE = re.compile(r"\.(?:c|m)?[jt]sx?$")
# A base failure of these kinds says the base checkout could not set the
# test up (a module, file or fixture is missing, the code does not parse),
# not that the test's own check failed there: never "preexisting".
_SETUP_KINDS = frozenset(
    {
        "ImportError",
        "ModuleNotFoundError",
        "SyntaxError",
        "IndentationError",
        "TabError",
        "FileNotFoundError",
        "NotADirectoryError",
        "PermissionError",
        "ConnectionError",
        "ConnectionRefusedError",
    }
)
_SETUP_MESSAGE_RE = re.compile(
    r"No module named|cannot import name|Cannot find (?:module|package)"
    r"|ERR_MODULE_NOT_FOUND|Failed to (?:load|resolve) (?:url|import)"
    r"|fixture '[^']*' not found|Test suite failed to run",
    re.IGNORECASE,
)
_JEST_REGEX_SPECIALS = re.compile(r"([\\^$.*+?()\[\]{}|])")


@dataclass
class FailureOrigin:
    test: str
    file: str | None
    line: int | None
    origin: str = "undetermined"
    detail: str = ""


@dataclass
class Attribution:
    """Where each failing test's failure comes from, for one done run."""

    base_sha: str
    base_label: str
    tests: list[FailureOrigin]
    # "checked": a base run answered for at least one test; "not_checked":
    # none was rerun (the reason says why).
    status: str = "checked"
    reason: str = ""
    seconds: float = 0.0
    command: str = ""
    # allow_preexisting_failures applied: preexisting failures do not block.
    allowed: bool = False

    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(ORIGINS, 0)
        for test in self.tests:
            counts[test.origin] = counts.get(test.origin, 0) + 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {
            "base": {"sha": self.base_sha, "label": self.base_label},
            "status": self.status,
            "reason": self.reason,
            "seconds": round(self.seconds, 1),
            "allowed": self.allowed,
            "counts": self.counts(),
            "tests": [
                {
                    "test": test.test,
                    "file": test.file,
                    "line": test.line,
                    "origin": test.origin,
                    "detail": test.detail,
                }
                for test in self.tests
            ],
        }


def base_label(comparison: Comparison) -> str:
    """How messages name the base: "origin/main (merge base 1a2b3c4)"."""
    short = comparison.base_sha[:7]
    if comparison.base_source == "merge_base":
        if comparison.base_ref:
            return f"{comparison.base_ref} (merge base {short})"
        return f"the merge base {short}"
    if comparison.base_source == "session":
        return f"the session start ({short})"
    return f"HEAD ({short})"


def display_id(case: CaseResult) -> str:
    if case.node_id:
        return case.node_id
    if case.classname and case.classname != case.name:
        return f"{case.classname} > {case.name}"
    return case.name


def judge_base_failure(head: CaseResult, base_cases: list) -> tuple[str, str]:
    """``("preexisting", message)`` only when the same test ran on the base
    and its own check failed the same way; otherwise
    ``("undetermined", reason)``. A base failure that comes from setup (an
    error outside the test body, a missing module, file or fixture, code that
    does not parse) or that differs in kind from this one proves nothing about
    the change, and calling it "preexisting" would hand the agent its excuse.
    """
    errored = [c for c in base_cases if c.outcome == "error"]
    if errored:
        return "undetermined", _short(
            "errored outside the test body on the base (setup or teardown)"
            + (f": {errored[0].message}" if errored[0].message else "")
        )
    failed = next(c for c in base_cases if c.outcome == "failed")
    kind = failed.kind
    message = failed.message or ""
    if kind in _SETUP_KINDS or _SETUP_MESSAGE_RE.search(message):
        return "undetermined", _short(
            f"fails on the base for a setup reason ({kind or 'missing module'})"
            + (f": {message}" if message else "")
        )
    if head.kind and kind and head.kind != kind:
        return "undetermined", _short(
            f"fails differently on the base ({kind} there, {head.kind} here)"
        )
    return "preexisting", _short(message)


def label(origin: FailureOrigin, base: str) -> str:
    """The words a failing-test finding carries after "<test> failed"."""
    if origin.origin == "preexisting":
        return f"already failing on {base}"
    if origin.origin == "introduced":
        return f"introduced by this change: passes on {base}"
    if origin.origin == "new_test":
        return f"introduced by this change: new test, not on {base}"
    return "not checked on the base" + (f": {origin.detail}" if origin.detail else "")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


class _Terminated(BaseException):
    """SIGTERM while the base checkout exists: clean up, then die as asked."""


def unchecked(
    comparison: Comparison, result: TestRunResult, reason: str
) -> Attribution:
    attribution = Attribution(
        base_sha=comparison.base_sha,
        base_label=base_label(comparison),
        tests=[
            FailureOrigin(display_id(case), case.file, case.line)
            for case in result.failures
        ],
    )
    if reason:
        _undetermined(attribution, reason)
        attribution.status = "not_checked"
    return attribution


def attribute_failures(ctx: CheckContext, result: TestRunResult) -> Attribution:
    started = time.monotonic()
    attribution = unchecked(ctx.comparison, result, "")
    previous = _install_term_handler()
    try:
        try:
            _attribute(ctx, result, attribution, started)
        except DoneError as exc:
            _undetermined(attribution, str(exc))
    except _Terminated:
        _restore_term_handler(previous)
        previous = None
        os.kill(os.getpid(), signal.SIGTERM)
        raise
    finally:
        if previous is not None:
            _restore_term_handler(previous)
    attribution.seconds = time.monotonic() - started
    if not any(test.origin != "undetermined" for test in attribution.tests):
        attribution.status = "not_checked"
        if not attribution.reason:
            details = [t.detail for t in attribution.tests if t.detail]
            attribution.reason = details[0] if details else "no base result"
    return attribution


def _install_term_handler():
    if threading.current_thread() is not threading.main_thread():
        return None
    try:
        current = signal.getsignal(signal.SIGTERM)
        if current not in (signal.SIG_DFL, None):
            return None  # someone else handles SIGTERM; leave it to them

        def handler(signum, frame):
            raise _Terminated()

        signal.signal(signal.SIGTERM, handler)
        return current
    except (ValueError, OSError):  # pragma: no cover - not the main thread
        return None


def _restore_term_handler(previous) -> None:
    try:
        signal.signal(signal.SIGTERM, previous)
    except (ValueError, OSError, TypeError):  # pragma: no cover
        pass


def _undetermined(attribution: Attribution, reason: str, indexes=None) -> None:
    reason = _short(reason)
    for index, test in enumerate(attribution.tests):
        if indexes is not None and index not in indexes:
            continue
        if test.origin == "undetermined" and not test.detail:
            test.detail = reason
    if indexes is None:
        attribution.reason = reason


def _attribute(
    ctx: CheckContext,
    result: TestRunResult,
    attribution: Attribution,
    started: float,
) -> None:
    from skylos.done.runner import _invocation

    comparison, config = ctx.comparison, ctx.config
    blocker = environment_blocker(comparison)
    if blocker:
        _undetermined(attribution, blocker)
        return
    invocation = _invocation(comparison.root, config)
    if invocation is None:
        _undetermined(attribution, "the test command is not available")
        return
    program = PurePosixPath(invocation.argv[0].replace("\\", "/")).name
    if program in _ENVIRONMENT_MANAGERS:
        _undetermined(
            attribution,
            f"the test command ({program}) sets up its own environment, and "
            "Skylos installs nothing into the base checkout",
        )
        return
    budget_end = started + config.preexisting_timeout_seconds
    with base_checkout(comparison, budget_end) as tree:
        if invocation.pytest:
            _attribute_pytest(ctx, result, attribution, invocation, tree, budget_end)
        else:
            _attribute_junit(ctx, result, attribution, invocation, tree, budget_end)


# ---------------------------------------------------------------------------
# Is a base run meaningful at all?
# ---------------------------------------------------------------------------


def environment_blocker(comparison: Comparison) -> str | None:
    """Why the installed environment cannot stand in for the base's, if so."""
    for changed in comparison.changed:
        for path in {changed.path, changed.base_path} - {None}:
            if _dependencies_differ(comparison, changed, path):
                return f"dependencies differ: {path} changed"
    if comparison.base_text(".gitmodules") is not None:
        return "the base has Git submodules, which the base checkout leaves out"
    attributes = comparison.base_text(".gitattributes") or ""
    if "filter=" in attributes:
        return (
            "the repository uses Git filters (such as LFS), which the base "
            "checkout does not run"
        )
    return None


def _dependencies_differ(comparison: Comparison, changed, path: str) -> bool:
    name = PurePosixPath(path).name
    if "node_modules/" in f"{path}/" or name in {".gitattributes"}:
        return False
    if name in _DEPENDENCY_FILES or _REQUIREMENTS_RE.match(name):
        return True
    if name == "pyproject.toml":
        return _pyproject_dependencies(
            comparison.base_text(changed.base_path)
        ) != _pyproject_dependencies(comparison.head_text(changed.head_path))
    if name == "package.json":
        return _package_dependencies(
            comparison.base_text(changed.base_path)
        ) != _package_dependencies(comparison.head_text(changed.head_path))
    return False


def _pyproject_dependencies(text: str | None):
    if text is None:
        return None
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        import tomli as tomllib
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return ("unreadable", text)
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    pdm = tool.get("pdm") if isinstance(tool.get("pdm"), dict) else {}
    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    hatch = tool.get("hatch") if isinstance(tool.get("hatch"), dict) else {}
    return json.dumps(
        {
            "build": data.get("build-system"),
            "dependencies": project.get("dependencies"),
            "optional": project.get("optional-dependencies"),
            "dynamic": project.get("dynamic"),
            "requires_python": project.get("requires-python"),
            "groups": data.get("dependency-groups"),
            "poetry": {
                key: poetry.get(key)
                for key in ("dependencies", "dev-dependencies", "group", "extras")
            },
            "pdm": pdm.get("dev-dependencies"),
            "uv": {
                key: uv.get(key)
                for key in (
                    "dev-dependencies",
                    "sources",
                    "override-dependencies",
                    "constraint-dependencies",
                    "workspace",
                )
            },
            "hatch": hatch.get("envs"),
        },
        sort_keys=True,
        default=str,
    )


def _package_dependencies(text: str | None):
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return ("unreadable", text)
    if not isinstance(data, dict):
        return ("unreadable", text)
    return json.dumps(
        {key: data.get(key) for key in _PACKAGE_JSON_KEYS}, sort_keys=True
    )


# ---------------------------------------------------------------------------
# The base checkout
# ---------------------------------------------------------------------------


class base_checkout:
    """A detached Git worktree of the base commit in a private temp folder.

    ``git worktree add`` writes only under the repository's
    ``.git/worktrees/``; the user's working tree, index, HEAD and refs stay as
    they are. Repository hooks, filters and helpers are disabled, as in every
    other Git call ``skylos done`` makes. The worktree and its registration are
    removed on the way out, including on errors, Ctrl-C and SIGTERM.
    """

    def __init__(self, comparison: Comparison, budget_end: float) -> None:
        self.comparison = comparison
        self.budget_end = budget_end
        self.parent: Path | None = None
        self.path: Path | None = None
        self.admin: Path | None = None
        self.env = {
            key: value
            for key, value in comparison._context.env.items()
            if key not in {"GIT_INDEX_FILE", "GIT_WORK_TREE"}
        }

    def __enter__(self) -> Path:
        overrides = self.comparison._context.filter_config_overrides
        if overrides is None:
            raise DoneError("could not safely read this repository's Git settings")
        self._prune_own_stale()
        self.parent = Path(tempfile.mkdtemp(prefix=_WORKTREE_PREFIX)).resolve()
        name = re.sub(r"[^A-Za-z0-9._-]", "_", self.comparison.root.name) or "base"
        self.path = self.parent / name
        try:
            completed = self._git(
                "worktree",
                "add",
                "--detach",
                "--quiet",
                str(self.path),
                self.comparison.base_sha,
                overrides=(
                    "advice.detachedHead=false",
                    "core.sparseCheckout=false",
                    "submodule.recurse=false",
                    *overrides,
                ),
                timeout=max(5.0, self.budget_end - time.monotonic()),
            )
        except subprocess.TimeoutExpired:
            self._cleanup()
            raise DoneError(
                "checking out the base ran out of time (preexisting_timeout_seconds)"
            ) from None
        except BaseException:
            self._cleanup()
            raise
        self.admin = self._admin_dir()
        if completed is None or completed.returncode != 0 or not self.path.is_dir():
            self._cleanup()
            raise DoneError("could not check out the base commit")
        return self.path

    def __exit__(self, *exc_info) -> None:
        self._cleanup()

    def _git(self, *args: str, overrides=(), timeout: float = _GIT_TIMEOUT_SECONDS):
        try:
            return subprocess.run(
                read_only_git_command(
                    list(args), config_overrides=["core.quotePath=false", *overrides]
                ),
                cwd=str(self.comparison.root),
                env=self.env,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except OSError:
            return None

    def _common_dir(self) -> Path | None:
        completed = self._git("rev-parse", "--git-common-dir", timeout=30)
        if completed is None or completed.returncode != 0:
            return None
        raw = completed.stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            return None
        path = Path(raw)
        if not path.is_absolute():
            path = self.comparison.root / path
        try:
            return path.resolve()
        except OSError:
            return None

    def _admin_dir(self) -> Path | None:
        """The worktree's registration folder, from its ``.git`` file."""
        if self.path is None:
            return None
        try:
            text = (self.path / ".git").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            return None
        if not text.startswith("gitdir:"):
            return None
        admin = Path(text[len("gitdir:") :].strip())
        if not admin.is_absolute():
            admin = self.path / admin
        try:
            admin = admin.resolve()
        except OSError:
            return None
        return admin if admin.parent.name == "worktrees" else None

    def _cleanup(self) -> None:
        if self.path is not None and self.path.exists():
            try:
                self._git("worktree", "remove", "--force", "--force", str(self.path))
            except (subprocess.SubprocessError, OSError):
                pass
        if self.parent is not None:
            shutil.rmtree(self.parent, ignore_errors=True)
        if self.admin is not None and self.admin.parent.name == "worktrees":
            # `git worktree remove` normally deletes it; never a global prune,
            # which would also drop the user's own unreachable worktrees.
            shutil.rmtree(self.admin, ignore_errors=True)
        self.path = self.parent = self.admin = None

    def _prune_own_stale(self) -> None:
        """Registrations an earlier, killed run left behind (only Skylos's)."""
        common = self._common_dir()
        if common is None:
            return
        try:
            entries = list(os.scandir(common / "worktrees"))
        except OSError:
            return
        for entry in entries[:1000]:
            try:
                gitdir = Path(
                    Path(entry.path, "gitdir").read_text(encoding="utf-8").strip()
                )
            except (OSError, UnicodeError):
                continue
            checkout = gitdir.parent
            if (
                checkout.parent.name.startswith(_WORKTREE_PREFIX)
                and not gitdir.exists()
                and not checkout.exists()
            ):
                shutil.rmtree(entry.path, ignore_errors=True)


# ---------------------------------------------------------------------------
# pytest
# ---------------------------------------------------------------------------


def _attribute_pytest(ctx, result, attribution, invocation, tree, budget_end):
    from skylos.done.runner import (
        _PLUGIN_MODULE,
        _PLUGIN_SOURCE,
        _Invocation,
        _run_once,
    )

    comparison = ctx.comparison
    base_paths = set(ctx._repository_paths()[0])
    changed_paths = {
        path
        for item in comparison.changed
        for path in (item.path, item.base_path)
        if path
    }
    renamed = {
        item.path: item.base_path
        for item in comparison.changed
        if item.status == "renamed" and item.base_path
    }
    requests: dict[int, str] = {}
    for index, case in enumerate(result.failures):
        origin = attribution.tests[index]
        node = case.node_id
        if not node or not case.file:
            origin.detail = "the results name no test file"
            continue
        if not (comparison.root / case.file).is_file():
            origin.detail = "the test path is not relative to the repository root"
            continue
        base_file = renamed.get(case.file, case.file)
        if base_file not in base_paths:
            origin.origin = "new_test"
            origin.detail = f"{case.file} is not on the base"
            continue
        if len(set(requests.values())) >= MAX_VERIFIED_TESTS:
            origin.detail = (
                f"only the first {MAX_VERIFIED_TESTS} failing tests are rerun"
            )
            continue
        requests[index] = base_file + node[len(case.file) :]
    if not requests:
        return
    failing_files = [requests[i].split("::", 1)[0] for i in sorted(requests)]
    controls = _pytest_controls(result, base_paths, changed_paths, failing_files)
    wanted = sorted(set(requests.values()) | set(controls))
    workdir = Path(tempfile.mkdtemp(prefix="skylos-done-prerun-")).resolve()
    base_invocation = _Invocation(
        _rebase_argv(invocation.argv, comparison.root, tree),
        pytest=True,
        auto=invocation.auto,
    )
    attribution.command = _shown(base_invocation)

    def base_run(nodes: list[str], name: str):
        """One pytest run of ``nodes`` in the base checkout: (problem, the
        cases it reported by node id, every node id it collected)."""
        select = workdir / f"{name}-select.json"
        _write_private_json(
            select, {"ids": nodes, "collected": str(workdir / f"{name}-collected")}
        )
        env = {
            "SKYLOS_DONE_SELECT": str(select),
            "SKYLOS_DONE_MODULES": str(workdir / f"{name}-modules"),
            "PYTHONPATH": _python_path(workdir, tree, comparison.root),
        }
        outcome = _run_once(
            tree,
            ctx.config,
            base_invocation,
            # A file that does not import on the base must not stop the
            # requested tests in other files from running.
            (
                "--continue-on-collection-errors",
                *sorted({node.split("::", 1)[0] for node in nodes}),
            ),
            workdir / f"{name}.xml",
            budget_end,
            extra_env=env,
        )
        problem = _outcome_problem(outcome, ctx.config)
        if problem:
            return problem, {}, set()
        leaked = _imported_working_tree(
            _read_channel(workdir, f"{name}-modules", dict),
            comparison.root,
            tree,
            base_paths | changed_paths,
        )
        if leaked:
            message = (
                f"the base run imported {leaked} from the working tree, not the "
                "base checkout"
            )
            return message, {}, set()
        by_node: dict[str, list] = {}
        for case in outcome.cases:
            if case.node_id:
                by_node.setdefault(case.node_id, []).append(case)
        return None, by_node, set(_read_channel(workdir, f"{name}-collected", list))

    try:
        (workdir / f"{_PLUGIN_MODULE}.py").write_text(_PLUGIN_SOURCE, encoding="utf-8")
        problem, by_node, collected = base_run(wanted, "first")
        if problem:
            _undetermined(attribution, problem, set(requests))
            return
        suspect = next(
            (
                node
                for node in controls
                if any(c.outcome in {"failed", "error"} for c in by_node.get(node, ()))
            ),
            None,
        )
        collected_files = {node.split("::", 1)[0] for node in collected}
        for index, node in requests.items():
            origin = attribution.tests[index]
            base_cases = by_node.get(node, [])
            outcomes = {c.outcome for c in base_cases}
            if outcomes & {"failed", "error"}:
                if suspect:
                    origin.detail = _short(
                        f"a control test that passes in the working tree failed "
                        f"in the base checkout ({suspect}); the base checkout may "
                        "lack files the tests need"
                    )
                else:
                    origin.origin, origin.detail = judge_base_failure(
                        result.failures[index], base_cases
                    )
            elif "passed" in outcomes:
                origin.origin = "introduced"
            elif "skipped" in outcomes:
                origin.detail = "skipped on the base"
            elif node in collected:
                origin.detail = "collected but not run on the base"
            elif node.split("::", 1)[0] in collected_files:
                origin.origin = "new_test"
                origin.detail = "no test with this id on the base"
            else:
                origin.detail = "the base run did not collect its file"

        # A failure counts here only when it fails twice, as in the working
        # tree: run the preexisting ones once more, so a flaky test is not
        # passed off as already failing.
        candidates = {
            index: node
            for index, node in requests.items()
            if attribution.tests[index].origin == "preexisting"
        }
        if candidates:
            if budget_end - time.monotonic() < _MIN_CONFIRM_SECONDS:
                problem, again = "no time was left for a second base run", {}
            else:
                problem, again, _ = base_run(sorted(set(candidates.values())), "again")
            for index, node in candidates.items():
                _confirm(
                    attribution.tests[index],
                    result.failures[index],
                    again.get(node, []),
                    problem,
                )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _confirm(origin: FailureOrigin, head, cases: list, problem: str | None) -> None:
    """Keep "preexisting" only if a second base run fails the same way."""
    if problem:
        verdict = ("undetermined", f"not confirmed by a second base run: {problem}")
    elif not any(c.outcome == "failed" for c in cases) or any(
        c.outcome == "passed" for c in cases
    ):
        verdict = (
            "undetermined",
            "failed on the base, then passed on a second base run (flaky)",
        )
    else:
        verdict = judge_base_failure(head, cases)
    if verdict[0] != "preexisting":
        origin.origin, origin.detail = "undetermined", _short(verdict[1])


def _pytest_controls(result, base_paths, changed_paths, failing_files) -> list[str]:
    """A few tests that passed here, in files this change did not touch.

    They should pass in the base checkout too; when one fails there instead,
    the base checkout is probably missing something the tests need (an
    ignored config file, a built extension), so its failures prove nothing.
    """
    order = {path: rank for rank, path in enumerate(dict.fromkeys(failing_files))}
    candidates = [
        case.node_id
        for case in result.cases
        if case.outcome == "passed"
        and case.node_id
        and case.file
        and case.file in base_paths
        and case.file not in changed_paths
    ]
    candidates.sort(key=lambda node: order.get(node.split("::", 1)[0], len(order)))
    return list(dict.fromkeys(candidates))[:MAX_CONTROL_TESTS]


def _python_path(workdir: Path, tree: Path, root: Path) -> str:
    """The plugin first, then the base checkout, then the inherited path
    with every entry inside the working tree moved to the base checkout."""
    entries = [str(workdir)]
    for candidate in (tree / "src", tree):
        if candidate.is_dir():
            entries.append(str(candidate))
    for entry in os.environ.get("PYTHONPATH", "").split(os.pathsep):
        if entry:
            entries.append(_rebase_path(entry, root, tree))
    return os.pathsep.join(dict.fromkeys(entries))


def _imported_working_tree(
    modules: dict, root: Path, tree: Path, project_paths: set[str]
) -> str | None:
    """A project module the base run loaded from outside the base checkout:
    from the working tree (an editable install) or an installed copy."""
    try:
        real_root, real_tree = root.resolve(), tree.resolve()
    except OSError:
        return None
    local_names = _top_level_modules(real_tree)
    for name, file in modules.items():
        if not isinstance(name, str) or not isinstance(file, str):
            continue
        path = Path(file)
        if _is_under(path, real_tree):
            continue
        if _is_under(path, real_root):
            relative = path.relative_to(real_root).as_posix()
            if relative in project_paths:
                return relative
            continue
        top = name.split(".", 1)[0]
        if top in local_names and "site-packages" in path.parts:
            return f"{top} (an installed copy)"
    return None


def _top_level_modules(tree: Path) -> set[str]:
    names = set()
    for directory in (tree, tree / "src"):
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries[:5000]:
            if entry.name.startswith((".", "_")) or entry.name in {
                "conftest.py",
                "setup.py",
                "noxfile.py",
                "tasks.py",
            }:
                continue
            if entry.is_dir(follow_symlinks=False) and os.path.exists(
                os.path.join(entry.path, "__init__.py")
            ):
                names.add(entry.name)
            elif entry.name.endswith(".py") and entry.is_file(follow_symlinks=False):
                names.add(entry.name[:-3])
    names -= {"test", "tests", "testing", "docs", "doc", "examples", "scripts"}
    return names


# ---------------------------------------------------------------------------
# Other runners (Jest, Vitest, go test via gotestsum, ...): JUnit results
# ---------------------------------------------------------------------------


def _attribute_junit(ctx, result, attribution, invocation, tree, budget_end):
    from skylos.done.runner import _Invocation, _run_once

    comparison, config = ctx.comparison, ctx.config
    base_paths = set(ctx._repository_paths()[0])
    changed_paths = {
        path
        for item in comparison.changed
        for path in (item.path, item.base_path)
        if path
    }
    files: dict[int, str | None] = {}
    pending: list[int] = []
    for index, case in enumerate(result.failures):
        origin = attribution.tests[index]
        file = case_file(case, comparison.root)
        files[index] = file
        if file is not None and file not in base_paths:
            origin.origin = "new_test"
            origin.detail = f"{file} is not on the base"
            continue
        if len(pending) >= MAX_VERIFIED_TESTS:
            origin.detail = (
                f"only the first {MAX_VERIFIED_TESTS} failing tests are rerun"
            )
            continue
        pending.append(index)
    if not pending:
        return

    link_node_modules(comparison.root, tree)
    needed = [files[i] for i in pending]
    narrowed = None
    if all(needed):
        narrowed = narrow_command(
            invocation.argv,
            sorted(set(needed)),
            _package_scripts(comparison),
        )
    argv = _rebase_argv(narrowed or invocation.argv, comparison.root, tree)
    base_invocation = _Invocation(tuple(argv), pytest=False, auto=False)
    attribution.command = _shown(base_invocation)
    if narrowed is None:
        attribution.reason = (
            "the command could not be narrowed to the failing files; "
            "the whole command ran on the base"
        )

    def base_run(argv: list[str], name: str):
        """One run in the base checkout: (problem, cases by key, files that
        reported a result)."""
        workdir = Path(tempfile.mkdtemp(prefix="skylos-done-prerun-")).resolve()
        try:
            outcome = _run_once(
                tree,
                config,
                _Invocation(tuple(argv), pytest=False, auto=False),
                (),
                workdir / f"{name}.xml",
                budget_end,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        problem = _outcome_problem(outcome, config)
        if problem:
            return problem, {}, set()
        index: dict[tuple, list] = {}
        reported = set()
        for case in outcome.cases:
            index.setdefault(case_key(case, tree), []).append(case)
            file = case_file(case, tree)
            if file:
                reported.add(file)
        # The next run writes the same report path: start it from nothing.
        report = tree / config.junit_xml if config.junit_xml else None
        if report is not None and report.is_file() and not report.is_symlink():
            report.unlink()
        return None, index, reported

    problem, base_index, reported_files = base_run(argv, "first")
    if problem:
        _undetermined(attribution, problem, set(pending))
        return
    head_passed = [
        case
        for case in result.cases
        if case.outcome == "passed"
        and (file := case_file(case, comparison.root))
        and file in base_paths
        and file not in changed_paths
    ]
    suspect = None
    for case in head_passed:
        base_cases = base_index.get(case_key(case, comparison.root), ())
        if any(c.outcome in {"failed", "error"} for c in base_cases):
            suspect = display_id(case)
            break
    head_keys: dict[tuple, int] = {}
    for case in result.cases:
        key = case_key(case, comparison.root)
        head_keys[key] = head_keys.get(key, 0) + 1
    for index in pending:
        case = result.failures[index]
        origin = attribution.tests[index]
        key = case_key(case, comparison.root)
        base_cases = base_index.get(key, [])
        outcomes = {c.outcome for c in base_cases}
        if head_keys.get(key, 0) > 1 or len(base_cases) > 1:
            # Results that name no file can repeat a title: which one is it?
            origin.detail = "several tests share this name in the results"
        elif outcomes & {"failed", "error"}:
            if suspect:
                origin.detail = _short(
                    f"a test that passes in the working tree failed in the base "
                    f"checkout ({suspect}); the base checkout may lack files the "
                    "tests need"
                )
            else:
                origin.origin, origin.detail = judge_base_failure(case, base_cases)
        elif "passed" in outcomes:
            origin.origin = "introduced"
        elif "skipped" in outcomes:
            origin.detail = "skipped on the base"
        elif files[index] and files[index] in reported_files:
            # JUnit lists only what ran, so a missing name is not proof the
            # test is new (pytest's collection list is; see above).
            origin.detail = "no test with this name ran on the base (new or renamed?)"
        else:
            origin.detail = "the base run reported no result for this test"

    # Only a failure that repeats counts: run the preexisting ones again.
    candidates = [i for i in pending if attribution.tests[i].origin == "preexisting"]
    if not candidates:
        return
    again_argv = argv
    if narrowed is not None:
        again = narrow_command(
            invocation.argv,
            sorted({files[i] for i in candidates}),
            _package_scripts(comparison),
        )
        if again is not None:
            again_argv = _rebase_argv(again, comparison.root, tree)
    if budget_end - time.monotonic() < _MIN_CONFIRM_SECONDS:
        problem, again = "no time was left for a second base run", {}
    else:
        problem, again, _ = base_run(again_argv, "again")
    for index in candidates:
        case = result.failures[index]
        _confirm(
            attribution.tests[index],
            case,
            again.get(case_key(case, comparison.root), []),
            problem,
        )


def case_file(case: CaseResult, root: Path) -> str | None:
    """The test's file, repository-relative: JUnit ``file``, or a Vitest
    classname that names an existing test file."""
    if case.file:
        return case.file
    name = (case.classname or "").replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    if (
        name
        and not name.startswith("/")
        and ".." not in name.split("/")
        and _JS_TEST_FILE_RE.search(name)
        and (root / name).is_file()
    ):
        return name
    return None


def case_key(case: CaseResult, root: Path) -> tuple:
    return (case_file(case, root), case.classname, case.name)


@dataclass
class LinkedModules:
    links: int = 0
    workspace_missing: list[str] = field(default_factory=list)


def link_node_modules(root: Path, tree: Path) -> LinkedModules:
    """Reuse the working tree's installed packages in the base checkout.

    Each ``node_modules`` folder becomes a real folder of symlinks to the
    working tree's entries, except workspace links (a symlink to a package
    inside the repository), which point at the base checkout's copy, so the
    base run never loads the working tree's code through them.
    """
    linked = LinkedModules()
    try:
        real_root = root.resolve()
    except OSError:
        return linked
    for relative in _node_modules_dirs(real_root):
        source = real_root / relative
        target = tree / relative
        if not target.parent.is_dir() or os.path.lexists(target):
            continue
        try:
            target.mkdir()
        except OSError:
            continue
        _link_entries(source, target, real_root, tree, linked, depth=0)
    return linked


def _link_entries(source, target, real_root, tree, linked, *, depth: int) -> None:
    try:
        entries = list(os.scandir(source))
    except OSError:
        return
    for entry in entries[:20000]:
        if entry.name in _UNSHARED_NODE_MODULES:
            continue
        destination = target / entry.name
        try:
            if entry.is_symlink():
                real = Path(os.path.realpath(entry.path))
                if (
                    _is_under(real, real_root)
                    and "node_modules" not in real.relative_to(real_root).parts
                ):
                    # A workspace package: use the base checkout's copy.
                    counterpart = tree / real.relative_to(real_root)
                    if counterpart.exists():
                        os.symlink(counterpart, destination)
                        linked.links += 1
                    else:
                        linked.workspace_missing.append(entry.name)
                    continue
                os.symlink(real, destination)
            elif (
                entry.is_dir(follow_symlinks=False)
                and entry.name.startswith("@")
                and depth == 0
            ):
                destination.mkdir()
                _link_entries(
                    Path(entry.path), destination, real_root, tree, linked, depth=1
                )
                continue
            else:
                os.symlink(entry.path, destination)
            linked.links += 1
        except (OSError, ValueError):
            continue


def _node_modules_dirs(root: Path) -> list[Path]:
    found: list[Path] = []
    visited = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and visited < _MAX_WALK_DIRS and len(found) < _MAX_NODE_MODULES_DIRS:
        directory, depth = stack.pop()
        visited += 1
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if entry.name == "node_modules":
                found.append(Path(entry.path).relative_to(root))
            elif entry.name not in _SKIP_WALK and depth < _MAX_WALK_DEPTH:
                stack.append((Path(entry.path), depth + 1))
    return sorted(found, key=lambda path: (len(path.parts), str(path)))


def _package_scripts(comparison: Comparison) -> dict:
    text = comparison.base_text("package.json")
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return scripts if isinstance(scripts, dict) else {}


def narrow_command(
    argv: tuple[str, ...] | list[str], files: list[str], scripts: dict
) -> list[str] | None:
    """The test command limited to ``files``, or None when Skylos cannot
    tell how this command selects files (the whole command runs instead).

    Jest and Vitest, run directly (``npx vitest run``, ``node_modules/.bin/jest``)
    or through an npm script that is a single Jest/Vitest command.
    """
    argv = list(argv)
    runner = _runner_at(argv)
    if runner is not None:
        return argv + _file_arguments(runner, files, separated="--" in argv)
    # npm test / npm run <script>, when the script is one Jest/Vitest command.
    name = PurePosixPath(argv[0]).name if argv else ""
    if name != "npm" or "--" in argv:
        return None
    words = [word for word in argv[1:] if not word.startswith("-")]
    if words[:1] in (["test"], ["t"], ["tst"]):
        script_name = "test"
    elif words[:1] in (["run"], ["run-script"]) and len(words) > 1:
        script_name = words[1]
    else:
        return None
    script = scripts.get(script_name)
    if not isinstance(script, str):
        return None
    from skylos.done.js_test_config import _commands

    commands = _commands(script)
    if len(commands) != 1:
        return None
    script_argv = commands[0][1]
    runner = _runner_at(script_argv)
    if runner is None:
        return None
    return argv + ["--"] + _file_arguments(runner, files, separated="--" in script_argv)


def _runner_at(argv: list[str]) -> str | None:
    from skylos.done.js_test_config import _ENV_ASSIGNMENT_RE

    index = 0
    while index < len(argv):
        token = argv[index]
        name = PurePosixPath(token).name
        if _ENV_ASSIGNMENT_RE.match(token):
            index += 1
        elif name in {"npx", "pnpx", "bunx", "env", "cross-env"}:
            index += 1
            while index < len(argv) and argv[index].startswith("-"):
                index += 1
        elif name in {"pnpm", "yarn", "npm"} and argv[index + 1 : index + 2] == [
            "exec"
        ]:
            index += 2
        elif name in {"pnpm", "yarn"} and _runner_name(
            argv[index + 1] if index + 1 < len(argv) else ""
        ):
            index += 1
        else:
            break
    if index >= len(argv):
        return None
    return _runner_name(argv[index])


def _runner_name(token: str) -> str | None:
    name = PurePosixPath(token).name
    for suffix in (".js", ".cjs", ".mjs"):
        name = name.removesuffix(suffix)
    return name if name in {"jest", "vitest"} else None


def _file_arguments(runner: str, files: list[str], *, separated: bool) -> list[str]:
    if runner == "jest":
        # Jest reads positional arguments as path regular expressions. After
        # an array option (--reporters=x) it would take them as more values,
        # so they follow "--".
        patterns = [_JEST_REGEX_SPECIALS.sub(r"\\\1", path) for path in files]
        return patterns if separated else ["--", *patterns]
    return list(files)  # Vitest: path filters ("--" would hide them)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _outcome_problem(outcome, config) -> str | None:
    if outcome.error == "timeout":
        return (
            f"the base run ran out of time after {outcome.seconds:.0f} s "
            "(preexisting_timeout_seconds)"
        )
    if outcome.error == "not_found":
        return "the test command could not start in the base checkout"
    if outcome.error == "junit_unreadable":
        return "the base run's test results could not be read"
    if not outcome.junit_found:
        tail = (outcome.output_tail or "").strip().splitlines()
        hint = f": {tail[-1]}" if tail else ""
        return _short(f"the base run wrote no test results{hint}")
    if not outcome.cases:
        tail = (outcome.output_tail or "").strip().splitlines()
        hint = f": {tail[-1]}" if tail else ""
        return _short(f"the base run reported no tests{hint}")
    return None


def _rebase_argv(argv, root: Path, tree: Path) -> list[str]:
    """The command for the base checkout: a relative program missing there
    (``.venv/bin/pytest``) runs from the working tree, never installed anew."""
    argv = list(argv)
    if argv:
        program = argv[0]
        if (
            ("/" in program or "\\" in program)
            and not os.path.isabs(program)
            and not (tree / program).exists()
            and (root / program).exists()
        ):
            argv[0] = str(root / program)
    return argv


def _rebase_path(entry: str, root: Path, tree: Path) -> str:
    try:
        path = Path(entry).resolve()
        return str(tree / path.relative_to(root.resolve()))
    except (OSError, ValueError):
        return entry


def _is_under(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _shown(invocation) -> str:
    argv = list(invocation.argv)
    if invocation.auto:
        argv[0] = "python"
    return " ".join(argv)[:120]


def _short(text: str, limit: int = MAX_DETAIL_CHARS) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _write_private_json(path: Path, data) -> None:
    from skylos.done.runner import _create_log

    with os.fdopen(_create_log(path), "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def _read_channel(workdir: Path, name: str, kind: type):
    """Merge what each test process wrote (``<name>.<pid>``)."""
    from skylos.done.runner import _read_regular

    merged = kind()
    try:
        entries = sorted(os.scandir(workdir), key=lambda entry: entry.name)
    except OSError:
        return merged
    for entry in entries:
        if not entry.name.startswith(name + "."):
            continue
        raw = _read_regular(Path(entry.path), 64 * 1024 * 1024)
        if raw is None:
            continue
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(data, kind):
            if kind is dict:
                merged.update(data)
            else:
                merged.extend(data)
    return merged


# ---------------------------------------------------------------------------
# Words for people and agents
# ---------------------------------------------------------------------------


def _names(tests: list[dict], limit: int = 5) -> str:
    names = [str(test.get("test")) for test in tests[:limit]]
    more = len(tests) - limit
    return ", ".join(names) + (f" and {more} more" if more > 0 else "")


def agent_message(origins: dict | None) -> str | None:
    """One plain sentence for the agent: which failures are its own.

    "2 failing tests are new in this change: a, b; 1 was already failing on
    origin/main (merge base 1a2b3c4): c. Fix the 2 new failures before saying
    you are done."
    """
    if not isinstance(origins, dict) or not origins.get("tests"):
        return None
    tests = [t for t in origins["tests"] if isinstance(t, dict)]
    base = (origins.get("base") or {}).get("label") or "the base"
    new = [t for t in tests if t.get("origin") in INTRODUCED]
    old = [t for t in tests if t.get("origin") == "preexisting"]
    unknown = [t for t in tests if t.get("origin") == "undetermined"]
    parts = []
    if new:
        noun = "test is" if len(new) == 1 else "tests are"
        parts.append(f"{len(new)} failing {noun} new in this change: {_names(new)}")
    if old:
        verb = "was" if len(old) == 1 else "were"
        allowed = (
            " (allowed by allow_preexisting_failures)" if origins.get("allowed") else ""
        )
        parts.append(
            f"{len(old)} {verb} already failing on {base}{allowed}: {_names(old)}"
        )
    if unknown:
        reason = next((t.get("detail") for t in unknown if t.get("detail")), "")
        why = f" ({reason})" if reason else ""
        parts.append(
            f"{len(unknown)} could not be checked on the base{why}: {_names(unknown)}"
        )
    sentence = "; ".join(parts) + "."
    if new:
        sentence += (
            f" Fix the {len(new)} new failure{'s' if len(new) != 1 else ''} "
            "before saying you are done."
        )
    elif unknown:
        sentence += " These still block; fix them before saying you are done."
    elif old and not origins.get("allowed"):
        sentence += (
            " Already-failing tests still block in this repository; fix them "
            "before saying you are done."
        )
    return sentence


def summary_counts(origins: dict | None) -> str | None:
    """ "2 introduced (1 new test), 1 already failing on <base>, 1 not checked"."""
    if not isinstance(origins, dict):
        return None
    counts = origins.get("counts") or {}
    new = int(counts.get("introduced", 0)) + int(counts.get("new_test", 0))
    parts = []
    if new:
        extra = (
            f" ({counts.get('new_test')} new test{'s' if counts.get('new_test') != 1 else ''})"
            if counts.get("new_test")
            else ""
        )
        parts.append(f"{new} introduced{extra}")
    if counts.get("preexisting"):
        parts.append(f"{counts['preexisting']} already failing on the base")
    if counts.get("undetermined"):
        parts.append(f"{counts['undetermined']} not checked on the base")
    return ", ".join(parts) or None
