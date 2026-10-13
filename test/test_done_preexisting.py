"""skylos done: rerun failing tests on the base and label each failure."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import preexisting
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_tests_pass
from skylos.done.config import CHECK_IDS, DoneConfig, parse_done_config
from skylos.done.engine import run
from skylos.done.receipt import (
    build_receipt,
    render_markdown,
    render_text,
    validate_receipt,
)
from skylos.done.runner import CaseResult, failure_kind


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(root: Path, rel: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / rel
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, dedent(text))


def _commit(root: Path, message: str = "change") -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


CALC = """\
def add(a, b):
    return a + b


def sub(a, b):
    return a - b


def mul(a, b):
    return a * b + 1  # already wrong on main
"""

TESTS = """\
from app.calc import add, mul, sub


def test_add():
    assert add(1, 2) == 3


def test_sub():
    assert sub(3, 1) == 2


def test_mul():
    assert mul(2, 3) == 6
"""

OTHER = """\
def test_other():
    assert True
"""


def _pyproject(extra: str = "") -> str:
    return (
        '[project]\nname = "demo"\nversion = "0.1.0"\n\n'
        '[tool.pytest.ini_options]\naddopts = "-q"\n\n'
        f"[tool.skylos.done]\ntest_budget_seconds = 120\n{extra}"
    )


def _make_repo(tmp_path: Path, extra: str = "") -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "app/__init__.py", "")
    _write(root, "app/calc.py", CALC)
    _write(root, "tests/test_calc.py", TESTS)
    _write(root, "tests/test_other.py", OTHER)
    _write(root, "pyproject.toml", _pyproject(extra))
    _commit(root, "base")
    _git(root, "switch", "-qc", "feature")
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return _make_repo(tmp_path)


def _tests_check(result):
    return next(c for c in result.checks if c.result.id == "tests_pass").result


def _origins(result) -> dict[str, str]:
    origins = _tests_check(result).failure_origins
    assert origins is not None
    return {t["test"]: t["origin"] for t in origins["tests"]}


def _snapshot(root: Path, *, outputs: frozenset[str] = frozenset()) -> dict:
    """Everything of the user's that the base run must leave alone."""
    git_dir = Path(_git(root, "rev-parse", "--absolute-git-dir").strip())
    worktrees = git_dir / "worktrees"
    return {
        "status": _git(root, "status", "--porcelain=v1", "--untracked-files=all"),
        "index": hashlib.sha256((git_dir / "index").read_bytes()).hexdigest(),  # skylos: ignore[SKY-D215] test fixture under pytest tmp_path
        "head": _git(root, "rev-parse", "HEAD"),
        "refs": _git(root, "for-each-ref"),
        "stash": _git(root, "stash", "list"),
        "worktrees": _git(root, "worktree", "list", "--porcelain"),
        "registrations": sorted(os.listdir(worktrees)) if worktrees.is_dir() else [],
        "files": sorted(
            str(p.relative_to(root))
            for p in root.rglob("*")
            # .pytest_cache: Skylos's own run of the tests in the working tree.
            if not {".git", ".skylos", ".pytest_cache", *outputs} & set(p.parts)
        ),
    }


@pytest.fixture
def own_tempdir(tmp_path: Path, monkeypatch) -> Path:
    """Base checkouts go to tempfile.gettempdir(); a directory of this test's
    own keeps other pytest-xdist workers' checkouts out of the leftover count."""
    own = tmp_path / "tempdir"
    own.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(own))
    return own


def _leftover_checkouts() -> list[str]:
    return sorted(
        name
        for name in os.listdir(tempfile.gettempdir())
        if name.startswith("skylos-done-base-")
    )


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def test_mixed_failures_are_labeled_and_every_one_still_blocks(repo: Path):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _write(
        repo,
        "tests/test_calc.py",
        TESTS + "\n\ndef test_add_big():\n    assert add(2, 2) == 5\n",
    )
    _write(repo, "tests/test_fresh.py", "def test_fresh():\n    assert 1 == 2\n")
    _commit(repo)

    result = run(repo, base_ref="main")

    assert result.verdict == "fail"
    tests = _tests_check(result)
    assert tests.status == "fail"
    assert _origins(result) == {
        "tests/test_calc.py::test_sub": "introduced",
        "tests/test_calc.py::test_mul": "preexisting",
        "tests/test_calc.py::test_add_big": "new_test",
        "tests/test_fresh.py::test_fresh": "new_test",
    }
    # Labels never loosen the default policy: all four failures block.
    assert all(f.blocking for f in tests.findings if "failed" in f.message)
    messages = {f.message.split(" failed", 1)[0]: f.message for f in tests.findings}
    assert (
        "already failing on main (merge base"
        in messages["tests/test_calc.py::test_mul"]
    )
    assert (
        "introduced by this change: passes on main"
        in messages["tests/test_calc.py::test_sub"]
    )
    assert "new test, not on main" in messages["tests/test_fresh.py::test_fresh"]

    receipt = build_receipt(result)
    assert validate_receipt(receipt) == []
    origins = receipt["failure_origins"]
    assert origins["status"] == "checked" and origins["allowed"] is False
    assert origins["counts"] == {
        "preexisting": 1,
        "introduced": 1,
        "new_test": 2,
        "undetermined": 0,
    }
    assert origins["base"]["label"].startswith("main (merge base ")
    text = render_text(receipt)
    assert "Failing tests rerun on main (merge base" in text
    assert "3 introduced (2 new tests), 1 already failing on the base" in text
    assert text.splitlines()[-1].startswith(
        "Verdict: FAIL: 4 of 6 tests failed when Skylos ran them (3 introduced"
    )
    assert "Failing tests rerun on main" in render_markdown(receipt)

    sentence = preexisting.agent_message(origins)
    assert sentence.startswith("3 failing tests are new in this change: ")
    assert "1 was already failing on main (merge base " in sentence
    assert "tests/test_calc.py::test_mul" in sentence
    assert sentence.endswith("Fix the 3 new failures before saying you are done.")


def test_base_run_leaves_the_users_tree_index_and_refs_alone(
    repo: Path, own_tempdir: Path
):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(repo)
    # Staged, unstaged and untracked work in progress.
    _write(repo, "tests/test_other.py", OTHER + "\n\ndef test_more():\n    pass\n")
    _git(repo, "add", "tests/test_other.py")
    _write(repo, "app/__init__.py", "# edited, not staged\n")
    _write(repo, "notes.txt", "scratch\n")
    before = _snapshot(repo)
    leftovers = _leftover_checkouts()

    result = run(repo, base_ref="main")

    assert _origins(result) == {
        "tests/test_calc.py::test_sub": "introduced",
        "tests/test_calc.py::test_mul": "preexisting",
    }
    assert _snapshot(repo) == before
    assert _leftover_checkouts() == leftovers


def test_renamed_test_file_is_rerun_under_its_base_path(repo: Path):
    _git(repo, "mv", "tests/test_calc.py", "tests/test_math.py")
    _commit(repo)

    result = run(repo, base_ref="main")

    assert _origins(result) == {"tests/test_math.py::test_mul": "preexisting"}


def test_head_base_labels_say_head(repo: Path):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))

    result = run(repo)  # base HEAD: only the uncommitted change counts

    origins = _tests_check(result).failure_origins
    assert origins["base"]["label"].startswith("HEAD (")
    assert _origins(result) == {
        "tests/test_calc.py::test_sub": "introduced",
        "tests/test_calc.py::test_mul": "preexisting",
    }


# ---------------------------------------------------------------------------
# allow_preexisting_failures (opt-in) and verify_preexisting
# ---------------------------------------------------------------------------


def test_allow_preexisting_failures_lets_only_verified_ones_pass(tmp_path: Path):
    root = _make_repo(tmp_path, "allow_preexisting_failures = true\n")
    _write(root, "tests/test_other.py", OTHER + "\n\ndef test_more():\n    pass\n")
    _commit(root)

    result = run(root, base_ref="main")

    tests = _tests_check(result)
    assert _origins(result) == {"tests/test_calc.py::test_mul": "preexisting"}
    assert tests.status == "pass", tests.summary
    assert "failing also on the base (allow_preexisting_failures)" in tests.summary
    assert result.verdict == "pass"
    receipt = build_receipt(result)
    assert validate_receipt(receipt) == []
    assert receipt["failure_origins"]["allowed"] is True
    finding = next(
        f for c in receipt["checks"] if c["id"] == "tests_pass" for f in c["findings"]
    )
    assert finding["message"].startswith("(advice) tests/test_calc.py::test_mul failed")
    assert "Allowed by allow_preexisting_failures" in render_text(receipt)

    # One introduced failure, and the run fails again.
    _write(root, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(root)
    result = run(root, base_ref="main")
    assert result.verdict == "fail"
    assert _tests_check(result).failure_origins["allowed"] is False
    assert all(f.blocking for f in _tests_check(result).findings)


def test_allow_preexisting_failures_never_applies_against_head(tmp_path: Path):
    root = _make_repo(tmp_path, "allow_preexisting_failures = true\n")
    # Without --base the base is HEAD, which an agent's own commits can move.
    result = run(root)
    assert _origins(result) == {"tests/test_calc.py::test_mul": "preexisting"}
    assert result.verdict == "fail"
    assert _tests_check(result).failure_origins["allowed"] is False


def test_verify_preexisting_off_keeps_the_old_receipt(tmp_path: Path):
    root = _make_repo(tmp_path, "verify_preexisting = false\n")
    _write(root, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(root)

    result = run(root, base_ref="main")

    assert result.verdict == "fail"
    assert _tests_check(result).failure_origins is None
    receipt = build_receipt(result)
    assert "failure_origins" not in receipt
    assert all(
        "(introduced" not in f["message"] and "already failing" not in f["message"]
        for c in receipt["checks"]
        for f in c["findings"]
    )


def test_passing_tests_never_start_a_base_run(repo: Path, monkeypatch):
    monkeypatch.setattr(
        preexisting,
        "attribute_failures",
        lambda *a: pytest.fail("no failures, no base run"),
    )
    _write(repo, "app/calc.py", CALC.replace("* b + 1", "* b"))
    _commit(repo)
    result = run(repo, base_ref="main")
    assert result.verdict == "pass"
    assert "failure_origins" not in build_receipt(result)


# ---------------------------------------------------------------------------
# Setup failures on the base are never "preexisting"
# ---------------------------------------------------------------------------

_HEAD_FAILING = """\
def test_target():
    assert 1 + 1 == 3
"""

_BASE_VARIANTS = {
    # The file does not import on the base: a collection error.
    "collection_error": "import not_a_real_module_xyz\n\n\ndef test_target():\n    assert False\n",
    # The test body imports something missing on the base.
    "import_in_body": "def test_target():\n    import not_a_real_module_xyz\n",
    # A fixture the base does not have: an error in setup, not the test.
    "missing_fixture": "def test_target(no_such_fixture_xyz):\n    assert False\n",
    # A data file missing from the base checkout.
    "missing_file": "def test_target():\n    open('not-there.json').read()\n",
    # The base does not even parse.
    # A module the test imports does not parse on the base. (A test file
    # that does not parse stops the whole gate before the tests run.)
    "syntax_error": "from tests.helper_mod import x\n\n\ndef test_target():\n    assert x\n",
    # Fails on the base too, but differently: not the same failure.
    "different_kind": "def test_target():\n    raise TypeError('boom')\n",
}


@pytest.mark.parametrize("variant", sorted(_BASE_VARIANTS))
def test_base_failures_from_setup_are_undetermined(tmp_path: Path, variant: str):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "pyproject.toml", _pyproject())
    _write(root, "tests/test_target.py", _BASE_VARIANTS[variant])
    if variant == "syntax_error":
        _write(root, "tests/helper_mod.py", "def broken(:\n    pass\n")
    _commit(root, "base")
    _git(root, "switch", "-qc", "feature")
    _write(root, "tests/test_target.py", _HEAD_FAILING)
    _commit(root)

    result = run(root, base_ref="main")

    assert result.verdict == "fail"
    origins = _tests_check(result).failure_origins
    (test,) = origins["tests"]
    assert test["test"] == "tests/test_target.py::test_target"
    assert test["origin"] == "undetermined", test
    assert test["detail"]
    assert "could not be checked on the base" in preexisting.agent_message(origins)


def test_failure_kind_reads_type_message_and_output():
    assert failure_kind("AssertionError", "x", None) == "AssertionError"
    assert failure_kind(None, "assert 1 == 2", None) == "AssertionError"
    assert failure_kind(None, "ImportError: no module", None) == "ImportError"
    assert failure_kind("", "requests.exceptions.ConnectionError: x", None) == (
        "ConnectionError"
    )
    assert failure_kind(None, "http://example.com: down", None) == ""
    assert (
        failure_kind(None, "", "trace\nE   ModuleNotFoundError: No module named 'x'\n")
        == "ModuleNotFoundError"
    )
    assert failure_kind(None, "expected 1 to be 2", None) == ""


def test_judge_needs_a_matching_test_body_failure():
    head = CaseResult(
        "t.py", "t", "test_a", 1, "failed", "assert 1", kind="AssertionError"
    )

    def base(outcome, message, kind=""):
        return CaseResult("t.py", "t", "test_a", 1, outcome, message, kind=kind)

    assert preexisting.judge_base_failure(
        head, [base("failed", "assert 2", "AssertionError")]
    ) == ("preexisting", "assert 2")
    assert preexisting.judge_base_failure(head, [base("failed", "x", "")])[0] == (
        "preexisting"
    )
    for cases in (
        [base("error", "fixture 'db' not found")],
        [base("failed", "assert 2", "AssertionError"), base("error", "teardown")],
        [base("failed", "ModuleNotFoundError: x", "ModuleNotFoundError")],
        [base("failed", "Error: Cannot find module './x'", "Error")],
        [base("failed", "boom", "TypeError")],
    ):
        assert preexisting.judge_base_failure(head, cases)[0] == "undetermined"


# ---------------------------------------------------------------------------
# When the base run cannot answer
# ---------------------------------------------------------------------------


def test_base_run_timeout_is_undetermined(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "pyproject.toml", _pyproject())
    _write(
        root,
        "tests/test_slow.py",
        "import time\n\n\ndef test_slow():\n    time.sleep(60)\n    assert False\n",
    )
    _commit(root, "base")
    _git(root, "switch", "-qc", "feature")
    _write(root, "tests/test_slow.py", "def test_slow():\n    assert False\n")
    _commit(root)
    ctx = CheckContext(
        open_comparison(root, "main"), DoneConfig(preexisting_timeout_seconds=3)
    )
    started = time.monotonic()

    check = check_tests_pass(ctx)

    assert time.monotonic() - started < 45
    assert check.status == "fail"
    (test,) = check.failure_origins["tests"]
    assert test["origin"] == "undetermined"
    assert "ran out of time" in test["detail"]
    assert check.failure_origins["status"] == "not_checked"


def test_changed_dependencies_make_every_failure_undetermined(repo: Path):
    _write(repo, "requirements.txt", "requests==2.0\n")
    _commit(repo, "base deps")
    _git(repo, "branch", "-f", "main")
    _write(repo, "requirements.txt", "requests==2.1\n")
    _commit(repo)

    result = run(repo, base_ref="main")

    origins = _tests_check(result).failure_origins
    assert origins["status"] == "not_checked"
    assert origins["reason"] == "dependencies differ: requirements.txt changed"
    assert {t["origin"] for t in origins["tests"]} == {"undetermined"}
    assert result.verdict == "fail"


def test_pyproject_edits_outside_dependencies_still_check(repo: Path):
    text = (repo / "pyproject.toml").read_text()
    _write(repo, "pyproject.toml", text + "\n[tool.ruff]\nline-length = 100\n")
    _commit(repo)
    result = run(repo, base_ref="main")
    assert _origins(result) == {"tests/test_calc.py::test_mul": "preexisting"}

    text = (repo / "pyproject.toml").read_text()
    _write(
        repo,
        "pyproject.toml",
        text.replace('version = "0.1.0"', 'version = "0.1.0"\ndependencies = ["x"]'),
    )
    _commit(repo)
    result = run(repo, base_ref="main")
    assert _tests_check(result).failure_origins["reason"] == (
        "dependencies differ: pyproject.toml changed"
    )


def test_package_json_dependencies_but_not_scripts_count(repo: Path):
    def package(**extra):
        return json.dumps({"name": "x", "scripts": {"test": "jest"}, **extra})

    _write(repo, "package.json", package())
    _commit(repo, "base pkg")
    base = _git(repo, "rev-parse", "HEAD").strip()
    _write(repo, "package.json", package(scripts={"test": "jest --ci"}))
    comparison = open_comparison(repo, base)
    assert preexisting.environment_blocker(comparison) is None
    _write(repo, "package.json", package(devDependencies={"jest": "^29"}))
    comparison = open_comparison(repo, base)
    assert preexisting.environment_blocker(comparison) == (
        "dependencies differ: package.json changed"
    )


def test_control_test_failing_on_the_base_voids_preexisting(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, ".gitignore", "local.cfg\n")
    _write(root, "pyproject.toml", _pyproject())
    _write(root, "app/__init__.py", "")
    _write(root, "app/calc.py", CALC.replace("* b + 1", "* b"))
    _write(
        root,
        "tests/test_calc.py",
        """\
        from pathlib import Path

        from app.calc import add, mul


        def test_add():
            assert add(1, 2) == 3


        def test_mul():
            # Needs an ignored local file: absent from any checkout of the base.
            assert Path("local.cfg").exists() and mul(2, 3) == 6
        """,
    )
    _write(
        root,
        "tests/test_env.py",
        "from pathlib import Path\n\n\ndef test_cfg():\n    assert Path('local.cfg').exists()\n",
    )
    _commit(root, "base")
    _write(root, "local.cfg", "x\n")
    _git(root, "switch", "-qc", "feature")
    _write(root, "app/calc.py", CALC)  # breaks mul: a real introduced failure
    _commit(root)

    result = run(root, base_ref="main")

    origins = _tests_check(result).failure_origins
    (test,) = origins["tests"]
    assert test["origin"] == "undetermined"
    assert "control test" in test["detail"] and "test_cfg" in test["detail"]


def test_working_tree_imports_are_detected(tmp_path: Path):
    root = (tmp_path / "root").resolve()
    tree = (tmp_path / "tree").resolve()
    (tree / "app").mkdir(parents=True)
    (tree / "app" / "__init__.py").write_text("")
    project = {"app/calc.py", "app/__init__.py"}
    site = tmp_path / "venv" / "lib" / "site-packages"

    def check(modules):
        return preexisting._imported_working_tree(modules, root, tree, project)

    assert check({"app.calc": str(tree / "app" / "calc.py")}) is None
    assert check({"app.calc": str(root / "app" / "calc.py")}) == "app/calc.py"
    # The working tree's own virtualenv is not project code.
    assert check({"six": str(root / ".venv" / "six.py")}) is None
    assert (
        check({"app": str(site / "app" / "__init__.py")}) == "app (an installed copy)"
    )
    assert check({"requests": str(site / "requests" / "__init__.py")}) is None


def test_base_run_that_imports_working_tree_code_is_undetermined(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "pyproject.toml", _pyproject())
    _write(root, "lib/app/__init__.py", "")
    _write(root, "lib/app/calc.py", CALC.replace("* b + 1", "* b"))
    _write(
        root,
        "tests/test_calc.py",
        "from app.calc import sub\n\n\ndef test_sub():\n    assert sub(3, 1) == 2\n",
    )
    _commit(root, "base")
    _git(root, "switch", "-qc", "feature")
    _write(root, "lib/app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(root)
    # Like an editable install of the working tree that Skylos cannot redirect.
    monkeypatch.setenv("PYTHONPATH", str(root.resolve() / "lib"))
    monkeypatch.setattr(preexisting, "_rebase_path", lambda entry, *a: entry)

    result = run(root, base_ref="main")

    (test,) = _tests_check(result).failure_origins["tests"]
    assert test["origin"] == "undetermined"
    assert "imported lib/app/" in test["detail"]
    assert "from the working tree" in test["detail"]

    # Redirected (the default), the base checkout's own copy runs.
    monkeypatch.undo()
    monkeypatch.setenv("PYTHONPATH", str(root.resolve() / "lib"))
    result = run(root, base_ref="main")
    assert _origins(result) == {"tests/test_calc.py::test_sub": "introduced"}


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_base_checkout_is_removed_when_the_run_breaks(
    repo: Path, monkeypatch, error, own_tempdir: Path
):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(repo)
    before = _snapshot(repo)
    leftovers = _leftover_checkouts()
    seen = {}

    def broken(ctx, result, attribution, invocation, tree, budget_end):
        seen["tree"] = tree
        assert (tree / "app" / "calc.py").read_text() == CALC  # the base's copy
        raise error("boom")

    monkeypatch.setattr(preexisting, "_attribute_pytest", broken)
    ctx = CheckContext(open_comparison(repo, "main"), DoneConfig())
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            check_tests_pass(ctx)
    else:
        check = check_tests_pass(ctx)
        assert check.status == "fail"  # the failures stand
        assert check.failure_origins["status"] == "not_checked"
        assert "could not finish (RuntimeError)" in check.failure_origins["reason"]
    assert not seen["tree"].exists()
    assert _snapshot(repo) == before
    assert _leftover_checkouts() == leftovers


def test_only_skylos_stale_registrations_are_pruned(repo: Path):
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir").strip())
    parent = Path(tempfile.mkdtemp(prefix="skylos-done-base-"))
    ours = parent / "repo"
    theirs = repo.parent / "users-own-worktree"
    _git(repo, "worktree", "add", "--detach", "-q", str(ours), "main")
    _git(repo, "worktree", "add", "--detach", "-q", str(theirs), "main")
    shutil.rmtree(parent)  # a killed run: folder gone, registration left
    shutil.rmtree(theirs)  # skylos: ignore[SKY-D215] test fixture under pytest tmp_path; the user's own worktree on an unmounted disk
    assert len(os.listdir(git_dir / "worktrees")) == 2

    with preexisting.base_checkout(
        open_comparison(repo, "main"), time.monotonic() + 60
    ):
        pass

    remaining = [
        (git_dir / "worktrees" / name / "gitdir").read_text().strip()  # skylos: ignore[SKY-D215] test fixture under pytest tmp_path
        for name in os.listdir(git_dir / "worktrees")
    ]
    assert remaining == [str(theirs.resolve() / ".git")] or remaining == [
        str(theirs / ".git")
    ]


# ---------------------------------------------------------------------------
# Settings and receipt
# ---------------------------------------------------------------------------


def test_settings_parse_with_bounds_and_plain_problems():
    config = parse_done_config("[tool.skylos.done]\n")
    assert config.verify_preexisting is True
    assert config.allow_preexisting_failures is False
    assert config.preexisting_timeout_seconds == 120

    config = parse_done_config(
        "[tool.skylos.done]\nallow_preexisting_failures = true\n"
        "preexisting_timeout_seconds = 30\n"
    )
    assert config.allow_preexisting_failures is True
    assert config.preexisting_timeout_seconds == 30

    config = parse_done_config(
        "[tool.skylos.done]\nverify_preexisting = 'yes'\n"
        "preexisting_timeout_seconds = 5\n"
    )
    assert config.verify_preexisting is True
    assert config.preexisting_timeout_seconds == 10
    assert "verify_preexisting must be true or false" in config.problems

    config = parse_done_config(
        "[tool.skylos.done]\nverify_preexisting = false\n"
        "allow_preexisting_failures = true\n"
    )
    assert config.allow_preexisting_failures is False
    assert any("needs verify_preexisting" in p for p in config.problems)


def test_default_settings_keep_their_earlier_digest():
    config = parse_done_config("[tool.skylos.done]\ntest_command = 'pytest'\n")
    canonical = json.dumps(
        {
            "test_command": ["pytest"],
            "junit_xml": None,
            "test_budget_seconds": config.test_budget_seconds,
            "changed_lines_budget_seconds": config.changed_lines_budget_seconds,
            "max_stop_blocks": config.max_stop_blocks,
            "protected_paths": list(config.protected_paths),
            "modes": {key: config.mode(key) for key in CHECK_IDS},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert config.digest() == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    allowed = parse_done_config(
        "[tool.skylos.done]\ntest_command = 'pytest'\nallow_preexisting_failures = true\n"
    )
    assert allowed.digest() != config.digest()


def test_receipt_rejects_malformed_failure_origins(repo: Path):
    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(repo)
    receipt = build_receipt(run(repo, base_ref="main"))
    assert validate_receipt(receipt) == []
    broken = json.loads(json.dumps(receipt))
    broken["failure_origins"]["counts"]["preexisting"] = 9
    assert validate_receipt(broken) == ["failure_origins counts do not match its tests"]
    broken = json.loads(json.dumps(receipt))
    broken["failure_origins"]["tests"][0]["origin"] = "blameless"
    assert validate_receipt(broken) == ["failure_origins has a malformed test"]


# ---------------------------------------------------------------------------
# JavaScript runners
# ---------------------------------------------------------------------------


def test_narrowing_jest_and_vitest_commands():
    files = ["src/a.test.ts", "app/[id]/page.test.tsx"]
    assert preexisting.narrow_command(("npx", "vitest", "run"), files, {}) == [
        "npx",
        "vitest",
        "run",
        *files,
    ]
    assert preexisting.narrow_command(
        ("node_modules/.bin/jest", "--ci", "--reporters=jest-junit"), files, {}
    ) == [
        "node_modules/.bin/jest",
        "--ci",
        "--reporters=jest-junit",
        "--",  # or --reporters would take the paths as more reporters
        r"src/a\.test\.ts",
        r"app/\[id\]/page\.test\.tsx",
    ]
    assert preexisting.narrow_command(("pnpm", "exec", "vitest"), files[:1], {}) == [
        "pnpm",
        "exec",
        "vitest",
        "src/a.test.ts",
    ]
    scripts = {
        "test": "vitest run --reporter=junit",
        "unit": "jest --ci",
        "ci": "tsc && jest",
    }
    assert preexisting.narrow_command(("npm", "test"), files[:1], scripts) == [
        "npm",
        "test",
        "--",
        "src/a.test.ts",
    ]
    assert preexisting.narrow_command(("npm", "run", "unit"), files[:1], scripts) == [
        "npm",
        "run",
        "unit",
        "--",
        "--",
        r"src/a\.test\.ts",
    ]
    # A chained script or an unknown runner runs whole on the base instead.
    assert preexisting.narrow_command(("npm", "run", "ci"), files, scripts) is None
    assert preexisting.narrow_command(("make", "test"), files, scripts) is None
    assert (
        preexisting.narrow_command(("npm", "test", "--", "x"), files, scripts) is None
    )


def test_node_modules_are_shared_but_workspace_links_point_at_the_base(
    tmp_path: Path,
):
    root = (tmp_path / "root").resolve()
    tree = (tmp_path / "tree").resolve()
    for base in (root, tree):
        (base / "packages" / "lib").mkdir(parents=True)
    modules = root / "node_modules"
    (modules / "left-pad").mkdir(parents=True)
    (modules / "@scope" / "util").mkdir(parents=True)
    (modules / ".cache").mkdir()
    (modules / "@scope" / "lib").symlink_to(root / "packages" / "lib")
    (root / "packages" / "lib" / "node_modules" / "dep").mkdir(parents=True)

    preexisting.link_node_modules(root, tree)

    linked = tree / "node_modules"
    assert linked.is_dir() and not linked.is_symlink()
    assert os.readlink(linked / "left-pad") == str(modules / "left-pad")
    assert os.readlink(linked / "@scope" / "util") == str(modules / "@scope" / "util")
    assert Path(os.readlink(linked / "@scope" / "lib")) == tree / "packages" / "lib"
    assert not (linked / ".cache").exists()
    nested = tree / "packages" / "lib" / "node_modules"
    assert os.readlink(nested / "dep") == str(
        root / "packages" / "lib" / "node_modules" / "dep"
    )


def _node_junit() -> bool:
    node = shutil.which("node")
    if node is None:
        return False
    out = subprocess.run(
        [node, "--test-reporter=junit", "-e", "1"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.returncode == 0


@pytest.mark.skipif(not _node_junit(), reason="needs node with the junit test reporter")
def test_node_test_runner_failures_are_labeled_from_junit(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(
        root,
        "pyproject.toml",
        "[tool.skylos.done]\n"
        'test_command = ["node", "--test", "--test-reporter=junit", '
        '"--test-reporter-destination=junit.xml"]\n'
        'junit_xml = "junit.xml"\n',
    )
    _write(root, ".gitignore", "junit.xml\n")
    _write(
        root,
        "src/calc.js",
        "exports.add = (a, b) => a + b;\nexports.mul = (a, b) => a * b + 1;\n",
    )
    _write(
        root,
        "src/calc.test.js",
        """\
        const test = require("node:test");
        const assert = require("node:assert");
        const { add, mul } = require("./calc");

        test("adds numbers", () => assert.strictEqual(add(1, 2), 3));
        test("multiplies numbers", () => assert.strictEqual(mul(2, 3), 6));
        """,
    )
    _commit(root, "base")
    _git(root, "switch", "-qc", "feature")
    _write(
        root,
        "src/calc.js",
        "exports.add = (a, b) => a - b;\nexports.mul = (a, b) => a * b + 1;\n",
    )
    _commit(root)
    # junit.xml: the working tree's own test run writes it.
    before = _snapshot(root, outputs=frozenset({"junit.xml"}))

    result = run(root, base_ref="main")

    assert result.verdict == "fail"
    origins = _tests_check(result).failure_origins
    assert {t["test"]: t["origin"] for t in origins["tests"]} == {
        "test > adds numbers": "introduced",
        "test > multiplies numbers": "preexisting",
    }
    assert "whole command ran on the base" in origins["reason"]
    assert _snapshot(root, outputs=frozenset({"junit.xml"})) == before


def test_stop_hook_message_names_the_agents_failures(repo: Path):
    from skylos.commands.hook_cmd import _done_origins_sentence

    _write(repo, "app/calc.py", CALC.replace("return a - b", "return a + b"))
    _commit(repo)
    result = run(repo, base_ref="main")
    sentence = _done_origins_sentence(result)
    assert sentence == (
        "1 failing test is new in this change: tests/test_calc.py::test_sub; "
        f"1 was already failing on {_tests_check(result).failure_origins['base']['label']}"
        ": tests/test_calc.py::test_mul. Fix the 1 new failure before saying you are done."
    )


def test_stop_hook_tells_the_agent_which_failures_are_its_own(tmp_path: Path):
    import io
    import shlex

    from skylos.commands.hook_cmd import HookDeps, run_hook_command

    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    command = shlex.join([sys.executable, "-m", "pytest", "-q"])
    _write(root, ".gitignore", ".skylos/\n__pycache__/\n")
    _write(
        root,
        "pyproject.toml",
        "[tool.skylos.done]\n"
        f"test_command = {json.dumps(command)}\n"
        "[tool.skylos.done.checks]\n"
        "unknown_imports = 'off'\n"
        "changed_lines_checked = 'off'\n",
    )
    _write(root, "app.py", "value = 1\nbroken = 2\n")
    _write(
        root,
        "test_app.py",
        "from app import broken, value\n\n\n"
        "def test_value():\n    assert value == 1\n\n\n"
        "def test_broken():\n    assert broken == 1\n",
    )
    _commit(root, "base")

    def hook(event):
        stdout = io.StringIO()
        deps = HookDeps()
        deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
        payload = {"cwd": str(root), "session_id": "session-1"}
        run_hook_command(
            [event, "--client", "claude"],
            stdin=io.StringIO(json.dumps(payload)),
            stdout=stdout,
            deps=deps,
        )
        text = stdout.getvalue().strip()
        return json.loads(text) if text else None

    hook("session-start")
    _write(root, "app.py", "value = 2\nbroken = 2\n")  # the agent's regression
    output = hook("stop")

    assert output["decision"] == "block"
    reason = output["reason"]
    assert reason.splitlines()[1] == (
        "1 failing test is new in this change: test_app.py::test_value; "
        "1 was already failing on the session start ("
        + _git(root, "rev-parse", "--short=7", "HEAD").strip()
        + "): test_app.py::test_broken. Fix the 1 new failure before saying you "
        "are done."
    )
    receipt = json.loads((root / ".skylos" / "receipts" / "latest.json").read_text())
    assert receipt["failure_origins"]["counts"]["preexisting"] == 1
    assert receipt["base"]["source"] == "session"


def test_commands_that_build_their_own_environment_are_not_rerun(
    tmp_path: Path, monkeypatch
):
    # A stand-in for `uv run`: in the base checkout the real one would create
    # and sync a new environment, which Skylos never does.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "uv"
    stub.write_text(f'#!/bin/sh\nshift 2\nexec "{sys.executable}" -m pytest "$@"\n')
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    root = _make_repo(
        tmp_path,
        'test_command = ["uv", "run", "pytest", "--junitxml=junit.xml"]\n'
        'junit_xml = "junit.xml"\n',
    )
    _write(root, ".gitignore", "junit.xml\n")
    _commit(root)

    result = run(root, base_ref="main")

    origins = _tests_check(result).failure_origins
    assert origins["status"] == "not_checked"
    assert "(uv) sets up its own environment" in origins["reason"]
    assert result.verdict == "fail"


def test_a_base_file_that_does_not_import_leaves_other_tests_checked(tmp_path: Path):
    root = _make_repo(tmp_path)
    _write(
        root,
        "tests/test_feat.py",
        "from app.feature import compute\n\n\ndef test_compute():\n"
        "    assert compute(2) == 4\n",
    )
    _git(root, "switch", "-q", "main")
    _commit(root, "main: a test for a module that is not there yet")
    _git(root, "switch", "-q", "feature")
    _git(root, "merge", "-q", "main")
    _write(root, "app/feature.py", "def compute(x):\n    return x * 2 + 1\n")
    _commit(root)

    result = run(root, base_ref="main")

    labels = _tests_check(result).failure_origins["tests"]
    by_test = {t["test"]: t for t in labels}
    assert by_test["tests/test_calc.py::test_mul"]["origin"] == "preexisting"
    feat = by_test["tests/test_feat.py::test_compute"]
    assert feat["origin"] == "undetermined"
    assert feat["detail"] == "the base run did not collect its file"


def test_a_flaky_base_failure_is_not_called_preexisting(tmp_path: Path, monkeypatch):
    root = _make_repo(tmp_path)
    _write(
        root,
        "tests/test_flaky.py",
        """\
        import os
        from pathlib import Path


        def test_flaky():
            counter = Path(os.environ["FLAKY_COUNTER"])
            n = int(counter.read_text() or "0") + 1 if counter.exists() else 1
            counter.write_text(str(n))
            assert n > 3
        """,
    )
    _git(root, "switch", "-q", "main")
    _commit(root, "main: a flaky test")
    _git(root, "switch", "-q", "feature")
    _git(root, "merge", "-q", "main")
    counter = tmp_path / "count"
    monkeypatch.setenv("FLAKY_COUNTER", str(counter))

    result = run(root, base_ref="main")

    # Here it failed twice (runs 1 and 2); on the base it failed (3), then passed (4).
    assert counter.read_text() == "4"
    by_test = {t["test"]: t for t in _tests_check(result).failure_origins["tests"]}
    flaky = by_test["tests/test_flaky.py::test_flaky"]
    assert flaky["origin"] == "undetermined"
    assert "then passed on a second base run (flaky)" in flaky["detail"]
    assert by_test["tests/test_calc.py::test_mul"]["origin"] == "preexisting"
