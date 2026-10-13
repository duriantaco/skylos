"""skylos cicd risk-review: risk classes, settings, outputs and human approvals."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.cicd import approval, approval_github
from skylos.cicd.approval import (
    VETO_CLASSES,
    analyze_change,
    is_migration_path,
    parse_approval_config,
    parse_numstat,
)
from skylos.commands import risk_review_cmd
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import checks as done_checks
from skylos.rules.ai_defect import diff_dependencies

GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"

CALC = """\
def add(a, b):
    return a + b


def sub(a, b):
    return a - b
"""
TESTS = """\
from app.calc import add, sub


def test_add():
    assert add(1, 2) == 3


def test_sub():
    assert sub(3, 1) == 2
"""
VIEWS = """\
from django.contrib.auth.decorators import login_required


@login_required
def export_customer(request):
    return 42
"""
PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests>=2.31"]

[tool.ruff.lint]
select = ["E", "F"]
"""
PACKAGE_JSON = """\
{
  "name": "demo-web",
  "version": "1.0.0",
  "scripts": {"build": "tsc"},
  "dependencies": {"left-pad": "^1.3.0"},
  "devDependencies": {"typescript": "^5.4.0"}
}
"""
WORKFLOW = """\
on: pull_request
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Lint
        run: ruff check .
"""
BASE_FILES = {
    "app/__init__.py": "",
    "app/calc.py": CALC,
    "app/views.py": VIEWS,
    "tests/test_calc.py": TESTS,
    "pyproject.toml": PYPROJECT,
    "requirements.txt": "requests==2.31.0\n",
    "package.json": PACKAGE_JSON,
    ".github/workflows/ci.yml": WORKFLOW,
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _write(root: Path, files: dict[str, str | None]) -> None:
    for rel, text in files.items():
        path = root / rel
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, dedent(text))


def _repo(tmp_path: Path, head: dict, *, base: dict | None = None) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {**BASE_FILES, **(base or {})})
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    _write(root, head)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "head", "--allow-empty")
    return root


def _analyze(tmp_path: Path, head: dict, *, base: dict | None = None):
    return analyze_change(str(_repo(tmp_path, head, base=base)), "main")


def _classes(result) -> list[str]:
    return result.classes_found


def _run(root: Path, *extra: str, fmt: str = "json", capsys=None):
    args = argparse.Namespace(path=str(root), base="main", format=fmt)
    for flag in extra:
        key, _, value = flag.partition("=")
        setattr(args, key, value)
    code = risk_review_cmd.run_risk_review(args)
    out = capsys.readouterr().out if capsys is not None else ""
    return code, (json.loads(out) if fmt == "json" and out else out)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No registry lookups and no GitHub context unless a test sets one."""
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {"findings": [], "registry_unreachable": False},
    )
    for name in (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_PATH",
        "GITHUB_BASE_REF",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_OUTPUT",
        "BITBUCKET_PR_DESTINATION_BRANCH",
        "SYSTEM_PULLREQUEST_TARGETBRANCH",
    ):
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# a clean change
# ---------------------------------------------------------------------------


def test_a_plain_code_change_has_no_risk_and_is_eligible(tmp_path: Path):
    result = _analyze(
        tmp_path, {"app/calc.py": CALC + "\n\ndef mul(a, b):\n    return a * b\n"}
    )
    assert result.vetoes == []
    assert result.eligible
    assert result.classes_checked == list(VETO_CLASSES)
    assert result.files_changed == 1 and result.lines_changed == 4


# ---------------------------------------------------------------------------
# tests_weakened
# ---------------------------------------------------------------------------


def test_deleted_and_skipped_tests_need_a_human(tmp_path: Path):
    head = TESTS.replace("def test_sub():\n    assert sub(3, 1) == 2\n", "").replace(
        "def test_add():", "import pytest\n\n\n@pytest.mark.skip\ndef test_add():"
    )
    result = _analyze(tmp_path, {"tests/test_calc.py": head})
    rules = {(r.cls, r.rule_id) for r in result.vetoes}
    assert ("tests_weakened", "SKY-A110") in rules
    assert ("tests_weakened", "SKY-A111") in rules
    deleted = next(r for r in result.vetoes if r.rule_id == "SKY-A110")
    assert deleted.file == "tests/test_calc.py"
    assert "test_sub was deleted" in deleted.reason


def test_moved_renamed_and_new_tests_are_not_weakening(tmp_path: Path):
    moved = TESTS.replace("def test_sub", "def test_sub_moved")
    result = _analyze(
        tmp_path,
        {
            "tests/test_calc.py": None,
            "tests/unit/test_calc.py": moved
            + "\n\ndef test_add_zero():\n    assert add(0, 0) == 0\n",
        },
    )
    assert "tests_weakened" not in _classes(result)


def test_test_deleted_with_the_feature_is_advice_not_a_risk(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {
            "app/calc.py": "def add(a, b):\n    return a + b\n",
            "tests/test_calc.py": TESTS.replace(
                "def test_sub():\n    assert sub(3, 1) == 2\n", ""
            ).replace("import add, sub", "import add"),
        },
    )
    assert "tests_weakened" not in _classes(result)
    assert any(a.rule_id == "SKY-A110" for a in result.advisories)


# ---------------------------------------------------------------------------
# auth_removed
# ---------------------------------------------------------------------------


def test_removed_auth_decorator_needs_a_human(tmp_path: Path):
    result = _analyze(
        tmp_path, {"app/views.py": VIEWS.replace("@login_required\n", "")}
    )
    risk = next(r for r in result.vetoes if r.cls == "auth_removed")
    assert risk.rule_id == "SKY-L021" and risk.file == "app/views.py"


def test_editing_a_protected_view_keeps_auth(tmp_path: Path):
    result = _analyze(tmp_path, {"app/views.py": VIEWS.replace("42", "43")})
    assert "auth_removed" not in _classes(result)


# ---------------------------------------------------------------------------
# dependency_changed (end to end; formats are covered further down)
# ---------------------------------------------------------------------------


def test_added_and_bumped_dependencies_need_a_human(tmp_path: Path):
    package = PACKAGE_JSON.replace(
        '"left-pad": "^1.3.0"', '"left-pad": "^1.3.0", "lodahs": "^4.17.21"'
    )
    result = _analyze(
        tmp_path,
        {"package.json": package, "requirements.txt": "requests==2.32.0\n"},
    )
    risks = [r for r in result.vetoes if r.cls == "dependency_changed"]
    assert {r.file for r in risks} == {"package.json", "requirements.txt"}
    npm = next(r for r in risks if r.file == "package.json")
    assert "lodahs (^4.17.21)" in npm.reason and npm.line == 5
    pip = next(r for r in risks if r.file == "requirements.txt")
    assert "requests ==2.31.0 -> ==2.32.0" in pip.reason


def test_version_bumps_scripts_and_section_moves_are_not_dependency_changes(
    tmp_path: Path,
):
    package = (
        PACKAGE_JSON.replace('"1.0.0"', '"1.1.0"')
        .replace('"tsc"', '"tsc -p ."')
        .replace('"dependencies": {"left-pad": "^1.3.0"}', '"dependencies": {}')
        .replace(
            '"devDependencies": {"typescript": "^5.4.0"}',
            '"devDependencies": {"typescript": "^5.4.0", "left-pad": "^1.3.0"}',
        )
    )
    result = _analyze(
        tmp_path,
        {
            "package.json": package,
            "pyproject.toml": PYPROJECT.replace("0.1.0", "0.2.0"),
        },
    )
    assert "dependency_changed" not in _classes(result)


def test_hallucinated_import_from_the_registry_check_is_a_dependency_risk(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {
            "findings": [
                {
                    "rule_id": "SKY-D222",
                    "file": "app/calc.py",
                    "line": 1,
                    "message": "import reqeusts: no such package on PyPI",
                },
                {
                    "rule_id": "SKY-D223",
                    "file": "app/calc.py",
                    "line": 2,
                    "message": "yaml is not declared",
                },
            ],
            "registry_unreachable": False,
        },
    )
    result = _analyze(
        tmp_path, {"app/calc.py": "import reqeusts\nimport yaml\n" + CALC}
    )
    assert [
        (r.rule_id, r.line) for r in result.vetoes if r.cls == "dependency_changed"
    ] == [("SKY-D222", 1)]
    assert [a.rule_id for a in result.advisories] == ["SKY-D223"]


def test_unreachable_registry_leaves_dependencies_unchecked(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {"findings": [], "registry_unreachable": True},
    )
    result = _analyze(tmp_path, {"app/calc.py": "import json\n" + CALC})
    assert "dependency_changed" in result.classes_incomplete
    assert not result.eligible


# ---------------------------------------------------------------------------
# ci_weakened
# ---------------------------------------------------------------------------


def test_quiet_lint_step_and_widened_permissions_need_a_human(tmp_path: Path):
    head = WORKFLOW.replace("ruff check .", "ruff check . || true").replace(
        "contents: read", "contents: write"
    )
    result = _analyze(tmp_path, {".github/workflows/ci.yml": head})
    rules = sorted(r.rule_id for r in result.vetoes if r.cls == "ci_weakened")
    assert rules == ["SKY-A103", "SKY-A121"]
    a103 = next(r for r in result.vetoes if r.rule_id == "SKY-A103")
    assert "contents: write" in a103.reason and a103.line == 3


def test_a_new_ci_step_is_not_weakening(tmp_path: Path):
    head = WORKFLOW + "      - name: Types\n        run: mypy app\n"
    result = _analyze(tmp_path, {".github/workflows/ci.yml": head})
    assert "ci_weakened" not in _classes(result)


# ---------------------------------------------------------------------------
# checks_silenced
# ---------------------------------------------------------------------------


def test_linter_rule_ignored_needs_a_human_but_inline_noqa_is_advice(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT + 'ignore = ["E501"]\n',
            "app/calc.py": "import os  # noqa\n" + CALC,
        },
    )
    silenced = [r for r in result.vetoes if r.cls == "checks_silenced"]
    assert [(r.rule_id, r.reason) for r in silenced] == [
        ("SKY-A119", "ruff now ignores E501")
    ]
    assert any(a.rule_id == "SKY-A118" for a in result.advisories)


def test_inline_suppression_alone_needs_no_approval(tmp_path: Path):
    result = _analyze(tmp_path, {"app/calc.py": "import os  # noqa: F401\n" + CALC})
    assert "checks_silenced" not in _classes(result)


APP_JS = (
    'function greet(name) {\n  return "hi " + name;\n}\nmodule.exports = { greet };\n'
)
TEST_JS = 'const { greet } = require("./app");\ntest("greet", () => {\n  expect(greet("a")).toBe("hi a");\n});\n'
WEB = {"web/app.js": APP_JS, "web/app.test.js": TEST_JS}


def _silenced(result) -> list[tuple]:
    return [
        (r.rule_id, r.file, r.line, r.reason)
        for r in result.vetoes
        if r.cls == "checks_silenced"
    ]


def test_whole_file_suppression_needs_a_human_and_is_not_also_advice(
    tmp_path: Path,
):
    result = _analyze(
        tmp_path, {"web/app.js": "/* eslint-disable */\n" + APP_JS}, base=WEB
    )
    assert _silenced(result) == [
        (
            "SKY-A118",
            "web/app.js",
            1,
            "adds eslint-disable with no reason: ESLint no longer checks this whole file",
        )
    ]
    assert not [a for a in result.advisories if a.rule_id == "SKY-A118"]
    assert not result.eligible


def test_named_or_one_line_suppressions_stay_advice(tmp_path: Path):
    app = APP_JS.replace(
        '  return "hi " + name;',
        "  // eslint-disable-next-line no-console\n  console.log(name);\n"
        '  return "hi " + name;',
    )
    result = _analyze(
        tmp_path,
        {"web/app.js": app, "app/calc.py": "# ruff: noqa: E501\n" + CALC},
        base=WEB,
    )
    assert "checks_silenced" not in _classes(result)
    assert sorted(a.file for a in result.advisories if a.rule_id == "SKY-A118") == [
        "app/calc.py",
        "web/app.js",
    ]


def test_blanket_suppression_in_a_test_file_counts_but_not_in_generated_code(
    tmp_path: Path,
):
    result = _analyze(
        tmp_path,
        {
            "web/app.test.js": "/* eslint-disable */\n" + TEST_JS,
            "web/gen.js": "// @generated\n/* eslint-disable */\nconst a = 1;\n",
        },
        base=WEB,
    )
    assert [file for _, file, _, _ in _silenced(result)] == ["web/app.test.js"]


def test_settings_that_exclude_only_tests_still_need_a_human(tmp_path: Path):
    pyproject = PYPROJECT.replace(
        "[tool.ruff.lint]",
        '[tool.ruff]\nextend-exclude = ["tests"]\n\n[tool.ruff.lint]',
    )
    result = _analyze(tmp_path, {"pyproject.toml": pyproject})
    [(rule, file, _, reason)] = _silenced(result)
    assert (rule, file) == ("SKY-A119", "pyproject.toml")
    assert reason.startswith("ruff now excludes 'tests', which holds only test files")


def test_teams_can_turn_checks_silenced_off_or_exclude_paths(tmp_path: Path):
    others = [c for c in VETO_CLASSES if c != "checks_silenced"]
    off = PYPROJECT + f"\n[tool.skylos.approval]\nveto_classes = {json.dumps(others)}\n"
    (tmp_path / "off").mkdir()
    result = _analyze(
        tmp_path / "off",
        {"web/app.js": "/* eslint-disable */\n" + APP_JS},
        base={**WEB, "pyproject.toml": off},
    )
    assert result.eligible and not result.advisories
    excluded = (
        PYPROJECT
        + '\n[tool.skylos.approval.exclude]\nchecks_silenced = ["web/legacy/**"]\n'
    )
    (tmp_path / "excluded").mkdir()
    result = _analyze(
        tmp_path / "excluded",
        {"web/legacy/old.js": "/* eslint-disable */\n" + APP_JS},
        base={"web/legacy/old.js": APP_JS, "pyproject.toml": excluded},
    )
    assert result.eligible and result.excluded == 1


# ---------------------------------------------------------------------------
# secret_added
# ---------------------------------------------------------------------------


def test_added_secret_needs_a_human(tmp_path: Path):
    result = _analyze(tmp_path, {"app/settings.py": f'GITHUB_TOKEN = "{GH_TOKEN}"\n'})
    risk = next(r for r in result.vetoes if r.cls == "secret_added")
    assert risk.rule_id == "SKY-S101" and risk.line == 1
    assert GH_TOKEN not in json.dumps(risk.to_dict())


def test_secret_reference_is_not_a_secret(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {"app/settings.py": 'import os\nGITHUB_TOKEN = os.environ["GITHUB_TOKEN"]\n'},
    )
    assert "secret_added" not in _classes(result)


# ---------------------------------------------------------------------------
# guardrail_config_changed, including rules other releases add
# ---------------------------------------------------------------------------


def test_skylos_settings_and_agent_permissions_need_a_human(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT + "\n[tool.skylos]\nexclude = ['app']\n",
            ".claude/settings.json": '{"permissions": {"allow": ["Bash(*)"]}}\n',
        },
    )
    risks = [r for r in result.vetoes if r.cls == "guardrail_config_changed"]
    assert {r.file for r in risks} == {"pyproject.toml", ".claude/settings.json"}
    assert {r.rule_id for r in risks} == {"SKY-A114"}


@pytest.mark.parametrize(
    "rule, expected",
    [
        ("SKY-A122", "guardrail_config_changed"),
        ("SKY-A123", "guardrail_config_changed"),
        ("SKY-A124", "ci_weakened"),
    ],
)
def test_rules_from_a_new_done_check_map_to_their_class(
    tmp_path: Path, monkeypatch, rule, expected
):
    def new_check(ctx):
        return done_checks.CheckResult(
            "new_check",
            rule,
            "fail",
            "new",
            findings=[
                done_checks.Finding(
                    rule, ".coderabbit.yaml", 3, "reviewer config edited"
                ),
                done_checks.Finding(rule, "a.py", 1, "(advice) maybe", blocking=False),
            ],
        )

    monkeypatch.setitem(done_checks.CHECKS, "new_check", (new_check, rule))
    result = _analyze(tmp_path, {"app/calc.py": CALC + "\n"})
    assert [(r.cls, r.rule_id, r.file) for r in result.vetoes] == [
        (expected, rule, ".coderabbit.yaml")
    ]
    assert [a.reason for a in result.advisories] == ["maybe"]


def test_a_scanner_marker_from_a_done_check_is_checks_silenced_advice(
    tmp_path: Path, monkeypatch
):
    # SKY-A125 maps to checks_silenced; like SKY-A118's inline suppressions,
    # a marker `done` reports is advice here even when the finding blocks.
    def new_check(ctx):
        return done_checks.CheckResult(
            "new_check",
            "SKY-A125",
            "fail",
            "new",
            findings=[done_checks.Finding("SKY-A125", "a.ts", 3, "adds skipcq")],
        )

    monkeypatch.setitem(done_checks.CHECKS, "new_check", (new_check, "SKY-A125"))
    result = _analyze(tmp_path, {"app/calc.py": CALC + "\n"})
    assert result.vetoes == []
    assert [(a.cls, a.rule_id, a.file) for a in result.advisories] == [
        ("checks_silenced", "SKY-A125", "a.ts")
    ]


def test_an_unknown_rule_from_a_one_class_check_still_counts(tmp_path, monkeypatch):
    def secrets(ctx):
        return done_checks.CheckResult(
            "secrets",
            "SKY-S101",
            "fail",
            "1 secret",
            findings=[done_checks.Finding("SKY-S199", "a.py", 2, "new secret kind")],
        )

    monkeypatch.setitem(done_checks.CHECKS, "secrets", (secrets, "SKY-S101"))
    result = _analyze(tmp_path, {"app/calc.py": CALC + "\n"})
    assert [(r.cls, r.rule_id) for r in result.vetoes] == [("secret_added", "SKY-S199")]


def test_a_new_done_check_that_cannot_finish_leaves_its_class_unchecked(
    tmp_path: Path, monkeypatch
):
    def broken(ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(done_checks.CHECKS, "new_check", (broken, "SKY-A122"))
    result = _analyze(tmp_path, {"app/calc.py": CALC + "\n"})
    assert list(result.classes_incomplete) == ["guardrail_config_changed"]
    assert "guardrail_config_changed" not in result.classes_checked


# ---------------------------------------------------------------------------
# migration_changed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "app/migrations/0002_add_email.py",
        "db/migrate/20240101000000_add_email.rb",
        "alembic/versions/3f2a_add_email.py",
        "prisma/migrations/20240101_init/migration.sql",
        "src/main/resources/db/migration/V2__email.sql",
        "Data/Migrations/20240101_Init.cs",
        "supabase/migrations/20240101_init.sql",
    ],
)
def test_migration_paths(path):
    assert is_migration_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "docs/migrations.md",
        "docs/migrations/upgrading-to-v2.md",
        "docs/migration/guide.mdx",
        "app/migrate.py",
        "vendor/github.com/acme/tool/migrations/0001.sql",
        "schema.sql",
    ],
)
def test_not_migration_paths(path):
    assert not is_migration_path(path)


def test_migration_change_needs_a_human_and_globs_extend_the_defaults(tmp_path: Path):
    base = {
        "pyproject.toml": PYPROJECT
        + '\n[tool.skylos.approval]\nmigration_globs = ["db/schema/*.sql"]\n'
    }
    result = _analyze(
        tmp_path,
        {
            "app/migrations/0002_email.py": "operations = []\n",
            "db/schema/001.sql": "create table t (id int);\n",
            "docs/migrations/v2.md": "# Upgrading\n",
        },
        base=base,
    )
    risks = [r for r in result.vetoes if r.cls == "migration_changed"]
    assert [(r.file, r.reason) for r in risks] == [
        (
            "app/migrations/0002_email.py",
            "adds database migration app/migrations/0002_email.py",
        ),
        ("db/schema/001.sql", "adds database migration db/schema/001.sql"),
    ]


# ---------------------------------------------------------------------------
# large_diff
# ---------------------------------------------------------------------------


def test_large_diff_thresholds_come_from_the_base_and_skip_lockfiles(tmp_path: Path):
    base = {
        "pyproject.toml": PYPROJECT
        + "\n[tool.skylos.approval]\nlarge_diff_lines = 10\nlarge_diff_files = 3\n"
    }
    lock = "\n".join(f"line {i}" for i in range(500)) + "\n"
    result = _analyze(
        tmp_path,
        {"app/calc.py": CALC + "\n# small\n", "uv.lock": lock},
        base=base,
    )
    assert "large_diff" not in _classes(result)
    assert result.files_changed == 1 and result.lines_changed == 2
    unreadable = next(r for r in result.vetoes if r.cls == "dependency_changed")
    assert unreadable.file == "uv.lock"
    assert "could not be compared" in unreadable.reason

    root = tmp_path / "second"
    root.mkdir()
    result = _analyze(
        root,
        {f"app/m{i}.py": f"X = {i}\n" for i in range(4)},
        base=base,
    )
    risk = next(r for r in result.vetoes if r.cls == "large_diff")
    assert risk.reason == (
        "changes 4 lines in 4 files (limit: 10 lines or 3 files; lockfiles not counted)"
    )


def test_gitattributes_cannot_hide_lines_from_the_size_check(tmp_path: Path):
    base = {
        ".gitattributes": "*.py -diff\n",
        "pyproject.toml": PYPROJECT
        + "\n[tool.skylos.approval]\nlarge_diff_lines = 50\n",
    }
    big = "".join(f"X{i} = {i}\n" for i in range(60))
    result = _analyze(tmp_path, {"app/big.py": big}, base=base)
    assert result.lines_changed == 60
    assert "large_diff" in _classes(result)


def test_parse_numstat_reads_renames_and_binaries():
    output = "3\t1\tsrc/a.py\x00-\t-\tlogo.png\x000\t0\t\x00old/b.py\x00new/b.py\x00"
    assert parse_numstat(output) == {
        "src/a.py": (3, 1),
        "logo.png": (None, None),
        "new/b.py": (0, 0),
    }


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------


def test_settings_parse_and_report_problems():
    config = parse_approval_config(
        dedent(
            """\
            [tool.skylos.approval]
            veto_classes = ["tests_weakened", "auth_removed", "nonsense"]
            large_diff_lines = "many"
            large_diff_files = 0
            migration_globs = ["db/*.sql", "/etc/x", "../up"]
            non_human_logins = ["release-robot", "not a login"]

            [tool.skylos.approval.exclude]
            secret_added = ["tests/fixtures/"]
            bogus = ["x"]
            """
        )
    )
    assert config.veto_classes == ("tests_weakened", "auth_removed")
    assert config.large_diff_lines == 800 and config.large_diff_files == 1
    assert config.migration_globs == ("db/*.sql",)
    assert config.non_human_logins == ("release-robot",)
    assert config.exclude == {"secret_added": ("tests/fixtures/",)}
    assert config.problems == (
        "veto_classes: unknown class 'nonsense' ignored",
        "exclude: unknown class 'bogus' ignored",
        "large_diff_lines must be a whole number",
        "large_diff_files must be between 1 and 1000000",
        "migration_globs: pattern '/etc/x' ignored",
        "migration_globs: pattern '../up' ignored",
        "non_human_logins: 'not a login' is not a GitHub login",
    )
    assert parse_approval_config(None).veto_classes == VETO_CLASSES
    assert parse_approval_config("not = [toml").problems


def test_turned_off_classes_and_excluded_paths_need_no_approval(tmp_path: Path):
    base = {
        "pyproject.toml": PYPROJECT
        + dedent(
            """
            [tool.skylos.approval]
            veto_classes = ["tests_weakened", "secret_added", "auth_removed"]

            [tool.skylos.approval.exclude]
            secret_added = ["tests/fixtures/"]
            """
        )
    }
    result = _analyze(
        tmp_path,
        {
            "tests/fixtures/token.py": f'TOKEN = "{GH_TOKEN}"\n',
            "requirements.txt": "requests==2.32.0\n",
            "app/views.py": VIEWS.replace("@login_required\n", ""),
        },
        base=base,
    )
    assert _classes(result) == ["auth_removed"]
    assert result.excluded == 1
    assert "dependency_changed" in result.classes_disabled
    assert result.classes_checked == ["tests_weakened", "auth_removed", "secret_added"]


def test_the_change_cannot_turn_off_its_own_risks(tmp_path: Path):
    loosened = PYPROJECT + "\n[tool.skylos.approval]\nveto_classes = []\n"
    result = _analyze(
        tmp_path,
        {"pyproject.toml": loosened, "requirements.txt": "requests==2.32.0\n"},
    )
    assert "dependency_changed" in _classes(result)
    assert "guardrail_config_changed" in _classes(result)


# ---------------------------------------------------------------------------
# command: formats, exit codes, GitHub files
# ---------------------------------------------------------------------------


def test_json_schema_and_exit_codes(tmp_path: Path, capsys):
    root = _repo(tmp_path, {"app/views.py": VIEWS.replace("@login_required\n", "")})
    code, payload = _run(root, capsys=capsys)
    data = payload["approval"]
    assert code == 1
    assert set(data) >= {
        "schema",
        "check",
        "verdict",
        "passed",
        "eligible",
        "complete",
        "needs_human_approval",
        "human_approval",
        "vetoes",
        "advisories",
        "classes_checked",
        "classes_incomplete",
        "classes_disabled",
        "base",
        "base_ref",
        "head",
        "head_dirty",
        "diff",
        "exit_code",
    }
    assert data["schema"] == "skylos.approval/v1"
    assert data["check"] == "Skylos risk review"
    assert data["verdict"] == "needs_human_approval"
    assert (data["eligible"], data["passed"], data["complete"]) == (False, False, True)
    assert data["needs_human_approval"] == ["auth_removed"]
    assert data["human_approval"] is None
    assert set(data["vetoes"][0]) == {"class", "rule_id", "file", "line", "reason"}
    assert data["head"] == _git(root, "rev-parse", "HEAD")
    assert data["base"] == _git(root, "rev-parse", "main")

    clean = tmp_path / "clean"
    clean.mkdir()
    root = _repo(clean, {"app/calc.py": CALC + "\n"})
    code, payload = _run(root, capsys=capsys)
    assert code == 0
    assert payload["approval"]["verdict"] == "eligible"
    assert payload["approval"]["eligible"] is True


def test_text_and_markdown_say_what_needs_a_human(tmp_path: Path, capsys):
    root = _repo(
        tmp_path,
        {
            "app/views.py": VIEWS.replace("@login_required\n", ""),
            "requirements.txt": "requests==2.32.0\n",
        },
    )
    code, text = _run(root, fmt="text", capsys=capsys)
    assert code == 1
    assert "Skylos risk review: NEEDS A HUMAN APPROVAL (exit 1)" in text
    assert "Needs a human approval: auth_removed (app/views.py:" in text
    assert "dependency_changed (requirements.txt:1)" in text
    code, markdown = _run(root, fmt="markdown", capsys=capsys)
    assert markdown.startswith("### Skylos risk review: NEEDS A HUMAN APPROVAL")
    assert "| `auth_removed` | SKY-L021 |" in markdown


def test_incomplete_analysis_exits_2_and_is_never_eligible(
    tmp_path: Path, monkeypatch, capsys
):
    def broken(ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(done_checks.CHECKS, "security_controls", (broken, "SKY-L021"))
    root = _repo(tmp_path, {"app/calc.py": CALC + "\n"})
    code, payload = _run(root, capsys=capsys)
    data = payload["approval"]
    assert code == 2
    assert data["verdict"] == "incomplete"
    assert (data["eligible"], data["passed"], data["complete"]) == (False, False, False)
    assert data["classes_incomplete"] == [
        {"class": "auth_removed", "reason": "Check could not finish (RuntimeError)"}
    ]


def test_own_comparison_failure_is_incomplete(tmp_path: Path, monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError("bad manifest reader")

    monkeypatch.setattr("skylos.cicd.approval_dependencies.dependency_changes", broken)
    result = _analyze(tmp_path, {"app/calc.py": CALC + "\n"})
    assert result.classes_incomplete == {
        "dependency_changed": "could not finish (ValueError)"
    }


def test_missing_base_or_repository_exits_2_with_a_json_error(tmp_path: Path, capsys):
    root = _repo(tmp_path, {"app/calc.py": CALC + "\n"})
    args = argparse.Namespace(path=str(root), base="origin/nowhere", format="json")
    assert risk_review_cmd.run_risk_review(args) == 2
    data = json.loads(capsys.readouterr().out)["approval"]
    assert data["verdict"] == "error" and data["passed"] is False
    assert "cannot find base 'origin/nowhere'" in data["error"]

    args = argparse.Namespace(path=str(root), base=None, format="json")
    assert risk_review_cmd.run_risk_review(args) == 2
    assert (
        "no base to compare with"
        in json.loads(capsys.readouterr().out)["approval"]["error"]
    )


def test_writes_step_summary_and_outputs(tmp_path: Path, monkeypatch, capsys):
    root = _repo(tmp_path, {"requirements.txt": "requests==2.32.0\n"})
    runner = tmp_path / "runner"
    runner.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(runner / "summary.md"))
    monkeypatch.setenv("GITHUB_OUTPUT", str(runner / "output"))
    code, _ = _run(root, fmt="text", capsys=capsys)
    assert code == 1
    assert (runner / "output").read_text() == (
        "passed=false\neligible=false\nclasses=dependency_changed\n"
    )
    assert (
        "Skylos risk review: NEEDS A HUMAN APPROVAL"
        in (runner / "summary.md").read_text()
    )


def test_base_ref_comes_from_the_pull_request_event(
    tmp_path: Path, monkeypatch, capsys
):
    root = _repo(tmp_path, {"app/calc.py": CALC + "\n"})
    _git(root, "update-ref", "refs/remotes/origin/main", "main")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"base": {"ref": "main"}}}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    args = argparse.Namespace(path=str(root), base=None, format="json")
    assert risk_review_cmd.run_risk_review(args) == 0
    assert json.loads(capsys.readouterr().out)["approval"]["base_ref"] == "origin/main"


# ---------------------------------------------------------------------------
# human approvals (GitHub API mocked; no network)
# ---------------------------------------------------------------------------


def _review(
    login, state="APPROVED", *, commit, rid=1, kind="User", association="MEMBER"
):
    return {
        "id": rid,
        "user": {"login": login, "type": kind},
        "state": state,
        "commit_id": commit,
        "author_association": association,
        "submitted_at": f"2026-10-13T10:00:{rid:02d}Z",
    }


class FakeGitHub:
    def __init__(self, reviews, permissions=None, fail=None):
        self.reviews = reviews
        self.permissions = permissions or {}
        self.fail = fail
        self.urls: list[str] = []

    def __call__(self, url: str):
        self.urls.append(url)
        if self.fail and self.fail in url:
            raise approval_github.GitHubApiError("HTTP 403")
        if "/reviews?" in url:
            page = int(url.rsplit("page=", 1)[1])
            return self.reviews[(page - 1) * 100 : page * 100]
        login = url.rsplit("/collaborators/", 1)[1].split("/", 1)[0]
        return {"permission": self.permissions.get(login, "write")}


@pytest.fixture
def pr_env(tmp_path: Path, monkeypatch):
    """A vetoed pull request in GitHub Actions; returns (root, head, set_api)."""
    root = _repo(tmp_path, {"requirements.txt": "requests==2.32.0\n"})
    head = _git(root, "rev-parse", "HEAD")
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "pull_request": {
                    "number": 7,
                    "head": {"sha": head},
                    "base": {"ref": "main"},
                }
            }
        )
    )
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/web")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))

    def set_api(fake):
        monkeypatch.setattr(approval_github, "_requests_getter", lambda token: fake)
        return fake

    return root, head, set_api


def test_a_person_with_write_access_approving_the_head_passes(pr_env, capsys):
    root, head, set_api = pr_env
    fake = set_api(
        FakeGitHub(
            [
                _review(
                    "copilot-pull-request-reviewer[bot]", commit=head, rid=1, kind="Bot"
                ),
                _review("alice", commit=head, rid=2),
            ]
        )
    )
    code, payload = _run(root, capsys=capsys)
    data = payload["approval"]
    assert code == 0
    assert data["verdict"] == "human_approved" and data["passed"] is True
    assert data["eligible"] is False
    assert data["human_approval"]["login"] == "alice"
    assert data["human_approval"]["ignored"] == [
        "copilot-pull-request-reviewer[bot] (not a person)"
    ]
    assert risk_review_cmd.headline(payload) == (
        "Human-approved: alice approved these risks: dependency_changed (1)"
    )
    assert fake.urls[0] == (
        "https://api.github.com/repos/acme/web/pulls/7/reviews?per_page=100&page=1"
    )
    assert (
        fake.urls[1]
        == "https://api.github.com/repos/acme/web/collaborators/alice/permission"
    )


@pytest.mark.parametrize(
    "reviews, ignored",
    [
        ([_review("ci-bot", commit="HEAD", kind="Bot")], ["ci-bot (not a person)"]),
        ([_review("renovate[bot]", commit="HEAD")], ["renovate[bot] (not a person)"]),
        ([_review("release-robot", commit="HEAD")], ["release-robot (not a person)"]),
        (
            [_review("alice", commit="0" * 40)],
            ["alice (approved an older commit 0000000)"],
        ),
        (
            [_review("drive-by", commit="HEAD", association="CONTRIBUTOR")],
            ["drive-by (no write access)"],
        ),
        (
            [
                _review("alice", commit="HEAD", rid=1),
                _review("alice", "CHANGES_REQUESTED", commit="HEAD", rid=2),
            ],
            [],
        ),
        ([_review("alice", "DISMISSED", commit="HEAD")], []),
        ([_review("alice", "COMMENTED", commit="HEAD")], []),
    ],
)
def test_approvals_that_do_not_count(pr_env, capsys, monkeypatch, reviews, ignored):
    root, head, set_api = pr_env
    for review in reviews:
        if review["commit_id"] == "HEAD":
            review["commit_id"] = head
    base_config = (
        PYPROJECT + '\n[tool.skylos.approval]\nnon_human_logins = ["Release-Robot"]\n'
    )
    _git(root, "switch", "-q", "main")
    _write(root, {"pyproject.toml": base_config})
    _git(root, "commit", "-qam", "settings")
    _git(root, "switch", "-q", "feature")
    set_api(FakeGitHub(reviews))
    code, payload = _run(root, capsys=capsys)
    data = payload["approval"]
    assert code == 1
    assert data["verdict"] == "needs_human_approval"
    assert data["human_approval"]["status"] == "missing"
    assert data["human_approval"]["ignored"] == ignored
    assert risk_review_cmd.headline(payload) == (
        "Needs a human approval: dependency_changed (requirements.txt:1)"
    )


def test_comment_after_an_approval_keeps_it(pr_env, capsys):
    root, head, set_api = pr_env
    set_api(
        FakeGitHub(
            [
                _review("alice", commit=head, rid=1),
                _review("alice", "COMMENTED", commit=head, rid=2),
            ]
        )
    )
    assert _run(root, capsys=capsys)[0] == 0


def test_approver_without_write_permission_does_not_count(pr_env, capsys):
    root, head, set_api = pr_env
    set_api(FakeGitHub([_review("bob", commit=head)], permissions={"bob": "read"}))
    code, payload = _run(root, capsys=capsys)
    assert code == 1
    assert payload["approval"]["human_approval"]["ignored"] == ["bob (no write access)"]


def test_reviews_are_read_across_pages(pr_env, capsys):
    root, head, set_api = pr_env
    reviews = [
        _review(f"bot{i}[bot]", "COMMENTED", commit=head, rid=i, kind="Bot")
        for i in range(1, 101)
    ] + [_review("alice", commit=head, rid=101)]
    fake = set_api(FakeGitHub(reviews))
    assert _run(root, capsys=capsys)[0] == 0
    assert sum("/reviews?" in url for url in fake.urls) == 2


@pytest.mark.parametrize("failing", ["/reviews?", "/permission"])
def test_github_api_errors_fail_closed(pr_env, capsys, failing):
    root, head, set_api = pr_env
    set_api(FakeGitHub([_review("alice", commit=head)], fail=failing))
    code, payload = _run(root, capsys=capsys)
    data = payload["approval"]
    assert code == 2
    assert data["verdict"] == "review_check_failed" and data["passed"] is False
    assert data["human_approval"]["detail"] == "could not read the reviews: HTTP 403"


def test_checked_commit_must_be_the_pull_request_head(pr_env, capsys, tmp_path):
    root, _head, set_api = pr_env
    event = json.loads(Path(tmp_path / "event.json").read_text())
    event["pull_request"]["head"]["sha"] = "1" * 40
    Path(tmp_path / "event.json").write_text(json.dumps(event))
    fake = set_api(FakeGitHub([_review("alice", commit="1" * 40)]))
    code, payload = _run(root, capsys=capsys)
    assert code == 2
    assert (
        "is not the pull request head"
        in payload["approval"]["human_approval"]["detail"]
    )
    assert fake.urls == []


def test_malformed_github_context_fails_closed(pr_env, capsys, monkeypatch):
    root, _head, _set_api = pr_env
    monkeypatch.setenv("GITHUB_API_URL", "http://api.example.com")
    code, payload = _run(root, capsys=capsys)
    assert code == 2
    assert payload["approval"]["human_approval"]["detail"] == (
        "GITHUB_API_URL must be an https:// URL"
    )


def test_no_reviews_are_read_when_nothing_needs_a_human(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path, {"app/calc.py": CALC + "\n"})
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"pull_request": {"number": 1, "head": {"sha": "f" * 40}}})
    )
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/web")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))

    def no_calls(token):
        raise AssertionError("no GitHub call expected")

    monkeypatch.setattr(approval_github, "_requests_getter", no_calls)
    assert _run(root, capsys=capsys)[0] == 0


def test_without_a_token_risks_are_reported_and_exit_1(pr_env, capsys, monkeypatch):
    root, _head, _set_api = pr_env
    monkeypatch.delenv("GITHUB_TOKEN")
    code, payload = _run(root, capsys=capsys)
    assert code == 1 and payload["approval"]["human_approval"] is None


def test_decide_never_passes_an_incomplete_result():
    result = approval.ApprovalResult("main", "a", "b", False, approval.ApprovalConfig())
    result.classes_incomplete["tests_weakened"] = "boom"
    human = approval_github.HumanApproval("approved", login="alice")
    assert risk_review_cmd.decide(result, human) == (2, "incomplete")
    result.classes_incomplete.clear()
    result.vetoes.append(approval.Risk("large_diff", None, None, None, "big"))
    assert risk_review_cmd.decide(result, None) == (1, "needs_human_approval")
    assert risk_review_cmd.decide(result, human) == (0, "human_approved")
    error = approval_github.HumanApproval("error", detail="x")
    assert risk_review_cmd.decide(result, error) == (2, "review_check_failed")
