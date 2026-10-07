"""skylos done: linters, type checkers, scanners and CI not silenced
(SKY-A118 inline suppressions, SKY-A119 settings, SKY-A121 CI)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_silenced_checks
from skylos.done.ci_checks import classify
from skylos.done.config import DEFAULT_MODES, DoneConfig, parse_done_config
from skylos.done.engine import run
from skylos.done.receipt import FIXES, LABELS
from skylos.done.suppressions import directives
from skylos.done.test_config import detect_loosened_test_config

A118, A119, A121 = "SKY-A118", "SKY-A119", "SKY-A121"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _write(root: Path, files: dict[str, str | None]) -> None:
    for rel, text in files.items():
        path = root / rel
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, dedent(text))


def _repo(tmp_path: Path, base: dict, head: dict) -> Path:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    _write(root, base)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base", "--allow-empty")
    _git(root, "switch", "-qc", "feature")
    _write(root, head)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "head", "--allow-empty")
    return root


def _check(tmp_path: Path, base: dict, head: dict):
    root = _repo(tmp_path, base, head)
    return check_silenced_checks(
        CheckContext(open_comparison(root, "main"), DoneConfig())
    )


def _messages(result, rule: str | None = None, *, blocking: bool | None = None):
    return [
        f.message
        for f in result.findings
        if (rule is None or f.rule == rule)
        and (blocking is None or f.blocking == blocking)
    ]


def _test_ci(tmp_path: Path, base: dict, head: dict) -> list[str]:
    root = _repo(tmp_path, base, head)
    return [
        f.message for f in detect_loosened_test_config(open_comparison(root, "main"))
    ]


APP = """\
import os


def main():
    return os.getcwd()
"""
SRC = {"app/__init__.py": "", "app/main.py": APP, "app/legacy/old.py": "x = 1\n"}

# ---------------------------------------------------------------------------
# SKY-A118: inline suppressions
# ---------------------------------------------------------------------------


def test_directives_read_each_language_and_skip_strings():
    py = dedent(
        """\
        import os  # noqa: F401
        x = "# noqa"  # type: ignore[attr-defined]  # upstream stub is wrong
        # the URL cannot be split
        y = 1  # noqa: E501
        if TYPE_CHECKING:  # pragma: no cover
            pass
        z = f()  # pragma: no cover
        """
    )
    found = {(d.line, d.name, d.rules, d.reason) for d in directives("a.py", py)}
    assert (1, "noqa", ("F401",), "") in found
    assert (2, "type: ignore", ("attr-defined",), "upstream stub is wrong") in found
    assert (4, "noqa", ("E501",), "the URL cannot be split") in found
    assert (7, "pragma: no cover", (), "") in found
    assert not any(line == 5 for line, *_ in found)  # the TYPE_CHECKING idiom
    js = dedent(
        """\
        // @ts-nocheck
        const a = 1; // eslint-disable-line no-console -- logging is wanted here
        // @ts-expect-error: upstream types are wrong
        c();
        // @ts-ignore
        d();
        // biome-ignore lint/suspicious/noExplicitAny: <explanation>
        const s = "// eslint-disable-line";
        """
    )
    found = {(d.line, d.name, d.scope, d.reason) for d in directives("a.ts", js)}
    assert (1, "@ts-nocheck", "file", "") in found
    assert (2, "eslint-disable-line", "line", "logging is wanted here") in found
    assert (3, "@ts-expect-error", "line", "upstream types are wrong") in found
    assert (5, "@ts-ignore", "line", "") in found
    assert (7, "biome-ignore", "line", "") in found  # the placeholder is no reason
    assert not any(line == 8 for line, *_ in found)
    go = 'package x\n//nolint:errcheck // closing cannot fail\nvar s = "//nolint"\n'
    assert [(d.line, d.rules, d.reason) for d in directives("a.go", go)] == [
        (2, ("errcheck",), "closing cannot fail")
    ]
    rust = '#![allow(dead_code)]\n#[allow(clippy::unwrap_used, reason = "checked")]\n'
    assert [(d.scope, d.rules, d.reason) for d in directives("a.rs", rust)] == [
        ("file", ("dead_code",), ""),
        ("line", ("clippy::unwrap_used",), "checked"),
    ]
    java = '@SuppressWarnings("unchecked")\nString s = "@SuppressWarnings(x)";\n'
    assert [(d.line, d.rules) for d in directives("A.java", java)] == [
        (1, ("unchecked",))
    ]


def test_added_suppression_without_a_reason_is_advice_and_counted(tmp_path: Path):
    result = _check(
        tmp_path,
        SRC,
        {
            "app/main.py": APP.replace(
                "import os\n", "import os\nimport sys  # noqa: F401\n"
            )
        },
    )
    assert result.status == "pass"
    (finding,) = result.findings
    assert finding.rule == A118 and not finding.blocking
    assert finding.file == "app/main.py" and finding.line == 2
    assert finding.message == "(advice) adds # noqa: F401 with no reason"
    assert result.evidence["suppressions_added"] == 1
    assert result.evidence["suppressions_no_reason"] == 1


def test_a_reason_on_the_line_or_just_above_is_quoted(tmp_path: Path):
    head = APP + dedent(
        """\


        URL = "https://example.com/a/very/long/path"  # noqa: E501  # a URL
        # The stub for this library is wrong, see issue 12.
        VALUE = os.environ.get("X").upper()  # type: ignore[union-attr]
        """
    )
    result = _check(tmp_path, SRC, {"app/main.py": head})
    messages = _messages(result, A118)
    assert any('(reason: "a URL")' in m for m in messages)
    assert any("The stub for this library is wrong" in m for m in messages)
    assert result.evidence["suppressions_no_reason"] == 0


def test_suppressions_already_there_moved_or_kept_on_an_edited_line_are_not_new(
    tmp_path: Path,
):
    base = {
        **SRC,
        "app/a.py": "def f(x):\n    return x.y  # type: ignore[attr-defined]\n",
        "app/b.py": "import os  # noqa: F401\n",
    }
    head = {
        # edited line that keeps its suppression
        "app/a.py": "def f(x, z=1):\n    return x.y + z  # type: ignore[attr-defined]\n",
        # moved to another file, reindented
        "app/b.py": None,
        "app/c.py": "if True:\n    import os  # noqa: F401\n",
        # an unchanged suppression further down is not on an added line
        "app/main.py": "# header\n" + APP,
    }
    result = _check(tmp_path, base, head)
    assert _messages(result, A118) == []
    assert result.evidence["suppressions_added"] == 0


def test_suppressions_in_test_files_and_generated_files_are_not_listed(
    tmp_path: Path,
):
    result = _check(
        tmp_path,
        SRC,
        {
            "tests/test_main.py": "from app.main import main  # noqa: F401\n",
            "src/api.test.ts": "// @ts-expect-error\nf(1);\n",
            "app/gen_pb2.py": "import os  # noqa: F401\n",
        },
    )
    assert _messages(result, A118) == []
    assert result.evidence["suppressions_in_tests"] == 2


def test_whole_file_suppression_in_an_existing_file_says_so(tmp_path: Path):
    base = {"src/a.ts": "export const a: number = 1;\n"}
    result = _check(
        tmp_path,
        base,
        {
            "src/a.ts": "// @ts-nocheck\nexport const a: number = 1;\n",
            "app/x.py": "# mypy: ignore-errors\nX = 1\n",
        },
    )
    messages = _messages(result, A118)
    assert (
        "(advice) adds @ts-nocheck with no reason: TypeScript no longer checks this file"
        in messages
    )
    assert (
        "(advice) adds # mypy: ignore-errors with no reason: mypy skips this file"
        in messages
    )
    assert result.evidence["suppressions_whole_file"] == 2
    assert result.status == "pass"  # advice


def test_eslint_reason_after_double_dash_and_strings_are_not_comments(
    tmp_path: Path,
):
    base = {"src/a.js": "export function f() {}\n"}
    head = {
        "src/a.js": dedent(
            """\
            export function f() {
              // eslint-disable-next-line no-console -- the CLI prints here
              console.log("x");
              const s = "// eslint-disable-line";
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              return s;
            }
            """
        )
    }
    result = _check(tmp_path, base, head)
    messages = _messages(result, A118)
    assert len(messages) == 2
    assert messages == [
        '(advice) adds eslint-disable-next-line no-console (reason: "the CLI prints here")',
        "(advice) adds eslint-disable-next-line @typescript-eslint/no-explicit-any with no reason",
    ]


def test_variable_used_only_to_hide_an_unused_warning(tmp_path: Path):
    base = {
        "app/m.py": "def f(a, b):\n    return a\n",
        "src/m.js": "export function g(a) { return 1; }\n",
    }
    head = {
        "app/m.py": "def f(a, b):\n    _ = b\n    return a\n\n\ndef h(c):\n    _ = c\n    return c\n",
        "src/m.js": "export function g(a) {\n  void a;\n  return 1;\n}\n",
    }
    result = _check(tmp_path, base, head)
    messages = _messages(result, A118)
    assert "(advice) _ = b only hides that b is unused" in messages
    assert not any("_ = c" in m for m in messages)  # c is used
    assert "(advice) void a; only hides that a is unused" in messages
    assert result.evidence["unused_var_tricks"] == 2


# ---------------------------------------------------------------------------
# SKY-A119: settings weakened
# ---------------------------------------------------------------------------

RUFF_BASE = '[project]\nname = "x"\n\n[tool.ruff.lint]\nselect = ["E", "F", "I"]\n'


def test_ruff_ignore_select_and_excludes(tmp_path: Path):
    head = (
        RUFF_BASE.replace('["E", "F", "I"]', '["E", "F", "B"]')
        + 'ignore = ["E501", "D100"]\n'
        + 'exclude = ["app/legacy", "dist"]\n'
        + '\n[tool.ruff.lint.per-file-ignores]\n"tests/*" = ["F401"]\n'
    )
    result = _check(
        tmp_path,
        {**SRC, "pyproject.toml": RUFF_BASE, "tests/test_a.py": "def test_a(): pass\n"},
        {"pyproject.toml": head},
    )
    blocking = _messages(result, A119, blocking=True)
    assert "ruff now ignores E501" in blocking
    assert "ruff no longer selects I" in blocking
    assert not any("D100" in m for m in blocking)  # D is not selected: no change
    assert not any("B" == m.split()[-1] for m in blocking)  # adding B strengthens
    assert "ruff now excludes 'app/legacy' (e.g. app/legacy/old.py)" in blocking
    assert not any("dist" in m for m in _messages(result))
    assert _messages(result, A119, blocking=False) == [
        "(advice) ruff now ignores F401 in 'tests/*' (e.g. tests/test_a.py), which "
        "holds only test files"
    ]
    assert result.status == "fail"
    finding = next(f for f in result.findings if f.message == "ruff now ignores E501")
    assert finding.file == "pyproject.toml" and finding.line == 6


def test_new_rules_and_moved_settings_are_not_weakening(tmp_path: Path):
    base = {
        **SRC,
        "setup.cfg": "[mypy]\nstrict = True\ndisable_error_code = misc\n",
        "pyproject.toml": RUFF_BASE,
    }
    head = {
        "setup.cfg": None,
        "pyproject.toml": RUFF_BASE.replace('"I"]', '"I", "UP"]')
        + '\n[tool.mypy]\nstrict = true\ndisable_error_code = ["misc"]\n',
    }
    result = _check(tmp_path, base, head)
    assert result.findings == [] and result.status == "pass"


def test_mypy_strict_off_is_reported_once_and_module_overrides(tmp_path: Path):
    base = {**SRC, "mypy.ini": "[mypy]\nstrict = True\nwarn_unreachable = True\n"}
    head = {
        "mypy.ini": dedent(
            """\
            [mypy]
            warn_unreachable = True
            disable_error_code = attr-defined

            [mypy-app.legacy.*]
            ignore_errors = True

            [mypy-boto3.*]
            ignore_errors = True
            """
        )
    }
    result = _check(tmp_path, base, head)
    assert sorted(_messages(result, A119)) == [
        "mypy now ignores all errors in app.legacy.* (e.g. app/legacy/old.py)",
        "mypy now ignores error code attr-defined",
        "mypy strict turned off",
    ]


def test_typescript_strictness_excludes_and_skiplibcheck(tmp_path: Path):
    base = {
        "src/a.ts": "export const a = 1;\n",
        "src/legacy/b.ts": "export const b = 1;\n",
        "tsconfig.json": '{"compilerOptions": {"strict": true}, "include": ["src"]}\n',
    }
    head = {
        "tsconfig.json": dedent(
            """\
            {
              // comments and trailing commas are allowed
              "compilerOptions": {
                "strict": true,
                "noImplicitAny": false,
                "skipLibCheck": true,
                "noUncheckedIndexedAccess": true,
              },
              "include": ["src"],
              "exclude": ["src/legacy", "dist"],
            }
            """
        )
    }
    result = _check(tmp_path, base, head)
    assert sorted(_messages(result, A119)) == [
        "TypeScript noImplicitAny turned off",
        "TypeScript now excludes 'src/legacy' (e.g. src/legacy/b.ts)",
    ]


def test_typescript_strict_off_through_a_local_base_config(tmp_path: Path):
    base = {
        "src/a.ts": "export const a = 1;\n",
        "tsconfig.base.json": '{"compilerOptions": {"strict": true}}\n',
        "tsconfig.json": '{"extends": "./tsconfig.base.json"}\n',
    }
    head = {"tsconfig.base.json": '{"compilerOptions": {"strict": false}}\n'}
    result = _check(tmp_path, base, head)
    assert "TypeScript strict turned off" in _messages(result, A119)
    # A package base config cannot be read: an inherited value is never assumed.
    other = _check(
        tmp_path / "pkg",
        {"src/a.ts": "x\n", "tsconfig.json": '{"extends": "@tsconfig/strictest"}\n'},
        {
            "tsconfig.json": '{"extends": "@tsconfig/strictest", "compilerOptions": {"checkJs": true}}\n'
        },
    )
    assert other.findings == []


ESLINT_FLAT = """\
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { ignores: ["dist/**"] },
  {
    files: ["**/*.ts"],
    rules: { "no-console": "error", eqeqeq: ["error", "always"] },
  },
];
"""


def test_eslint_flat_config_rules_off_lowered_ignores_and_presets(tmp_path: Path):
    base = {
        "src/a.ts": "export const a = 1;\n",
        "src/legacy/b.ts": "export const b = 1;\n",
        "eslint.config.mjs": ESLINT_FLAT,
    }
    head = (
        ESLINT_FLAT.replace('"no-console": "error"', '"no-console": "off"')
        .replace(
            'eqeqeq: ["error", "always"]',
            'eqeqeq: "warn", "no-var": "error", "@typescript-eslint/no-explicit-any": 0',
        )
        .replace('"dist/**"', '"dist/**", "build/", "src/legacy/**"')
        .replace("  ...tseslint.configs.recommended,\n", "")
    )
    result = _check(tmp_path, base, {"eslint.config.mjs": head})
    assert sorted(_messages(result, A119)) == [
        "ESLint no longer extends tseslint.configs.recommended",
        "ESLint now ignores 'src/legacy/**' (e.g. src/legacy/b.ts)",
        "ESLint rule @typescript-eslint/no-explicit-any turned off for **/*.ts",
        "ESLint rule eqeqeq lowered from error to warn for **/*.ts",
        "ESLint rule no-console turned off for **/*.ts",
    ]


def test_eslint_recommended_swapped_for_strict_and_legacy_migration(tmp_path: Path):
    base = {
        "src/a.ts": "export const a = 1;\n",
        ".eslintrc.json": dedent(
            """\
            {
              "extends": ["plugin:@typescript-eslint/recommended"],
              "rules": {"no-console": "off", "eqeqeq": "error"}
            }
            """
        ),
    }
    head = {
        ".eslintrc.json": None,
        "eslint.config.js": dedent(
            """\
            module.exports = [
              {
                extends: ["plugin:@typescript-eslint/strict"],
                rules: { "no-console": "off", eqeqeq: "error" },
              },
            ];
            """
        ),
    }
    result = _check(tmp_path, base, head)
    assert result.findings == []


def test_dynamic_eslint_config_is_skipped(tmp_path: Path):
    base = {
        "src/a.js": "x\n",
        "eslint.config.js": "export default [{rules: {eqeqeq: 'error'}}];\n",
    }
    head = {
        "eslint.config.js": "export default (env) => [{rules: {eqeqeq: env ? 'off' : 'error'}}];\n"
    }
    assert _messages(_check(tmp_path, base, head), A119) == []


def test_biome_sonar_golangci_cargo_pyright(tmp_path: Path):
    base = {
        "src/a.ts": "x\n",
        "src/legacy/b.ts": "x\n",
        "main.go": "package main\n",
        "biome.json": '{"linter": {"enabled": true, "rules": {"suspicious": {"noExplicitAny": "error"}}}}\n',
        "sonar-project.properties": "sonar.projectKey=x\nsonar.sources=src\n",
        ".golangci.yml": "linters:\n  enable: [errcheck, govet]\n",
        "Cargo.toml": '[package]\nname = "x"\n\n[lints.clippy]\nunwrap_used = "deny"\n',
        "pyrightconfig.json": '{"typeCheckingMode": "strict"}\n',
        "app/a.py": "x = 1\n",
    }
    head = {
        "biome.json": '{"linter": {"enabled": false, "rules": {"suspicious": {"noExplicitAny": "off"}}}}\n',
        "sonar-project.properties": dedent(
            """\
            sonar.projectKey=x
            sonar.sources=src
            sonar.exclusions=src/legacy/**
            sonar.issue.ignore.multicriteria=e1
            sonar.issue.ignore.multicriteria.e1.ruleKey=typescript:S1234
            sonar.issue.ignore.multicriteria.e1.resourceKey=**/*.ts
            """
        ),
        ".golangci.yml": "linters:\n  enable: [govet]\n  disable: [staticcheck]\n",
        "Cargo.toml": '[package]\nname = "x"\n\n[lints.clippy]\nunwrap_used = "allow"\n',
        "pyrightconfig.json": '{"typeCheckingMode": "basic", "reportMissingImports": "none"}\n',
    }
    messages = sorted(_messages(_check(tmp_path, base, head), A119))
    assert messages == [
        "Biome linter turned off",
        "Biome rule suspicious/noExplicitAny turned off",
        "Cargo lints rule clippy::unwrap_used lowered from deny to allow",
        "SonarQube now excludes 'src/legacy/**' (e.g. src/legacy/b.ts)",
        "SonarQube now ignores rule typescript:S1234 in **/*.ts",
        "golangci-lint no longer enables errcheck",
        "golangci-lint now disables staticcheck",
        "pyright rule reportMissingImports turned off",
        "pyright typeCheckingMode lowered from strict to basic",
    ]


def test_secret_scanner_allow_lists(tmp_path: Path):
    baseline = (
        '{"results": {"app/a.py": [{"type": "Secret Keyword", '
        '"hashed_secret": "%s", "line_number": %d}]}}\n'
    )
    base = {
        "app/a.py": "x = 1\n",
        ".gitleaksignore": "abc:app/a.py:generic-api-key:1\n",
        ".secrets.baseline": baseline % ("aaaa1111", 1),
    }
    head = {
        ".gitleaksignore": "abc:app/a.py:generic-api-key:1\ndef:app/b.py:aws-access-token:3\n",
        # the known secret moved down a line: not a new one
        ".secrets.baseline": (baseline % ("aaaa1111", 2)).replace(
            "]}}", ', {"type": "AWS Access Key", "hashed_secret": "bbbb2222"}]}}'
        ),
    }
    assert sorted(_messages(_check(tmp_path, base, head), A119)) == [
        "detect-secrets now accepts a AWS Access Key in app/a.py (bbbb2222)",
        "gitleaks now allows the finding def:app/b.py:aws-access-token:3",
    ]


# ---------------------------------------------------------------------------
# SKY-A121: CI checks weakened (and SKY-A112 for test steps)
# ---------------------------------------------------------------------------

WORKFLOW = """\
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Lint
        run: npx eslint . --max-warnings 0
      - name: Types
        run: mypy src
      - run: rm -rf build || true
      - uses: github/codeql-action/analyze@v3
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest -q
  ci-ok:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""
CI = ".github/workflows/ci.yml"


def test_classify_reads_wrappers_scripts_and_targets():
    scripts = {"lint": "eslint . && tsc --noEmit"}
    assert classify("uv run --frozen mypy src") == ("type check", {"mypy"})
    assert classify("pnpm lint", scripts) == (
        "lint",
        {"script:lint", "eslint", "tsc"},
    )
    assert classify("ruff format .") is None
    assert classify("ruff format --check .") == ("lint", {"ruff"})
    assert classify("npm install") is None
    assert classify("make lint") == ("lint", {"make lint"})


def test_ci_lint_step_that_can_now_fail(tmp_path: Path):
    head = WORKFLOW.replace(
        "npx eslint . --max-warnings 0", "npx eslint . || true"
    ).replace(
        "        run: mypy src\n",
        "        run: mypy src\n        continue-on-error: true\n",
    )
    result = _check(tmp_path, {CI: WORKFLOW}, {CI: head})
    lines = {f.message.split(" in job")[0]: f.line for f in result.findings}
    assert lines == {"CI lint step 'Lint'": 7, "CI type check step 'Types'": 11}
    assert sorted(_messages(result, A121)) == [
        "CI lint step 'Lint' in job 'lint' can now fail without failing the build "
        "(--max-warnings 0 dropped, failure swallowed in the script)",
        "CI type check step 'Types' in job 'lint' can now fail without failing the "
        "build (continue-on-error)",
    ]
    assert result.status == "fail"


def test_ci_step_renamed_moved_or_new_and_quiet_is_not_weakening(tmp_path: Path):
    head = WORKFLOW.replace("name: Lint", "name: ESLint").replace(
        "      - uses: github/codeql-action/analyze@v3\n", ""
    ) + dedent(
        """\
          extra:
            runs-on: ubuntu-latest
            continue-on-error: true
            steps:
              - run: npx stylelint "**/*.css"
        """
    )
    moved = dedent(
        """\
        on: pull_request
        jobs:
          codeql:
            runs-on: ubuntu-latest
            steps:
              - uses: github/codeql-action/analyze@v4
        """
    )
    result = _check(
        tmp_path, {CI: WORKFLOW}, {CI: head, ".github/workflows/codeql.yml": moved}
    )
    assert _messages(result, A121) == []


def test_ci_check_removed_disabled_untriggered_or_no_longer_required(
    tmp_path: Path,
):
    head = (
        WORKFLOW.replace("on: [push, pull_request]", "on: [push]")
        .replace("      - uses: github/codeql-action/analyze@v3\n", "")
        .replace(
            "        run: mypy src\n", "        run: mypy src\n        if: false\n"
        )
        .replace("needs: [lint, test]", "needs: [test]")
    )
    messages = _messages(_check(tmp_path, {CI: WORKFLOW}, {CI: head}), A121)
    assert sorted(messages) == [
        "CI no longer runs github/codeql-action/analyze: security scan step "
        "'github/codeql-action/analyze' in job 'lint' removed, and no other step "
        "runs it",
        "CI type check step 'Types' in job 'lint' is now disabled (if: false): "
        "mypy no longer runs",
        "CI workflow no longer runs on pull requests (eslint, "
        "github/codeql-action/analyze, mypy)",
        "CI workflow no longer runs on pull requests (pytest)",
        "job 'ci-ok' no longer needs job 'lint' (eslint)",
    ]


def test_ci_workflow_deleted_reports_its_checks_once(tmp_path: Path):
    lint = dedent(
        """\
        on: pull_request
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: ruff check .
              - run: ruff format --check .
        """
    )
    result = _check(
        tmp_path,
        {".github/workflows/lint.yml": lint},
        {".github/workflows/lint.yml": None},
    )
    assert _messages(result, A121) == [
        "CI no longer runs ruff: lint step 'ruff check .' in job 'lint' removed, "
        "and no other step runs it"
    ]


def test_ci_test_steps_removed_or_disabled_are_advice_here_not_test_settings(
    tmp_path: Path,
):
    head = WORKFLOW.replace(
        "      - run: pytest -q\n", "      - run: pytest -q\n        if: ${{ false }}\n"
    )
    result = _check(tmp_path, {CI: WORKFLOW}, {CI: head})
    assert _messages(result, A121) == [
        "CI test step 'pytest -q' in job 'test' is now disabled (if: false): "
        "pytest no longer runs"
    ]
    # SKY-A112 (which blocks by default) is unchanged by these patterns
    assert _test_ci(tmp_path / "again", {CI: WORKFLOW}, {CI: head}) == []


def test_ci_quiet_github_test_step_is_still_reported_once(tmp_path: Path):
    head = WORKFLOW.replace("run: pytest -q", "run: pytest -q || true")
    messages = _test_ci(tmp_path, {CI: WORKFLOW}, {CI: head})
    assert len([m for m in messages if m.startswith("CI test")]) == 1


GITLAB = """\
stages: [check, test]
.base:
  image: python:3.12
lint:
  extends: .base
  stage: check
  script:
    - ruff check .
    - mypy src
unit:
  stage: test
  script:
    - pytest -q
"""


def test_gitlab_jobs_that_may_fail_or_were_removed(tmp_path: Path):
    head = GITLAB.replace(
        "  stage: check\n", "  stage: check\n  allow_failure: true\n"
    ).replace("unit:\n  stage: test\n  script:\n    - pytest -q\n", "")
    root = _repo(tmp_path, {".gitlab-ci.yml": GITLAB}, {".gitlab-ci.yml": head})
    comparison = open_comparison(root, "main")
    result = check_silenced_checks(CheckContext(comparison, DoneConfig()))
    assert sorted(_messages(result, A121)) == [
        "CI lint job 'lint' can now fail without failing the pipeline (allow_failure)",
        "CI no longer runs pytest: test job 'unit' removed, and no other step runs it",
    ]
    assert detect_loosened_test_config(comparison) == []


# ---------------------------------------------------------------------------
# settings, receipt, engine
# ---------------------------------------------------------------------------


def test_defaults_labels_and_modes():
    assert DEFAULT_MODES["silenced_checks"] == "advise"
    config = parse_done_config("[tool.skylos.done.checks]\nsilenced_checks = 'block'\n")
    assert config.mode("silenced_checks") == "block"
    assert "silenced_checks" in LABELS and "silenced_checks" in FIXES


@pytest.mark.parametrize("mode, verdict_fails", [("block", True), ("advise", False)])
def test_engine_blocks_on_weakened_settings_per_base_mode(
    tmp_path: Path, mode: str, verdict_fails: bool
):
    base = {
        **SRC,
        "pyproject.toml": RUFF_BASE
        + f"\n[tool.skylos.done.checks]\ntests_pass = 'off'\nsilenced_checks = '{mode}'\n",
    }
    root = _repo(
        tmp_path,
        base,
        {
            "pyproject.toml": base["pyproject.toml"].replace(
                'select = ["E", "F", "I"]',
                'select = ["E", "F", "I"]\nignore = ["F401"]',
            )
        },
    )
    result = run(root, base_ref="main", run_tests=False)
    outcome = next(c for c in result.checks if c.result.id == "silenced_checks")
    assert outcome.mode == mode and outcome.result.status == "fail"
    assert outcome.result.evidence["settings_weakened"] == 1
    assert (result.verdict == "fail") is verdict_fails


def test_rules_are_documented():
    from skylos.rules.catalog import get_rule_name

    assert get_rule_name("SKY-A118") == "Inline suppression added"
    assert get_rule_name("SKY-A119") == "Linter or scanner settings weakened"
    assert get_rule_name("SKY-A121") == "CI check weakened"
    root = Path(__file__).resolve().parents[1]
    dictionary = (root / "dictionary.md").read_text()
    docs = (root / "docs" / "done-gate.md").read_text()
    for rule in ("A118", "A119", "A121"):
        assert f"| {rule} |" in dictionary
        assert f"SKY-{rule}" in docs
    assert "silenced_checks" in docs


def test_ci_check_moved_into_a_script_or_composite_action_still_runs(tmp_path: Path):
    base = {
        CI: WORKFLOW,
        "package.json": '{"scripts": {"verify": "echo"}}\n',
    }
    head_workflow = WORKFLOW.replace(
        "run: npx eslint . --max-warnings 0", "run: npm run verify"
    ).replace("        run: mypy src\n", "        uses: ./.github/actions/types\n")
    head = {
        CI: head_workflow,
        "package.json": '{"scripts": {"verify": "eslint . --max-warnings 0"}}\n',
        ".github/actions/types/action.yml": dedent(
            """\
            runs:
              using: composite
              steps:
                - run: mypy src
                  shell: bash
            """
        ),
    }
    assert _messages(_check(tmp_path, base, head), A121) == []


def test_ci_exit_zero_options_action_inputs_and_unrelated_fallbacks(tmp_path: Path):
    base = dedent(
        """\
        on: pull_request
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  ruff check .
                  pylint pkg
              - uses: golangci/golangci-lint-action@v6
                with:
                  version: latest
              - run: rm -rf build
        """
    )
    head = (
        base.replace("ruff check .", "ruff check . --exit-zero")
        .replace(
            "version: latest", "version: latest\n          args: --issues-exit-code=0"
        )
        .replace("rm -rf build", "rm -rf build || true")
    )
    messages = sorted(_messages(_check(tmp_path, {CI: base}, {CI: head}), A121))
    assert messages == [
        "CI lint step 'golangci/golangci-lint-action' in job 'lint' can now fail "
        "without failing the build (--issues-exit-code 0)",
        "CI lint step 'ruff check . --exit-zero' in job 'lint' can now fail without "
        "failing the build (--exit-zero)",
    ]


def test_pre_commit_hooks_removed_renamed_upstream_or_made_manual(tmp_path: Path):
    config = dedent(
        """\
        repos:
          - repo: https://github.com/astral-sh/ruff-pre-commit
            rev: v0.5.0
            hooks:
              - id: ruff
              - id: ruff-format
          - repo: https://github.com/pre-commit/mirrors-mypy
            rev: v1.10.0
            hooks:
              - id: mypy
          - repo: https://github.com/Yelp/detect-secrets
            rev: v1.5.0
            hooks:
              - id: detect-secrets
        """
    )
    head = (
        config.replace("rev: v0.5.0", "rev: v0.12.0")
        .replace("- id: ruff\n", "- id: ruff-check\n")
        .replace("      - id: mypy\n", "      - id: mypy\n        stages: [manual]\n")
        .replace("      - id: detect-secrets\n", "      - id: gitleaks\n")
    )
    messages = sorted(
        _messages(
            _check(
                tmp_path,
                {".pre-commit-config.yaml": config},
                {".pre-commit-config.yaml": head},
            ),
            A119,
        )
    )
    assert messages == [
        "pre-commit no longer runs hook detect-secrets",
        "pre-commit no longer runs hook mypy",
    ]


def test_typescript_include_narrowed_only_when_files_drop_out(tmp_path: Path):
    base = {
        "src/a.ts": "x\n",
        "scripts/b.ts": "x\n",
        "tsconfig.json": '{"include": ["src", "scripts"]}\n',
    }
    narrowed = _check(tmp_path, base, {"tsconfig.json": '{"include": ["src"]}\n'})
    assert _messages(narrowed, A119) == [
        "TypeScript no longer includes 'scripts' (e.g. scripts/b.ts)"
    ]
    widened = _check(
        tmp_path / "w", base, {"tsconfig.json": '{"include": ["**/*.ts"]}\n'}
    )
    assert widened.findings == []


def test_setup_cfg_flake8_pylint_and_scanner_ignore_files(tmp_path: Path):
    base = {
        **SRC,
        "setup.cfg": "[flake8]\nmax-line-length = 100\n\n[pylint.messages_control]\ndisable = C0114\n",
        ".semgrepignore": "dist/\n",
        ".trivyignore": "CVE-2020-0001\n",
        ".github/codeql/codeql-config.yml": "paths-ignore:\n  - dist\n",
    }
    head = {
        "setup.cfg": dedent(
            """\
            [flake8]
            max-line-length = 100
            extend-ignore = E203, W503
            per-file-ignores =
                app/legacy/*.py: F401,E501

            [pylint.messages_control]
            disable = C0114, too-many-branches
            """
        ),
        ".semgrepignore": "dist/\napp/legacy/\n# a comment\n",
        ".trivyignore": "CVE-2020-0001\nCVE-2024-1234 # no fix yet\n",
        ".github/codeql/codeql-config.yml": "paths-ignore:\n  - dist\n  - app\n",
    }
    messages = sorted(_messages(_check(tmp_path, base, head), A119))
    assert messages == [
        "CodeQL now ignores 'app' (e.g. app/__init__.py)",
        "Semgrep now ignores 'app/legacy/' (e.g. app/legacy/old.py)",
        "Trivy now ignores CVE-2024-1234",
        "flake8 now ignores E203",
        "flake8 now ignores E501 in 'app/legacy/*.py' (e.g. app/legacy/old.py)",
        "flake8 now ignores F401 in 'app/legacy/*.py' (e.g. app/legacy/old.py)",
        "flake8 now ignores W503",
        "pylint now disables too-many-branches",
    ]


def test_placeholder_reason_and_kotlin_go_rust_files(tmp_path: Path):
    base = {
        "a.kt": "fun f() = 1\n",
        "main.go": "package main\n",
        "src/lib.rs": "fn f() {}\n",
    }
    head = {
        "a.kt": '@Suppress("UNCHECKED_CAST") // TODO\nfun f() = 1\n',
        "main.go": "package main\n\nfunc f() { g() //nolint:errcheck // g never fails\n}\n",
        "src/lib.rs": '#[allow(dead_code, reason = "kept for the FFI table")]\nfn f() {}\n',
    }
    messages = _messages(_check(tmp_path, base, head), A118)
    assert len(messages) == 3
    assert '(advice) adds @Suppress("UNCHECKED_CAST") with no reason' in messages
    assert '(advice) adds nolint:errcheck (reason: "g never fails")' in messages
    assert any('(reason: "kept for the FFI table")' in m for m in messages)


def test_ci_check_moved_to_another_workflow_and_made_quiet_is_not_running(
    tmp_path: Path,
):
    ci = dedent(
        """\
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: python -m build
              - run: twine check dist/*
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: ruff check .
        """
    )
    head_ci = ci[: ci.index("  lint:")]
    checks = dedent(
        """\
        on: [pull_request, workflow_dispatch]
        jobs:
          style:
            runs-on: ubuntu-latest
            continue-on-error: true
            steps:
              - uses: actions/checkout@v4
              - name: Style
                run: ruff check --output-format=github .
        """
    )
    result = _check(
        tmp_path,
        {CI: ci},
        {CI: head_ci, ".github/workflows/checks.yml": checks},
    )
    assert _messages(result, A121) == [
        "CI no longer runs ruff: lint step 'ruff check .' in job 'lint' removed, "
        "and no other step runs it"
    ]


def test_ci_scheduled_workflows_never_gated_a_merge(tmp_path: Path):
    scheduled = dedent(
        """\
        on:
          schedule:
            - cron: "0 6 * * 1"
          workflow_dispatch:
        jobs:
          refresh:
            runs-on: ubuntu-latest
            steps:
              - run: pytest -q tests/test_data.py
              - run: ruff check data/
        """
    )
    path = ".github/workflows/refresh.yml"
    gone = _check(tmp_path, {path: scheduled}, {path: None})
    assert _messages(gone, A121) == []
    assert _test_ci(tmp_path / "t", {path: scheduled}, {path: None}) == []
    assert _messages(gone, A121) == []
    # a gate turned into a scheduled job is reported once, as the trigger
    gate = scheduled.replace(
        'on:\n  schedule:\n    - cron: "0 6 * * 1"\n  workflow_dispatch:\n',
        "on: [pull_request]\n",
    )
    moved = _check(tmp_path / "m", {path: gate}, {path: scheduled})
    assert _messages(moved, A121) == [
        "CI workflow no longer runs on pull requests (ruff)",
        "CI workflow no longer runs on pull requests (pytest)",
    ]


def test_a_new_package_with_its_own_settings_weakens_nothing(tmp_path: Path):
    head = {
        "packages/new/src/a.ts": "export const a = 1;\n",
        "packages/new/eslint.config.js": "export default [{rules: {'no-console': 'off'}, ignores: ['src/gen/**']}];\n",
        "packages/new/ruff.toml": '[lint]\nignore = ["E501"]\n',
        "packages/new/tool.py": "x = 1\n",
    }
    result = _check(tmp_path, SRC, head)
    assert _messages(result, A119) == []
    # A new settings file next to code that existed is not a new package.
    old = _check(
        tmp_path / "old",
        {**SRC, "app/b.py": "y = 2\n"},
        {"app/ruff.toml": '[lint]\nselect = ["E", "F"]\nignore = ["F401"]\n'},
    )
    assert _messages(old, A119) == ["ruff now ignores F401"]


def test_line_numbers_follow_git_with_form_feeds():
    source = "a = 1\n\x0c\nimport os  # noqa: F401\n"
    assert [(d.line, d.name) for d in directives("a.py", source)] == [(3, "noqa")]


def test_ci_package_manager_switch_is_not_a_removal(tmp_path: Path):
    """From the zod history: pnpm replaced by another package manager."""
    base_ci = dedent(
        """\
        on: pull_request
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm install
              - run: pnpm lint:check
              - run: pnpm check:comments
          test:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm test
        """
    )
    head_ci = base_ci.replace("pnpm install", "nub install --frozen-lockfile")
    head_ci = head_ci.replace("pnpm lint:check", "nub run lint:check")
    head_ci = head_ci.replace("pnpm check:comments", "nub run check:comments")
    head_ci = head_ci.replace("pnpm test", "nub run test")
    package = '{"scripts": {"lint:check": "biome lint .", "check:comments": "node c.js", "test": "vitest run"}}\n'
    base = {CI: base_ci, "package.json": package}
    head = {
        CI: head_ci,
        "package.json": package.replace("biome lint", "nub exec biome lint"),
    }
    assert _messages(_check(tmp_path, base, head), A121) == []
    assert _test_ci(tmp_path / "t", base, head) == []


def test_ci_unrelated_fallback_in_a_step_that_now_runs_tests(tmp_path: Path):
    """From the skylos-cloud history: a test command added to a step that
    already had ``trap '... || true' EXIT`` makes the CI stronger."""
    step = dedent(
        """\
        on: pull_request
        jobs:
          validate:
            runs-on: ubuntu-latest
            steps:
              - name: Probe
                run: |
                  npm run start &
                  trap 'kill "$!" 2>/dev/null || true' EXIT
                  npm run probe:ctas:ci
        """
    )
    head = step.replace(
        "          npm run probe:ctas:ci\n",
        "          npm run test:security-probes\n          npm run probe:ctas:ci\n",
    )
    assert _test_ci(tmp_path, {CI: step}, {CI: head}) == []
    swallowed = head.replace(
        "npm run test:security-probes", "npm run test:security-probes || true"
    )
    assert len(_test_ci(tmp_path / "s", {CI: step}, {CI: swallowed})) == 1


def test_release_workflow_made_manual_while_another_gate_runs_its_checks(
    tmp_path: Path,
):
    """From the zod history: release.yml moved to workflow_dispatch."""
    release = dedent(
        """\
        on: [push]
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: npx biome lint .
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """
    )
    gate = release.replace("on: [push]", "on: [push, pull_request]").replace(
        "              - run: npm publish\n", "              - run: echo\n"
    )
    files = {
        ".github/workflows/release.yml": release,
        ".github/workflows/test.yml": gate,
    }
    manual = release.replace("on: [push]", "on: [workflow_dispatch]")
    result = _check(tmp_path, files, {".github/workflows/release.yml": manual})
    assert _messages(result, A121) == []
    alone = _check(
        tmp_path / "alone",
        {".github/workflows/release.yml": release},
        {".github/workflows/release.yml": manual},
    )
    assert _messages(alone, A121) == ["CI workflow no longer runs on pushes (biome)"]


def test_eslint_legacy_to_flat_migration_and_generated_ignores(tmp_path: Path):
    """From the fastify history: standard's .eslintrc replaced by neostandard."""
    base = {
        "lib/a.js": "module.exports = 1\n",
        "lib/validator.js": "// This file is autogenerated by build.js, do not edit\nmodule.exports = 2\n",
        ".eslintrc": '{"extends": "standard"}\n',
        "types/.eslintrc.json": '{"extends": ["eslint:recommended", "plugin:@typescript-eslint/recommended"]}\n',
        "types/index.d.ts": "export {}\n",
    }
    head = {
        ".eslintrc": None,
        "types/.eslintrc.json": None,
        "eslint.config.js": dedent(
            """\
            const neo = require('neostandard')
            module.exports = [
              { ignores: ['lib/validator.js'] },
              ...neo({ ts: true }),
            ]
            """
        ),
    }
    assert _messages(_check(tmp_path, base, head), A119) == []
