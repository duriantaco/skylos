"""CI steps that run tests, linters, type checkers and scanners, and the
changes that let them fail quietly or stop them running.

GitHub Actions workflows and GitLab CI files are compared base against head.
A step is a test step when its script runs a test runner (SKY-A112, read by
``test_config.py``) and a check step when it runs a linter, type checker,
formatter check or scanner, directly, through a package.json script or a
make/tox/nox target, or through a known action (SKY-A121). A step that does
both is a test step, so it is reported once.

Reported:

* a check step that can now fail without failing the build:
  ``continue-on-error: true`` on the step or its job, a script failure
  swallowed (``|| true``, ``|| echo``, ``; exit 0``, ``set +e``), an
  exit-zero option (``--exit-zero``, ``--exit-code 0``,
  ``--issues-exit-code=0``), fewer failing findings (``--max-warnings``
  raised or dropped, ``semgrep --error`` dropped, a higher ``npm audit``
  level, new ``--ignore`` options), or an action told not to fail; GitLab
  ``allow_failure`` and ``when: manual``. A new check that was never
  required is not a weakening. (Quiet GitHub test steps are reported by
  ``test_config.py``, unchanged.)
* a test or check that no longer runs: its step or job removed, unless the
  same tool still runs in any workflow, composite action or GitLab file at
  head (a renamed or moved step is not a removal); ``if: false`` or
  ``when: never``;
* a workflow with such steps that no longer runs on pull requests or pushes;
* an aggregate job (one that checks out no code) that no longer ``needs`` a
  job running such steps.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import yaml

RULE_CI_CHECK = "SKY-A121"

_PR_EVENTS = frozenset({"pull_request", "pull_request_target", "merge_group"})
_GATE_EVENTS = _PR_EVENTS | {"push", "workflow_call"}

# Commands run through these are the command after them.
_WRAPPERS = frozenset(
    {
        "npx",
        "pnpx",
        "bunx",
        "uvx",
        "pipx",
        "env",
        "time",
        "sudo",
        "exec",
        "command",
        "nice",
        "xvfb-run",
    }
)
_RUNNERS = {  # "<runner> run" / "<runner> exec"
    "nub": {"exec", "x"},
    "deno": {"run"},
    "uv": {"run", "tool"},
    "poetry": {"run"},
    "pipenv": {"run"},
    "pdm": {"run"},
    "hatch": {"run"},
    "rye": {"run"},
    "bundle": {"exec"},
    "npm": {"exec"},
    "pnpm": {"exec", "dlx"},
    "yarn": {"dlx", "exec"},
    "go": {"run"},
}
_PACKAGE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun", "nub"})
# "<runner> run|task <script>": package scripts and task runners Skylos does
# not know by name (deno task, mise run, a new package manager).
_SCRIPT_VERBS = frozenset({"run", "task", "run-script"})
_PM_BUILTINS = frozenset(
    {
        "install",
        "i",
        "ci",
        "add",
        "remove",
        "publish",
        "pack",
        "version",
        "init",
        "config",
        "cache",
        "set",
        "link",
        "dedupe",
        "outdated",
        "why",
        "info",
        "view",
        "start",
        "build",
        "dev",
        "exec",
        "dlx",
        "x",
        "create",
        "global",
        "setup",
    }
)

# Tools by first word: category, and a test on the rest of the command.
_LINT = "lint"
_TYPES = "type check"
_FORMAT = "format check"
_SCAN = "security scan"
_CHECK = "check"


def _always(_: list[str]) -> bool:
    return True


def _has(*flags: str):
    return lambda args: any(a in flags or a.split("=")[0] in flags for a in args)


def _sub(*names: str):
    return lambda args: bool(args) and args[0] in names


_TOOLS: dict[str, tuple[str, object]] = {
    "flake8": (_LINT, _always),
    "pylint": (_LINT, _always),
    "pycodestyle": (_LINT, _always),
    "pydocstyle": (_LINT, _always),
    "pyflakes": (_LINT, _always),
    "vulture": (_LINT, _always),
    "yamllint": (_LINT, _always),
    "eslint": (_LINT, _always),
    "oxlint": (_LINT, _always),
    "stylelint": (_LINT, _always),
    "markdownlint": (_LINT, _always),
    "markdownlint-cli2": (_LINT, _always),
    "shellcheck": (_LINT, _always),
    "hadolint": (_LINT, _always),
    "actionlint": (_LINT, _always),
    "golangci-lint": (_LINT, _always),
    "staticcheck": (_LINT, _always),
    "revive": (_LINT, _always),
    "rubocop": (_LINT, _always),
    "ktlint": (_LINT, _always),
    "detekt": (_LINT, _always),
    "swiftlint": (_LINT, _always),
    "phpcs": (_LINT, _always),
    "sqlfluff": (_LINT, _sub("lint")),
    "knip": (_LINT, _always),
    "biome": (_LINT, _sub("lint", "check", "ci")),
    "pre-commit": (_LINT, _sub("run")),
    "black": (_FORMAT, _has("--check", "--diff")),
    "isort": (_FORMAT, _has("--check", "--check-only", "--diff", "-c")),
    "prettier": (_FORMAT, _has("--check", "-c", "--list-different", "-l")),
    "gofmt": (_FORMAT, _has("-l", "-d")),
    "dprint": (_FORMAT, _sub("check")),
    "mypy": (_TYPES, _always),
    "pyright": (_TYPES, _always),
    "basedpyright": (_TYPES, _always),
    "pyre": (_TYPES, _always),
    "pytype": (_TYPES, _always),
    "tsc": (_TYPES, _always),
    "vue-tsc": (_TYPES, _always),
    "svelte-check": (_TYPES, _always),
    "phpstan": (_TYPES, _always),
    "psalm": (_TYPES, _always),
    "flow": (_TYPES, _sub("check")),
    "bandit": (_SCAN, _always),
    "semgrep": (_SCAN, _always),
    "gitleaks": (_SCAN, _always),
    "trufflehog": (_SCAN, _always),
    "detect-secrets": (_SCAN, _always),
    "detect-secrets-hook": (_SCAN, _always),
    "snyk": (_SCAN, _sub("test", "code", "container", "iac")),
    "trivy": (_SCAN, _always),
    "grype": (_SCAN, _always),
    "pip-audit": (_SCAN, _always),
    "safety": (_SCAN, _sub("check", "scan")),
    "osv-scanner": (_SCAN, _always),
    "sonar-scanner": (_SCAN, _always),
    "checkov": (_SCAN, _always),
    "tfsec": (_SCAN, _always),
    "kics": (_SCAN, _always),
    "govulncheck": (_SCAN, _always),
    "gosec": (_SCAN, _always),
    "brakeman": (_SCAN, _always),
    "bundler-audit": (_SCAN, _always),
    "audit-ci": (_SCAN, _always),
    "zizmor": (_SCAN, _always),
    "codeql": (_SCAN, _sub("database")),
}
_SUBCOMMANDS: dict[tuple[str, str], str] = {
    ("go", "vet"): _LINT,
    ("cargo", "clippy"): _LINT,
    ("cargo", "check"): _TYPES,
    ("cargo", "audit"): _SCAN,
    ("cargo", "deny"): _SCAN,
    ("npm", "audit"): _SCAN,
    ("pnpm", "audit"): _SCAN,
    ("yarn", "audit"): _SCAN,
    ("bun", "audit"): _SCAN,
}
# Script and target names that run checks.
_CHECK_NAMES = {
    "lint": _LINT,
    "eslint": _LINT,
    "stylelint": _LINT,
    "prettier": _FORMAT,
    "format-check": _FORMAT,
    "fmt-check": _FORMAT,
    "typecheck": _TYPES,
    "type-check": _TYPES,
    "types": _TYPES,
    "check-types": _TYPES,
    "tsc": _TYPES,
    "mypy": _TYPES,
    "audit": _SCAN,
    "security": _SCAN,
    "vet": _LINT,
    "check": _CHECK,
}
# Actions that are checks, by repository (and path) without the version.
_ACTIONS = {
    "github/codeql-action/analyze": _SCAN,
    "golangci/golangci-lint-action": _LINT,
    "astral-sh/ruff-action": _LINT,
    "chartboost/ruff-action": _LINT,
    "jpetrucciani/ruff-check": _LINT,
    "psf/black": _FORMAT,
    "super-linter/super-linter": _LINT,
    "github/super-linter": _LINT,
    "oxsecurity/megalinter": _LINT,
    "jakebailey/pyright-action": _TYPES,
    "ludeeus/action-shellcheck": _LINT,
    "hadolint/hadolint-action": _LINT,
    "pre-commit/action": _LINT,
    "wearerequired/lint-action": _LINT,
    "actions-rs/clippy-check": _LINT,
    "sonarsource/sonarqube-scan-action": _SCAN,
    "sonarsource/sonarcloud-github-action": _SCAN,
    "sonarsource/sonarqube-quality-gate-action": _SCAN,
    "returntocorp/semgrep-action": _SCAN,
    "semgrep/semgrep-action": _SCAN,
    "gitleaks/gitleaks-action": _SCAN,
    "zricethezav/gitleaks-action": _SCAN,
    "trufflesecurity/trufflehog": _SCAN,
    "aquasecurity/trivy-action": _SCAN,
    "anchore/scan-action": _SCAN,
    "pypa/gh-action-pip-audit": _SCAN,
    "actions/dependency-review-action": _SCAN,
    "bridgecrewio/checkov-action": _SCAN,
    "embarkstudios/cargo-deny-action": _SCAN,
    "rustsec/audit-check": _SCAN,
    "golang/govulncheck-action": _SCAN,
    "securego/gosec": _SCAN,
}
_ACTION_PREFIXES = {"snyk/actions/": _SCAN, "reviewdog/action-": _LINT}
# Action inputs that stop it failing the build.
_QUIET_INPUTS = {
    "fail-on-error": False,
    "fail_on_error": False,
    "fail-on-findings": False,
    "fail_on_findings": False,
    "fail-build": False,
    "fail_build": False,
    "fail-on-severity": "none",
    "soft_fail": True,
    "soft-fail": True,
    "continue-on-error": True,
    "exit-code": "0",
    "exit_code": "0",
}
_AUDIT_LEVELS = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}
# Options that stop a tool reporting some findings, per tool.
_IGNORE_OPTIONS = {
    "ruff": ("--ignore", "--extend-ignore"),
    "flake8": ("--ignore", "--extend-ignore"),
    "pylint": ("--disable", "-d"),
    "pip-audit": ("--ignore-vuln",),
    "safety": ("--ignore", "-i"),
    "bandit": ("--skip", "-s"),
    "golangci-lint": ("--disable", "-D"),
}
# Package-manager options taking a value, before the script name.
_PM_VALUE_OPTIONS = frozenset(
    {"--filter", "-F", "-C", "--dir", "--prefix", "--workspace", "-w", "--cwd"}
)

_GITLAB_RESERVED = frozenset(
    {
        "stages",
        "variables",
        "default",
        "include",
        "workflow",
        "image",
        "services",
        "before_script",
        "after_script",
        "cache",
        "types",
    }
)


@dataclass
class Step:
    file: str
    job: str
    label: str  # the step's name, first line of its script, or action
    keys: frozenset[str]  # the tools it runs, as compared with other steps
    category: str
    quiet: set[str] = field(default_factory=set)
    disabled: str = ""  # how it was turned off, "" when it runs
    flags: dict[str, object] = field(default_factory=dict)
    needle: str = ""  # text to find its line by
    gitlab: bool = False


@dataclass
class _Workflow:
    steps: list[Step]
    triggers: set[str] | None  # None: GitLab, or not readable
    needs: dict[str, set[str]]  # job -> jobs it needs
    aggregate: set[str]  # jobs that check out no code
    # Tools any enabled step runs, however it is named or called.
    running: set[str] = field(default_factory=set)

    @property
    def gate(self) -> bool:
        """Runs on pull requests or pushes (or is called by a workflow that
        may): a scheduled or manual workflow never decided a merge."""
        return self.triggers is None or bool(self.triggers & _GATE_EVENTS)


# ---------------------------------------------------------------------------
# Reading commands
# ---------------------------------------------------------------------------


def _logical_lines(script: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", script)
    return [line for line in joined.splitlines() if line.strip()]


def _segments(line: str) -> list[tuple[str, str]]:
    """(command, its ``||`` fallback) for each command joined by ``&&``,
    ``||``, ``;`` or ``|``. The fallback is the rest of the line after the
    ``||`` that follows the command."""
    out = []
    position = 0
    for part in re.split(r"&&|\|\||;|(?<!\|)\|(?!\|)", line):
        start = line.find(part, position)
        position = start + len(part) if start >= 0 else position
        if not part.strip() or re.fullmatch(r"\s*(?:true|:|exit\s+0)\s*", part):
            continue
        rest = line[position:]
        fallback = re.match(r"\s*\|\|(.*)", rest)
        out.append((part.strip(), fallback.group(1).strip() if fallback else ""))
    return out


def _tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, comments=True)
    except ValueError:
        tokens = command.split()
    while tokens and (
        re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]) or tokens[0] in _WRAPPERS
    ):
        tokens = tokens[1:]
        while tokens and tokens[0].startswith("-"):
            tokens = tokens[1:]  # npx --yes, env -i
    if len(tokens) >= 2 and tokens[1] in _RUNNERS.get(tokens[0], ()):
        tokens = tokens[2:]
        while tokens and tokens[0].startswith("-"):
            tokens = tokens[1:]
    if (
        len(tokens) >= 3
        and tokens[0] in {"python", "python3", "py"}
        and tokens[1] == "-m"
    ):
        tokens = tokens[2:]
    if tokens:
        tokens[0] = PurePosixPath(tokens[0]).name
    return tokens


def classify(
    command: str,
    scripts: dict[str, str] | None = None,
    depth: int = 0,
    *,
    permissive: bool = False,
):
    """(category, keys) of the checks one command runs, or None. With
    ``permissive``, any package.json script counts, so a check moved behind
    a script with another name still counts as running."""
    tokens = _tokens(command)
    if not tokens:
        return None
    first, args = tokens[0], tokens[1:]
    if first == "ruff":
        if args[:1] == ["format"] and not _has("--check", "--diff")(args):
            return None
        return _LINT, {"ruff"}
    if first in _TOOLS:
        category, accepts = _TOOLS[first]
        return (category, {first}) if accepts(args) else None
    if args and (first, args[0]) in _SUBCOMMANDS:
        return _SUBCOMMANDS[(first, args[0])], {f"{first} {args[0]}"}
    if first == "cargo" and args[:1] == ["fmt"] and "--check" in args:
        return _FORMAT, {"cargo fmt"}
    if first in _PACKAGE_MANAGERS and args:
        while args and args[0].startswith("-"):
            args = args[2:] if args[0] in _PM_VALUE_OPTIONS else args[1:]
        if args[:1] == ["workspaces"] and args[1:2] in (["run"], ["foreach"]):
            args = [a for a in args[1:] if not a.startswith("-")]
        if not args:
            return None
        name = args[1] if args[0] == "run" and len(args) > 1 else args[0]
        if args[0] != "run" and (name in _PM_BUILTINS or name.startswith("-")):
            return None
        if name == "ruff" or name in _TOOLS:
            found = classify(
                " ".join(args[1:] if args[0] == "run" else args), scripts, depth + 1
            )
            if found:
                return found[0], found[1] | {f"script:{name}"}
        return _script(name, scripts, depth, permissive)
    if first in {"turbo", "nx"}:
        tasks = [a for a in args if not a.startswith("-")]
        if tasks[:1] in (["run"], ["run-many"], ["affected"]):
            tasks = tasks[1:]
        if first == "nx":
            tasks += [
                v
                for f, v in zip(args, args[1:])
                if f in {"-t", "--target", "--targets"}
            ]
        names = [t.split(":")[0] for t in tasks]
        found = [n for n in names if n in _CHECK_NAMES]
        if found:
            return _CHECK_NAMES[found[0]], {f"script:{n}" for n in found}
        return None
    if first in {"make", "just"} and args:
        target = next((a for a in args if not a.startswith("-")), "")
        category = _CHECK_NAMES.get(target.split(":")[0].replace("_", "-"))
        return (category, {f"{first} {target}"}) if category else None
    if args and args[0] in _SCRIPT_VERBS:
        name = _script_name(args[1:])
        if name and (name.split(":")[0] in _CHECK_NAMES or name in (scripts or {})):
            return _script(name, scripts, depth, permissive)
    if first in {"tox", "nox"}:
        selected = []
        for flag, value in zip(args, args[1:]):
            if flag in {"-e", "-s", "--session", "--sessions"}:
                selected += value.split(",")
        found = [
            (_CHECK_NAMES.get(s.split("-")[0]) or _TOOLS.get(s, (None,))[0], s)
            for s in selected
        ]
        found = [(c, s) for c, s in found if c]
        if found:
            return found[0][0], {f"{first} {s}" for _, s in found}
        return None
    if first in {"gradle", "gradlew", "./gradlew"}:
        tasks = [a for a in args if not a.startswith("-")]
        checks = [
            t
            for t in tasks
            if t
            in {
                "check",
                "lint",
                "detekt",
                "ktlintCheck",
                "spotbugsMain",
                "sonar",
                "sonarqube",
                "checkstyleMain",
                "pmdMain",
            }
        ]
        if checks:
            return _LINT, {f"gradle {t}" for t in checks}
    if first == "mvn":
        goals = [a for a in args if re.match(r"(?:checkstyle|spotbugs|pmd|sonar):", a)]
        if goals:
            return _LINT, {f"mvn {g}" for g in goals}
    return None


def _script_name(args: list[str]) -> str | None:
    """The first argument that is not an option (``--filter x`` skipped)."""
    index = 0
    while index < len(args):
        token = args[index]
        if token in _PM_VALUE_OPTIONS:
            index += 2
            continue
        if not token.startswith("-"):
            return token
        index += 1
    return None


def _script(name: str, scripts: dict[str, str] | None, depth: int, permissive: bool):
    base = name.split(":")[0]
    keys = {f"script:{base}"}
    category = _CHECK_NAMES.get(base)
    if category is None and not permissive:
        return None
    body = (scripts or {}).get(name)
    if isinstance(body, str) and depth < 2:
        for line in _logical_lines(body):
            for command, _ in _segments(line):
                found = classify(command, scripts, depth + 1, permissive=permissive)
                if found:
                    keys |= found[1]
    return (category or _CHECK, keys)


def _running_keys(script: str, kind: str, scripts) -> set[str]:
    """Tools a script runs so that their failure fails it."""
    keys: set[str] = set()
    if re.search(r"(?m)^\s*set\s+\+e\b", script):
        return keys
    for line in _logical_lines(script):
        if re.search(r";\s*(?:true|exit\s+0)\s*$", line.rstrip()):
            continue
        for command, fallback in _segments(line):
            if _fails_quietly(fallback):
                continue
            if kind == "test":
                keys |= _test_keys(command)
            else:
                found = classify(command, scripts, permissive=True)
                if found:
                    keys |= found[1]
    return keys


def _test_keys(script: str) -> set[str]:
    from skylos.done.test_config import _TEST_STEP_RE

    keys = set()
    tokens = _tokens(script)
    if len(tokens) >= 2 and (
        tokens[0] in _PACKAGE_MANAGERS or tokens[1] in _SCRIPT_VERBS
    ):
        rest = tokens[2:] if tokens[1] in _SCRIPT_VERBS else tokens[1:]
        name = _script_name(rest)
        if name and name.split(":")[0] == "test":
            keys.add("script:test")
    for match in _TEST_STEP_RE.finditer(script):
        text = " ".join(match.group(0).split())
        if re.match(r"(?:npm|yarn|pnpm|bun)\s", text):
            keys.add("script:test")
        elif text.startswith("make"):
            keys.add("make test")
        elif text.startswith(("mvn", "gradle")):
            keys.add(text.split()[0])
        else:
            keys.add(text)
    return keys


def test_failure_swallowed(script: str) -> bool:
    """Whether a script lets a test command it runs fail quietly (an
    unrelated command's ``|| true`` in the same script does not count)."""
    return "failure swallowed in the script" in _script_quiet(script, "test", None)[1]


def _fails_quietly(fallback: str) -> bool:
    """A ``||`` fallback that turns the failure into success (``|| exit 1``,
    ``|| false`` and ``|| (echo x; exit 1)`` keep it a failure)."""
    if not fallback:
        return False
    if re.match(r"\(?\s*(?:false\b|exit\s*(?:$|\)|[1-9]|\$))", fallback):
        return False
    return not re.search(r"\b(?:exit|return)\s+(?:[1-9]|\$)|\bfalse\b", fallback)


def _script_quiet(script: str, kind: str, scripts) -> tuple[set[str], set[str], dict]:
    """(keys, quiet reasons, flags) of the commands of ``kind`` a script runs."""
    keys: set[str] = set()
    quiet: set[str] = set()
    flags: dict[str, object] = {}
    category = ""
    if re.search(r"(?m)^\s*set\s+\+e\b", script):
        quiet.add("failure swallowed in the script")
    for line in _logical_lines(script):
        stripped = line.rstrip()
        swallow_line = bool(re.search(r";\s*(?:true|exit\s+0)\s*$", stripped))
        for command, fallback in _segments(line):
            if kind == "test":
                found = ("test", _test_keys(command)) if _test_keys(command) else None
            else:
                found = classify(command, scripts)
            if not found:
                continue
            category = category or found[0]
            keys |= found[1]
            if _fails_quietly(fallback) or swallow_line:
                quiet.add("failure swallowed in the script")
            tokens = _tokens(command)
            for option in ("--exit-zero",):
                if option in tokens:
                    quiet.add(option)
            for option in ("--exit-code", "--issues-exit-code"):
                value = _option(tokens, option)
                if value == "0":
                    quiet.add(f"{option} 0")
            flags.update(_finding_flags(tokens))
    return keys, quiet, {"category": category, **flags}


def _option(tokens: list[str], name: str) -> str | None:
    for index, token in enumerate(tokens):
        if token == name and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith(name + "="):
            return token.split("=", 1)[1]
    return None


def _finding_flags(tokens: list[str]) -> dict[str, object]:
    """Options that decide which findings fail the command."""
    flags: dict[str, object] = {}
    if not tokens:
        return flags
    tool = tokens[0]
    warnings = _option(tokens, "--max-warnings")
    if tool == "eslint" or warnings is not None:
        flags["max-warnings"] = int(warnings) if (warnings or "").isdigit() else None
    if tool == "semgrep":
        flags["semgrep --error"] = "--error" in tokens
    if tool in _PACKAGE_MANAGERS and tokens[1:2] == ["audit"]:
        level = _option(tokens, "--audit-level") or _option(tokens, "--level")
        flags["audit-level"] = _AUDIT_LEVELS.get(level or "low", 1)
    ignored = set()
    options = _IGNORE_OPTIONS.get(tool, ())
    for index, token in enumerate(tokens):
        name, _, value = token.partition("=")
        if name in options:
            value = value or (tokens[index + 1] if index + 1 < len(tokens) else "")
            ignored |= {f"{name} {v}" for v in value.split(",") if v}
    flags["ignores"] = frozenset(ignored)
    return flags


def _flag_changes(before: dict, after: dict) -> set[str]:
    changes = set()
    if "max-warnings" in before:
        old, new = before["max-warnings"], after.get("max-warnings")
        if old is not None and (new is None or new > old):
            changes.add(
                f"--max-warnings {old} raised to {new}"
                if new is not None
                else f"--max-warnings {old} dropped"
            )
    if before.get("semgrep --error") and after.get("semgrep --error") is False:
        changes.add("semgrep --error dropped")
    if "audit-level" in before and after.get("audit-level", 0) > before["audit-level"]:
        changes.add("audit level raised")
    for ignore in sorted(
        after.get("ignores", frozenset()) - before.get("ignores", frozenset())
    ):
        changes.add(ignore)
    return changes


# ---------------------------------------------------------------------------
# Reading workflows
# ---------------------------------------------------------------------------


def _load(text: str | None):
    if not text:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _literal_true(value) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _literal_false_if(value) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        text = value.strip().lower()
        return text in {"false", "${{ false }}", "${{false}}", "0", "${{ 0 }}"}
    return False


def _triggers(data: dict) -> set[str] | None:
    value = data.get("on", data.get(True))
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(v) for v in value}
    if isinstance(value, dict):
        return {str(k) for k in value}
    return None


def _github(path: str, text: str | None, kind: str, scripts) -> _Workflow | None:
    data = _load(text)
    if data is None:
        return None
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        # A composite action: runs.steps.
        runs = data.get("runs")
        if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
            jobs = {"(action)": {"steps": runs["steps"]}}
        else:
            return None
    steps: list[Step] = []
    needs: dict[str, set[str]] = {}
    aggregate: set[str] = set()
    running: set[str] = set()
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_id = str(job_id)
        raw_needs = job.get("needs")
        needs[job_id] = (
            {raw_needs}
            if isinstance(raw_needs, str)
            else {str(n) for n in raw_needs or [] if isinstance(n, str)}
        )
        job_steps = job.get("steps") if isinstance(job.get("steps"), list) else []
        if not any(
            isinstance(s, dict)
            and str(s.get("uses", "")).startswith("actions/checkout")
            for s in job_steps
        ) and not job.get("uses"):
            aggregate.add(job_id)
        job_quiet = _literal_true(job.get("continue-on-error"))
        job_off = _literal_false_if(job.get("if"))
        if isinstance(job.get("uses"), str) and kind == "check":
            uses = job["uses"].split("@")[0].lower()
            category = _action_category(uses)
            if category:
                steps.append(
                    Step(
                        path,
                        job_id,
                        uses,
                        frozenset({f"action:{uses}"}),
                        category,
                        disabled="if: false on the job" if job_off else "",
                        needle=job["uses"],
                    )
                )
        if not job_off and not job_quiet and isinstance(job.get("uses"), str):
            running.add("action:" + job["uses"].split("@")[0].lower())
        for step in job_steps:
            if not isinstance(step, dict):
                continue
            if (
                not job_off
                and not job_quiet
                and not _literal_false_if(step.get("if"))
                and not _literal_true(step.get("continue-on-error"))
            ):
                if isinstance(step.get("run"), str):
                    running |= _running_keys(step["run"], kind, scripts)
                if isinstance(step.get("uses"), str):
                    running.add("action:" + step["uses"].split("@")[0].lower())
            found = _github_step(path, job_id, step, kind, scripts)
            if found is None:
                continue
            if job_quiet:
                found.quiet.add("continue-on-error on the job")
            if job_off:
                found.disabled = "if: false on the job"
            elif _literal_false_if(step.get("if")):
                found.disabled = "if: false"
            steps.append(found)
    return _Workflow(steps, _triggers(data), needs, aggregate, running)


def _action_category(uses: str) -> str | None:
    if uses in _ACTIONS:
        return _ACTIONS[uses]
    for prefix, category in _ACTION_PREFIXES.items():
        if uses.startswith(prefix):
            return category
    return None


def _github_step(path, job_id, step: dict, kind: str, scripts) -> Step | None:
    run = step.get("run")
    uses = step.get("uses")
    name = step.get("name")
    if isinstance(run, str):
        from skylos.done.test_config import _TEST_STEP_RE

        if kind == "check" and _TEST_STEP_RE.search(run):
            return None  # a test step: SKY-A112 reports it
        keys, quiet, flags = _script_quiet(run, kind, scripts)
        if not keys:
            return None
        label = str(name or run.strip().splitlines()[0])[:80]
        found_category = flags.pop("category", "")
        category = "test" if kind == "test" else str(found_category or _CHECK)
        if _literal_true(step.get("continue-on-error")):
            quiet.add("continue-on-error")
        return Step(
            path,
            job_id,
            label,
            frozenset(keys),
            category,
            quiet,
            flags=flags,
            needle=str(name or run.strip().splitlines()[0]),
        )
    if isinstance(uses, str) and kind == "check":
        action = uses.split("@")[0].lower()
        category = _action_category(action)
        if not category:
            return None
        quiet = set()
        if _literal_true(step.get("continue-on-error")):
            quiet.add("continue-on-error")
        inputs = step.get("with") if isinstance(step.get("with"), dict) else {}
        for key, value in inputs.items():
            if key in _QUIET_INPUTS and _same(value, _QUIET_INPUTS[key]):
                quiet.add(f"{key}: {str(value).lower()}")
        args = inputs.get("args")
        if isinstance(args, str):
            tokens = args.split()
            if "--exit-zero" in tokens:
                quiet.add("--exit-zero")
            if _option(tokens, "--issues-exit-code") == "0":
                quiet.add("--issues-exit-code 0")
        return Step(
            path,
            job_id,
            str(name or action)[:80],
            frozenset({f"action:{action}"}),
            category,
            quiet,
            needle=uses,
        )
    return None


def _same(value, expected) -> bool:
    if isinstance(expected, bool):
        return (value is expected) or str(value).strip().lower() == str(
            expected
        ).lower()
    return str(value).strip().lower() == str(expected)


def _gitlab(path: str, text: str | None, kind: str, scripts) -> _Workflow | None:
    data = _load(text)
    if data is None:
        return None
    templates = {
        k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, dict)
    }
    steps: list[Step] = []
    running: set[str] = set()
    for name, job in templates.items():
        if name in _GITLAB_RESERVED or name.startswith("."):
            continue
        merged = _gitlab_job(job, templates, 0)
        script = _flatten(merged.get("script"))
        if not script:
            continue
        text_script = "\n".join(script)
        from skylos.done.test_config import _TEST_STEP_RE

        off = merged.get("when") == "never" or (
            isinstance(merged.get("rules"), list)
            and merged["rules"]
            and all(
                isinstance(r, dict) and r.get("when") == "never"
                for r in merged["rules"]
            )
        )
        allowed = merged.get("allow_failure")
        if not off and not (
            _literal_true(allowed)
            or isinstance(allowed, dict)
            or (merged.get("when") == "manual" and allowed is not False)
        ):
            running |= _running_keys(text_script, kind, scripts)

        if kind == "check" and _TEST_STEP_RE.search(text_script):
            continue
        keys, quiet, flags = _script_quiet(text_script, kind, scripts)
        if not keys:
            continue
        found_category = flags.pop("category", "")
        category = "test" if kind == "test" else str(found_category or _CHECK)
        allow = merged.get("allow_failure")
        if _literal_true(allow) or isinstance(allow, dict):
            quiet.add("allow_failure")
        if merged.get("when") == "manual" and allow is not False:
            quiet.add("when: manual")
        disabled = "when: never" if off else ""
        steps.append(
            Step(
                path,
                name,
                name,
                frozenset(keys),
                category,
                quiet,
                disabled,
                flags,
                needle=f"{name}:",
                gitlab=True,
            )
        )
    return _Workflow(steps, None, {}, set(), running)


def _gitlab_job(job: dict, templates: dict, depth: int) -> dict:
    parents = job.get("extends")
    merged: dict = {}
    if depth < 5:
        for parent in [parents] if isinstance(parents, str) else parents or []:
            if isinstance(parent, str) and parent in templates:
                merged.update(_gitlab_job(templates[parent], templates, depth + 1))
    merged.update(job)
    return merged


def _flatten(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out = []
        for item in value:
            out += _flatten(item)
        return out
    return []


def is_ci_file(path: str) -> bool:
    return is_github_workflow(path) or is_gitlab_ci(path)


def is_github_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def _is_composite_action(path: str) -> bool:
    return path.startswith(".github/actions/") and PurePosixPath(path).name in {
        "action.yml",
        "action.yaml",
    }


def is_gitlab_ci(path: str) -> bool:
    return path == ".gitlab-ci.yml" or (
        path.startswith(".gitlab/") and path.endswith((".yml", ".yaml"))
    )


def _read(path: str, text: str | None, kind: str, scripts) -> _Workflow | None:
    if is_gitlab_ci(path):
        return _gitlab(path, text, kind, scripts)
    return _github(path, text, kind, scripts)


# ---------------------------------------------------------------------------
# Comparing
# ---------------------------------------------------------------------------


def ci_weakening(comparison, kind: str) -> list[tuple[str, int | None, str]]:
    """(file, line, message) for each way the change lets CI ``kind`` steps
    ("test" or "check") fail quietly or stop running."""
    changed = [
        c
        for c in comparison.changed
        if is_ci_file(c.path) or (c.base_path and is_ci_file(c.base_path))
    ]
    if not changed:
        return []
    head_scripts = _scripts(comparison.head_text("package.json"))
    base_scripts = _scripts(comparison.base_text("package.json"))
    running: set[str] = set()  # tools some step still runs at head
    gates: list[tuple[str, set[str] | None, set[str]]] = []
    for path in _head_ci_paths(comparison):
        workflow = _read(path, comparison.head_text(path), kind, head_scripts)
        if workflow and workflow.gate:
            keys = workflow.running | {
                key
                for s in workflow.steps
                if not s.disabled and not s.quiet
                for key in s.keys
            }
            running |= keys
            gates.append((path, workflow.triggers, keys))

    def elsewhere(path: str, events: set[str]) -> set[str]:
        """Tools other gates run on any of ``events`` (composite actions and
        GitLab files, without GitHub triggers, count for every event)."""
        return {
            key
            for other, triggers, keys in gates
            if other != path and (triggers is None or triggers & events)
            for key in keys
        }

    findings: list[tuple[str, int | None, str]] = []
    for item in changed:
        base_path = (
            item.base_path if item.base_path and is_ci_file(item.base_path) else None
        )
        head_path = (
            item.head_path if item.head_path and is_ci_file(item.head_path) else None
        )
        head_text = comparison.head_text(head_path) if head_path else None
        before = (
            _read(base_path, comparison.base_text(base_path), kind, base_scripts)
            if base_path
            else None
        )
        after = _read(head_path, head_text, kind, head_scripts) if head_path else None
        if (
            head_path
            and head_text is not None
            and after is None
            and _load(head_text) is None
        ):
            continue  # unreadable at head: nothing to compare
        findings += _compare(
            head_path or base_path, head_text, before, after, running, kind, elsewhere
        )
    return findings


def _scripts(text: str | None) -> dict[str, str]:
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return (
        {k: v for k, v in scripts.items() if isinstance(v, str)}
        if isinstance(scripts, dict)
        else {}
    )


def _head_ci_paths(comparison) -> list[str]:
    from skylos.done.base import _git_text

    listed = _git_text(
        comparison._context,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        ".github",
        ".gitlab-ci.yml",
        ".gitlab",
    )
    paths = [p for p in (listed or "").split("\0") if p]
    return sorted(p for p in paths if is_ci_file(p) or _is_composite_action(p))


def _compare(path, head_text, before, after, running, kind, elsewhere=None):
    findings = []
    base_steps = before.steps if before and before.gate else []
    # Steps that stopped gating because the triggers changed are reported
    # once, as the lost trigger, not as removed steps.
    head_steps = after.steps if after else []

    def line_of(needle: str, after_line: int = 0) -> int | None:
        """The first line holding ``needle``, at or after ``after_line``."""
        if not head_text or not needle:
            return None
        first = needle.strip().splitlines()[0] if needle.strip() else ""
        for index, line in enumerate(head_text.splitlines(), 1):
            if index >= after_line and first and first in line:
                return index
        return None

    def step_line(step: Step, setting: str | None = None) -> int | None:
        """The step's own line, or the line of ``setting`` just below it, or
        else just below its job's line (a job-level setting)."""
        own = line_of(step.needle)
        if setting is None:
            return own
        for start, window in ((own, 8), (line_of(f"{step.job}:"), 12)):
            found = line_of(setting, start) if start else None
            if found is not None and found - start <= window:
                return found
        return own

    def where(step: Step) -> str:
        if step.gitlab:
            return f"job {step.job!r}"
        return f"step {step.label!r} in job {step.job!r}"

    # Fail quietly. GitHub test steps are test_config.py's (unchanged).
    if (kind == "check" or is_gitlab_ci(path)) and (after is None or after.gate):
        for step in head_steps:
            if step.disabled:
                continue
            counterpart = _counterpart(step, base_steps)
            if counterpart is None:
                continue  # a new check: never required, so not weakened
            new = step.quiet - counterpart.quiet
            new |= _flag_changes(counterpart.flags, step.flags)
            if not new:
                continue
            build = "pipeline" if step.gitlab else "build"
            setting = (
                "allow_failure"
                if "allow_failure" in new
                else "continue-on-error"
                if any("continue-on-error" in n for n in new)
                else None
            )
            findings.append(
                (
                    path,
                    step_line(step, setting),
                    f"CI {step.category} {where(step)} can now fail without failing "
                    f"the {build} ({', '.join(sorted(new))})",
                )
            )
    # Stop running.
    reported: set[str] = set()
    for step in base_steps:
        if step.disabled or step.keys & running:
            continue
        if any(s.keys & step.keys and not s.disabled for s in head_steps):
            continue  # still here, only quiet: reported above
        twin = next(
            (
                s
                for s in head_steps
                if s.disabled and (s.keys & step.keys or s.label == step.label)
            ),
            None,
        )
        tools = ", ".join(_show(k) for k in sorted(step.keys))
        if tools in reported:
            continue
        reported.add(tools)
        if twin is not None:
            findings.append(
                (
                    path,
                    step_line(twin, "if:" if "if" in twin.disabled else "when:"),
                    f"CI {step.category} {where(twin)} is now disabled "
                    f"({twin.disabled}): {tools} no longer runs",
                )
            )
        else:
            findings.append(
                (
                    path,
                    None,
                    f"CI no longer runs {tools}: {step.category} {where(step)} "
                    "removed, and no other step runs it",
                )
            )
    # No longer triggered on pull requests or pushes.
    if (
        before
        and after
        and before.triggers
        and after.triggers is not None
        and base_steps
    ):
        lost = None
        if before.triggers & _PR_EVENTS and not after.triggers & _PR_EVENTS:
            lost = "pull requests"
        elif "push" in before.triggers and not after.triggers & (_PR_EVENTS | {"push"}):
            lost = "pushes"
        # Tools another gate still runs did not stop being checked.
        events = set(_PR_EVENTS) if lost == "pull requests" else {"push", *_PR_EVENTS}
        still = elsewhere(path, events) if elsewhere else set()
        stopped = {_show(k) for s in base_steps if not s.keys & still for k in s.keys}
        if lost and stopped:
            tools = ", ".join(sorted(stopped)[:4])
            findings.append(
                (
                    path,
                    line_of("on:"),
                    f"CI workflow no longer runs on {lost} ({tools})",
                )
            )
    # An aggregate job that no longer needs a job with such steps.
    if before and after:
        jobs_with_steps = {s.job for s in head_steps if not s.disabled}
        for job, needed in after.needs.items():
            if job not in after.aggregate or job not in before.needs:
                continue
            for lost_job in sorted(before.needs[job] - needed):
                if lost_job in jobs_with_steps:
                    tools = ", ".join(
                        sorted(
                            {
                                _show(k)
                                for s in head_steps
                                if s.job == lost_job and not s.disabled
                                for k in s.keys
                            }
                        )[:3]
                    )
                    findings.append(
                        (
                            path,
                            line_of("needs"),
                            f"job {job!r} no longer needs job {lost_job!r} ({tools})",
                        )
                    )
    return findings


def _counterpart(step: Step, base_steps: list[Step]) -> Step | None:
    same_job = [s for s in base_steps if s.job == step.job]
    for pool in (same_job, base_steps):
        for candidate in pool:
            if candidate.label == step.label and candidate.keys & step.keys:
                return candidate
        for candidate in pool:
            if candidate.keys & step.keys:
                return candidate
    return None


def _show(key: str) -> str:
    if key.startswith("script:"):
        return f"the {key[len('script:') :]} script"
    if key.startswith("action:"):
        return key[len("action:") :]
    return key
