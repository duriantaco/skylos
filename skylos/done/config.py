"""``[tool.skylos.done]`` settings, read from the base, never the working tree."""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

# Check ids are shared with Skylos Cloud's agent-check policy: renaming one
# makes the workspace settings stop applying to it.
CHECK_IDS = (
    "tests_pass",
    "test_tampering",
    "gate_tampering",
    "secrets",
    "unknown_imports",
    "changed_lines_checked",
    "test_special_casing",
    "silenced_checks",
    "security_controls",
    "guardrail_tampering",
    "branch_orphans",
)
MODES = ("block", "advise", "shadow", "off")

# Checks that report facts (tests failed, a test was deleted, gate settings
# changed, a credential was added) block by default. Import resolution still
# has known false alarms, so it advises until it has a measured track record.
DEFAULT_MODES = {
    "tests_pass": "block",
    "test_tampering": "block",
    "gate_tampering": "block",
    "secrets": "block",
    "unknown_imports": "advise",
    # Some lines are not worth a test; the plan keeps this advisory until
    # partner reviews measure how often a missed line matters.
    "changed_lines_checked": "advise",
    # Code that answers the tests' exact inputs, detects the test run or
    # rigs its comparisons. Weaker signals inside it are advice.
    "test_special_casing": "block",
    # Silenced linters, type checkers, scanners and CI. A study of 450 merged
    # agent pull requests found no deliberate silencing, so it advises; with
    # "block", weakened settings and CI block and inline suppressions stay
    # advice.
    "silenced_checks": "advise",
    "security_controls": "block",
    # AI-reviewer instructions or settings changed (SKY-A122) and scanner
    # suppression markers added (SKY-A125). Reported, never blocking by
    # default: most such edits are deliberate. "block" makes them decide.
    "guardrail_tampering": "advise",
    # Code the change left with no callers (SKY-A135/A136/A137). Dead-code
    # analysis has known false alarms, so it advises until it has a measured
    # track record; with "block", the rules in branch_orphans_block_rules block.
    "branch_orphans": "advise",
}
ORPHAN_RULES = ("SKY-A135", "SKY-A136", "SKY-A137")
# With branch_orphans = "block": code made dead and new code nothing calls
# block; new code only tests call stays advice unless listed.
DEFAULT_ORPHANS_BLOCK_RULES = ("SKY-A135", "SKY-A136")
# Skylos's own settings and the agent hook files that run it. Not all of
# .claude/ or .cursor/: skills and rules there are ordinary project files.
DEFAULT_PROTECTED_PATHS = (
    ".skylos/",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".cursor/hooks.json",
)
DEFAULT_TEST_BUDGET_SECONDS = 300
MIN_TEST_BUDGET_SECONDS = 10
MAX_TEST_BUDGET_SECONDS = 3600
DEFAULT_MAX_STOP_BLOCKS = 3
MIN_STOP_BLOCKS = 1
MAX_STOP_BLOCKS = 10
MAX_PROTECTED_PATHS = 100
DEFAULT_CHANGED_LINES_BUDGET_SECONDS = 120
MIN_CHANGED_LINES_BUDGET_SECONDS = 10
MAX_CHANGED_LINES_BUDGET_SECONDS = 1800
# Rerunning failing tests on the base commit to tell failures the change
# introduced from ones that were already there (see preexisting.py).
DEFAULT_PREEXISTING_TIMEOUT_SECONDS = 120
MIN_PREEXISTING_TIMEOUT_SECONDS = 10
MAX_PREEXISTING_TIMEOUT_SECONDS = 1800


@dataclass(frozen=True)
class DoneConfig:
    test_command: tuple[str, ...] | None = None
    junit_xml: str | None = None
    test_budget_seconds: int = DEFAULT_TEST_BUDGET_SECONDS
    changed_lines_budget_seconds: int = DEFAULT_CHANGED_LINES_BUDGET_SECONDS
    max_stop_blocks: int = DEFAULT_MAX_STOP_BLOCKS
    protected_paths: tuple[str, ...] = DEFAULT_PROTECTED_PATHS
    orphans_block_rules: tuple[str, ...] = DEFAULT_ORPHANS_BLOCK_RULES
    modes: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_MODES))
    # When tests fail, rerun just the failing ones on the base commit and say
    # which the change introduced. Labels only: every failure still blocks...
    verify_preexisting: bool = True
    # ...unless a person opts in here: failures verified to fail on the base
    # too stop blocking (introduced and undetermined ones still block).
    allow_preexisting_failures: bool = False
    preexisting_timeout_seconds: int = DEFAULT_PREEXISTING_TIMEOUT_SECONDS
    # True when the base's pyproject.toml has a [tool.skylos.done] table.
    configured: bool = False
    # Settings that were ignored, said on the receipt instead of failing.
    problems: tuple[str, ...] = ()

    def mode(self, check_id: str) -> str:
        return self.modes.get(check_id, DEFAULT_MODES.get(check_id, "off"))

    def digest(self) -> str:
        """sha256 of the effective settings, so a receipt names what it applied."""
        settings = {
            "test_command": list(self.test_command or ()),
            "junit_xml": self.junit_xml,
            "test_budget_seconds": self.test_budget_seconds,
            "changed_lines_budget_seconds": self.changed_lines_budget_seconds,
            "max_stop_blocks": self.max_stop_blocks,
            "protected_paths": list(self.protected_paths),
            "modes": {key: self.mode(key) for key in CHECK_IDS},
        }
        # Later settings join the digest only when they differ from their
        # defaults, so a configuration that does not use them keeps its digest.
        if tuple(self.orphans_block_rules) != DEFAULT_ORPHANS_BLOCK_RULES:
            settings["orphans_block_rules"] = list(self.orphans_block_rules)
        if not self.verify_preexisting:
            settings["verify_preexisting"] = False
        if self.allow_preexisting_failures:
            settings["allow_preexisting_failures"] = True
        if self.preexisting_timeout_seconds != DEFAULT_PREEXISTING_TIMEOUT_SECONDS:
            settings["preexisting_timeout_seconds"] = self.preexisting_timeout_seconds
        canonical = json.dumps(settings, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def base_config_text(comparison, *, sha: str | None = None) -> str | None:
    """The repository-root Skylos config at the base commit (or ``sha``).

    The same file ``load_config`` reads at the root: ``.skylos.toml``, else
    ``skylos.toml``, else ``pyproject.toml``. Never the working tree.
    """
    for name in (".skylos.toml", "skylos.toml"):
        text = comparison.base_text(name, sha=sha)
        if text is not None:
            return text
    return comparison.base_text("pyproject.toml", sha=sha)


def skylos_settings_table(data) -> dict | None:
    """``[tool.skylos]`` of a pyproject.toml, or a skylos.toml's settings
    (its ``[tool.skylos]`` or ``[skylos]`` table, else its top level; a
    pyproject.toml has no top-level ``done`` or ``approval`` table)."""
    if not isinstance(data, dict):
        return None
    tool = data.get("tool")
    if isinstance(tool, dict) and "skylos" in tool:
        return tool.get("skylos")
    if isinstance(data.get("skylos"), dict):
        return data["skylos"]
    return {key: value for key, value in data.items() if key != "tool"}


def parse_done_config(pyproject_text: str | None) -> DoneConfig:
    """Effective settings from a pyproject.toml's or skylos.toml's text
    (None: no file)."""
    if pyproject_text is None:
        return DoneConfig()
    try:
        data = tomllib.loads(pyproject_text)
    except (tomllib.TOMLDecodeError, ValueError):
        return DoneConfig(problems=("pyproject.toml at the base is not valid TOML",))

    skylos = skylos_settings_table(data)
    table = skylos.get("done") if isinstance(skylos, dict) else None
    if table is None:
        return DoneConfig()
    if not isinstance(table, dict):
        return DoneConfig(problems=("[tool.skylos.done] is not a table",))

    problems: list[str] = []
    test_command = _test_command(table.get("test_command"), problems)
    junit_xml = _junit_xml(table.get("junit_xml"), problems)
    budget = _bounded_int(
        table.get("test_budget_seconds"),
        "test_budget_seconds",
        DEFAULT_TEST_BUDGET_SECONDS,
        MIN_TEST_BUDGET_SECONDS,
        MAX_TEST_BUDGET_SECONDS,
        problems,
    )
    changed_lines_budget = _bounded_int(
        table.get("changed_lines_budget_seconds"),
        "changed_lines_budget_seconds",
        DEFAULT_CHANGED_LINES_BUDGET_SECONDS,
        MIN_CHANGED_LINES_BUDGET_SECONDS,
        MAX_CHANGED_LINES_BUDGET_SECONDS,
        problems,
    )
    stop_blocks = _bounded_int(
        table.get("max_stop_blocks"),
        "max_stop_blocks",
        DEFAULT_MAX_STOP_BLOCKS,
        MIN_STOP_BLOCKS,
        MAX_STOP_BLOCKS,
        problems,
    )
    protected = _protected_paths(table.get("protected_paths"), problems)
    orphan_rules = _orphans_block_rules(
        table.get("branch_orphans_block_rules"), problems
    )
    modes = _modes(table.get("checks"), problems)
    verify_preexisting = _bool(
        table.get("verify_preexisting"), "verify_preexisting", True, problems
    )
    allow_preexisting = _bool(
        table.get("allow_preexisting_failures"),
        "allow_preexisting_failures",
        False,
        problems,
    )
    preexisting_timeout = _bounded_int(
        table.get("preexisting_timeout_seconds"),
        "preexisting_timeout_seconds",
        DEFAULT_PREEXISTING_TIMEOUT_SECONDS,
        MIN_PREEXISTING_TIMEOUT_SECONDS,
        MAX_PREEXISTING_TIMEOUT_SECONDS,
        problems,
    )
    if allow_preexisting and not verify_preexisting:
        # Nothing is verified, so nothing can be allowed.
        problems.append(
            "allow_preexisting_failures needs verify_preexisting; failures still block"
        )
        allow_preexisting = False
    return DoneConfig(
        test_command=test_command,
        junit_xml=junit_xml,
        test_budget_seconds=budget,
        changed_lines_budget_seconds=changed_lines_budget,
        max_stop_blocks=stop_blocks,
        protected_paths=protected,
        orphans_block_rules=orphan_rules,
        modes=modes,
        verify_preexisting=verify_preexisting,
        allow_preexisting_failures=allow_preexisting,
        preexisting_timeout_seconds=preexisting_timeout,
        configured=True,
        problems=tuple(problems),
    )


def _test_command(value, problems: list[str]) -> tuple[str, ...] | None:
    if value is None:
        return None
    # A list is passed through as-is; a string is split like a shell would,
    # but it never runs through a shell (no pipes, globs or variables).
    if isinstance(value, str):
        try:
            parts = shlex.split(value)
        except ValueError:
            problems.append("test_command could not be parsed")
            return None
    elif isinstance(value, list) and all(isinstance(part, str) for part in value):
        parts = list(value)
    else:
        problems.append("test_command must be a string or a list of strings")
        return None
    if not parts or not parts[0].strip():
        problems.append("test_command is empty")
        return None
    return tuple(parts)


def _junit_xml(value, problems: list[str]) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or value.startswith(("/", "~"))
        or ".." in value.replace("\\", "/").split("/")
    ):
        problems.append("junit_xml must be a path inside the repository")
        return None
    return value.strip()


def _bounded_int(value, name, default, minimum, maximum, problems) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        problems.append(f"{name} must be a whole number")
        return default
    if value < minimum or value > maximum:
        problems.append(f"{name} must be between {minimum} and {maximum}")
        return min(max(value, minimum), maximum)
    return value


def _bool(value, name: str, default: bool, problems: list[str]) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        problems.append(f"{name} must be true or false")
        return default
    return value


def _protected_paths(value, problems: list[str]) -> tuple[str, ...]:
    if value is None:
        return DEFAULT_PROTECTED_PATHS
    if not isinstance(value, list) or not all(isinstance(p, str) for p in value):
        problems.append("protected_paths must be a list of strings")
        return DEFAULT_PROTECTED_PATHS
    cleaned = []
    for raw in value[:MAX_PROTECTED_PATHS]:
        path = raw.strip().replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        if path and not path.startswith("/") and ".." not in path.split("/"):
            cleaned.append(path)
        else:
            problems.append(f"protected path {raw!r} ignored")
    if len(value) > MAX_PROTECTED_PATHS:
        problems.append(f"only the first {MAX_PROTECTED_PATHS} protected paths apply")
    return tuple(dict.fromkeys(cleaned))


def _orphans_block_rules(value, problems: list[str]) -> tuple[str, ...]:
    if value is None:
        return DEFAULT_ORPHANS_BLOCK_RULES
    if not isinstance(value, list) or not all(isinstance(r, str) for r in value):
        problems.append("branch_orphans_block_rules must be a list of rule ids")
        return DEFAULT_ORPHANS_BLOCK_RULES
    rules = []
    for rule in value:
        if rule in ORPHAN_RULES:
            rules.append(rule)
        else:
            problems.append(
                f"branch_orphans_block_rules: {rule!r} is not one of "
                + ", ".join(ORPHAN_RULES)
            )
    return tuple(dict.fromkeys(rules))


def _modes(value, problems: list[str]) -> dict[str, str]:
    modes = dict(DEFAULT_MODES)
    if value is None:
        return modes
    if not isinstance(value, dict):
        problems.append("[tool.skylos.done.checks] is not a table")
        return modes
    for key, mode in value.items():
        if key not in CHECK_IDS:
            # Later releases add checks; an older CLI ignores them.
            continue
        if mode in MODES:
            modes[key] = mode
        else:
            problems.append(f"{key} = {mode!r} is not one of {', '.join(MODES)}")
    return modes
