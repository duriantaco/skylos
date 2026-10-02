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
}
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


@dataclass(frozen=True)
class DoneConfig:
    test_command: tuple[str, ...] | None = None
    junit_xml: str | None = None
    test_budget_seconds: int = DEFAULT_TEST_BUDGET_SECONDS
    max_stop_blocks: int = DEFAULT_MAX_STOP_BLOCKS
    protected_paths: tuple[str, ...] = DEFAULT_PROTECTED_PATHS
    modes: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_MODES))
    # True when the base's pyproject.toml has a [tool.skylos.done] table.
    configured: bool = False
    # Settings that were ignored, said on the receipt instead of failing.
    problems: tuple[str, ...] = ()

    def mode(self, check_id: str) -> str:
        return self.modes.get(check_id, DEFAULT_MODES.get(check_id, "off"))

    def digest(self) -> str:
        """sha256 of the effective settings, so a receipt names what it applied."""
        canonical = json.dumps(
            {
                "test_command": list(self.test_command or ()),
                "junit_xml": self.junit_xml,
                "test_budget_seconds": self.test_budget_seconds,
                "max_stop_blocks": self.max_stop_blocks,
                "protected_paths": list(self.protected_paths),
                "modes": {key: self.mode(key) for key in CHECK_IDS},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_done_config(pyproject_text: str | None) -> DoneConfig:
    """Effective settings from a pyproject.toml's text (None: no file)."""
    if pyproject_text is None:
        return DoneConfig()
    try:
        data = tomllib.loads(pyproject_text)
    except (tomllib.TOMLDecodeError, ValueError):
        return DoneConfig(problems=("pyproject.toml at the base is not valid TOML",))

    tool = data.get("tool")
    skylos = tool.get("skylos") if isinstance(tool, dict) else None
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
    stop_blocks = _bounded_int(
        table.get("max_stop_blocks"),
        "max_stop_blocks",
        DEFAULT_MAX_STOP_BLOCKS,
        MIN_STOP_BLOCKS,
        MAX_STOP_BLOCKS,
        problems,
    )
    protected = _protected_paths(table.get("protected_paths"), problems)
    modes = _modes(table.get("checks"), problems)
    return DoneConfig(
        test_command=test_command,
        junit_xml=junit_xml,
        test_budget_seconds=budget,
        max_stop_blocks=stop_blocks,
        protected_paths=protected,
        modes=modes,
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
