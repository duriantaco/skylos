"""Static package-script evidence for AVA and tsd development entry points."""

from __future__ import annotations

import fnmatch
from functools import lru_cache
from pathlib import Path

_AVA_CONFIG_NAMES = ("ava.config.js", "ava.config.mjs", "ava.config.cjs")
_AVA_DEFAULT_PATTERNS = (
    "test.*",
    "src/test.*",
    "source/test.*",
    "**/__tests__/**/*",
    "**/*.spec.*",
    "**/*.test.*",
    "**/test-*.*",
    "**/test/**/*",
    "**/tests/**/*",
)


def _has_dependency(package: dict, tool: str) -> bool:
    for field in ("dependencies", "devDependencies"):
        dependencies = package.get(field)
        if isinstance(dependencies, dict) and isinstance(dependencies.get(tool), str):
            return bool(dependencies[tool])
    return False


def _inventory(package_root: str, files: set[str]) -> dict[str, str]:
    root = Path(package_root).resolve()
    inventory = {}
    for filename in files:
        path = Path(filename).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if len(relative.parts) <= 128:
            inventory[relative.as_posix()] = str(path)
    return inventory


def _simple_pattern(pattern: str) -> bool:
    # Do not approximate extglobs/brace expansion or paths outside the package.
    return (
        0 < len(pattern) <= 1024
        and len(pattern.split("/")) <= 128
        and not (
            pattern.startswith("/")
            or ".." in pattern.split("/")
            or any(character in pattern for character in "{}()\\")
        )
    )


def _matches(relative: str, pattern: str) -> bool:
    path_parts = relative.split("/")
    pattern_parts = pattern.removeprefix("./").rstrip("/").split("/")

    @lru_cache(maxsize=None)
    def match(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        part = pattern_parts[pattern_index]
        if part == "**":
            return match(path_index, pattern_index + 1) or (
                path_index < len(path_parts) and match(path_index + 1, pattern_index)
            )
        return (
            path_index < len(path_parts)
            and fnmatch.fnmatchcase(path_parts[path_index].lower(), part.lower())
            and match(path_index + 1, pattern_index + 1)
        )

    return match(0, 0)


def _has_ava_config(package_root: str) -> bool:
    directory = Path(package_root).resolve()
    while True:
        if any((directory / name).is_file() for name in _AVA_CONFIG_NAMES):
            return True
        if (directory / ".git").exists() or directory.parent == directory:
            return False
        directory = directory.parent


def _ava_entries(
    package_root: str, package: dict, inventory: dict[str, str]
) -> set[str]:
    # External configuration may override package defaults. Do not execute it or
    # infer selections from defaults when its static values are unavailable.
    if _has_ava_config(package_root):
        return set()
    config = package.get("ava", {})
    if not isinstance(config, dict):
        return set()
    extensions = config.get("extensions", ["js", "mjs"])
    if (
        not isinstance(extensions, list)
        or len(extensions) > 512
        or not all(isinstance(x, str) for x in extensions)
    ):
        return set()
    patterns = config.get("files")
    if "files" not in config:
        patterns = list(_AVA_DEFAULT_PATTERNS)
    elif (
        not isinstance(patterns, list)
        or not patterns
        or len(patterns) > 512
        or not all(
            isinstance(x, str) and _simple_pattern(x.lstrip("!")) for x in patterns
        )
    ):
        return set()
    elif all(pattern.startswith("!") for pattern in patterns):
        patterns = [*_AVA_DEFAULT_PATTERNS, *patterns]

    include = [pattern for pattern in patterns if not pattern.startswith("!")]
    exclude = [pattern[1:] for pattern in patterns if pattern.startswith("!")]
    defaults = "files" not in config or all(x.startswith("!") for x in config["files"])
    matches = set()
    for relative, filename in inventory.items():
        parts = relative.split("/")
        if (
            parts[-1].startswith("_")
            or any(part.startswith(".") or part == "node_modules" for part in parts)
            or Path(relative).suffix.removeprefix(".") not in extensions
        ):
            continue
        if defaults and any(
            (
                directory.lower() in {"test", "tests"}
                and any(
                    part.lower() in {"helpers", "helper", "fixtures", "fixture"}
                    for part in parts[index + 1 : -1]
                )
            )
            or (
                directory.lower() == "__tests__"
                and any(
                    part.lower()
                    in {"__helpers__", "__helper__", "__fixtures__", "__fixture__"}
                    for part in parts[index + 1 : -1]
                )
            )
            for index, directory in enumerate(parts[:-1])
        ):
            continue
        if any(_matches(relative, pattern) for pattern in include) and not any(
            _matches(relative, pattern)
            or _matches(relative, pattern.rstrip("/") + "/**")
            for pattern in exclude
        ):
            matches.add(filename)
    return matches


def _tsd_entries(package: dict, inventory: dict[str, str]) -> set[str]:
    typings = package.get("types") or package.get("typings")
    if typings is None:
        main = package.get("main")
        typings = Path(main).stem + ".d.ts" if isinstance(main, str) else "index.d.ts"
    if not isinstance(typings, str) or not _simple_pattern(typings):
        return set()
    typings = typings.removeprefix("./")
    if not typings.endswith(".d.ts") or typings not in inventory:
        return set()
    basename = typings[:-5]
    direct = {
        inventory[filename]
        for filename in (basename + ".test-d.ts", basename + ".test-d.tsx")
        if filename in inventory
    }
    if direct:
        return direct
    config = package.get("tsd", {})
    if not isinstance(config, dict):
        return set()
    directory = config.get("directory", "test-d")
    if not isinstance(directory, str) or not _simple_pattern(directory):
        return set()
    directory = directory.removeprefix("./").rstrip("/")
    return {
        filename
        for relative, filename in inventory.items()
        if relative.startswith(directory + "/") and relative.endswith((".ts", ".tsx"))
    }


def discover_test_tool_entries(
    package_root: str, package: dict, files: set[str], commands: list[list[str]]
) -> dict[str, str]:
    """Recognize bare, declared test runners without guessing CLI overrides."""
    inventory = _inventory(package_root, files)
    entries = {}
    for command in commands:
        if len(command) != 1 or not _has_dependency(package, command[0]):
            continue
        tool = command[0]
        if tool == "ava":
            matches = _ava_entries(package_root, package, inventory)
        elif tool == "tsd":
            matches = _tsd_entries(package, inventory)
        else:
            continue
        entries.update((filename, f"{tool}-derived-root") for filename in matches)
    return entries
