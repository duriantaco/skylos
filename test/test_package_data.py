"""Every data file the package reads at runtime must ship in the wheel.

The import-name mapping used by the dependency checks was missing from the
published wheel, which turned real imports such as ``sorl`` into CRITICAL
"hallucinated dependency" findings. A tracked non-Python file under
``skylos/`` must be listed in ``[tool.setuptools.package-data]`` or below as
deliberately not shipped.
"""

import fnmatch
import subprocess
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]

NOT_SHIPPED = (
    # Go engine sources and a local build; the engine binary is found on PATH
    # or through SKYLOS_GO_BIN, not inside the Python package.
    "skylos/engines/go/*",
    # Developer notes; nothing reads them at runtime.
    "skylos/llm/README.md",
)


def _package_data_patterns():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = config["tool"]["setuptools"]["package-data"]
    return [
        f"{package.replace('.', '/')}/{pattern}"
        for package, patterns in package_data.items()
        for pattern in patterns
    ]


def _tracked_data_files():
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z", "skylos"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("needs a git checkout")
    return [
        path
        for path in listed.decode().split("\0")
        if path and not path.endswith(".py")
    ]


def _matches(path, patterns):
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def test_every_tracked_data_file_ships_or_is_marked_unshipped():
    shipped = _package_data_patterns()

    undecided = [
        path
        for path in _tracked_data_files()
        if not _matches(path, shipped) and not _matches(path, NOT_SHIPPED)
    ]

    assert undecided == []


def test_package_data_patterns_match_real_files():
    tracked = _tracked_data_files()

    stale = [p for p in _package_data_patterns() if not fnmatch.filter(tracked, p)]

    assert stale == []
