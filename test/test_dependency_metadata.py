from pathlib import Path

import tomllib
from packaging.requirements import Requirement
from packaging.version import Version
import pytest


ROOT = Path(__file__).resolve().parents[1]


def _runtime_requirements():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = {}
    for value in metadata["project"]["dependencies"]:
        requirement = Requirement(value)
        requirements[requirement.name] = requirement
    return requirements


@pytest.mark.parametrize(
    ("package", "supported", "next_breaking"),
    [
        ("mcp", "1.29.0", "2.0.0"),
        ("tree-sitter", "0.26.0", "0.27.0"),
        ("tree-sitter-typescript", "0.23.2", "0.24.0"),
        ("tree-sitter-go", "0.25.0", "0.26.0"),
        ("tree-sitter-java", "0.23.5", "0.24.0"),
        ("tree-sitter-php", "0.24.1", "0.25.0"),
        ("tree-sitter-rust", "0.24.2", "0.25.0"),
        ("tree-sitter-dart-orchard", "0.5.0", "0.6.0"),
    ],
)
def test_runtime_dependency_compatibility_bands(package, supported, next_breaking):
    requirement = _runtime_requirements()[package]

    assert Version(supported) in requirement.specifier
    assert Version(next_breaking) not in requirement.specifier
