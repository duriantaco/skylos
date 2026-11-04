"""Exact registry pins in Cargo.toml, composer.json and pubspec.yaml.

These manifests mostly declare version ranges, which are counted as
unresolved and never turned into a guessed version. Only an exact pin is a
queryable identity: Cargo ``=x.y.z``, a bare Composer version, a bare pub
version. Git, path, SDK and private-registry declarations are not public
registry packages and are neither queried nor counted; the lockfile next to
the manifest names them. A pub ``dependency_overrides`` entry replaces the
package's other declarations, so only the override is read.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.rules.sca.cargo_lockfile import semver
from skylos.rules.sca.composer_lockfile import composer_version
from skylos.rules.sca.lockfile_types import LockfileParseError
from skylos.rules.sca.npm_lockfile import _source_lines
from skylos.rules.sca.pnpm_lockfile import _line
from skylos.rules.sca.pubspec_lockfile import load_pub_yaml, public_pub_host

_CARGO_SECTIONS = (
    ("dependencies", False),
    ("dev-dependencies", True),
    ("dev_dependencies", True),
    ("build-dependencies", False),
    ("build_dependencies", False),
)
_CARGO_SOURCE_KEYS = frozenset({"git", "path", "registry", "registry-index"})
_CARGO_EXACT = re.compile(r"=\s*(?P<version>[0-9][0-9A-Za-z.+-]*)\s*\Z")
_COMPOSER_PLATFORM = re.compile(
    r"(?:php(?:-64bit|-ipv6|-zts|-debug)?|hhvm|composer"
    r"|composer-plugin-api|composer-runtime-api|ext-.+|lib-.+)\Z",
    re.IGNORECASE,
)
_COMPOSER_SECTIONS = (("require", False), ("require-dev", True))
_COMPOSER_SHORT_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z")
_PUB_SECTIONS = (
    ("dependencies", False),
    ("dev_dependencies", True),
    ("dependency_overrides", None),
)
_PUB_SOURCE_KEYS = frozenset({"git", "path", "sdk"})


def _toml(text: str) -> dict:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return {}
    if isinstance(data, dict):
        return data
    return {}


def _cargo_tables(data: dict):
    for section, dev in _CARGO_SECTIONS:
        yield section, data.get(section), dev
    targets = data.get("target")
    if isinstance(targets, dict):
        for spec in targets.values():
            if isinstance(spec, dict):
                for section, dev in _CARGO_SECTIONS:
                    yield section, spec.get(section), dev


def _cargo_entry(name: str, spec) -> tuple[str, str | None, str | None]:
    """("skip" | "unresolved" | "exact", crate name, exact version)."""
    crate = name
    requirement = spec
    if isinstance(spec, dict):
        if _CARGO_SOURCE_KEYS.intersection(spec):
            return "skip", None, None
        if spec.get("workspace") is True:
            return "unresolved", None, None
        crate = spec.get("package", name)
        requirement = spec.get("version")
    if not isinstance(crate, str) or not isinstance(requirement, str):
        return "unresolved", None, None
    match = _CARGO_EXACT.fullmatch(requirement.strip())
    if match is None or not semver(match["version"]):
        return "unresolved", None, None
    return "exact", crate, match["version"]


def _cargo_entries(text: str):
    for section, table, dev in _cargo_tables(_toml(text)):
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            kind, crate, version = _cargo_entry(name, spec)
            if kind != "skip":
                yield section, name, dev, kind, crate, version


def cargo_declaration_count(text: str) -> int:
    return sum(1 for _ in _cargo_entries(text))


def _toml_key_line(text: str, name: str) -> int:
    key = re.compile(
        rf"""^\s*(?:{re.escape(name)}|"{re.escape(name)}")\s*=|\.(?:{re.escape(name)}|"{re.escape(name)}")\s*\]\s*$"""
    )
    for lineno, line in enumerate(text.splitlines(), 1):
        if key.search(line):
            return lineno
    return 1


def parse_cargo_toml(path: Path, *, text: str) -> list[dict]:
    dependencies = []
    for section, name, dev, kind, crate, version in _cargo_entries(text):
        if kind != "exact":
            continue
        dependencies.append(
            {
                "name": crate,
                "version": version,
                "ecosystem": "crates.io",
                "file": str(path),
                "line": _toml_key_line(text, name),
                "snippet": f'{name} = "={version}"',
                "version_spec": f"={version}",
                "exact": True,
                "dependency_section": section,
                "dependency_kind": "direct",
                "dependency_dev": dev,
            }
        )
    return dependencies


def _composer_entries(text: str):
    try:
        data = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return
    if not isinstance(data, dict):
        return
    for section, dev in _COMPOSER_SECTIONS:
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if _COMPOSER_PLATFORM.fullmatch(name) or "/" not in name:
                continue
            version = None
            if isinstance(spec, str):
                version = composer_version(_without_equals(spec.strip()))
            if version is not None and _COMPOSER_SHORT_RELEASE.fullmatch(version):
                version = ".".join([*version.split("."), "0", "0"][:3])
            yield section, name, dev, version, spec


def _without_equals(spec: str) -> str:
    for prefix in ("==", "="):
        if spec.startswith(prefix):
            return spec[len(prefix) :].strip()
    return spec


def composer_declaration_count(text: str) -> int:
    return sum(1 for _ in _composer_entries(text))


def parse_composer_json(path: Path, *, text: str) -> list[dict]:
    entries = list(_composer_entries(text))
    lines = _source_lines(text, {(section, name) for section, name, *_ in entries})
    dependencies = []
    for section, name, dev, version, spec in entries:
        if version is None:
            continue
        dependencies.append(
            {
                "name": name.lower(),
                "version": version,
                "ecosystem": "Packagist",
                "file": str(path),
                "line": lines.get((section, name), 1),
                "snippet": f'"{name}": "{spec}"',
                "version_spec": spec,
                "exact": True,
                "dependency_section": section,
                "dependency_kind": "direct",
                "dependency_dev": dev,
            }
        )
    return dependencies


def _pub_entry(spec) -> tuple[str, str | None]:
    """("skip" | "unresolved" | "exact", exact version)."""
    requirement = spec
    if isinstance(spec, dict):
        if _PUB_SOURCE_KEYS.intersection(spec):
            return "skip", None
        hosted = spec.get("hosted")
        if isinstance(hosted, dict):
            hosted = hosted.get("url")
        if hosted is not None and not public_pub_host(hosted):
            return "skip", None
        requirement = spec.get("version")
    if semver(requirement):
        return "exact", requirement
    return "unresolved", None


def _pub_document(text: str):
    try:
        data = load_pub_yaml(text)
    except LockfileParseError:
        return None
    if isinstance(data, dict):
        return data
    return None


def pubspec_is_valid(text: str) -> bool:
    return _pub_document(text) is not None


def pubspec_uses_workspace(text: str) -> bool:
    """A pub workspace member resolves with the workspace root's pubspec.lock."""
    data = _pub_document(text)
    return data is not None and data.get("resolution") == "workspace"


def _pub_entries(text: str):
    """Declarations pub resolves; an override replaces every other one of its name."""
    data = _pub_document(text)
    if data is None:
        return
    overridden = set()
    if isinstance(data.get("dependency_overrides"), dict):
        overridden = set(data["dependency_overrides"])
    for section, dev in _PUB_SECTIONS:
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if section != "dependency_overrides" and name in overridden:
                continue
            kind, version = _pub_entry(spec)
            if kind != "skip":
                yield section, table, name, dev, version


def pubspec_declaration_count(text: str) -> int:
    return sum(1 for _ in _pub_entries(text))


def parse_pubspec_yaml(path: Path, *, text: str) -> list[dict]:
    dependencies = []
    for section, table, name, dev, version in _pub_entries(text):
        if version is None:
            continue
        dependencies.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "Pub",
                "file": str(path),
                "line": _line(table, name),
                "snippet": f"{name}: {version}",
                "version_spec": version,
                "exact": True,
                "dependency_section": section,
                "dependency_kind": "direct",
                "dependency_dev": dev,
            }
        )
    return dependencies


def cargo_toml_is_valid(text: str) -> bool:
    try:
        return isinstance(tomllib.loads(text), dict)
    except (tomllib.TOMLDecodeError, RecursionError):
        return False


def composer_json_is_valid(text: str) -> bool:
    try:
        return isinstance(json.loads(text), dict)
    except (TypeError, ValueError, RecursionError):
        return False
