"""Cargo.lock packages get a dependency scope from the workspace manifests.

Advisories reachable only through dev-dependencies or test-only optional
dependencies stay in the report and in gates but leave the default listing;
normal, build-only and optional-feature crates stay listed.
"""

from __future__ import annotations

from pathlib import Path

from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.listing import is_listed, low_risk_context
from skylos.rules.sca import vulnerability_scanner as sca
from skylos.rules.sca.advisory_metadata import extract_advisory_metadata
from skylos.rules.sca.cargo_lockfile import parse_cargo_lock

_REGISTRY = 'source = "registry+https://github.com/rust-lang/crates.io-index"'


def _package(name, version="1.0.0", deps=(), local=False):
    lines = ["[[package]]", f'name = "{name}"', f'version = "{version}"']
    if not local:
        lines.append(_REGISTRY)
    if deps:
        lines.append("dependencies = [" + ", ".join(f'"{d}"' for d in deps) + "]")
    return "\n".join(lines) + "\n"


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


_WORKSPACE = {
    "Cargo.toml": '[workspace]\nmembers = ["app", "helper"]\n',
    "app/Cargo.toml": """[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1"
helper = { path = "../helper" }
fancy = { version = "1", optional = true }
shelltest = { version = "1", optional = true }
renamed_xml = { package = "quick-xml", version = "0.30" }

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[build-dependencies]
cc = "1"

[dev-dependencies]
snapbox = "1"
serde = { version = "1", features = ["derive"] }

[features]
default = []
pretty = ["dep:fancy"]
shell-tests = ["dep:shelltest"]
""",
    "app/src/lib.rs": '#[cfg(feature = "pretty")]\npub use fancy::Pretty;\n',
    "app/tests/shell.rs": '#[cfg(feature = "shell-tests")]\nuse shelltest::Term;\n',
    "helper/Cargo.toml": """[package]
name = "helper"
version = "0.1.0"

[dependencies]
itoa = "1"
""",
}

_LOCK = "version = 4\n\n" + "\n".join(
    [
        _package(
            "app",
            "0.1.0",
            [
                "serde",
                "helper",
                "fancy",
                "shelltest",
                "quick-xml",
                "winapi",
                "cc",
                "snapbox",
            ],
            local=True,
        ),
        _package("helper", "0.1.0", ["itoa"], local=True),
        _package("serde"),
        _package("itoa"),
        _package("fancy", deps=["unicode-width"]),
        _package("unicode-width"),
        _package("shelltest", deps=["openssl"]),
        _package("openssl"),
        _package("quick-xml", "0.30.0"),
        _package("winapi", "0.3.9"),
        _package("cc"),
        _package("snapbox", deps=["similar", "serde"]),
        _package("similar"),
    ]
)


def _scopes(tmp_path, files=None, lock=_LOCK, text=None):
    _write(
        tmp_path, {**(files if files is not None else _WORKSPACE), "Cargo.lock": lock}
    )
    inventory = parse_cargo_lock(tmp_path / "Cargo.lock", text=text)
    return {d["name"]: d.get("dependency_scope") for d in inventory.dependencies}


def test_each_locked_crate_gets_its_strongest_scope(tmp_path):
    assert _scopes(tmp_path) == {
        "serde": "normal",  # also a dev-dependency: normal wins
        "itoa": "normal",  # through the path dependency's own manifest
        "fancy": "optional-feature",  # used by src/ behind a feature
        "unicode-width": "optional-feature",
        "shelltest": "dev-only",  # optional, but only tests/ name it
        "openssl": "dev-only",
        "quick-xml": "normal",  # renamed with `package =`
        "winapi": "normal",  # target-specific normal dependency
        "cc": "build-only",
        "snapbox": "dev-only",
        "similar": "dev-only",
    }


def test_default_feature_and_member_requests_enable_optional_dependencies(tmp_path):
    files = dict(_WORKSPACE)
    files["app/Cargo.toml"] = files["app/Cargo.toml"].replace(
        "default = []", 'default = ["shell-tests"]'
    )
    files["helper/Cargo.toml"] += (
        '\n[dependencies.app]\npath = "../app"\nfeatures = ["pretty"]\n'
    )
    lock = _LOCK.replace('dependencies = ["itoa"]', 'dependencies = ["itoa", "app"]')
    scopes = _scopes(tmp_path, files, lock)
    assert scopes["shelltest"] == "normal"
    assert scopes["fancy"] == "normal"


def test_unexplained_lockfile_is_left_unclassified(tmp_path):
    files = dict(_WORKSPACE)
    files["app/Cargo.toml"] = files["app/Cargo.toml"].replace('cc = "1"', "")
    assert set(_scopes(tmp_path, files).values()) == {None}
    files = dict(_WORKSPACE)
    del files["helper/Cargo.toml"]
    assert set(_scopes(tmp_path / "missing", files).values()) == {None}


def test_lockfile_text_from_another_revision_is_not_classified(tmp_path):
    other = _LOCK.replace('version = "0.30.0"', 'version = "0.31.0"')
    assert set(_scopes(tmp_path, text=other).values()) == {None}
    assert _scopes(tmp_path / "same", text=_LOCK)["snapbox"] == "dev-only"


def _advisory(scope, informational=None):
    dependency = {
        "name": "openssl",
        "version": "1.0.0",
        "ecosystem": "crates.io",
        "file": "Cargo.lock",
        "line": 3,
        "dependency_scope": scope,
    }
    dependency["dependency_occurrences"] = [{"dependency_scope": scope}]
    affected = {"package": {"ecosystem": "crates.io", "name": "openssl"}}
    if informational:
        affected["database_specific"] = {"informational": informational}
    advisory = {"id": "RUSTSEC-2025-0004", "summary": "test", "affected": [affected]}
    return sca._make_finding(
        dependency, extract_advisory_metadata(advisory, dependency)
    )


def test_dev_only_cargo_advisories_are_kept_but_not_listed():
    dev = _advisory("dev-only")
    assert low_risk_context(dev)["reason"] == "dev-only-dependency"
    assert dev["metadata"]["dependency_scope"] == "dev-only"
    shipped = [
        _advisory(scope) for scope in ("normal", "build-only", "optional-feature", None)
    ]
    assert all(low_risk_context(row) is None for row in shipped)
    view = apply_advice_policy({"dependency_vulnerabilities": [dev, shipped[0]]})
    rows = view["dependency_vulnerabilities"]
    assert [is_listed(row, "dependency_vulnerabilities") for row in rows] == [
        False,
        True,
    ]


def test_one_shipped_occurrence_keeps_the_advisory_listed():
    dependency = {
        "name": "openssl",
        "version": "1.0.0",
        "ecosystem": "crates.io",
        "file": "Cargo.lock",
        "line": 3,
        "dependency_scope": "dev-only",
        "dependency_occurrences": [
            {"dependency_scope": "dev-only"},
            {"dependency_scope": "normal"},
        ],
    }
    assert not sca._is_cargo_dev_only_dependency(dependency)
    affected = {"package": {"ecosystem": "crates.io", "name": "openssl"}}
    advisory = {"id": "RUSTSEC-2025-0004", "summary": "test", "affected": [affected]}
    finding = sca._make_finding(
        dependency, extract_advisory_metadata(advisory, dependency)
    )
    assert low_risk_context(finding) is None
