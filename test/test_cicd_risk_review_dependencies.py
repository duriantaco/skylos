"""Dependency manifests and lockfiles compared by the risk review."""

from __future__ import annotations

import json
from dataclasses import dataclass
from textwrap import dedent

import pytest

from skylos.cicd.approval_dependencies import (
    dependency_changes,
    dependency_file_kind,
    is_lockfile,
)


@dataclass(frozen=True)
class Changed:
    path: str
    status: str
    base_path: str | None


def _changes(base: dict, head: dict, *, also_at_head: dict | None = None):
    """Compare two snapshots; ``also_at_head`` holds unchanged head files."""
    base = {k: dedent(v) for k, v in base.items()}
    head = {k: dedent(v) for k, v in head.items()}
    unchanged = {k: dedent(v) for k, v in (also_at_head or {}).items()}
    changed = []
    for path in sorted(set(base) | set(head)):
        if path in base and path in head:
            if base[path] != head[path]:
                changed.append(Changed(path, "modified", path))
        elif path in head:
            changed.append(Changed(path, "added", None))
        else:
            changed.append(Changed(path, "deleted", path))
    every_head = {**unchanged, **head}
    return dependency_changes(
        changed,
        base_text=base.get,
        head_text=every_head.get,
        head_paths=sorted(every_head),
    )


def _reasons(changes) -> dict[str, str]:
    return {c.file: c.reason for c in changes}


# ---------------------------------------------------------------------------
# file kinds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, kind",
    [
        ("package.json", ("manifest", "npm")),
        ("web/package-lock.json", ("lockfile", "npm_lock")),
        ("requirements/dev.txt", ("manifest", "requirements")),
        ("dev-requirements.in", ("manifest", "requirements")),
        ("constraints.txt", ("manifest", "requirements")),
        ("go.sum", ("lockfile", "go_sum")),
        ("gradle/libs.versions.toml", ("manifest", "gradle_catalog")),
        ("src/App/App.csproj", ("manifest", "nuget")),
        ("app/build.gradle.kts", ("manifest", "gradle")),
        ("bun.lockb", ("lockfile", "opaque")),
        ("node_modules/x/package.json", None),
        ("docs/requirements.md", None),
        ("README.txt", None),
    ],
)
def test_dependency_file_kinds(path, kind):
    assert dependency_file_kind(path) == kind


def test_lockfiles_are_recognized():
    assert is_lockfile("Cargo.lock") and is_lockfile("a/b/yarn.lock")
    assert not is_lockfile("Cargo.toml")


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

PKG = {
    "name": "web",
    "version": "1.0.0",
    "scripts": {"test": "vitest"},
    "dependencies": {"react": "^18.2.0", "@acme/ui": "^1.0.0", "shared": "workspace:*"},
    "devDependencies": {"vitest": "^1.6.0"},
}


def _pkg(**changes) -> str:
    data = json.loads(json.dumps(PKG))
    for key, value in changes.items():
        data[key] = value
    return json.dumps(data, indent=2) + "\n"


def test_npm_added_and_bumped_dependencies():
    head = _pkg(
        dependencies={**PKG["dependencies"], "react": "^18.3.0", "left-pad": "1.3.0"}
    )
    changes = _changes({"package.json": _pkg()}, {"package.json": head})
    assert len(changes) == 1
    assert changes[0].reason == (
        "adds or changes 2 dependencies: left-pad (1.3.0); react ^18.2.0 -> ^18.3.0"
    )
    assert changes[0].line == 8


def test_npm_version_scripts_section_moves_and_workspace_specs_are_not_changes():
    head = _pkg(
        version="1.1.0",
        scripts={"test": "vitest run"},
        dependencies={"@acme/ui": "^1.0.0", "shared": "workspace:^"},
        devDependencies={"vitest": "^1.6.0", "react": "^18.2.0"},
    )
    assert _changes({"package.json": _pkg()}, {"package.json": head}) == []


def test_npm_bump_of_a_package_this_repository_builds_is_not_a_change():
    head = _pkg(dependencies={**PKG["dependencies"], "@acme/ui": "^1.1.0"})
    ui = {"packages/ui/package.json": '{"name": "@acme/ui", "version": "1.1.0"}\n'}
    assert _changes({"package.json": _pkg()}, {"package.json": head}, also_at_head=ui) == []
    assert _changes({"package.json": _pkg()}, {"package.json": head}) != []


def test_npm_overrides_and_patches_count():
    head = _pkg(overrides={"semver": {"lru-cache": "7.0.0"}})
    reason = _reasons(_changes({"package.json": _pkg()}, {"package.json": head}))
    assert reason["package.json"] == (
        "adds or changes 1 dependency: overrides semver>lru-cache (7.0.0)"
    )


def test_package_lock_root_version_and_workspace_links_are_not_changes():
    base = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web", "version": "1.0.0"},
            "packages/ui": {"name": "@acme/ui", "version": "1.0.0"},
            "node_modules/@acme/ui": {"resolved": "packages/ui", "link": True},
            "node_modules/react": {"version": "18.2.0", "integrity": "sha512-a"},
        },
    }
    head = json.loads(json.dumps(base))
    head["packages"][""]["version"] = "1.1.0"
    head["packages"]["packages/ui"]["version"] = "1.1.0"
    files = lambda data: {"package-lock.json": json.dumps(data, indent=2)}
    assert _changes(files(base), files(head)) == []
    head["packages"]["node_modules/react"] = {"version": "18.3.1", "integrity": "sha512-b"}
    head["packages"]["node_modules/react/node_modules/loose-envify"] = {
        "version": "1.4.0"
    }
    changes = _changes(files(base), files(head))
    assert changes[0].reason == (
        "adds or changes 2 locked packages: loose-envify@1.4.0; "
        "react 18.2.0 -> 18.3.1"
    )
    assert changes[0].line is None


def test_package_lock_same_version_new_checksum_is_a_change():
    entry = lambda h: {
        "package-lock.json": json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0", "integrity": h}}}
        )
    }
    assert _changes(entry("sha512-x"), entry("sha512-y"))[0].reason == (
        "adds or changes 1 locked package: a@1.0.0 (checksum changed)"
    )


def test_package_lock_v1_nested():
    data = lambda v: {
        "package-lock.json": json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "a": {"version": "1.0.0", "dependencies": {"b": {"version": v}}},
                    "local": {"version": "file:../local"},
                },
            }
        )
    }
    assert _changes(data("2.0.0"), data("2.0.0")) == []
    assert "b 2.0.0 -> 2.1.0" in _changes(data("2.0.0"), data("2.1.0"))[0].reason


YARN_V1 = """\
# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"
  integrity sha512-abc
  dependencies:
    debug "^4.1.0"

debug@^4.1.0:
  version "4.3.4"
  integrity sha512-def
"""
YARN_BERRY = """\
__metadata:
  version: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abc

"web@workspace:.":
  version: 0.0.0-use.local
  resolution: "web@workspace:."
  linkType: soft
"""


def test_yarn_lock_v1_and_berry():
    bumped = YARN_V1.replace('version "4.3.4"', 'version "4.3.5"')
    assert "debug 4.3.4 -> 4.3.5" in _changes(
        {"yarn.lock": YARN_V1}, {"yarn.lock": bumped}
    )[0].reason
    own = YARN_BERRY.replace("0.0.0-use.local", "0.0.1-use.local")
    assert _changes({"yarn.lock": YARN_BERRY}, {"yarn.lock": own}) == []
    added = YARN_BERRY + '\n"zod@npm:^3.23.0":\n  version: 3.23.8\n  checksum: 10c0/def\n'
    assert "zod@3.23.8" in _changes(
        {"yarn.lock": YARN_BERRY}, {"yarn.lock": added}
    )[0].reason


PNPM = """\
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react:
        specifier: ^18.2.0
        version: 18.2.0

packages:

  react@18.2.0:
    resolution: {integrity: sha512-a}

  '@types/react@18.2.0':
    resolution: {integrity: sha512-b}

snapshots:

  react@18.2.0: {}
"""


def test_pnpm_lock_packages_only():
    importer_only = PNPM.replace("specifier: ^18.2.0", "specifier: ^18.2.1")
    assert _changes({"pnpm-lock.yaml": PNPM}, {"pnpm-lock.yaml": importer_only}) == []
    bumped = PNPM.replace("'@types/react@18.2.0'", "'@types/react@18.3.0'")
    assert "@types/react 18.2.0 -> 18.3.0" in _changes(
        {"pnpm-lock.yaml": PNPM}, {"pnpm-lock.yaml": bumped}
    )[0].reason


def test_bun_text_lock():
    lock = dedent(
        """\
        {
          "lockfileVersion": 1,
          "workspaces": {
            "": {"name": "web"},
          },
          "packages": {
            "react": ["react@18.2.0", "", {}, "sha512-a"],
            "ui": ["ui@workspace:packages/ui"],
          }
        }
        """
    )
    bumped = lock.replace("react@18.2.0", "react@18.3.0")
    assert "react 18.2.0 -> 18.3.0" in _changes({"bun.lock": lock}, {"bun.lock": bumped})[0].reason


def test_opaque_lockfile_change_counts():
    changes = _changes({"bun.lockb": "a"}, {"bun.lockb": "b"})
    assert changes[0].reason == (
        "lockfile bun.lockb changed (this format is not compared entry by entry)"
    )


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_requirements_lines_options_and_continuations():
    base = "requests==2.31.0 \\\n    --hash=sha256:aaa\n-e .\n# comment\n"
    head = (
        "requests==2.31.0 \\\n    --hash=sha256:aaa\n-e .\n# changed comment\n"
        "-e ./plugins/local\n"
    )
    assert _changes({"requirements.txt": base}, {"requirements.txt": head}) == []
    head = base + "--extra-index-url https://pkgs.example.com/simple\nhttpx[http2]>=0.27\n"
    reason = _changes({"requirements.txt": base}, {"requirements.txt": head})[0].reason
    assert reason == (
        "adds or changes 2 dependencies: httpx ([http2]>=0.27); "
        "--extra-index-url https://pkgs.example.com/simple"
    )


PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests>=2.31"]

[project.optional-dependencies]
test = ["pytest>=8", "demo[extra]"]

[build-system]
requires = ["hatchling"]

[tool.uv.sources]
shared = { path = "../shared" }

[tool.poetry.dependencies]
python = "^3.10"
rich = "^13.0"
"""


def test_pyproject_sections_and_what_is_not_a_change():
    unchanged = PYPROJECT.replace('"0.1.0"', '"0.2.0"').replace(
        'python = "^3.10"', 'python = "^3.11"'
    ).replace('"../shared"', '"../shared2"')
    assert _changes({"pyproject.toml": PYPROJECT}, {"pyproject.toml": unchanged}) == []
    head = (
        PYPROJECT.replace('"hatchling"', '"hatchling>=1.25"')
        .replace('rich = "^13.0"', 'rich = "^13.7"')
        .replace('"pytest>=8"', '"pytest>=8", "hypothesis"')
    )
    reason = _changes({"pyproject.toml": PYPROJECT}, {"pyproject.toml": head})[0].reason
    assert reason == (
        "adds or changes 3 dependencies: hatchling  -> >=1.25; hypothesis; "
        "rich ^13.0 -> ^13.7"
    )


def test_a_change_shows_the_value_that_file_had():
    a = '[build-system]\nrequires = ["flit-core>=3.11,<4.0"]\n'
    b = '[build-system]\nrequires = ["flit-core>=3.9,<4.0"]\n'
    changes = _changes(
        {"a/pyproject.toml": a, "b/pyproject.toml": b},
        {
            "a/pyproject.toml": a.replace("<4.0", "<5.0"),
            "b/pyproject.toml": b.replace("<4.0", "<5.0"),
        },
    )
    assert _reasons(changes) == {
        "a/pyproject.toml": "adds or changes 1 dependency: flit-core >=3.11,<4.0 -> >=3.11,<5.0",
        "b/pyproject.toml": "adds or changes 1 dependency: flit-core >=3.9,<4.0 -> >=3.9,<5.0",
    }


def test_moving_requirements_from_setup_py_to_pyproject_is_not_a_change():
    setup = 'from setuptools import setup\nsetup(name="demo", install_requires=["requests>=2.31", "click"])\n'
    pyproject = '[project]\nname = "demo"\ndependencies = ["requests>=2.31", "click"]\n'
    assert _changes(
        {"setup.py": setup}, {"pyproject.toml": pyproject}
    ) == []
    added = pyproject.replace('"click"', '"click", "rich"')
    assert "rich" in _changes({"setup.py": setup}, {"pyproject.toml": added})[0].reason


def test_setup_cfg_and_dynamic_setup_py():
    base = "[options]\ninstall_requires =\n    requests\n"
    head = base + "    rich>=13\n"
    assert "rich (>=13)" in _changes({"setup.cfg": base}, {"setup.cfg": head})[0].reason
    dynamic = "from setuptools import setup\nsetup(install_requires=open('r.txt').read().split())\n"
    assert _changes({"setup.py": dynamic}, {"setup.py": dynamic + "# note\n"}) == []


def test_python_locks_skip_the_project_itself():
    uv = '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = {{ editable = "." }}\n\n[[package]]\nname = "idna"\nversion = "{v}"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
    own = uv.replace('"0.1.0"', '"0.2.0"')
    assert _changes({"uv.lock": uv.format(v="3.7")}, {"uv.lock": own.format(v="3.7")}) == []
    assert "idna 3.7 -> 3.8" in _changes(
        {"uv.lock": uv.format(v="3.7")}, {"uv.lock": uv.format(v="3.8")}
    )[0].reason
    poetry = '[[package]]\nname = "idna"\nversion = "3.7"\n\n[[package]]\nname = "local"\nversion = "1"\n[package.source]\ntype = "directory"\nurl = "../local"\n'
    assert _changes({"poetry.lock": poetry}, {"poetry.lock": poetry.replace('version = "1"', 'version = "2"')}) == []


def test_pipfile_and_pipfile_lock():
    pipfile = '[packages]\nrequests = "*"\nlocal = {path = "."}\n'
    assert "flask" in _changes(
        {"Pipfile": pipfile}, {"Pipfile": pipfile + 'flask = "==3.0"\n'}
    )[0].reason
    lock = {"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}
    bumped = {"default": {"requests": {"version": "==2.32.0"}}, "develop": {}}
    assert "requests 2.31.0 -> 2.32.0" in _changes(
        {"Pipfile.lock": json.dumps(lock)}, {"Pipfile.lock": json.dumps(bumped)}
    )[0].reason


# ---------------------------------------------------------------------------
# Go, Rust, PHP, Ruby, JVM, Dart, .NET
# ---------------------------------------------------------------------------

GO_MOD = """\
module github.com/acme/app

go 1.22

require (
\tgithub.com/acme/app/sdk v0.1.0
\tgolang.org/x/net v0.20.0 // indirect
)

replace github.com/acme/app/sdk => ./sdk
"""


def test_go_mod_and_go_sum():
    unchanged = GO_MOD.replace("go 1.22", "go 1.23").replace("v0.1.0", "v0.2.0")
    sdk = {"sdk/go.mod": "module github.com/acme/app/sdk\n"}
    assert _changes({"go.mod": GO_MOD}, {"go.mod": unchanged}, also_at_head=sdk) == []
    head = GO_MOD.replace("v0.20.0", "v0.23.0").replace(
        ")\n", "\tgithub.com/google/uuid v1.6.0\n)\n", 1
    )
    reason = _changes({"go.mod": GO_MOD}, {"go.mod": head}, also_at_head=sdk)[0].reason
    assert reason == (
        "adds or changes 2 dependencies: github.com/google/uuid (v1.6.0); "
        "golang.org/x/net v0.20.0 -> v0.23.0"
    )
    total = "golang.org/x/net v0.20.0 h1:a=\ngolang.org/x/net v0.20.0/go.mod h1:b=\n"
    assert _changes({"go.sum": total}, {"go.sum": total}) == []
    assert _changes({"go.sum": total}, {"go.sum": total + "github.com/google/uuid v1.6.0 h1:c=\n"})


def test_cargo_manifest_and_lock():
    cargo = '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1"\ncore = { path = "../core", version = "0.1" }\n'
    head = cargo.replace('version = "0.1.0"', 'version = "0.2.0"').replace(
        'version = "0.1" }', 'version = "0.2" }'
    )
    assert _changes({"Cargo.toml": cargo}, {"Cargo.toml": head}) == []
    head = cargo.replace('serde = "1"', 'serde = "1"\ntokio = { version = "1", features = ["full"] }')
    assert "tokio" in _changes({"Cargo.toml": cargo}, {"Cargo.toml": head})[0].reason
    lock = '[[package]]\nname = "app"\nversion = "{own}"\n\n[[package]]\nname = "serde"\nversion = "{serde}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "abc"\n'
    assert _changes(
        {"Cargo.lock": lock.format(own="0.1.0", serde="1.0.200")},
        {"Cargo.lock": lock.format(own="0.2.0", serde="1.0.200")},
    ) == []
    assert "serde 1.0.200 -> 1.0.201" in _changes(
        {"Cargo.lock": lock.format(own="0.1.0", serde="1.0.200")},
        {"Cargo.lock": lock.format(own="0.1.0", serde="1.0.201")},
    )[0].reason


def test_composer_gemfile_and_their_locks():
    composer = '{"name": "acme/app", "require": {"php": ">=8.1", "monolog/monolog": "^3.0"}}'
    php_only = composer.replace(">=8.1", ">=8.2")
    assert _changes({"composer.json": composer}, {"composer.json": php_only}) == []
    assert _changes(
        {"composer.json": composer}, {"composer.json": composer.replace("^3.0", "^3.5")}
    )
    gemfile = "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem 'local', path: '../local'\n"
    assert _changes({"Gemfile": gemfile}, {"Gemfile": gemfile + "gem 'pry', group: :development\n"})
    lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      actionpack (= 7.1.0)\n\nPATH\n  remote: ../local\n  specs:\n    local (0.1.0)\n"
    assert _changes({"Gemfile.lock": lock}, {"Gemfile.lock": lock.replace("local (0.1.0)", "local (0.2.0)")}) == []
    assert "rails 7.1.0 -> 7.1.1" in _changes(
        {"Gemfile.lock": lock}, {"Gemfile.lock": lock.replace("rails (7.1.0)", "rails (7.1.1)")}
    )[0].reason


POM = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.acme</groupId>
    <artifactId>acme-parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>service</artifactId>
  <properties>
    <jackson.version>2.17.0</jackson.version>
    <java.release>21</java.release>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>
</project>
"""


def test_maven_pom_internal_parent_and_properties():
    parent = {"pom.xml": "<project><groupId>com.acme</groupId><artifactId>acme-parent</artifactId></project>"}
    release = POM.replace("<version>1.0.0</version>", "<version>1.1.0</version>").replace(
        "<java.release>21", "<java.release>22"
    )
    assert _changes({"service/pom.xml": POM}, {"service/pom.xml": release}, also_at_head=parent) == []
    bumped = POM.replace("2.17.0", "2.17.1")
    reason = _changes({"service/pom.xml": POM}, {"service/pom.xml": bumped}, also_at_head=parent)[0]
    assert "jackson.version 2.17.0 -> 2.17.1" in reason.reason and reason.line == 9
    unsafe = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>' + POM
    assert "could not be compared" in _changes(
        {"service/pom.xml": POM}, {"service/pom.xml": unsafe}
    )[0].reason


def test_gradle_catalog_and_lockfile():
    gradle = 'dependencies {\n    implementation("com.squareup.okhttp3:okhttp:4.12.0")\n    implementation(project(":core"))\n}\n'
    assert "okhttp 4.12.0 -> 5.0.0" in _changes(
        {"build.gradle.kts": gradle}, {"build.gradle.kts": gradle.replace("4.12.0", "5.0.0")}
    )[0].reason
    catalog = '[versions]\nokhttp = "4.12.0"\n\n[libraries]\nokhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }\n'
    assert "versions.okhttp" in _changes(
        {"gradle/libs.versions.toml": catalog},
        {"gradle/libs.versions.toml": catalog.replace('"4.12.0"', '"5.0.0"')},
    )[0].reason
    lock = "com.squareup.okhttp3:okhttp:4.12.0=runtimeClasspath\nempty=\n"
    assert _changes({"gradle.lockfile": lock}, {"gradle.lockfile": lock.replace("4.12.0", "5.0.0")})


def test_pubspec_csproj_and_nuget_lock():
    pubspec = "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.2.0\n  local:\n    path: ../local\n"
    assert _changes({"pubspec.yaml": pubspec}, {"pubspec.yaml": pubspec.replace("path: ../local", "path: ../local2")}) == []
    assert "http ^1.2.0 -> ^1.3.0" in _changes(
        {"pubspec.yaml": pubspec}, {"pubspec.yaml": pubspec.replace("^1.2.0", "^1.3.0")}
    )[0].reason
    csproj = '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Serilog" Version="3.1.1" /><ProjectReference Include="../Core/Core.csproj" /></ItemGroup></Project>'
    assert "serilog 3.1.1 -> 4.0.0" in _changes(
        {"App.csproj": csproj}, {"App.csproj": csproj.replace("3.1.1", "4.0.0")}
    )[0].reason
    lock = {"version": 1, "dependencies": {"net8.0": {"Serilog": {"type": "Direct", "resolved": "3.1.1", "contentHash": "x"}, "Core": {"type": "Project"}}}}
    assert _changes({"packages.lock.json": json.dumps(lock)}, {"packages.lock.json": json.dumps(lock)}) == []


# ---------------------------------------------------------------------------
# removed, replaced and unreadable files
# ---------------------------------------------------------------------------


def test_removed_lockfile_with_its_project_still_there_counts():
    lock = json.dumps({"lockfileVersion": 3, "packages": {}})
    changes = _changes(
        {"package-lock.json": lock, "package.json": _pkg()},
        {"package.json": _pkg()},
    )
    assert _reasons(changes) == {
        "package-lock.json": "removes lockfile package-lock.json while its project "
        "stays: installs are no longer pinned to it"
    }


def test_removed_package_with_its_lockfile_is_not_a_change():
    lock = json.dumps({"lockfileVersion": 3, "packages": {}})
    assert _changes(
        {"tools/x/package-lock.json": lock, "tools/x/package.json": _pkg()}, {}
    ) == []


def test_lockfile_swapped_for_another_package_manager_is_compared():
    npm = json.dumps(
        {"lockfileVersion": 3, "packages": {"node_modules/debug": {"version": "4.3.4", "integrity": "sha512-def"}}}
    )
    yarn = 'debug@^4.1.0:\n  version "4.3.4"\n  integrity sha512-def\n'
    assert _changes({"package-lock.json": npm}, {"yarn.lock": yarn}) == []


def test_unreadable_or_invalid_manifests_are_reported_not_skipped():
    changes = _changes({"package.json": _pkg()}, {"package.json": "{ not json"})
    assert changes[0].reason.startswith(
        "package.json changed but could not be compared (could not parse it"
    )
    unreadable = dependency_changes(
        [Changed("Cargo.toml", "modified", "Cargo.toml")],
        base_text=lambda p: "[dependencies]\n",
        head_text=lambda p: None,
    )
    assert "not readable as UTF-8 text" in unreadable[0].reason
