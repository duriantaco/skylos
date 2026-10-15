"""bun.lock (Bun's text lockfile, versions 0–3) as a supported SCA input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.rules.sca import vulnerability_scanner as scanner
from skylos.rules.sca.bun_lockfile import parse_bun_lock
from skylos.rules.sca.lockfile_types import LockfileLimitError, LockfileParseError

# Shape of Dependabot's simple_v3 fixture (a real Bun 1.4.0 lockfile), plus a
# workspace, a scoped package and a Git dependency.
V3 = """{
  "lockfileVersion": 3,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bun-v3-project",
      "dependencies": {
        "etag": "1.0.1",
        "is-number": "7.0.0",
        "is-odd": "3.0.1",
      },
      "devDependencies": {
        "@types/node": "^20",
      },
    },
    "packages/ui": {
      "name": "@acme/ui",
    },
  },
  "overrides": {
    "is-odd": {
      "is-number": "6.0.0",
    },
  },
  "packages": {
    "@acme/ui": ["@acme/ui@workspace:packages/ui"],

    "@types/node": ["@types/node@20.1.0", "", {}, "sha512-q"],

    "etag": ["etag@1.0.1", "", {}, "sha512-a"],

    "is-number": ["is-number@7.0.0", "", {}, "sha512-b"],

    "is-odd": ["is-odd@3.0.1", "", { "dependencies": { "is-number": "^6.0.0" } }, "sha512-c"],

    "is-odd/is-number": ["is-number@6.0.0", "", {}, "sha512-d"],
  }
}
"""


def _deps(inventory):
    return {(d["name"], d["version"]): d for d in inventory.dependencies}


@pytest.mark.parametrize("version", [0, 1, 2, 3])
def test_every_known_lockfile_version_parses(version):
    text = V3.replace('"lockfileVersion": 3', f'"lockfileVersion": {version}')

    inventory = parse_bun_lock(Path("bun.lock"), text=text)

    assert inventory.format_version == version
    deps = _deps(inventory)
    assert set(deps) == {
        ("@types/node", "20.1.0"),
        ("etag", "1.0.1"),
        ("is-number", "7.0.0"),
        ("is-number", "6.0.0"),
        ("is-odd", "3.0.1"),
    }
    assert deps[("etag", "1.0.1")]["dependency_kind"] == "direct"
    assert deps[("is-number", "6.0.0")]["dependency_kind"] == "transitive"
    assert deps[("is-number", "6.0.0")]["package_path"] == "is-odd/is-number"
    assert deps[("@types/node", "20.1.0")]["dependency_kind"] == "direct"
    assert (
        deps[("etag", "1.0.1")]["line"]
        == V3.splitlines().index('    "etag": ["etag@1.0.1", "", {}, "sha512-a"],') + 1
    )
    assert inventory.local_package_count == 1
    assert inventory.workspace_paths == ["packages/ui"]
    assert inventory.not_checked[0]["reason"] == "workspace_package"
    assert inventory.unresolved == []


def test_git_and_private_registry_entries_are_not_queried():
    text = """{
      "lockfileVersion": 1,
      "workspaces": {"": {"name": "x"}},
      "packages": {
        "mylib": ["mylib@github:me/mylib#abc123", {}, "abc123"],
        "internal": ["internal@1.0.0", "https://npm.example.com/", {}, "sha512-x"],
        "tarball": ["tarball@https://example.com/t.tgz", {}],
      },
    }"""

    inventory = parse_bun_lock(Path("bun.lock"), text=text)

    assert inventory.dependencies == []
    assert sorted(i["reason"] for i in inventory.unresolved) == [
        "non_registry_source",
        "non_registry_source",
        "non_registry_source",
    ]
    assert inventory.non_registry_names == ["internal", "mylib", "tarball"]


def test_unknown_lockfile_version_is_a_parse_error():
    with pytest.raises(LockfileParseError):
        parse_bun_lock(Path("bun.lock"), text='{"lockfileVersion": 4, "packages": {}}')


def test_malformed_and_duplicate_keys_are_parse_errors():
    with pytest.raises(LockfileParseError):
        parse_bun_lock(Path("bun.lock"), text='{"lockfileVersion": 1, "packages": [}')
    with pytest.raises(LockfileParseError):
        parse_bun_lock(
            Path("bun.lock"),
            text='{"lockfileVersion": 1, "lockfileVersion": 2, "packages": {}}',
        )


def test_package_limit():
    packages = {f"p{i}": [f"p{i}@1.0.0", "", {}, "x"] for i in range(5)}
    text = json.dumps({"lockfileVersion": 1, "packages": packages})
    with pytest.raises(LockfileLimitError):
        parse_bun_lock(Path("bun.lock"), text=text, max_packages=4)


def test_comma_inside_strings_is_kept():
    text = (
        '{"lockfileVersion": 1, "packages": {"a": ["a@1.0.0", "", {"x": ",]"}, "s"],},}'
    )

    inventory = parse_bun_lock(Path("bun.lock"), text=text)

    assert [d["name"] for d in inventory.dependencies] == ["a"]


def test_scanner_reads_bun_lock(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"etag": "^1.0.0"}}), encoding="utf-8"
    )
    (tmp_path / "bun.lock").write_text(V3, encoding="utf-8")

    inventory = scanner.collect_dependencies(tmp_path)

    receipt = inventory.receipt
    assert receipt["supported_lockfile_count"] == 1
    assert receipt["parse_error_count"] == 0
    locked = {
        (d["name"], d["version"]) for d in inventory if d.get("lockfile_version") == 3
    }
    assert ("is-number", "6.0.0") in locked
    assert receipt["unsupported_lockfile_count"] == 0
