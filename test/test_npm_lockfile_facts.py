"""Binary names and peer hosts read from lockfiles (no node_modules)."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality import npm_dependencies as npm
from skylos.rules.quality.npm_lockfiles import lockfile_facts


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _scan(root, *files, **kwargs):
    receipt = {}
    findings = npm.scan_npm_dependencies(root, files, coverage=receipt, **kwargs)
    return findings, receipt


def _names(findings, rule):
    return {item["name"] for item in findings if item["rule_id"] == rule}


_PACKAGE_LOCK = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app"},
        "node_modules/@angular/compiler-cli": {
            "version": "20.0.0",
            "bin": {"ngc": "bundles/src/bin/ngc.js", "ng-xi18n": "bundles/src/bin/ng_xi18n.js"},
            "peerDependencies": {"@angular/compiler": "20.0.0", "typescript": ">=5.8"},
        },
        "node_modules/single-bin": {"version": "1.0.0", "bin": "cli.js"},
    },
}


def test_package_lock_bins_and_peers(tmp_path):
    _write(tmp_path / "package-lock.json", json.dumps(_PACKAGE_LOCK))
    facts = lockfile_facts(tmp_path)
    assert facts.providers("ngc") == {"@angular/compiler-cli"}
    assert facts.providers("single-bin") == {"single-bin"}
    assert facts.peers["@angular/compiler-cli"] == {"@angular/compiler", "typescript"}


def test_pnpm_lock_peers_only(tmp_path):
    _write(
        tmp_path / "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies: {}\n\n"
        "packages:\n\n"
        "  '@vitejs/plugin-vue@5.0.0':\n    resolution: {integrity: sha512-x}\n"
        "    engines: {node: ^18.0.0}\n    peerDependencies:\n      vite: ^5.0.0\n      vue: ^3.2.25\n\n"
        "  vite@5.0.0:\n    resolution: {integrity: sha512-y}\n    hasBin: true\n\n"
        "snapshots:\n\n  vite@5.0.0: {}\n",
    )
    facts = lockfile_facts(tmp_path)
    assert facts.peers["@vitejs/plugin-vue"] == {"vite", "vue"}
    assert facts.bins == {}  # pnpm records hasBin, not the names


def test_yarn_berry_bins_and_peers_and_yarn1_has_none(tmp_path):
    _write(
        tmp_path / "berry/yarn.lock",
        '__metadata:\n  version: 8\n\n'
        '"@angular/compiler-cli@npm:^20.0.0":\n  version: 20.0.0\n'
        "  peerDependencies:\n    typescript: \">=5.8\"\n"
        "  bin:\n    ngc: bundles/src/bin/ngc.js\n  languageName: node\n",
    )
    facts = lockfile_facts(tmp_path / "berry")
    assert facts.providers("ngc") == {"@angular/compiler-cli"}
    assert facts.peers["@angular/compiler-cli"] == {"typescript"}
    _write(tmp_path / "classic/yarn.lock", '# yarn lockfile v1\n\n"foo@^1":\n  version "1.0.0"\n')
    facts = lockfile_facts(tmp_path / "classic")
    assert facts.bins == {} and facts.peers == {}


def test_bun_lock(tmp_path):
    _write(
        tmp_path / "bun.lock",
        '{\n  "lockfileVersion": 1,\n  "packages": {\n'
        '    "@angular/compiler-cli": ["@angular/compiler-cli@20.0.0", "", {"peerDependencies": {"typescript": ">=5.8"}, "bin": {"ngc": "x.js"}}, "sha512-x"],\n'
        "  },\n}\n",
    )
    facts = lockfile_facts(tmp_path)
    assert facts.providers("ngc") == {"@angular/compiler-cli"}


def test_lockfile_bin_maps_a_script_binary_to_its_provider(tmp_path):
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "app", "scripts": {"types": "ngc -p tsconfig.json"}, "devDependencies": {"@angular/compiler-cli": "20"}}),
    )
    without, _ = _scan(tmp_path)
    _write(tmp_path / "package-lock.json", json.dumps(_PACKAGE_LOCK))
    found, _ = _scan(tmp_path)
    # ``ngc`` is already in the static provider table; the lockfile agrees.
    assert _names(found, npm.RULE_BINARY) == set() == _names(without, npm.RULE_BINARY)
    assert "@angular/compiler-cli" not in _names(found, npm.RULE_UNUSED)


def test_lockfile_bin_credits_an_unlisted_provider_name(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {"node_modules/@acme/tools": {"version": "1.0.0", "bin": {"acme-gen": "gen.js"}}}}
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "app", "scripts": {"gen": "acme-gen"}, "devDependencies": {"@acme/tools": "1"}}),
    )
    before, receipt = _scan(tmp_path)
    # Without the lockfile the provider is unknown: held back, not reported.
    assert "@acme/tools" not in _names(before, npm.RULE_UNUSED)
    assert "@acme/tools" in {item["name"] for item in receipt["abstained_dependencies"]}
    _write(tmp_path / "package-lock.json", json.dumps(lock))
    after, receipt = _scan(tmp_path)
    assert "@acme/tools" not in _names(after, npm.RULE_UNUSED)
    assert "@acme/tools" not in {item["name"] for item in receipt["abstained_dependencies"]}
    assert _names(after, npm.RULE_BINARY) == set()


def test_lockfile_peers_credit_a_used_hosts_peer(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {"node_modules/acme-ui": {"version": "1.0.0", "peerDependencies": {"acme-theme": "1"}}}}
    _write(tmp_path / "package.json", json.dumps({"name": "app", "dependencies": {"acme-ui": "1", "acme-theme": "1", "unused-lib": "1"}}))
    source = _write(tmp_path / "src/index.ts", 'import "acme-ui";\n')
    before, _ = _scan(tmp_path, source)
    assert {"acme-theme", "unused-lib"} <= _names(before, npm.RULE_UNUSED)
    _write(tmp_path / "package-lock.json", json.dumps(lock))
    after, _ = _scan(tmp_path, source)
    assert _names(after, npm.RULE_UNUSED) == {"unused-lib"}


def test_lockfile_without_bins_never_adds_findings(tmp_path):
    # A lock entry that lists no bin does not prove the package has none: the
    # unknown-provider hold stays.
    lock = {"lockfileVersion": 3, "packages": {"node_modules/@acme/tools": {"version": "1.0.0"}}}
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "app", "scripts": {"gen": "acme-gen"}, "devDependencies": {"@acme/tools": "1"}}),
    )
    before, _ = _scan(tmp_path)
    _write(tmp_path / "package-lock.json", json.dumps(lock))
    after, _ = _scan(tmp_path)
    assert {(i["rule_id"], i["name"]) for i in after} <= {(i["rule_id"], i["name"]) for i in before}


# Config files listed in the plugin table name the packages a tool loads.


def test_plugin_table_data_configs_credit_the_packages_they_name(tmp_path):
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "app", "devDependencies": {"mocha": "10", "ts-node": "10", "left-over": "1"}, "scripts": {"test": "mocha"}}),
    )
    before, _ = _scan(tmp_path)
    assert {"ts-node", "left-over"} <= _names(before, npm.RULE_UNUSED)
    _write(tmp_path / ".mocharc.yml", "require:\n  - ts-node/register\nspec: test/**/*.spec.ts\n")
    after, _ = _scan(tmp_path)
    assert "ts-node" not in _names(after, npm.RULE_UNUSED)
    assert "left-over" in _names(after, npm.RULE_UNUSED)


def test_word_list_configs_never_credit_packages(tmp_path):
    _write(tmp_path / "package.json", json.dumps({"name": "app", "dependencies": {"lodash": "4"}}))
    _write(tmp_path / ".cspell.json", json.dumps({"words": ["lodash"]}))
    findings, _ = _scan(tmp_path)
    assert "lodash" in _names(findings, npm.RULE_UNUSED)


def test_a_source_module_named_like_a_config_is_not_a_config(tmp_path):
    # ``.config/prisma.ts`` is Prisma's config; ``src/lib/prisma.ts`` is code.
    _write(tmp_path / "package.json", json.dumps({"name": "app", "dependencies": {"left-pad": "1"}}))
    source = _write(tmp_path / "src/lib/prisma.ts", 'export const label = "left-pad";\n')
    findings, _ = _scan(tmp_path, source)
    assert "left-pad" in _names(findings, npm.RULE_UNUSED)
