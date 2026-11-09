"""ca9-backed supply-chain findings and the dependency inventory / posture
upload blocks.

ca9.api is replaced by a local fake that follows the API v1 contract and is
deliberately looser than the real engine (it flags every Git and URL entry and
every registry entry without integrity), so the tests prove Skylos only
reports what its own inventory supports.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path
from types import SimpleNamespace

import pytest

import skylos.rules.sca.vulnerability_scanner as sca
from skylos import api
from skylos.rules.sca import supply_chain
from skylos.rules.sca.posture import (
    dependency_inventory_summary,
    supply_chain_posture,
)
from skylos.supply_chain.policy import SupplyChainPolicy

REAL_LOAD_CA9_API = supply_chain.load_ca9_api
SHA = "0123456789abcdef0123456789abcdef01234567"
NON_HEX_40 = "mainmainmainmainmainmainmainmainmainmain"
HASH = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"
POLICY = SupplyChainPolicy(
    internal_packages=("acme-*",),
    private_registries=("https://pypi.acme.example/simple",),
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text, encoding="utf-8"
    )
    return path


class FakeCa9:
    """API v1 shape; looser than ca9 so Skylos's own checks are exercised."""

    API_VERSION = 1

    class FeedUnavailable(RuntimeError):
        pass

    def __init__(self, *, feed=None, raise_on_evaluate=False):
        self.calls = []
        self.feed = feed
        self.raise_on_evaluate = raise_on_evaluate
        self.feed_calls = 0

    def evaluate_packages(self, packages, *, options):
        packages = list(packages)
        self.calls.append((packages, options))
        if self.raise_on_evaluate:
            raise RuntimeError("engine broke")
        findings = []
        for package in packages:
            base = {
                "ecosystem": package["ecosystem"],
                "name": package["name"],
                "version": package["version"],
                "file": package["file"],
                "line": package["line"],
                "severity": "MEDIUM",
                "action": "warn",
                "evidence": {},
            }
            kind = package["source_kind"]
            if kind == "git":
                findings.append({**base, "signal_type": "git_dependency"})
            if kind == "url":
                findings.append({**base, "signal_type": "direct_url_dependency"})
            if kind == "registry" and not package["integrity"]:
                findings.append({**base, "signal_type": "missing_integrity"})
            if kind == "registry":
                findings.append(
                    {
                        **base,
                        "signal_type": "new_package_version",
                        "evidence": {"age_hours": 2},
                    }
                )
            internal = any(
                fnmatch(package["name"], pattern)
                for pattern in options["internal_packages"]
            )
            if (
                kind == "registry"
                and internal
                and package["registry_mode"] != "exclusive"
            ):
                findings.append(
                    {
                        **base,
                        "signal_type": "dependency_confusion",
                        "evidence": {"internal_pattern": "acme-*"},
                    }
                )
        return {
            "findings": findings,
            "receipt": {"checked": len(packages), "complete": True},
        }

    def malware_matches(self, packages, *, feed_dir=None):
        self.feed_calls += 1
        if self.feed is None:
            raise self.FeedUnavailable("no feed")
        return [
            {
                "signal_type": "malware",
                "ecosystem": package["ecosystem"],
                "name": package["name"],
                "version": package["version"],
                "file": package["file"],
                "line": package["line"],
                "evidence": {"malware_id": self.feed[package["name"]]},
            }
            for package in packages
            if package["name"] in self.feed
        ]


@pytest.fixture
def offline_osv(monkeypatch):
    """OSV answers with no advisories unless a test replaces it."""
    state = {"complete": True}

    def query(deps, cache):
        return sca.OsvQueryResult(
            [], receipt={"status": "complete", "complete": state["complete"]}
        )

    monkeypatch.setattr(sca, "_query_osv_batch", query)
    return state


NO_POLICY = SupplyChainPolicy()


def _scan(tmp_path, monkeypatch, fake, policy=NO_POLICY):
    monkeypatch.setattr(supply_chain, "load_ca9_api", lambda: fake)
    monkeypatch.setattr(
        "skylos.supply_chain.policy.load_supply_chain_policy", lambda root: policy
    )
    result = sca.scan_dependencies(tmp_path)
    return result, [(row["rule_id"], row["symbol"]) for row in result]


def test_mutable_git_and_url_sources_report_src003(tmp_path, monkeypatch, offline_osv):
    _write(
        tmp_path / "requirements.txt",
        "git+https://github.com/someone/utilx@main#egg=utilx\n"
        "https://files.example/payload-1.0.tar.gz\n"
        f"git+https://github.com/someone/pinned@{SHA}#egg=pinned\n"
        f"https://files.example/hashed-1.0.tar.gz#{HASH.replace(':', '=')}\n"
        f"hashed2 @ https://files.example/hashed2-2.0.tar.gz --hash={HASH}\n"
        f"nonhex @ git+https://github.com/someone/nonhex@{NON_HEX_40}\n"
        "./vendor/local-1.0.tar.gz\n"
        "requests==2.32.3\n",
    )
    _result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert sorted(rows) == [
        ("SKY-SCA-SRC003", "nonhex"),
        ("SKY-SCA-SRC003", "payload@1.0"),
        ("SKY-SCA-SRC003", "utilx"),
    ]


def test_package_json_git_and_tarball_specs_without_a_lockfile(
    tmp_path, monkeypatch, offline_osv
):
    dependencies = {
        "pinned": f"https://github.com/acme/pinned.git#{SHA}",
        "branch": "https://github.com/acme/branch.git#main",
        "short": "acme/short",
        "tarball": "https://files.example/tarball-1.0.0.tgz",
        "registry": "1.0.0",
    }
    _write(tmp_path / "package.json", json.dumps({"dependencies": dependencies}))
    _result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert sorted(rows) == [
        ("SKY-SCA-SRC003", "branch"),
        ("SKY-SCA-SRC003", "short"),
        ("SKY-SCA-SRC003", "tarball"),
    ]


def test_mutable_source_reports_never_carry_url_credentials(
    tmp_path, monkeypatch, offline_osv
):
    _write(
        tmp_path / "requirements.txt",
        "git+https://x-access-token:ghp_secret@github.com/acme/tool@main#egg=tool\n",
    )
    result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert rows == [("SKY-SCA-SRC003", "tool")]
    assert "ghp_secret" not in json.dumps(list(result))


def _npm_lock(tmp_path, entry):
    _write(
        tmp_path / "package-lock.json",
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "dependencies": {"ansi-styles": "6.2.1"}},
                    "node_modules/ansi-styles": {
                        "version": "6.2.1",
                        "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-6.2.1.tgz",
                        **entry,
                    },
                },
            }
        ),
    )


@pytest.mark.parametrize(
    "entry,expected",
    [
        ({}, [("SKY-SCA-INT001", "ansi-styles@6.2.1")]),
        ({"integrity": ""}, [("SKY-SCA-INT001", "ansi-styles@6.2.1")]),
        ({"integrity": "sha512-" + "A" * 86 + "=="}, []),
        ({"inBundle": True}, []),
    ],
)
def test_lockfile_registry_entry_without_integrity_reports_int001(
    tmp_path, monkeypatch, offline_osv, entry, expected
):
    _npm_lock(tmp_path, entry)
    _result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert rows == expected


def test_requirements_without_hash_never_report_int001(
    tmp_path, monkeypatch, offline_osv
):
    _write(tmp_path / "requirements.txt", "requests==2.32.3\n")
    _result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert rows == []


@pytest.mark.parametrize(
    "requirements,policy,expected",
    [
        (
            "--extra-index-url https://pypi.acme.example/simple\nacme-billing==2.0.0\nrequests==2.32.3\n",
            POLICY,
            [("SKY-SCA-SRC001", "acme-billing@2.0.0")],
        ),
        (
            "--extra-index-url https://pypi.acme.example/simple\nAcme_Billing==2.0.0\n",
            POLICY,
            [("SKY-SCA-SRC001", "acme-billing@2.0.0")],
        ),
        (
            "--index-url https://pypi.acme.example/simple\nacme-billing==2.0.0\n",
            POLICY,
            [],
        ),
        (
            "--extra-index-url https://pypi.acme.example/simple\nacme-billing==2.0.0\n",
            SupplyChainPolicy(),
            [],
        ),
        ("acme-billing==2.0.0\n", POLICY, []),
    ],
)
def test_dependency_confusion_needs_internal_patterns_and_registry_evidence(
    tmp_path, monkeypatch, offline_osv, requirements, policy, expected
):
    _write(tmp_path / "requirements.txt", requirements)
    result, rows = _scan(tmp_path, monkeypatch, FakeCa9(), policy)
    assert rows == expected
    for row in result:
        assert row["severity"] == "CRITICAL"


def test_release_age_is_reported_only_when_the_policy_sets_a_window(
    tmp_path, monkeypatch, offline_osv
):
    _write(tmp_path / "requirements.txt", f"requests==2.32.3 --hash={HASH}\n")
    _result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert rows == []
    fake = FakeCa9()
    _result, rows = _scan(
        tmp_path, monkeypatch, fake, SupplyChainPolicy(min_release_age_hours=24)
    )
    assert rows == [("SKY-SCA-AGE001", "requests@2.32.3")]
    assert fake.calls[0][1]["min_release_age_hours"] == 24


@pytest.mark.parametrize(
    "engine,note",
    [
        (None, supply_chain.NOTE_API_UNAVAILABLE),
        (FakeCa9(raise_on_evaluate=True), supply_chain.NOTE_API_FAILED),
    ],
)
def test_missing_or_broken_ca9_is_a_receipt_note(
    tmp_path, monkeypatch, offline_osv, engine, note
):
    _write(tmp_path / "requirements.txt", "git+https://github.com/a/b@main#egg=b\n")
    result, rows = _scan(tmp_path, monkeypatch, engine)
    assert rows == []
    assert note in result.receipt["supply_chain"]["notes"]


@pytest.mark.parametrize(
    "version,usable", [(0, False), ("1", False), (1, True), (2, True)]
)
def test_ca9_api_is_used_only_from_api_version_1(monkeypatch, version, usable):
    import ca9

    engine = SimpleNamespace(API_VERSION=version)
    monkeypatch.setattr(ca9, "api", engine, raising=False)
    monkeypatch.setitem(sys.modules, "ca9.api", engine)
    assert (REAL_LOAD_CA9_API() is engine) is usable


def test_incomplete_osv_falls_back_to_the_ca9_feed(tmp_path, monkeypatch, offline_osv):
    _npm_lock(tmp_path, {"integrity": "sha512-" + "A" * 86 + "==", "dev": True})
    offline_osv["complete"] = False
    fake = FakeCa9(feed={"ansi-styles": "MAL-2099-1"})
    result, rows = _scan(tmp_path, monkeypatch, fake)
    assert rows == [("SKY-SCA-MAL-2099-1", "ansi-styles@6.2.1")]
    finding = result[0]
    assert finding["severity"] == "CRITICAL"
    assert finding["metadata"]["malware_source"] == "ca9_feed"
    assert "low_risk_context" not in finding
    receipt = result.receipt["supply_chain"]
    assert receipt["malware_sources"] == ["osv", "ca9_feed"]
    assert result.receipt["complete"] is False

    offline_osv["complete"] = True
    fake = FakeCa9(feed={"ansi-styles": "MAL-2099-1"})
    _result, rows = _scan(tmp_path, monkeypatch, fake)
    assert rows == []
    assert fake.feed_calls == 0


def test_incomplete_osv_without_a_feed_says_so(tmp_path, monkeypatch, offline_osv):
    _npm_lock(tmp_path, {"integrity": "sha512-" + "A" * 86 + "=="})
    offline_osv["complete"] = False
    result, rows = _scan(tmp_path, monkeypatch, FakeCa9())
    assert rows == []
    receipt = result.receipt["supply_chain"]
    assert supply_chain.NOTE_FEED_UNAVAILABLE in receipt["notes"]
    assert receipt["malware_sources"] == ["osv"]


def test_inventory_is_sorted_deduplicated_and_capped(tmp_path, monkeypatch):
    _write(tmp_path / "requirements.txt", "zeta==1.0\nAlpha_Pkg==2.0\nalpha-pkg==2.0\n")
    inventory = sca.collect_dependencies(tmp_path)
    summary = dependency_inventory_summary(inventory, tmp_path)
    assert summary["schema"] == "skylos.dependency_inventory.v1"
    assert [row["name"] for row in summary["packages"]] == ["alpha-pkg", "zeta"]
    assert summary["packages"][0] == {
        "ecosystem": "pypi",
        "name": "alpha-pkg",
        "version": "2.0",
        "direct": True,
        "dev": False,
        "file": "requirements.txt",
    }
    assert (summary["total"], summary["truncated"], summary["complete"]) == (
        2,
        False,
        True,
    )
    monkeypatch.setattr("skylos.rules.sca.posture.MAX_INVENTORY_PACKAGES", 1)
    capped = dependency_inventory_summary(inventory, tmp_path)
    assert (capped["total"], capped["truncated"], capped["complete"]) == (
        2,
        True,
        False,
    )
    assert [row["name"] for row in capped["packages"]] == ["alpha-pkg"]


def _git(root: Path, *args):
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        },
    )


def _npm_repo(root: Path, *, workflow: str, npmrc: str):
    _write(
        root / "package.json",
        json.dumps({"name": "app", "dependencies": {"ansi-styles": "6.2.1"}}),
    )
    _npm_lock(root, {"integrity": "sha512-" + "A" * 86 + "=="})
    _write(root / ".npmrc", npmrc)
    _write(root / ".github" / "workflows" / "ci.yml", workflow)


def _statuses(posture):
    return {check["id"]: check["status"] for check in posture["checks"]}


PINNED_WORKFLOW = f"""name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
        with:
          persist-credentials: false
      - uses: some-org/setup-thing@{SHA}
      - run: npm ci --ignore-scripts
"""
LOOSE_WORKFLOW = """name: ci
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/setup-thing@v1
      - run: npm install
      - run: npm test
        env:
          TOKEN: ${{ secrets.NPM_TOKEN }}
"""


def test_posture_passes_only_with_evidence(tmp_path):
    _npm_repo(tmp_path, workflow=PINNED_WORKFLOW, npmrc="min-release-age=3\n")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    posture = supply_chain_posture(tmp_path, sca.collect_dependencies(tmp_path))
    assert posture["schema"] == "skylos.supply_chain_posture.v1"
    assert posture["ecosystems"] == ["npm"]
    assert _statuses(posture) == {
        "lockfile_committed": "pass",
        "frozen_install_ci": "pass",
        "install_scripts_disabled": "pass",
        "release_age_cooldown": "pass",
        "actions_pinned": "pass",
        "no_pr_target_checkout": "pass",
    }


def test_posture_fails_loose_installs_and_unknown_outside_git(tmp_path):
    _npm_repo(tmp_path, workflow=LOOSE_WORKFLOW, npmrc="")
    posture = supply_chain_posture(tmp_path, sca.collect_dependencies(tmp_path))
    assert _statuses(posture) == {
        "lockfile_committed": "unknown",
        "frozen_install_ci": "fail",
        "install_scripts_disabled": "fail",
        "release_age_cooldown": "fail",
        "actions_pinned": "fail",
        "no_pr_target_checkout": "fail",
    }


def test_posture_reads_only_the_repository_own_workflows_and_files(tmp_path):
    _npm_repo(tmp_path, workflow=PINNED_WORKFLOW, npmrc="min-release-age=3\n")
    _write(tmp_path / ".github" / "workflows" / "examples" / "demo.yml", LOOSE_WORKFLOW)
    _write(
        tmp_path / "vendor" / "checkout" / "package.json",
        json.dumps({"dependencies": {"x": "1.0.0"}}),
    )
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "package.json", "package-lock.json", ".npmrc", ".github")
    statuses = _statuses(
        supply_chain_posture(tmp_path, sca.collect_dependencies(tmp_path))
    )
    assert statuses["actions_pinned"] == "pass"
    assert statuses["no_pr_target_checkout"] == "pass"
    assert statuses["lockfile_committed"] == "pass"


def test_untracked_lockfile_is_not_committed(tmp_path):
    _npm_repo(tmp_path, workflow=PINNED_WORKFLOW, npmrc="")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "package.json", ".npmrc", ".github")
    posture = supply_chain_posture(tmp_path, sca.collect_dependencies(tmp_path))
    assert _statuses(posture)["lockfile_committed"] == "fail"


def test_upload_carries_inventory_and_posture_next_to_sca_coverage(monkeypatch):
    inventory = {
        "schema": "skylos.dependency_inventory.v1",
        "complete": True,
        "truncated": False,
        "total": 1,
        "packages": [
            {
                "ecosystem": "npm",
                "name": "chalk",
                "version": "5.3.0",
                "direct": True,
                "dev": False,
                "file": "package-lock.json",
            }
        ],
    }
    posture = {
        "schema": "skylos.supply_chain_posture.v1",
        "ecosystems": ["npm"],
        "checks": [
            {
                "id": "release_age_cooldown",
                "status": "fail",
                "detail": "no min-release-age in .npmrc",
                "paths": [".npmrc"],
            }
        ],
    }
    result = {
        "analysis_summary": {
            "sca_coverage": {"status": "complete", "complete": True},
            "dependency_inventory": inventory,
            "supply_chain_posture": posture,
        },
        "analysis_errors": [],
        "dependency_vulnerabilities": [],
    }
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    prepared = api._prepare_report_upload(copy.deepcopy(result), analyzer_owned=True)
    run_summary = prepared.core_payload["runs"][0]["properties"]["summary"]
    for summary in (run_summary, prepared.compatibility_payload["summary"]):
        assert summary["dependency_inventory"] == inventory
        assert summary["supply_chain_posture"] == posture
        assert summary["sca_coverage"]["complete"] is True
    assert (
        prepared.legacy_payload["runs"][0]["properties"]["summary"][
            "dependency_inventory"
        ]
        == inventory
    )
    assert "dependency_inventory" not in prepared.scan_summary
    assert prepared.scan_summary["supply_chain_posture"] == posture


def _real_ca9_api():
    try:
        from ca9 import api as engine
    except ImportError:
        return None
    if getattr(engine, "API_VERSION", 0) < 1:
        return None
    return engine


@pytest.mark.skipif(_real_ca9_api() is None, reason="ca9.api (API v1) is not installed")
def test_real_ca9_engine_reports_only_mutable_sources(
    tmp_path, monkeypatch, offline_osv
):
    _write(
        tmp_path / "requirements.txt",
        "git+https://github.com/someone/utilx@main#egg=utilx\n"
        "https://files.example/payload-1.0.tar.gz\n"
        f"git+https://github.com/someone/pinned@{SHA}#egg=pinned\n"
        f"hashed2 @ https://files.example/hashed2-2.0.tar.gz --hash={HASH}\n"
        "--extra-index-url https://pypi.acme.example/simple\n"
        "acme-billing==2.0.0\n",
    )
    _result, rows = _scan(tmp_path, monkeypatch, _real_ca9_api(), POLICY)
    assert sorted(rows) == [
        ("SKY-SCA-SRC001", "acme-billing@2.0.0"),
        ("SKY-SCA-SRC003", "payload@1.0"),
        ("SKY-SCA-SRC003", "utilx"),
    ]


def test_fixture_manifests_do_not_decide_the_lockfile_posture(tmp_path):
    for folder in ("test/fixtures/app", "benchmarks/case", "examples/demo"):
        _write(
            tmp_path / folder / "package.json",
            json.dumps({"dependencies": {"left-pad": "1.3.0"}}),
        )
    _write(tmp_path / ".github" / "workflows" / "ci.yml", PINNED_WORKFLOW)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    only_fixtures = supply_chain_posture(tmp_path, sca.collect_dependencies(tmp_path))
    assert _statuses(only_fixtures)["lockfile_committed"] == "not_applicable"

    _write(
        tmp_path / "apps" / "test-runner" / "package.json",
        json.dumps({"dependencies": {"left-pad": "1.3.0"}}),
    )
    _git(tmp_path, "add", "-A")
    posture = supply_chain_posture(tmp_path, sca.collect_dependencies(tmp_path))
    check = next(item for item in posture["checks"] if item["id"] == "lockfile_committed")
    assert check["status"] == "fail"
    assert check["paths"] == ["apps/test-runner/package.json"]
