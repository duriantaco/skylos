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

from skylos.commands import hook_supply_chain
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
    spec = json.loads(text)["hookSpecificOutput"]
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
    assert "published 2 hours ago" in reason and "wait 24 hours" in reason
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
    assert decision == "deny" and "wait 24 hours" in reason
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
    monkeypatch.setattr(hook_supply_chain, "MAX_LOCKED_PACKAGES", 2)
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
