"""A scan fails for a finding or a real gap, not for a private package or a blip."""

import json
import os
import subprocess
import time

import pytest
from ca9.models import ApiUsageHit, Evidence, Verdict, VerdictResult, Vulnerability

from skylos.api import sca_coverage_for_upload
from skylos.cicd.workflow import generate_workflow
from skylos.core.cloud_gate import cloud_ignores_unreachable_dependency
from skylos.core.gate_incomplete import _blocking_sca_reason
from skylos.core.gatekeeper import _sca_required_coverage_reasons, sca_coverage_warnings
from skylos.core.sca_baseline import dependency_scan_complete
from skylos.core.sca_coverage import (
    NON_REGISTRY_COVERAGE_STATUS,
    SAVED_ANSWERS_COVERAGE_STATUS,
)
from skylos.reporting.sca_summary import group_advisories, summary_footer
from skylos.rules.sca import osv_answers
from skylos.rules.sca import supply_chain_diff as diff
from skylos.rules.sca import vulnerability_scanner as sca
from skylos.rules.sca.reachability import reachability_tier

INTEGRITY = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
SHA = "0123456789012345678901234567890123456789"
TARBALL = f"https://codeload.github.com/acme/mylib/tar.gz/{SHA}"
LODASH_ENTRY = {
    "version": "4.17.21",
    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
    "integrity": INTEGRITY,
}


def npm_lock(packages):
    roots = {"": {"name": "p", "version": "1.0.0"}}
    return json.dumps(
        {
            "name": "p",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {**roots, **packages},
        }
    )


GIT_ENTRY = {
    "version": "1.0.0",
    "resolved": f"git+ssh://git@github.com/acme/mylib.git#{SHA}",
}
PRIVATE_ENTRY = {
    "version": "1.0.0",
    "resolved": "https://npm.corp.example/@corp/x/-/x-1.0.0.tgz",
    "integrity": INTEGRITY,
}
PNPM_LOCK = f"""lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
      mylib:
        specifier: github:acme/mylib
        version: {TARBALL}

packages:

  lodash@4.17.21:
    resolution: {{integrity: {INTEGRITY}}}

  mylib@{TARBALL}:
    resolution: {{tarball: {TARBALL}}}
    version: 1.0.0

snapshots:

  lodash@4.17.21: {{}}

  mylib@{TARBALL}: {{}}
"""
YARN_LOCK = f"""# yarn lockfile v1


lodash@4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"
  integrity {INTEGRITY}

"mylib@github:acme/mylib":
  version "1.0.0"
  resolved "{TARBALL}"
"""
POETRY_LOCK = """[[package]]
name = "requests"
version = "2.32.3"
description = "x"
optional = false
python-versions = ">=3.8"
files = []

[[package]]
name = "corp"
version = "1.0.0"
description = "x"
optional = false
python-versions = ">=3.8"
files = []

[package.source]
type = "legacy"
url = "https://pypi.corp.example/simple"
reference = "corp"

[metadata]
lock-version = "2.1"
python-versions = "^3.9"
content-hash = "0"
"""
PIPFILE_LOCK = json.dumps(
    {
        "_meta": {
            "hash": {"sha256": "0" * 64},
            "pipfile-spec": 6,
            "requires": {},
            "sources": [
                {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True},
                {
                    "name": "corp",
                    "url": "https://pypi.corp.example/simple",
                    "verify_ssl": True,
                },
            ],
        },
        "default": {
            "requests": {"index": "pypi", "version": "==2.32.3", "hashes": []},
            "corp": {"index": "corp", "version": "==1.0.0", "hashes": []},
        },
        "develop": {},
    }
)

BUN_LOCK = json.dumps(
    {
        "lockfileVersion": 1,
        "workspaces": {"": {"name": "p"}},
        "packages": {
            "ms": ["ms@2.1.3", "", {}, INTEGRITY],
            "mylib": ["mylib@github:acme/mylib#0123456", {}, "acme-mylib-0123456"],
        },
    }
)

SOURCE_CASES = {
    "bun git": ("bun.lock", BUN_LOCK, "ms", "mylib"),
    "npm git": (
        "package-lock.json",
        npm_lock({"node_modules/lodash": LODASH_ENTRY, "node_modules/mylib": GIT_ENTRY}),
        "lodash",
        "mylib",
    ),
    "npm private registry": (
        "package-lock.json",
        npm_lock(
            {"node_modules/lodash": LODASH_ENTRY, "node_modules/@corp/x": PRIVATE_ENTRY}
        ),
        "lodash",
        "@corp/x",
    ),
    "pnpm git tarball": ("pnpm-lock.yaml", PNPM_LOCK, "lodash", "mylib"),
    "yarn git tarball": ("yarn.lock", YARN_LOCK, "lodash", "mylib"),
    "poetry private index": ("poetry.lock", POETRY_LOCK, "requests", "corp"),
    "pipenv private index": ("Pipfile.lock", PIPFILE_LOCK, "requests", "corp"),
}


@pytest.mark.parametrize("case", SOURCE_CASES.values(), ids=SOURCE_CASES.keys())
def test_private_source_is_listed_and_public_packages_stay_queried(
    monkeypatch, tmp_path, case
):
    filename, text, public, private = case
    (tmp_path / filename).write_text(text)

    result = _scan(monkeypatch, Live(), tmp_path)
    receipt = result.receipt

    assert receipt["status"] == NON_REGISTRY_COVERAGE_STATUS
    assert receipt["complete"] is False
    assert receipt["unresolved_lockfile_dependency_count"] == 0
    assert receipt["non_registry_lockfile_dependency_count"] == 1
    assert _blocking_sca_reason(receipt) is None
    queried = {dep["name"] for dep in sca.collect_dependencies(tmp_path)}
    assert public in queried
    assert private not in queried
    assert [e.get("name", e.get("package")) for e in receipt["lockfile_not_checked"]] == [
        private
    ]


def test_private_package_is_not_requeried_through_its_manifest_pin(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"mylib": "1.0.0", "lodash": "4.17.21"}})
    )
    (tmp_path / "package-lock.json").write_text(
        npm_lock({"node_modules/lodash": LODASH_ENTRY, "node_modules/mylib": GIT_ENTRY})
    )

    queried = {dep["name"] for dep in sca.collect_dependencies(tmp_path)}

    assert "mylib" not in queried


@pytest.mark.parametrize(
    "entry",
    [
        {"version": "1.0.0", "resolved": 7},
        {
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
        },
    ],
    ids=["malformed source", "registry tarball of another package"],
)
def test_contradictory_source_still_stops_the_scan(tmp_path, entry):
    (tmp_path / "package-lock.json").write_text(
        npm_lock({"node_modules/mylib": entry})
    )

    receipt = sca.collect_dependencies(tmp_path).receipt

    assert receipt["status"] == "incomplete"
    assert _blocking_sca_reason(receipt) is not None


def _mirror_lock(private_count, public_count):
    packages = {}
    for index in range(private_count):
        name = f"corp-{index}"
        packages[f"node_modules/{name}"] = {
            "version": "1.0.0",
            "resolved": f"https://npm.corp.example/{name}/-/{name}-1.0.0.tgz",
            "integrity": INTEGRITY,
        }
    for index in range(public_count):
        name = f"pub-{index}"
        packages[f"node_modules/{name}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
            "integrity": INTEGRITY,
        }
    return npm_lock(packages)


@pytest.mark.parametrize(
    "private_count,public_count",
    [(30, 0), (6, 1), (6, 5)],
    ids=["everything behind a mirror", "nearly everything", "more unchecked than checked"],
)
def test_scan_stops_when_most_packages_went_unchecked(
    monkeypatch, tmp_path, private_count, public_count
):
    (tmp_path / "package-lock.json").write_text(
        _mirror_lock(private_count, public_count)
    )

    result = _scan(monkeypatch, Live(), tmp_path)
    reason = _blocking_sca_reason(result.receipt)

    assert result.receipt["status"] == "incomplete"
    assert result.receipt["most_packages_not_checked"] is True
    assert reason is not None
    assert f"{private_count} packages come from a private registry" in reason.text


def test_known_vulnerability_is_kept_when_most_packages_went_unchecked(
    monkeypatch, tmp_path
):
    (tmp_path / "package-lock.json").write_text(_mirror_lock(6, 1))

    result = _scan(monkeypatch, Live({"pub-0": ["GHSA-test-one"]}), tmp_path)

    assert result.receipt["status"] == "incomplete"
    assert [f["metadata"]["package_name"] for f in result] == ["pub-0"]


@pytest.mark.parametrize(
    "private_count,public_count",
    [(4, 0), (4, 1), (6, 6), (6, 20)],
    ids=["a few alone", "a few with public", "half", "a minority"],
)
def test_private_minority_stays_a_listed_limitation(
    monkeypatch, tmp_path, private_count, public_count
):
    (tmp_path / "package-lock.json").write_text(
        _mirror_lock(private_count, public_count)
    )

    result = _scan(monkeypatch, Live(), tmp_path)

    assert result.receipt["status"] == NON_REGISTRY_COVERAGE_STATUS
    assert "most_packages_not_checked" not in result.receipt
    assert _blocking_sca_reason(result.receipt) is None


def test_uploaded_receipt_names_files_without_local_paths():
    coverage = {
        "status": NON_REGISTRY_COVERAGE_STATUS,
        "lockfile_not_checked": [
            {
                "name": "corp",
                "reason": "non_public_registry",
                "file": "/Users/someone/work/app/poetry.lock",
            }
        ],
        "lockfile_issues": [{"file": "C:\\work\\app\\package-lock.json"}],
        "unsupported_inputs": [{"file": "/home/runner/work/app/pom.xml"}],
    }

    uploaded = json.dumps(sca_coverage_for_upload(coverage))

    assert "/Users/someone" not in uploaded and "runner" not in uploaded
    assert "work" not in uploaded
    cleaned = sca_coverage_for_upload(coverage)
    assert cleaned["lockfile_not_checked"][0] == {
        "name": "corp",
        "reason": "non_public_registry",
        "file": "poetry.lock",
    }
    assert cleaned["lockfile_issues"][0]["file"] == "package-lock.json"


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _write(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _repo(root, files):
    _write(root, files)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return _git(root, "rev-parse", "HEAD")


def _change(root, files):
    _write(root, files)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")


def _new_source_findings(root, **options):
    findings, receipt, _errors = diff.supply_chain_diff_findings(
        root,
        "main",
        dependencies=True,
        security=False,
        review_upgrades=False,
        **options,
    )
    return [f for f in findings if f["rule_id"] == diff.RULE_NEW_SOURCE], receipt


def _on_branch(root):
    _git(root, "checkout", "-q", "-b", "change")


def test_lockfile_repointed_at_an_unknown_host_is_blocked(tmp_path):
    _repo(
        tmp_path, {"package-lock.json": npm_lock({"node_modules/lodash": LODASH_ENTRY})}
    )
    _on_branch(tmp_path)
    moved = {
        "version": "4.17.21",
        "resolved": "https://evil.example/lodash-4.17.21.tgz",
        "integrity": INTEGRITY,
    }
    _change(tmp_path, {"package-lock.json": npm_lock({"node_modules/lodash": moved})})

    findings, _receipt = _new_source_findings(tmp_path)

    assert [f["metadata"]["package_name"] for f in findings] == ["lodash"]
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["metadata"]["source_hosts"] == ["evil.example"]
    assert "evil.example" in findings[0]["message"]


def test_new_git_dependency_is_reported(tmp_path):
    _repo(
        tmp_path, {"package-lock.json": npm_lock({"node_modules/lodash": LODASH_ENTRY})}
    )
    _on_branch(tmp_path)
    _change(
        tmp_path,
        {
            "package-lock.json": npm_lock(
                {"node_modules/lodash": LODASH_ENTRY, "node_modules/mylib": GIT_ENTRY}
            )
        },
    )

    findings, _receipt = _new_source_findings(tmp_path)

    assert [f["metadata"]["package_name"] for f in findings] == ["mylib"]


def test_existing_private_dependency_stays_quiet_when_others_change(tmp_path):
    _repo(
        tmp_path,
        {
            "package-lock.json": npm_lock(
                {"node_modules/lodash": LODASH_ENTRY, "node_modules/mylib": GIT_ENTRY}
            )
        },
    )
    _on_branch(tmp_path)
    bumped = {**LODASH_ENTRY, "version": "4.17.20"}
    bumped["resolved"] = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    _change(
        tmp_path,
        {
            "package-lock.json": npm_lock(
                {"node_modules/lodash": bumped, "node_modules/mylib": GIT_ENTRY}
            )
        },
    )

    findings, receipt = _new_source_findings(tmp_path)

    assert findings == []
    assert receipt["checks"]["package_sources"]["status"] == "checked"


def test_existing_private_dependency_repointed_at_another_host_is_reported(tmp_path):
    _repo(
        tmp_path,
        {"package-lock.json": npm_lock({"node_modules/mylib": GIT_ENTRY})},
    )
    _on_branch(tmp_path)
    moved = {
        "version": "1.0.0",
        "resolved": f"git+ssh://git@git.evil.example/acme/mylib.git#{SHA}",
    }
    _change(tmp_path, {"package-lock.json": npm_lock({"node_modules/mylib": moved})})

    findings, _receipt = _new_source_findings(tmp_path)

    assert findings[0]["metadata"]["source_hosts"] == ["git.evil.example"]


def test_lockfile_moved_to_another_folder_is_not_a_new_source(tmp_path):
    lock = npm_lock({"node_modules/mylib": GIT_ENTRY})
    _repo(tmp_path, {"a/package-lock.json": lock})
    _on_branch(tmp_path)
    _git(tmp_path, "mv", "a", "b")
    _git(tmp_path, "commit", "-qm", "move")

    findings, _receipt = _new_source_findings(tmp_path)

    assert findings == []


@pytest.mark.parametrize(
    "filename,text,name",
    [
        (
            "uv.lock",
            'version = 1\nrequires-python = ">=3.9"\n\n[[package]]\nname = "corp"\nversion = "1.0.0"\nsource = { registry = "https://pypi.corp.example/simple" }\n',
            "corp",
        ),
        (
            "Cargo.lock",
            f'version = 3\n\n[[package]]\nname = "mylib"\nversion = "1.0.0"\nsource = "git+https://github.com/acme/mylib#{SHA}"\n',
            "mylib",
        ),
    ],
    ids=["uv", "cargo"],
)
def test_new_source_check_covers_formats_that_already_listed_sources(
    tmp_path, filename, text, name
):
    _repo(tmp_path, {"README.md": "x"})
    _on_branch(tmp_path)
    _change(tmp_path, {filename: text})

    findings, _receipt = _new_source_findings(tmp_path)

    assert [f["metadata"]["package_name"] for f in findings] == [name]


def test_base_branch_internal_packages_exempts_a_new_private_source(
    tmp_path, monkeypatch
):
    base = _repo(
        tmp_path,
        {"pyproject.toml": '[tool.skylos.supply_chain]\ninternal_packages = ["my*"]\n'},
    )
    monkeypatch.setenv("SKYLOS_POLICY_BASE", base)
    _on_branch(tmp_path)
    _change(
        tmp_path,
        {"package-lock.json": npm_lock({"node_modules/mylib": GIT_ENTRY})},
    )

    findings, _receipt = _new_source_findings(tmp_path)

    assert findings == []


def test_pull_request_cannot_exempt_its_own_new_source(tmp_path, monkeypatch):
    base = _repo(tmp_path, {"pyproject.toml": "[tool.skylos]\n"})
    monkeypatch.setenv("SKYLOS_POLICY_BASE", base)
    _on_branch(tmp_path)
    _change(
        tmp_path,
        {
            "pyproject.toml": '[tool.skylos.supply_chain]\ninternal_packages = ["my*"]\n',
            "package-lock.json": npm_lock({"node_modules/mylib": GIT_ENTRY}),
        },
    )

    findings, _receipt = _new_source_findings(tmp_path)

    assert [f["metadata"]["package_name"] for f in findings] == ["mylib"]


class Response:
    headers = {}

    def __init__(self, payload, status=200):
        self.payload = payload
        self.status_code = status

    def iter_content(self, chunk_size):
        yield json.dumps(self.payload).encode("utf-8")

    def close(self):
        pass


def pypi_advisory(advisory_id="GHSA-test-one", name="example"):
    return {
        "id": advisory_id,
        "summary": "Example advisory",
        "aliases": [],
        "database_specific": {"severity": "HIGH"},
        "references": [],
        "affected": [
            {
                "package": {"name": name, "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "3.0.0"}],
                    }
                ],
            }
        ],
    }


class Live:
    """OSV answering; ``vulns`` maps a package name to its advisory IDs."""

    def __init__(self, vulns=None, failures=0, details_fail=False):
        self.vulns = vulns or {}
        self.failures = failures
        self.details_fail = details_fail
        self.posts = 0
        self.gets = []

    def post(self, url, **kwargs):
        self.posts += 1
        if self.failures:
            self.failures -= 1
            raise ConnectionError("down")
        results = []
        for query in kwargs["json"]["queries"]:
            ids = self.vulns.get(query["package"]["name"], [])
            results.append({"vulns": [{"id": item} for item in ids]})
        return Response({"results": results})

    def get(self, url, **kwargs):
        advisory_id = url.rsplit("/", 1)[-1]
        self.gets.append(advisory_id)
        if self.details_fail:
            raise ConnectionError("down")
        return Response(pypi_advisory(advisory_id))


class Down:
    def __init__(self):
        self.posts = 0
        self.gets = []

    def post(self, url, **kwargs):
        self.posts += 1
        raise ConnectionError("down")

    def get(self, url, **kwargs):
        self.gets.append(url)
        raise ConnectionError("down")


@pytest.fixture
def no_retry_wait(monkeypatch):
    monkeypatch.setattr(sca, "OSV_RETRY_DELAYS", (0.0, 0.0))


def _project(root, requirements="example==1.0.0\n"):
    root.mkdir(exist_ok=True)
    (root / "requirements.txt").write_text(requirements)
    return root


def _scan(monkeypatch, transport, root):
    monkeypatch.setattr(sca, "_requests", transport)
    return sca.scan_dependencies(root)


def _ids(result):
    return {f["metadata"]["vuln_id"] for f in result if f["metadata"].get("vuln_id")}


def test_a_failed_request_is_retried_and_the_scan_completes(
    monkeypatch, tmp_path, no_retry_wait
):
    live = Live(failures=1)

    result = _scan(monkeypatch, live, _project(tmp_path / "p"))

    assert live.posts == 2
    assert result.receipt["status"] == "complete"
    assert result.receipt["complete"] is True


def test_retries_stop_at_the_budget_during_an_outage(
    monkeypatch, tmp_path, no_retry_wait
):
    monkeypatch.setattr(sca, "OSV_RETRY_BUDGET_SECONDS", -1.0)
    down = Down()

    _scan(monkeypatch, down, _project(tmp_path / "p"))

    assert down.posts == 1


def test_outage_reuses_saved_answers_and_never_claims_a_clean_result(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    _scan(monkeypatch, Live({"example": ["GHSA-test-one"]}), root)
    down = Down()

    result = _scan(monkeypatch, down, root)
    receipt = result.receipt

    assert _ids(result) == {"GHSA-test-one"}
    assert receipt["status"] == SAVED_ANSWERS_COVERAGE_STATUS
    assert receipt["complete"] is False
    assert receipt["query"]["saved_answers"]["package_count"] == 1
    assert down.gets == []
    assert _blocking_sca_reason(receipt) is None
    summary = {"analysis_summary": {"sca_coverage": receipt}}
    assert dependency_scan_complete(summary) is False
    assert _sca_required_coverage_reasons(receipt, require_resolved=False)
    assert any("saved answers" in line for line in sca_coverage_warnings(summary))


def test_saved_clean_answer_reports_no_findings_but_stays_limited(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    _scan(monkeypatch, Live(), root)

    result = _scan(monkeypatch, Down(), root)

    assert _ids(result) == set()
    assert result.receipt["status"] == SAVED_ANSWERS_COVERAGE_STATUS
    assert result.receipt["complete"] is False


def test_package_with_no_saved_answer_still_stops_the_scan(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    _scan(monkeypatch, Live({"example": ["GHSA-test-one"]}), root)
    _project(root, "example==1.0.0\nother==2.0.0\n")

    result = _scan(monkeypatch, Down(), root)

    assert result.receipt["status"] == "incomplete"
    assert _blocking_sca_reason(result.receipt) is not None
    assert _ids(result) == {"GHSA-test-one"}


def test_saved_answers_expire(monkeypatch, tmp_path, no_retry_wait):
    root = _project(tmp_path / "p")
    _scan(monkeypatch, Live(), root)
    later = time.time() + osv_answers.MAX_ANSWER_AGE_SECONDS + 3600
    monkeypatch.setattr(osv_answers.time, "time", lambda: later)

    result = _scan(monkeypatch, Down(), root)

    assert result.receipt["status"] == "incomplete"


def test_store_inside_the_scanned_repository_is_never_used(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    monkeypatch.setenv("XDG_CACHE_HOME", str(root / ".cache"))
    _scan(monkeypatch, Live(), root)

    assert not (root / ".cache").exists()
    assert _scan(monkeypatch, Down(), root).receipt["status"] == "incomplete"


def test_planted_answer_in_a_store_inside_the_repository_is_ignored(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    cache = root / ".cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    store = cache / "skylos" / "osv-answers.json"
    store.parent.mkdir(parents=True)
    store.write_text(
        json.dumps(
            {
                "version": osv_answers.STORE_VERSION,
                "packages": {
                    "PyPI:example:1.0.0": {"ids": [], "at": time.time()},
                },
                "advisories": {},
            }
        )
    )

    assert _scan(monkeypatch, Down(), root).receipt["status"] == "incomplete"


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"version": 999, "packages": {}, "advisories": {}}),
        json.dumps(
            {
                "version": osv_answers.STORE_VERSION,
                "packages": {
                    "PyPI:example:1.0.0": {"ids": ["not an id!"], "at": time.time()}
                },
                "advisories": {},
            }
        ),
        json.dumps(
            {
                "version": osv_answers.STORE_VERSION,
                "packages": {
                    "PyPI:example:1.0.0": {"ids": [], "at": time.time() + 86_400}
                },
                "advisories": {},
            }
        ),
    ],
    ids=["malformed", "other version", "invalid id", "dated in the future"],
)
def test_damaged_store_is_ignored(monkeypatch, tmp_path, no_retry_wait, content):
    store = osv_answers.store_path()
    store.parent.mkdir(parents=True)
    store.write_text(content)

    result = _scan(monkeypatch, Down(), _project(tmp_path / "p"))

    assert result.receipt["status"] == "incomplete"


def test_symlinked_store_is_neither_read_nor_followed(
    monkeypatch, tmp_path, no_retry_wait
):
    target = tmp_path / "elsewhere.json"
    target.write_text("keep")
    store = osv_answers.store_path()
    store.parent.mkdir(parents=True)
    os.symlink(target, store)
    root = _project(tmp_path / "p")

    _scan(monkeypatch, Live(), root)

    assert target.read_text() == "keep"
    assert _scan(monkeypatch, Down(), root).receipt["status"] == "incomplete"


def test_live_answer_overrides_a_saved_clean_answer(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    _scan(monkeypatch, Live(), root)

    result = _scan(monkeypatch, Live({"example": ["GHSA-test-one"]}), root)

    assert _ids(result) == {"GHSA-test-one"}
    assert result.receipt["status"] == "complete"
    assert _ids(_scan(monkeypatch, Down(), root)) == {"GHSA-test-one"}


def test_failed_detail_lookup_uses_the_saved_document(
    monkeypatch, tmp_path, no_retry_wait
):
    root = _project(tmp_path / "p")
    _scan(monkeypatch, Live({"example": ["GHSA-test-one"]}), root)

    result = _scan(
        monkeypatch, Live({"example": ["GHSA-test-one"]}, details_fail=True), root
    )

    assert result.receipt["status"] == SAVED_ANSWERS_COVERAGE_STATUS
    assert result[0]["metadata"]["advisory_status"] == "complete"


def test_failed_detail_lookup_without_a_saved_document_stops_the_scan(
    monkeypatch, tmp_path, no_retry_wait
):
    result = _scan(
        monkeypatch,
        Live({"example": ["GHSA-test-one"]}, details_fail=True),
        _project(tmp_path / "p"),
    )

    assert result.receipt["status"] == "incomplete"
    assert _ids(result) == {"GHSA-test-one"}


def test_workflow_keeps_saved_answers_between_runs_only_with_dependency_scans():
    with_sca = generate_workflow(analysis_types=["dead-code", "security", "sca"])
    without = generate_workflow(analysis_types=["dead-code", "security"])

    assert with_sca.count("actions/cache/restore@55cc8345") == 1
    assert with_sca.count("actions/cache/save@55cc8345") == 1
    assert "actions/cache/" not in without
    restore = with_sca.index("actions/cache/restore@")
    analysis = with_sca.index("Run Skylos Analysis")
    save = with_sca.index("actions/cache/save@")
    assert restore < analysis < save
    assert with_sca.count("continue-on-error: true\n        uses: actions/cache/") == 2


def _result(verdict, **evidence):
    vulnerability = Vulnerability(
        id="GHSA-x",
        package_name="example",
        package_version="1.0.0",
        severity="HIGH",
        title="x",
    )
    return VerdictResult(
        vulnerability=vulnerability,
        verdict=verdict,
        reason="x",
        evidence=Evidence(**evidence),
    )


HIT = ApiUsageHit(file_path="/repo/app.py", line=3)
DIRECT = {"declared_direct_dependency": True, "dependency_graph_available": True}


@pytest.mark.parametrize(
    "verdict,evidence,expected",
    [
        (Verdict.INCONCLUSIVE, {"package_imported": True, "api_usage_hits": (HIT,)}, "used"),
        (Verdict.REACHABLE, {"package_imported": True}, "used"),
        (Verdict.INCONCLUSIVE, {"package_imported": True}, "imported"),
        (Verdict.INCONCLUSIVE, DIRECT, "not_imported"),
        (Verdict.INCONCLUSIVE, {"dependency_graph_available": True}, "unknown"),
        (
            Verdict.INCONCLUSIVE,
            {**DIRECT, "indirect_use_signals": ("console script gunicorn",)},
            "unknown",
        ),
        (Verdict.INCONCLUSIVE, {"declared_direct_dependency": True}, "unknown"),
        (Verdict.INCONCLUSIVE, {**DIRECT, "unproven_import_mappings": ("x",)}, "unknown"),
        (Verdict.INCONCLUSIVE, {**DIRECT, "dependency_graph_unresolved": ("x",)}, "unknown"),
        (Verdict.UNREACHABLE_STATIC, {"version_in_range": False, "api_usage_hits": (HIT,)}, "unreachable"),
        (Verdict.UNREACHABLE_DYNAMIC, {"package_imported": True}, "unreachable"),
    ],
    ids=[
        "api call beats an inconclusive verdict",
        "reachable verdict",
        "imported without a vulnerable call",
        "direct dependency never imported",
        "transitive dependency is not low priority",
        "command-line tool is not low priority",
        "no dependency graph is not low priority",
        "guessed import name is not low priority",
        "incomplete graph is not low priority",
        "version outside the range beats a call",
        "proved not executed",
    ],
)
def test_reachability_tier(verdict, evidence, expected):
    assert reachability_tier(_result(verdict, **evidence)) == expected


def _advisory(name, severity="HIGH", tier=None, **metadata):
    data = {"vuln_id": f"GHSA-{name}", "package_name": name, "package_version": "1"}
    if tier:
        data["reachability_tier"] = tier
    data.update(metadata)
    return {"severity": severity, "file": "req.txt", "line": 1, "metadata": data}


def test_packages_sort_by_severity_then_use_and_none_are_dropped():
    findings = [
        _advisory("critical-no-import", "CRITICAL", "not_imported"),
        _advisory("low-called", "LOW", "used"),
        _advisory("high-imported", "HIGH", "imported"),
        _advisory("high-called", "HIGH", "used"),
        _advisory("critical-npm", "CRITICAL"),
        _advisory("malware", "MEDIUM", malicious=True),
    ]

    order = [group.name for group in group_advisories(findings)]

    assert order == [
        "malware",
        "critical-npm",
        "high-called",
        "high-imported",
        "low-called",
        "critical-no-import",
    ]


def test_finding_without_a_tier_keeps_its_package_at_normal_priority():
    group = group_advisories(
        [
            _advisory("mixed", "HIGH", "not_imported"),
            _advisory("mixed", "HIGH"),
        ]
    )[0]

    assert group.lower_priority is False


def test_use_text_names_the_call_site():
    group = group_advisories(
        [
            _advisory(
                "called",
                "HIGH",
                "used",
                reachability_call_sites=[{"file": "app.py", "line": 3}],
            )
        ]
    )[0]

    assert group.use_text() == "called at app.py:3"


def test_footer_says_the_gate_counts_everything_only_when_tiers_exist():
    tiered = group_advisories([_advisory("a", "HIGH", "not_imported")])
    untiered = group_advisories([_advisory("b", "HIGH")])

    assert "1 no import found" in summary_footer(tiered)
    assert "The gate counts all of them" in summary_footer(tiered)
    assert "Use:" not in summary_footer(untiered)


@pytest.mark.parametrize("tier", ["not_imported", "imported", "unknown"])
def test_tier_does_not_change_what_the_cloud_gate_treats_as_unreachable(tier):
    finding = _advisory(
        "a", "HIGH", tier, reachability_verdict="inconclusive", vuln_id="GHSA-a"
    )

    assert cloud_ignores_unreachable_dependency(finding) is False
