"""SKY-SCA-NEW001 and the SKY-D223 wording for packages with little history."""

import textwrap

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.core import gatekeeper
from skylos.rules.sca import package_history
from skylos.rules.sca.package_history import (
    NOTE_HISTORY_CAPPED,
    NOTE_HISTORY_UNAVAILABLE,
    NOTE_NAMES_NOT_CHECKED,
    RULE_UNPROVEN_PACKAGE,
    evaluate_package_history,
)
from skylos.supply_chain.policy import (
    SupplyChainPolicy,
    _combine,
    _parse_layer,
    package_matches,
)

HISTORIES = {
    "brand-new": {
        "status": "new",
        "age_days": 4,
        "release_count": 1,
        "owners": ["someone"],
    },
    "barely-used": {"status": "thin_history", "age_days": 96, "release_count": 1},
    "requests": {"status": "established", "age_days": 5753, "release_count": 160},
    "offline": {
        "status": "unknown",
        "reason": "registry metadata could not be fetched",
    },
    "ghost": {"status": "missing"},
}


class _Api:
    def __init__(self, histories=HISTORIES):
        self.histories = histories
        self.calls = []

    def package_history(self, ecosystem, name):
        self.calls.append((ecosystem, name))
        answer = dict(self.histories.get(name, {"status": "established"}))
        answer.setdefault("ecosystem", ecosystem)
        answer.setdefault("name", name)
        if ecosystem == "pypi":
            answer.setdefault("registry_url", f"https://pypi.org/project/{name}/")
            answer.setdefault(
                "report_url", f"https://pypi.org/project/{name}/submit-malware-report/"
            )
        return answer


@pytest.fixture(autouse=True)
def _real_history_function(monkeypatch):
    monkeypatch.setattr(
        package_history,
        "history_function",
        lambda api: getattr(api, "package_history", None),
    )


def _dep(name, ecosystem="PyPI", version="1.0.0", **extra):
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "file": "requirements.txt",
        "line": 3,
        "snippet": f"{name}=={version}",
        **extra,
    }


def _policy(**kwargs):
    return SupplyChainPolicy(**kwargs)


def test_new_and_thin_history_dependencies_are_reported():
    api = _Api()
    inventory = [
        _dep("brand-new"),
        _dep("barely-used"),
        _dep("requests"),
        _dep("ghost"),
    ]
    findings, receipt = evaluate_package_history(inventory, _policy(), api=api)
    assert [finding["symbol"] for finding in findings] == ["brand-new", "barely-used"]
    first = findings[0]
    assert first["rule_id"] == RULE_UNPROVEN_PACKAGE
    assert first["severity"] == "MEDIUM"
    assert first["file"] == "requirements.txt" and first["line"] == 3
    assert (
        "first published on PyPI 4 days ago, 1 release, published by someone"
        in first["message"]
    )
    assert "https://pypi.org/project/brand-new/" in first["message"]
    assert "approved_packages" in first["message"]
    metadata = first["metadata"]
    assert metadata["history_status"] == "new"
    assert metadata["approve_with"] == "pypi:brand-new"
    assert metadata["action"] == "warn"
    assert metadata["report_url"].endswith("/submit-malware-report/")
    assert receipt["status"] == "complete"
    assert receipt["results"] == {
        "new": 1,
        "thin_history": 1,
        "established": 1,
        "missing": 1,
    }


def test_block_mode_raises_severity_and_off_mode_looks_nothing_up():
    api = _Api()
    findings, _ = evaluate_package_history(
        [_dep("brand-new")], _policy(unproven_packages="block"), api=api
    )
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["metadata"]["action"] == "block"
    api = _Api()
    findings, receipt = evaluate_package_history(
        [_dep("brand-new")], _policy(unproven_packages="off"), api=api
    )
    assert findings == [] and api.calls == [] and receipt["status"] == "off"


def test_private_internal_approved_and_transitive_names_are_never_looked_up():
    api = _Api()
    inventory = [
        _dep("acme-core"),
        _dep("brand-new", registry="https://pypi.acme.dev/simple"),
        _dep("barely-used"),
        _dep("deep-dep", lockfile_version="1.0.0", dependency_kind="transitive"),
        _dep("requests", lockfile_version="2.0.0", dependency_kind="direct"),
    ]
    policy = _policy(
        internal_packages=("acme-*",), approved_packages=("pypi:barely_used",)
    )
    findings, receipt = evaluate_package_history(inventory, policy, api=api)
    assert findings == []
    assert api.calls == [("pypi", "requests")]
    assert receipt["skipped"] == {
        "transitive": 1,
        "internal": 1,
        "private_registry": 1,
        "approved": 1,
    }


def test_unreadable_registry_is_incomplete_and_reports_nothing():
    findings, receipt = evaluate_package_history(
        [_dep("offline")], _policy(), api=_Api()
    )
    assert findings == []
    assert receipt["status"] == "incomplete"
    assert receipt["results"] == {"unknown": 1}


def test_lookup_error_and_missing_engine_do_not_fail_the_scan():
    class Broken:
        def package_history(self, ecosystem, name):
            raise RuntimeError("boom")

    findings, receipt = evaluate_package_history(
        [_dep("brand-new")], _policy(), api=Broken()
    )
    assert findings == [] and receipt["results"] == {"unknown": 1}
    findings, receipt = evaluate_package_history(
        [_dep("brand-new")], _policy(), api=object()
    )
    assert findings == []
    assert receipt["status"] == "unavailable"
    assert receipt["notes"] == [NOTE_HISTORY_UNAVAILABLE]


def test_lookups_are_capped(monkeypatch):
    monkeypatch.setattr(package_history, "MAX_HISTORY_LOOKUPS", 2)
    api = _Api()
    inventory = [_dep(f"pkg-{index}") for index in range(5)]
    _, receipt = evaluate_package_history(inventory, _policy(), api=api)
    assert len(api.calls) == 2
    assert receipt["not_checked"] == 3
    assert NOTE_HISTORY_CAPPED in receipt["notes"]
    assert receipt["status"] == "incomplete"


def _project(tmp_path, dependencies, extra=""):
    listed = ", ".join(f'"{item}"' for item in dependencies)
    (tmp_path / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] fixed filename; every caller uses a fresh pytest tmp_path
        textwrap.dedent(
            f"""
            [project]
            name = "demo"
            version = "0.1.0"
            dependencies = [{listed}]
            {extra}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    return tmp_path


def test_names_declared_without_a_version_are_checked_and_located(tmp_path):
    root = _project(tmp_path, ["requests>=2", "Brand_New", "barely-used"])
    api = _Api()
    findings, _ = evaluate_package_history([], _policy(), api=api, root=root)
    by_name = {finding["symbol"]: finding for finding in findings}
    assert set(by_name) == {"brand-new", "barely-used"}
    assert by_name["brand-new"]["file"].endswith("pyproject.toml")
    assert by_name["brand-new"]["line"] == 4
    assert ("pypi", "demo") not in api.calls


def test_bare_names_stay_private_without_internal_patterns(tmp_path):
    root = _project(tmp_path, ["brand-new"])
    api = _Api()
    policy = _policy(private_registries=("https://pypi.acme.dev/simple",))
    findings, receipt = evaluate_package_history([], policy, api=api, root=root)
    assert findings == [] and api.calls == []
    assert NOTE_NAMES_NOT_CHECKED in receipt["notes"]


@pytest.mark.parametrize(
    "pattern, ecosystem, name, expected",
    [
        ("brand-new", "pypi", "Brand_New", True),
        ("pypi:brand.new", "pypi", "brand-new", True),
        ("npm:brand-new", "pypi", "brand-new", False),
        ("npm:@acme/*", "npm", "@acme/tool", True),
        ("acme-*", "pypi", "acme-core", True),
        ("other", "pypi", "brand-new", False),
    ],
)
def test_approved_package_patterns(pattern, ecosystem, name, expected):
    assert package_matches(ecosystem, name, (pattern,)) is expected


def test_policy_mode_only_tightens_and_approvals_are_combined():
    local = _parse_layer(
        {"unproven_packages": "block", "approved_packages": ["pypi:mine"]}, "pyproject"
    )
    cloud = _parse_layer(
        {"unproven_packages": "warn", "approved_packages": ["pypi:org-approved"]},
        "Skylos Cloud",
    )
    policy = _combine(local, cloud, ())
    assert policy.unproven_packages == "block"
    assert policy.approved_packages == ("pypi:mine", "pypi:org-approved")
    assert policy.is_approved("pypi", "mine") and policy.is_approved("pypi", "org_approved")

    stricter_cloud = _combine(
        _parse_layer({"unproven_packages": "off"}, "pyproject"),
        _parse_layer({"unproven_packages": "warn"}, "Skylos Cloud"),
        (),
    )
    assert stricter_cloud.unproven_packages == "warn"
    assert _combine(_parse_layer({}, "a"), _parse_layer({}, "b"), ()).unproven_packages == "warn"

    bad = _parse_layer({"unproven_packages": "maybe", "approved_packages": "x"}, "pyproject")
    assert len(bad.problems) == 2 and bad.values == {}


def _gate_finding(action):
    return {"rule_id": RULE_UNPROVEN_PACKAGE, "metadata": {"action": action}}


def test_gates_count_the_finding_only_in_block_mode():
    warn, block = _gate_finding("warn"), _gate_finding("block")
    other = {"rule_id": "SKY-SCA-AGE001", "metadata": {}}
    assert gatekeeper._built_in_gate_dependencies([warn, block, other]) == [
        block,
        other,
    ]
    assert gatekeeper._gate_dependencies([warn, block, other]) == [block, other]


def _scan_import(monkeypatch, tmp_path, histories, extra=""):
    repo = _project(tmp_path, ["requests"], extra)
    source = tmp_path / "app.py"
    source.write_text(  # skylos: ignore[SKY-D324] fixed filename; every caller uses a fresh pytest tmp_path
        "import brand_new\n", encoding="utf-8"
    )
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", dict)
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", dict)
    monkeypatch.setattr(dep, "_check_pypi_status", lambda name, _cache: "exists")
    api = _Api(histories)
    monkeypatch.setattr("skylos.rules.sca.supply_chain.load_ca9_api", lambda: api)
    findings = dep.scan_python_dependency_hallucinations(repo, [source])
    return [f for f in findings if f.get("rule_id") == "SKY-D223"], api


def test_undeclared_import_of_a_new_package_asks_for_a_check(monkeypatch, tmp_path):
    histories = {"brand-new": HISTORIES["brand-new"]}
    findings, _ = _scan_import(monkeypatch, tmp_path, histories)
    assert len(findings) == 1
    message = findings[0]["message"]
    assert "has little history" in message
    assert "before declaring it" in message
    assert "Add to" not in message
    assert findings[0]["metadata"]["approve_with"] == "pypi:brand-new"
    assert findings[0]["metadata"]["history_status"] == "new"


def test_undeclared_import_of_an_established_package_keeps_its_message(
    monkeypatch, tmp_path
):
    findings, _ = _scan_import(monkeypatch, tmp_path, {})
    assert len(findings) == 1
    assert "has little history" not in findings[0]["message"]
    assert "Not found in" in findings[0]["message"]


def test_undeclared_import_of_an_approved_package_is_not_looked_up(
    monkeypatch, tmp_path
):
    extra = '[tool.skylos.supply_chain]\napproved_packages = ["pypi:brand-new"]'
    findings, api = _scan_import(
        monkeypatch, tmp_path, {"brand-new": HISTORIES["brand-new"]}, extra
    )
    assert api.calls == []
    assert "has little history" not in findings[0]["message"]
