from __future__ import annotations

import json

from skylos.rules.danger.danger_hallucination.manifest_dependency_hallucination import (
    RULE_ID_DEPENDENCY_HALLUCINATION,
    RULE_ID_VERSION_HALLUCINATION,
    STATUS_EXISTS,
    STATUS_MISSING_PACKAGE,
    STATUS_MISSING_VERSION,
    scan_manifest_dependency_hallucinations,
)
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
)


def _status_checker(statuses, calls):
    def checker(ecosystem, name, version, _cache):
        calls.append((ecosystem, name, version))
        key = (ecosystem, name, version)
        if key in statuses:
            return statuses[key]
        return STATUS_EXISTS

    return checker


def _messages(findings):
    messages = []
    for finding in findings:
        messages.append(finding["message"])
    return messages


def test_scan_package_json_flags_missing_npm_package_and_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {
        "dependencies": {
            "leftpadz": "9.9.9",
            "stale-version": "^99.0.0",
            "realpkg": "1.2.3",
        },
        "devDependencies": {
            "devghost": "2.0.0",
        },
    }
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    calls = []
    statuses = {
        (ECOSYSTEM_NPM, "leftpadz", "9.9.9"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_NPM, "stale-version", "99.0.0"): STATUS_MISSING_VERSION,
        (ECOSYSTEM_NPM, "devghost", "2.0.0"): STATUS_MISSING_VERSION,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )
    rule_ids = []
    for finding in findings:
        rule_ids.append(finding["rule_id"])

    assert len(findings) == 3
    assert RULE_ID_DEPENDENCY_HALLUCINATION in rule_ids
    assert rule_ids.count(RULE_ID_VERSION_HALLUCINATION) == 2
    assert any("leftpadz" in message for message in _messages(findings))
    assert any("stale-version@99.0.0" in message for message in _messages(findings))
    assert (ECOSYSTEM_NPM, "realpkg", "1.2.3") in calls


def test_scan_go_mod_flags_missing_go_module_and_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text(
        "\n".join(
            [
                "module example.com/demo",
                "",
                "go 1.22",
                "",
                "require (",
                "    github.com/real/pkg v1.2.3",
                "    github.com/no/module v0.0.1",
                "    github.com/real/pkg v9.9.9",
                ")",
                "",
            ]
        ),
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_GO, "github.com/no/module", "0.0.1"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_GO, "github.com/real/pkg", "9.9.9"): STATUS_MISSING_VERSION,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )
    messages = _messages(findings)

    assert len(findings) == 2
    assert any("github.com/no/module" in message for message in messages)
    assert any("github.com/real/pkg@9.9.9" in message for message in messages)
    assert (ECOSYSTEM_GO, "github.com/real/pkg", "1.2.3") in calls


def test_scan_requirements_txt_flags_missing_pypi_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "\n".join(
            [
                "requests==999.0.0",
                "click==8.1.7",
            ]
        ),
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_PYPI, "requests", "999.0.0"): STATUS_MISSING_VERSION,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_ID_VERSION_HALLUCINATION
    assert "requests@999.0.0" in findings[0]["message"]
    assert (ECOSYSTEM_PYPI, "click", "8.1.7") in calls


def test_scan_manifest_dependency_statuses_are_cached(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {"dependencies": {"stale-version": "99.0.0"}}
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    calls = []
    statuses = {
        (ECOSYSTEM_NPM, "stale-version", "99.0.0"): STATUS_MISSING_VERSION,
    }

    first = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )

    def fail_checker(_ecosystem, _name, _version, _cache):
        raise AssertionError("cached dependency status should be reused")

    second = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=fail_checker,
    )

    assert len(first) == 1
    assert len(second) == 1
    assert calls == [(ECOSYSTEM_NPM, "stale-version", "99.0.0")]
