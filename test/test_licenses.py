"""License collection, SPDX normalization, SPDX 2.3 export, and license policy."""

import json
import re
import socket

import pytest

from skylos.commands.sbom_cmd import run_sbom_command
from skylos.config import load_config
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.sbom import cyclonedx_bom
from skylos.reporting.spdx import spdx_document
from skylos.rules.sca import licenses as lic
from skylos.rules.sca import vulnerability_scanner as sca


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


def _npm(root, extra=None):
    packages = {
        "": {"name": "app", "dependencies": {"parent": "^1", "gpl-lib": "1.0.0"}},
        "node_modules/parent": {
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {"@example/child": "^2"},
        },
        "node_modules/@example/child": {
            "version": "2.0.0",
            "license": "(MIT OR Apache-2.0)",
        },
        "node_modules/gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"},
        "node_modules/mystery": {"version": "0.1.0", "license": "BSD"},
        "node_modules/nolicense": {"version": "0.2.0"},
    }
    packages.update(extra or {})
    _write(
        root / "package-lock.json",
        json.dumps({"lockfileVersion": 3, "packages": packages}),
    )


def _dist_info(
    root, name, version, *, license_field=None, expression=None, classifiers=()
):
    site = root / ".venv" / "lib" / "python3.12" / "site-packages"
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    if expression:
        lines.append(f"License-Expression: {expression}")
    if license_field:
        lines.append(f"License: {license_field}")
    lines.extend(f"Classifier: {item}" for item in classifiers)
    _write(site / f"{name}-{version}.dist-info" / "METADATA", "\n".join(lines) + "\n")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Default license collection and SBOM export must never open a socket."""

    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(sca, "_requests", None)
    monkeypatch.setattr(sca, "_query_osv_batch", forbidden)


# ---------------------------------------------------------------- normalization


@pytest.mark.parametrize(
    "value, expected",
    [
        ("MIT", "MIT"),
        ("mit", "MIT"),
        ("MIT License", "MIT"),
        ("The MIT License", "MIT"),
        ("Apache 2.0", "Apache-2.0"),
        ("Apache License, Version 2.0", "Apache-2.0"),
        ("apache-2.0", "Apache-2.0"),
        ("BSD-3-Clause", "BSD-3-Clause"),
        ("New BSD", "BSD-3-Clause"),
        ("ISC", "ISC"),
        ("GPL-3.0", "GPL-3.0-only"),
        ("GPL-2.0+", "GPL-2.0-or-later"),
        ("GPLv3+", "GPL-3.0-or-later"),
        ("AGPL-3.0", "AGPL-3.0-only"),
        ("(MIT OR Apache-2.0)", "MIT OR Apache-2.0"),
        ("MIT or Apache-2.0", "MIT OR Apache-2.0"),
        ("((MIT))", "MIT"),
        ("(MIT OR Apache-2.0) AND ISC", "(MIT OR Apache-2.0) AND ISC"),
        (
            "GPL-2.0-only WITH Classpath-exception-2.0",
            "GPL-2.0-only WITH Classpath-exception-2.0",
        ),
        ("LicenseRef-Acme-Proprietary", "LicenseRef-Acme-Proprietary"),
        ({"type": "MIT", "url": "https://x"}, "MIT"),
        ([{"type": "MIT"}, {"type": "Apache-2.0"}], "MIT OR Apache-2.0"),
        ("License :: OSI Approved :: MIT License", "MIT"),
        (
            "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
            "GPL-3.0-or-later",
        ),
    ],
)
def test_normalization_table(value, expected):
    assert lic.normalize_license(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "BSD",
        "BSD License",
        "GPL",
        "GPLv3",
        "Apache",
        "Apache Software License",
        "License :: OSI Approved :: BSD License",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "UNLICENSED",
        "SEE LICENSE IN LICENSE.md",
        "Public Domain",
        "Dual License",
        "MIT AND",
        "MIT WITH Nonexistent-exception",
        "",
        None,
        42,
        [{"type": "MIT"}, {"type": "BSD"}],
    ],
)
def test_ambiguous_values_are_not_guessed(value):
    assert lic.normalize_license(value) is None


# ------------------------------------------------------------------- collection


def test_npm_lockfile_licenses_and_unknown_is_noassertion(tmp_path):
    _npm(tmp_path)
    inventory = sca.collect_dependencies(tmp_path)
    licenses = lic.collect_licenses(inventory, tmp_path)
    records = {d["name"]: licenses.get_record(d) for d in inventory}
    assert records["parent"]["license"] == "MIT"
    assert records["parent"]["source"] == "package-lock.json"
    assert records["@example/child"]["license"] == "MIT OR Apache-2.0"
    assert records["gpl-lib"]["license"] == "GPL-3.0-only"
    assert records["gpl-lib"]["declared"] == "GPL-3.0"
    assert records["mystery"]["license"] == lic.NOASSERTION
    assert records["mystery"]["declared"] == "BSD"
    assert records["nolicense"]["license"] == lic.NOASSERTION
    assert licenses.receipt["mode"] == "offline"
    assert licenses.receipt["declared_count"] == 3
    assert licenses.receipt["noassertion_count"] == 2
    assert licenses.receipt["lookup"] == {"enabled": False}


def test_npm_installed_package_json_must_match_version(tmp_path):
    _write(
        tmp_path / "package.json", '{"dependencies":{"left":"1.0.0","right":"2.0.0"}}'
    )
    _write(
        tmp_path / "node_modules" / "left" / "package.json",
        '{"name":"left","version":"1.0.0","license":"ISC"}',
    )
    _write(
        tmp_path / "node_modules" / "right" / "package.json",
        '{"name":"right","version":"9.9.9","license":"MIT"}',
    )
    inventory = sca.collect_dependencies(tmp_path)
    licenses = lic.collect_licenses(inventory, tmp_path)
    records = {d["name"]: licenses.get_record(d) for d in inventory}
    assert records["left"] == {
        "license": "ISC",
        "source": "node_modules/package.json",
        "declared": "ISC",
    }
    assert records["right"]["license"] == lic.NOASSERTION


def test_python_metadata_from_project_venv_requires_exact_version(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "skylos-fake-expr==1.0\nskylos-fake-cls==2.0\nskylos-fake-mismatch==3.0\n"
        "skylos-fake-ambiguous==4.0\n",
    )
    _dist_info(tmp_path, "skylos_fake_expr", "1.0", expression="Apache-2.0 OR MIT")
    _dist_info(
        tmp_path,
        "skylos-fake-cls",
        "2.0",
        license_field="see LICENSE file for the full text of the licence",
        classifiers=["License :: OSI Approved :: MIT License"],
    )
    _dist_info(tmp_path, "skylos-fake-mismatch", "3.1", license_field="MIT")
    _dist_info(
        tmp_path,
        "skylos-fake-ambiguous",
        "4.0",
        classifiers=["License :: OSI Approved :: BSD License"],
    )
    inventory = sca.collect_dependencies(tmp_path)
    licenses = lic.collect_licenses(inventory, tmp_path)
    records = {d["name"]: licenses.get_record(d) for d in inventory}
    assert records["skylos-fake-expr"]["license"] == "Apache-2.0 OR MIT"
    assert records["skylos-fake-expr"]["source"] == "python-metadata:License-Expression"
    assert records["skylos-fake-cls"]["license"] == "MIT"
    assert records["skylos-fake-cls"]["source"] == "python-metadata:Classifier"
    assert records["skylos-fake-mismatch"]["license"] == lic.NOASSERTION
    assert records["skylos-fake-mismatch"]["source"] == "none"
    assert records["skylos-fake-ambiguous"]["license"] == lic.NOASSERTION


def test_go_has_no_offline_license_source(tmp_path):
    _write(
        tmp_path / "go.mod", "module example.org/app\nrequire example.org/lib v1.2.0\n"
    )
    inventory = sca.collect_dependencies(tmp_path)
    licenses = lic.collect_licenses(inventory, tmp_path)
    assert licenses.get_record(inventory[0])["license"] == lic.NOASSERTION


def test_lookup_is_opt_in_and_only_fills_unknowns(tmp_path):
    _npm(tmp_path)
    inventory = sca.collect_dependencies(tmp_path)
    calls = []

    def fake_fetch(dependency, timeout):
        calls.append((dependency["name"], timeout))
        if dependency["name"] == "mystery":
            return {"license": "BSD-2-Clause", "source": "deps.dev", "declared": "x"}
        raise TimeoutError

    assert (
        lic.collect_licenses(inventory, tmp_path).receipt["lookup"]["enabled"] is False
    )
    assert calls == []
    licenses = lic.collect_licenses(inventory, tmp_path, lookup=True, fetch=fake_fetch)
    assert sorted(name for name, _ in calls) == ["mystery", "nolicense"]
    assert all(timeout == lic.LOOKUP_TIMEOUT_SECONDS for _, timeout in calls)
    records = {d["name"]: licenses.get_record(d) for d in inventory}
    assert records["mystery"]["license"] == "BSD-2-Clause"
    assert records["nolicense"]["license"] == lic.NOASSERTION
    assert licenses.receipt["lookup"] == {
        "enabled": True,
        "provider": "deps.dev",
        "attempted": 2,
        "errors": 1,
    }


# ------------------------------------------------------------------- CycloneDX


def test_cyclonedx_components_carry_licenses(tmp_path):
    _npm(tmp_path)
    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)
    components = {item["purl"]: item for item in document["components"]}
    assert components["pkg:npm/parent@1.0.0"]["licenses"] == [
        {"license": {"id": "MIT"}}
    ]
    assert components["pkg:npm/%40example/child@2.0.0"]["licenses"] == [
        {"expression": "MIT OR Apache-2.0"}
    ]
    assert components["pkg:npm/gpl-lib@1.0.0"]["licenses"] == [
        {"license": {"id": "GPL-3.0-only"}}
    ]
    # Unknown in CycloneDX is the absence of a licenses entry, never a guess.
    assert "licenses" not in components["pkg:npm/mystery@0.1.0"]
    assert "licenses" not in components["pkg:npm/nolicense@0.2.0"]
    assert {
        "name": "skylos:license:source",
        "value": "package-lock.json",
    } in components["pkg:npm/parent@1.0.0"]["properties"]
    props = {p["name"]: p["value"] for p in document["metadata"]["properties"]}
    assert props["skylos:licenses"] != "not_collected"
    receipt = json.loads(props["skylos:licenses"])
    assert receipt["declared_count"] == 3 and receipt["noassertion_count"] == 2


# ------------------------------------------------------------------------ SPDX

# Required-field subset of the official SPDX 2.3 JSON schema
# (spdx-spec support/2.3 schemas/spdx-schema.json). The full schema is not
# vendored; these are the document/package/relationship requirements.
_SPDX_SUBSET_SCHEMA = {
    "type": "object",
    "required": [
        "spdxVersion",
        "dataLicense",
        "SPDXID",
        "name",
        "documentNamespace",
        "creationInfo",
    ],
    "properties": {
        "spdxVersion": {"const": "SPDX-2.3"},
        "dataLicense": {"const": "CC0-1.0"},
        "SPDXID": {"const": "SPDXRef-DOCUMENT"},
        "documentNamespace": {"type": "string", "pattern": "^https?://"},
        "creationInfo": {
            "type": "object",
            "required": ["created", "creators"],
            "properties": {
                "created": {
                    "type": "string",
                    "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                },
                "creators": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "string",
                        "pattern": "^(Tool|Organization|Person): ",
                    },
                },
            },
        },
        "packages": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["SPDXID", "name", "downloadLocation"],
                "properties": {
                    "SPDXID": {
                        "type": "string",
                        "pattern": r"^SPDXRef-[A-Za-z0-9.\-]+$",
                    },
                    "filesAnalyzed": {"type": "boolean"},
                    "externalRefs": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "referenceCategory",
                                "referenceType",
                                "referenceLocator",
                            ],
                            "properties": {
                                "referenceCategory": {
                                    "enum": [
                                        "OTHER",
                                        "PERSISTENT-ID",
                                        "SECURITY",
                                        "PACKAGE-MANAGER",
                                        "PACKAGE_MANAGER",
                                        "PERSISTENT_ID",
                                    ]
                                }
                            },
                        },
                    },
                    "primaryPackagePurpose": {
                        "enum": [
                            "OTHER",
                            "INSTALL",
                            "ARCHIVE",
                            "FIRMWARE",
                            "APPLICATION",
                            "FRAMEWORK",
                            "LIBRARY",
                            "CONTAINER",
                            "SOURCE",
                            "DEVICE",
                            "OPERATING_SYSTEM",
                            "FILE",
                        ]
                    },
                },
            },
        },
        "relationships": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["spdxElementId", "relationshipType", "relatedSpdxElement"],
            },
        },
    },
}


def test_spdx_document_structure(tmp_path):
    _npm(tmp_path)
    document = spdx_document(sca.collect_dependencies(tmp_path), tmp_path)
    try:
        import jsonschema
    except ImportError:  # pragma: no cover
        jsonschema = None
    if jsonschema is not None:
        jsonschema.validate(document, _SPDX_SUBSET_SCHEMA)

    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["creationInfo"]["creators"][0].startswith("Tool: skylos-")
    packages = {item["SPDXID"]: item for item in document["packages"]}
    assert len(packages) == len(document["packages"])  # unique ids
    root = packages["SPDXRef-RootPackage"]
    deps = {
        item["externalRefs"][0]["referenceLocator"]: item
        for item in document["packages"]
        if item is not root
    }
    parent = deps["pkg:npm/parent@1.0.0"]
    assert parent["name"] == "parent"
    assert parent["versionInfo"] == "1.0.0"
    assert parent["downloadLocation"] == "NOASSERTION"
    assert parent["licenseConcluded"] == "NOASSERTION"
    assert parent["licenseDeclared"] == "MIT"
    assert parent["copyrightText"] == "NOASSERTION"
    assert parent["filesAnalyzed"] is False
    assert parent["externalRefs"] == [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:npm/parent@1.0.0",
        }
    ]
    assert deps["pkg:npm/%40example/child@2.0.0"]["name"] == "@example/child"
    assert (
        deps["pkg:npm/%40example/child@2.0.0"]["licenseDeclared"] == "MIT OR Apache-2.0"
    )
    assert deps["pkg:npm/mystery@0.1.0"]["licenseDeclared"] == "NOASSERTION"
    assert deps["pkg:npm/nolicense@0.2.0"]["licenseDeclared"] == "NOASSERTION"

    edges = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in document["relationships"]
    }
    ids = {ref: item["SPDXID"] for ref, item in deps.items()}
    assert ("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-RootPackage") in edges
    assert ("SPDXRef-RootPackage", "DEPENDS_ON", ids["pkg:npm/parent@1.0.0"]) in edges
    assert ("SPDXRef-RootPackage", "DEPENDS_ON", ids["pkg:npm/gpl-lib@1.0.0"]) in edges
    assert (
        ids["pkg:npm/parent@1.0.0"],
        "DEPENDS_ON",
        ids["pkg:npm/%40example/child@2.0.0"],
    ) in edges
    # Every referenced element exists, and every package is reachable from root.
    known = set(packages) | {"SPDXRef-DOCUMENT"}
    assert all(a in known and b in known for a, _, b in edges)
    assert {b for _, _, b in edges} >= set(packages)
    assert str(tmp_path) not in json.dumps(document)


def test_spdx_license_ref_gets_extracted_licensing_info(tmp_path):
    _write(
        tmp_path / "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "dependencies": {"acme": "1.0.0"}},
                    "node_modules/acme": {
                        "version": "1.0.0",
                        "license": "LicenseRef-Acme",
                    },
                },
            }
        ),
    )
    document = spdx_document(sca.collect_dependencies(tmp_path), tmp_path)
    assert document["hasExtractedLicensingInfos"] == [
        {"licenseId": "LicenseRef-Acme", "extractedText": "LicenseRef-Acme"}
    ]


def test_spdx_created_honours_source_date_epoch(tmp_path, monkeypatch):
    _npm(tmp_path)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    document = spdx_document(sca.collect_dependencies(tmp_path), tmp_path)
    assert document["creationInfo"]["created"] == "1970-01-01T00:00:00Z"
    again = spdx_document(sca.collect_dependencies(tmp_path), tmp_path)
    assert again == document


def test_sbom_cli_spdx_format_offline(tmp_path, capsys):
    _npm(tmp_path)
    assert run_sbom_command([str(tmp_path), "--format", "spdx-json"]) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert re.match(r"^https://", document["documentNamespace"])
    assert captured.err == ""


def test_sbom_cli_default_makes_no_network_calls(tmp_path, capsys):
    _npm(tmp_path)
    _write(tmp_path / "requirements.txt", "skylos-fake-pkg==1.0\n")
    _write(
        tmp_path / "go.mod", "module example.org/app\nrequire example.org/lib v1.2.0\n"
    )
    # The autouse fixture makes any socket use raise.
    assert run_sbom_command([str(tmp_path)]) == 0
    assert run_sbom_command([str(tmp_path), "--format", "spdx-json"]) == 0
    capsys.readouterr()


# ---------------------------------------------------------------------- policy


def _findings(tmp_path, config, **kwargs):
    inventory = sca.collect_dependencies(tmp_path)
    licenses = lic.collect_licenses(inventory, tmp_path)
    return lic.evaluate_license_policy(inventory, licenses, config, tmp_path, **kwargs)


def test_policy_deny_produces_finding(tmp_path):
    _npm(tmp_path)
    findings = _findings(tmp_path, {"license_deny": ["GPL-3.0-only", "AGPL-3.0-only"]})
    assert [f["symbol"] for f in findings] == ["gpl-lib@1.0.0"]
    finding = findings[0]
    assert finding["rule_id"] == "SKY-SCA-LIC001"
    assert finding["category"] == "DEPENDENCY"
    assert finding["severity"] == "HIGH"
    assert finding["metadata"]["license"] == "GPL-3.0-only"
    assert finding["metadata"]["denied_licenses"] == ["GPL-3.0-only"]
    assert finding["file"].endswith("package-lock.json")
    assert "GPL-3.0-only" in finding["message"]


def test_policy_severity_glob_and_deprecated_deny_ids(tmp_path):
    _npm(tmp_path)
    findings = _findings(
        tmp_path, {"license_deny": ["GPL-*"], "license_severity": "medium"}
    )
    assert [f["symbol"] for f in findings] == ["gpl-lib@1.0.0"]
    assert findings[0]["severity"] == "MEDIUM"
    # A deprecated id in config normalizes the same way as package metadata.
    assert _findings(tmp_path, {"license_deny": ["GPL-3.0"]})


def test_policy_or_expression_with_permitted_choice_is_not_a_violation(tmp_path):
    _npm(tmp_path)
    assert not [
        f
        for f in _findings(tmp_path, {"license_deny": ["Apache-2.0"]})
        if f["symbol"] == "@example/child@2.0.0"
    ]
    violations = _findings(tmp_path, {"license_deny": ["Apache-2.0", "MIT"]})
    assert {f["symbol"] for f in violations} == {"@example/child@2.0.0", "parent@1.0.0"}


def test_policy_allow_list(tmp_path):
    _npm(tmp_path)
    findings = _findings(tmp_path, {"license_allow": ["MIT"]})
    assert [f["symbol"] for f in findings] == ["gpl-lib@1.0.0"]
    assert findings[0]["metadata"]["policy"] == "allow"
    assert findings[0]["metadata"]["disallowed_licenses"] == ["GPL-3.0-only"]


def test_unknown_license_never_produces_a_finding(tmp_path):
    _npm(tmp_path)
    findings = _findings(tmp_path, {"license_deny": ["*"], "license_allow": ["0BSD"]})
    symbols = {f["symbol"] for f in findings}
    assert "mystery@0.1.0" not in symbols
    assert "nolicense@0.2.0" not in symbols
    assert symbols == {"parent@1.0.0", "@example/child@2.0.0", "gpl-lib@1.0.0"}


def test_policy_exceptions_and_project_ignore(tmp_path):
    _npm(tmp_path)
    config = {"license_deny": ["GPL-3.0-only"], "license_exceptions": ["gpl-lib@1.0.0"]}
    assert _findings(tmp_path, config) == []
    config = {"license_deny": ["GPL-3.0-only"]}
    assert _findings(tmp_path, config, project_ignore={"SKY-SCA-LIC001"}) == []


def test_policy_inline_ignore_on_manifest_line(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "skylos-fake-gpl==1.0  # skylos: ignore[SKY-SCA-LIC001] legal approved\n"
        "skylos-fake-agpl==2.0\n",
    )
    _dist_info(tmp_path, "skylos-fake-gpl", "1.0", license_field="GPL-3.0-only")
    _dist_info(tmp_path, "skylos-fake-agpl", "2.0", expression="AGPL-3.0-only")
    suppressed = []
    findings = _findings(
        tmp_path, {"license_deny": ["GPL-*", "AGPL-*"]}, suppressed=suppressed
    )
    assert [f["symbol"] for f in findings] == ["skylos-fake-agpl@2.0"]
    assert [f["symbol"] for f in suppressed] == ["skylos-fake-gpl@1.0"]
    assert suppressed[0]["reason"] == "inline ignore comment"


def test_no_policy_means_no_work(tmp_path, monkeypatch):
    _npm(tmp_path)
    monkeypatch.setattr(
        sca, "collect_dependencies", lambda *a, **k: pytest.fail("should not run")
    )
    assert lic.scan_license_policy(tmp_path, {}) == []
    assert lic.scan_license_policy(tmp_path, {"license_deny": []}) == []


def test_config_keys_load_and_sanitize(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos]\nlicense_deny = ["GPL-3.0-only", 7]\n'
        'license_allow = "MIT"\nlicense_severity = "bogus"\n',
    )
    config = load_config(tmp_path)
    assert config["license_deny"] == ["GPL-3.0-only"]
    assert config["license_allow"] == []
    assert config["license_exceptions"] == []
    assert config["license_severity"] == "HIGH"


def test_synced_license_policy_cannot_be_weakened_by_repo(tmp_path):
    _write(
        tmp_path / ".skylos" / "config.yaml",
        "license_deny:\n  - AGPL-3.0-only\nlicense_severity: CRITICAL\n",
    )
    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos]\nlicense_deny = []\nlicense_exceptions = ["evil"]\n'
        'license_severity = "LOW"\nignore = ["SKY-SCA-LIC001", "SKY-U001"]\n',
    )
    config = load_config(tmp_path)
    assert config["license_deny"] == ["AGPL-3.0-only"]
    assert config["license_exceptions"] == []
    assert config["license_severity"] == "CRITICAL"
    assert "SKY-SCA-LIC001" not in config["ignore"]
    assert "SKY-U001" in config["ignore"]


def test_full_scan_reports_license_findings_in_sca_bucket(tmp_path):
    from skylos.analyzer import analyze

    _npm(tmp_path)
    _write(tmp_path / "app.py", "x = 1\n")
    _write(tmp_path / "pyproject.toml", '[tool.skylos]\nlicense_deny = ["GPL-*"]\n')
    result = json.loads(analyze(str(tmp_path), enable_sca=True))
    rule_ids = [f["rule_id"] for f in result.get("dependency_vulnerabilities", [])]
    assert rule_ids == ["SKY-SCA-LIC001"]
    assert result["analysis_summary"]["sca_count"] == 1

    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos]\nlicense_deny = ["GPL-*"]\nignore = ["SKY-SCA-LIC001"]\n',
    )
    result = json.loads(analyze(str(tmp_path), enable_sca=True))
    assert not result.get("dependency_vulnerabilities")


def test_rule_is_cataloged_and_documented():
    from pathlib import Path

    from skylos.rules.catalog import get_rule_catalog

    rules = {rule["id"]: rule for rule in get_rule_catalog()}
    assert rules["SKY-SCA-LIC001"]["category"] == "dependency"
    dictionary = Path(__file__).resolve().parents[1] / "dictionary.md"
    assert "| SKY-SCA-LIC001 |" in dictionary.read_text(encoding="utf-8")


def test_inline_ignore_applies_to_any_declaring_occurrence(tmp_path):
    _write(tmp_path / "requirements.txt", "skylos-fake-gpl==1.0\n")
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndependencies = [\n'
        '  "skylos-fake-gpl==1.0",  # skylos: ignore[SKY-SCA-LIC001]\n]\n',
    )
    _dist_info(tmp_path, "skylos-fake-gpl", "1.0", license_field="GPL-3.0-only")
    inventory = sca.collect_dependencies(tmp_path)
    assert len(inventory[0]["dependency_occurrences"]) == 2
    assert _findings(tmp_path, {"license_deny": ["GPL-*"]}) == []
