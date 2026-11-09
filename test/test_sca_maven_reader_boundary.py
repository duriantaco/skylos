"""Unscanned POM metadata cannot establish parent or reactor coverage proof."""

from pathlib import Path

import pytest

from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_listed
from skylos.rules.sca import maven_pom as maven
from skylos.rules.sca import vulnerability_scanner as sca
from test.test_sca_more_ecosystems import (
    LOG4J,
    _dependencies,
    _pom,
    _write,
    osv as osv,
)


def _outside_parses(monkeypatch, root):
    parsed = []
    original = maven._model

    def record(path, text):
        if not Path(path).resolve().is_relative_to(root.resolve()):
            parsed.append(str(path))
        return original(path, text)

    monkeypatch.setattr(maven, "_model", record)
    return parsed


def _gate(result):
    return check_gate(
        {
            "dependency_vulnerabilities": list(result),
            "analysis_summary": {"sca_coverage": result.receipt},
        },
        {"gate": {"max_dependency_vulnerabilities": 0}},
    )[0]


def _assert_declared_finding(result, osv):
    assert osv.queried() == [("Maven", LOG4J, "2.14.1")]
    [finding] = result
    assert finding["rule_id"] == "SKY-SCA-OSV-TEST-0"
    assert finding["metadata"]["package_name"] == LOG4J
    assert finding["metadata"]["package_version"] == "2.14.1"
    assert is_listed(finding)
    assert _gate(result) is False


@pytest.mark.parametrize("reference", ["directory", "file", "directory-link"])
@pytest.mark.parametrize("valid_xml", [True, False], ids=["matching-pom", "bad-xml"])
def test_module_metadata_cannot_follow_a_pom_outside_the_scan_root(
    tmp_path, monkeypatch, osv, reference, valid_xml
):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    _write(outside, {"pom.xml": _pom(f"{LOG4J}:2.14.1") if valid_xml else "<bad"})
    module = "vendor/local"
    if reference == "file":
        module += "/pom.xml"
    _write(
        root,
        {
            "pom.xml": _pom(
                "example:application:1.0.0",
                f"<modules><module>{module}</module></modules>"
                + _dependencies(f"{LOG4J}:2.14.1"),
            )
        },
    )
    if reference == "directory-link":
        (root / "vendor").mkdir()
        (root / "vendor/local").symlink_to(outside, target_is_directory=True)
    else:
        (root / "vendor/local").mkdir(parents=True)
        (root / "vendor/local/pom.xml").symlink_to(outside / "pom.xml")
    outside_parses = _outside_parses(monkeypatch, root)

    result = sca.scan_dependencies(root)

    assert outside_parses == []
    _assert_declared_finding(result, osv)
    assert result.receipt["status"] == "complete"
    assert result.receipt["parse_error_count"] == 0
    assert result.receipt["unresolved_dependency_count"] == 0


@pytest.mark.parametrize("reference", ["directory", "file"])
@pytest.mark.parametrize("valid_xml", [True, False], ids=["matching-pom", "bad-xml"])
def test_parent_directory_cannot_follow_a_pom_outside_the_scan_root(
    tmp_path, monkeypatch, osv, reference, valid_xml
):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    parent = _pom(
        "example:parent:1.0.0",
        "<properties><library.version>2.14.1</library.version></properties>",
    )
    _write(outside, {"pom.xml": parent if valid_xml else "<bad"})
    relative = "../vendor/parent"
    if reference == "file":
        relative += "/pom.xml"
    _write(
        root,
        {
            "app/pom.xml": _pom(
                "example:application:1.0.0",
                _dependencies(f"{LOG4J}:${{library.version}}"),
                "<parent><groupId>example</groupId><artifactId>parent</artifactId>"
                f"<version>1.0.0</version><relativePath>{relative}</relativePath>"
                "</parent>",
            )
        },
    )
    (root / "vendor/parent").mkdir(parents=True)
    (root / "vendor/parent/pom.xml").symlink_to(outside / "pom.xml")
    outside_parses = _outside_parses(monkeypatch, root)

    result = sca.scan_dependencies(root)

    assert outside_parses == []
    assert osv.queried() == []
    assert list(result) == []
    assert result.receipt["status"] == "complete_with_unresolved_versions"
    assert result.receipt["unresolved_dependency_count"] == 1
    assert result.receipt["parse_error_count"] == 0


def test_symlinked_enclosing_aggregator_is_not_reactor_proof(
    tmp_path, monkeypatch, osv
):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    _write(
        root,
        {"app/pom.xml": _pom("example:app:1.0.0", _dependencies(f"{LOG4J}:2.14.1"))},
    )
    _write(
        outside,
        {
            "pom.xml": _pom(
                f"{LOG4J}:2.14.1", f"<modules><module>{root / 'app'}</module></modules>"
            )
        },
    )
    (root / "pom.xml").symlink_to(outside / "pom.xml")
    outside_parses = _outside_parses(monkeypatch, root)

    result = sca.scan_dependencies(root)

    assert outside_parses == []
    _assert_declared_finding(result, osv)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["parse_error_count"] == 1
    assert result.receipt["parse_errors"][0]["file"] == str(root / "pom.xml")


def test_normal_parent_directory_still_resolves_versions(tmp_path, osv):
    _write(
        tmp_path,
        {
            "vendor/parent/pom.xml": _pom(
                "example:parent:1.0.0",
                "<properties><library.version>2.14.1</library.version></properties>",
            ),
            "app/pom.xml": _pom(
                "example:app:1.0.0",
                _dependencies(f"{LOG4J}:${{library.version}}"),
                "<parent><groupId>example</groupId><artifactId>parent</artifactId>"
                "<version>1.0.0</version><relativePath>../vendor/parent</relativePath></parent>",
            ),
        },
    )

    result = sca.scan_dependencies(tmp_path)

    _assert_declared_finding(result, osv)
    assert result.receipt["status"] == "complete"
    assert result.receipt["unresolved_dependency_count"] == 0


@pytest.mark.parametrize(
    "directory_alias", [True, False], ids=["directory", "final-file"]
)
def test_in_root_directory_alias_keeps_the_final_filename_policy(
    tmp_path, osv, directory_alias
):
    _write(
        tmp_path,
        {
            "pom.xml": _pom(
                "example:app:1.0.0",
                "<modules><module>vendor/alias</module></modules>"
                + _dependencies(f"{LOG4J}:2.14.1"),
            ),
            "real-module/pom.xml": _pom(f"{LOG4J}:2.14.1"),
        },
    )
    (tmp_path / "vendor").mkdir()
    if directory_alias:
        (tmp_path / "vendor/alias").symlink_to(
            tmp_path / "real-module", target_is_directory=True
        )
    else:
        (tmp_path / "vendor/alias").mkdir()
        (tmp_path / "vendor/alias/pom.xml").symlink_to(tmp_path / "real-module/pom.xml")

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "complete"
    assert result.receipt["parse_error_count"] == 0
    if directory_alias:
        assert osv.queried() == []
        assert list(result) == []
        assert _gate(result) is True
    else:
        _assert_declared_finding(result, osv)


@pytest.mark.parametrize("replacement", ["symlink", "directory", "missing"])
def test_cached_reactor_tree_rechecks_a_module_replaced_by_a_symlink(
    tmp_path, monkeypatch, replacement
):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    body = "<modules><module>local</module></modules>" + _dependencies(
        f"{LOG4J}:2.14.1"
    )
    text = _pom("example:app:1.0.0", body)
    _write(root, {"pom.xml": text, "local/pom.xml": _pom(f"{LOG4J}:2.14.1")})
    _write(outside, {"pom.xml": _pom(f"{LOG4J}:2.14.1")})
    cache = maven.PomCache()
    assert maven.pom_inventory(root / "pom.xml", text, root=root, cache=cache) == (
        [],
        0,
    )
    (root / "local/pom.xml").unlink()
    if replacement == "symlink":
        (root / "local/pom.xml").symlink_to(outside / "pom.xml")
    elif replacement == "directory":
        (root / "local/pom.xml").mkdir()
    outside_parses = _outside_parses(monkeypatch, root)

    dependencies, counted = maven.pom_inventory(
        root / "pom.xml", text, root=root, cache=cache
    )

    assert outside_parses == []
    assert [(d["name"], d["version"]) for d in dependencies] == [(LOG4J, "2.14.1")]
    assert counted == 1


def test_a_preloaded_outside_parent_is_not_accepted_from_the_cache(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    _write(
        outside,
        {
            "pom.xml": _pom(
                "example:parent:1.0.0",
                "<properties><library.version>2.14.1</library.version></properties>",
            )
        },
    )
    text = _pom(
        "example:app:1.0.0",
        _dependencies(f"{LOG4J}:${{library.version}}"),
        "<parent><groupId>example</groupId><artifactId>parent</artifactId>"
        "<version>1.0.0</version><relativePath>../vendor/parent</relativePath></parent>",
    )
    _write(root, {"app/pom.xml": text})
    (root / "vendor/parent").mkdir(parents=True)
    (root / "vendor/parent/pom.xml").symlink_to(outside / "pom.xml")
    cache = maven.PomCache()
    maven.parse_pom_xml(outside / "pom.xml", root=outside, cache=cache)
    outside_parses = _outside_parses(monkeypatch, root)

    dependencies, counted = maven.pom_inventory(
        root / "app/pom.xml", text, root=root, cache=cache
    )

    assert outside_parses == []
    assert dependencies == []
    assert counted == 1


def test_cached_parent_is_rechecked_after_its_filename_becomes_a_symlink(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    parent = _pom(
        "example:parent:1.0.0",
        "<properties><library.version>2.14.1</library.version></properties>",
    )
    text = _pom(
        "example:app:1.0.0",
        _dependencies(f"{LOG4J}:${{library.version}}"),
        "<parent><groupId>example</groupId><artifactId>parent</artifactId>"
        "<version>1.0.0</version><relativePath>../vendor/parent</relativePath></parent>",
    )
    _write(root, {"app/pom.xml": text, "vendor/parent/pom.xml": parent})
    _write(outside, {"pom.xml": parent})
    cache = maven.PomCache()
    dependencies, counted = maven.pom_inventory(
        root / "app/pom.xml", text, root=root, cache=cache
    )
    assert [(d["name"], d["version"]) for d in dependencies] == [(LOG4J, "2.14.1")]
    assert counted == 1
    (root / "vendor/parent/pom.xml").unlink()
    (root / "vendor/parent/pom.xml").symlink_to(outside / "pom.xml")
    outside_parses = _outside_parses(monkeypatch, root)

    dependencies, counted = maven.pom_inventory(
        root / "app/pom.xml", text, root=root, cache=cache
    )

    assert outside_parses == []
    assert dependencies == []
    assert counted == 1


def test_explicit_root_rejects_an_outside_top_level_pom_before_parsing(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    _write(
        outside,
        {"pom.xml": _pom("example:app:1.0.0", _dependencies(f"{LOG4J}:2.14.1"))},
    )
    outside_parses = _outside_parses(monkeypatch, root)

    assert maven.parse_pom_xml(outside / "pom.xml", root=root) == []
    assert outside_parses == []
