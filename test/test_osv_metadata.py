from copy import deepcopy

import pytest

from skylos.rules.sca.advisory_metadata import (
    advisory_matches_dependency,
    extract_advisory_metadata,
)


@pytest.fixture
def dep():
    return {"name": "lodash", "ecosystem": "npm", "version": "4.17.20"}


@pytest.fixture
def advisory():
    return {
        "id": "GHSA-test",
        "summary": "A reported package vulnerability",
        "aliases": ["CVE-2021-0000"],
        "database_specific": {"severity": "MODERATE"},
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                    }
                ],
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
    }


def test_hydrated_metadata_has_real_labels_and_fix_without_fabricated_cvss(
    advisory, dep
):
    result = extract_advisory_metadata(advisory, dep)
    assert result["severity"] == "MEDIUM"
    assert result["cvss_score"] is None
    assert result["severity_vectors"] == advisory["severity"]
    assert result["fixed_version"] == "4.17.21"
    assert result["fixed_versions"] == ["4.17.21"]
    assert result["affected_range"] == "<4.17.21"
    assert result["aliases"] == ["CVE-2021-0000"]
    assert result["references"] == ["https://example.com/advisory"]
    assert advisory_matches_dependency(advisory, dep)


@pytest.mark.parametrize(
    "score,severity",
    [
        (0, "LOW"),
        (3.9, "LOW"),
        (4, "MEDIUM"),
        (7, "HIGH"),
        (9, "CRITICAL"),
        ("10", "CRITICAL"),
    ],
)
def test_actual_numeric_cvss_is_preserved(score, severity, advisory, dep):
    advisory["database_specific"] = {"cvss_score": score}
    result = extract_advisory_metadata(advisory, dep)
    assert result["cvss_score"] == float(score)
    assert result["severity"] == severity


@pytest.mark.parametrize("score", [True, False, "nan", "inf", -1, 11, {}, None])
def test_invalid_numeric_scores_are_not_classified(score, advisory, dep):
    advisory["database_specific"] = {"cvss_score": score}
    result = extract_advisory_metadata(advisory, dep)
    assert result["cvss_score"] is None
    assert result["severity"] == "UNKNOWN"


def test_highest_reported_numeric_score_is_used(advisory, dep):
    advisory["severity"] = [
        {"type": "CVSS_V3", "score": "5.1"},
        {"type": "CVSS_V4", "score": "9.2"},
    ]
    assert extract_advisory_metadata(advisory, dep)["cvss_score"] == 9.2


def test_untyped_database_score_is_not_assumed_to_be_cvss(advisory, dep):
    advisory["database_specific"] = {"score": 0.8}
    result = extract_advisory_metadata(advisory, dep)
    assert result["cvss_score"] is None
    assert result["severity"] == "UNKNOWN"


def test_package_severity_is_selected_without_unrelated_package_scores(advisory, dep):
    advisory["database_specific"] = {"severity": "CRITICAL", "cvss_score": 10}
    advisory["severity"] = [{"type": "CVSS_V3", "score": "10"}]
    advisory["affected"][0]["severity"] = [{"type": "CVSS_V3", "score": "5.1"}]
    unrelated = deepcopy(advisory["affected"][0])
    unrelated["package"]["name"] = "another-package"
    unrelated["severity"] = [{"type": "CVSS_V3", "score": "9.8"}]
    advisory["affected"].append(unrelated)
    result = extract_advisory_metadata(advisory, dep)
    assert result["cvss_score"] == 5.1
    assert result["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "label,expected",
    [
        ("LOW", "LOW"),
        ("moderate", "MEDIUM"),
        ("MEDIUM", "MEDIUM"),
        ("high", "HIGH"),
        ("CRITICAL", "CRITICAL"),
    ],
)
def test_matching_ecosystem_severity_label_is_used_without_numeric_invention(
    label, expected, advisory, dep
):
    advisory.pop("database_specific")
    advisory["affected"][0]["ecosystem_specific"] = {"severity": label}
    result = extract_advisory_metadata(advisory, dep)
    assert result["severity"] == expected
    assert result["cvss_score"] is None
    assert result["severity_vectors"] == advisory["severity"]


@pytest.mark.parametrize("label", [None, 9.8, "9.8", "UNKNOWN", "important", {}])
def test_unrecognized_ecosystem_label_is_not_interpreted_as_cvss(label, advisory, dep):
    advisory.pop("database_specific")
    advisory["affected"][0]["ecosystem_specific"] = {"severity": label}
    result = extract_advisory_metadata(advisory, dep)
    assert result["severity"] == "UNKNOWN"
    assert result["cvss_score"] is None


@pytest.mark.parametrize(
    "package",
    [{"name": "other", "ecosystem": "npm"}, {"name": "lodash", "ecosystem": "PyPI"}],
)
def test_unrelated_package_ecosystem_severity_is_ignored(package, advisory, dep):
    advisory.pop("database_specific")
    unrelated = deepcopy(advisory["affected"][0])
    unrelated["package"] = package
    unrelated["ecosystem_specific"] = {"severity": "CRITICAL"}
    advisory["affected"].append(unrelated)
    result = extract_advisory_metadata(advisory, dep)
    assert result["severity"] == "UNKNOWN"
    assert result["cvss_score"] is None


def test_ecosystem_label_coexists_with_matching_package_vector(advisory, dep):
    advisory.pop("database_specific")
    advisory["affected"][0]["severity"] = advisory.pop("severity")
    advisory["affected"][0]["ecosystem_specific"] = {"severity": "HIGH"}
    result = extract_advisory_metadata(advisory, dep)
    assert result["severity"] == "HIGH"
    assert result["cvss_score"] is None
    assert result["severity_vectors"] == advisory["affected"][0]["severity"]


def test_ecosystem_label_does_not_replace_actual_numeric_score(advisory, dep):
    advisory["database_specific"] = {"cvss_score": 9.8}
    advisory["affected"][0]["ecosystem_specific"] = {"severity": "HIGH"}
    result = extract_advisory_metadata(advisory, dep)
    assert result["severity"] == "CRITICAL"
    assert result["cvss_score"] == 9.8


@pytest.mark.parametrize(
    "change",
    [{"name": "different"}, {"ecosystem": "PyPI"}, {"name": "Lodash"}, {"name": None}],
)
def test_other_package_metadata_is_never_an_upgrade_hint(change, advisory, dep):
    advisory["affected"][0]["package"].update(change)
    assert not advisory_matches_dependency(advisory, dep)
    result = extract_advisory_metadata(advisory, dep)
    assert result["fixed_version"] is None
    assert result["fixed_versions"] == []
    assert result["affected_range"] == "unknown"


def test_pypi_canonical_name_and_stable_release_comparison(advisory):
    advisory["affected"][0] = {
        "package": {"name": "My.Python_package", "ecosystem": "PyPI"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1"}, {"fixed": "1.2"}]}
        ],
    }
    dep = {"name": "my-python-package", "ecosystem": "PyPI", "version": "1.1.0"}
    assert advisory_matches_dependency(advisory, dep)
    assert extract_advisory_metadata(advisory, dep)["fixed_version"] == "1.2"
    dep["version"] = "1.2.0"
    assert extract_advisory_metadata(advisory, dep)["fixed_version"] is None


@pytest.mark.parametrize(
    "current", ["4.17.21", "5.0.0", "4.17.20-beta", "4.17.20+build"]
)
def test_no_downgrade_equal_or_unproven_version_hint(current, advisory, dep):
    dep["version"] = current
    result = extract_advisory_metadata(advisory, dep)
    assert result["fixed_version"] is None
    assert result["fixed_versions"] == ["4.17.21"]


def test_multiple_release_branches_preserve_fixes_without_choosing_one(advisory, dep):
    advisory["affected"][0]["ranges"].append(
        {"type": "SEMVER", "events": [{"introduced": "5.0.0"}, {"fixed": "5.2.0"}]}
    )
    result = extract_advisory_metadata(advisory, dep)
    assert result["fixed_version"] is None
    assert result["fixed_versions"] == ["4.17.21", "5.2.0"]
    assert result["affected_range"] == "<4.17.21; >=5.0.0, <5.2.0"


def test_current_version_outside_fixed_interval_gets_no_hint(advisory, dep):
    advisory["affected"][0]["ranges"][0]["events"][0] = {"introduced": "4.17.21"}
    advisory["affected"][0]["ranges"][0]["events"][1] = {"fixed": "4.17.22"}
    assert extract_advisory_metadata(advisory, dep)["fixed_version"] is None


def test_reintroduced_vulnerability_does_not_suggest_affected_fix(advisory, dep):
    advisory["affected"][0]["ranges"].append(
        {"type": "SEMVER", "events": [{"introduced": "4.17.21"}]}
    )
    assert extract_advisory_metadata(advisory, dep)["fixed_version"] is None


@pytest.mark.parametrize("versions", [["4.17.21"], ["unrecognized-version"]])
def test_explicit_affected_versions_veto_unsafe_hint(versions, advisory, dep):
    advisory["affected"][0]["versions"] = versions
    assert extract_advisory_metadata(advisory, dep)["fixed_version"] is None


def test_git_fix_is_not_reported_as_package_upgrade(advisory, dep):
    advisory["affected"][0]["ranges"] = [
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "a" * 40}]}
    ]
    result = extract_advisory_metadata(advisory, dep)
    assert result["fixed_version"] is None
    assert result["fixed_versions"] == []


@pytest.mark.parametrize(
    "ending,expected", [("last_affected", "<=4.17.21"), ("limit", "<4.17.21")]
)
def test_nonfix_range_end_is_displayed_but_not_an_upgrade(
    ending, expected, advisory, dep
):
    advisory["affected"][0]["ranges"][0]["events"][1] = {ending: "4.17.21"}
    result = extract_advisory_metadata(advisory, dep)
    assert result["affected_range"] == expected
    assert result["fixed_versions"] == []
    assert result["fixed_version"] is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        "bad",
        [None],
        [{"events": None}],
        [{"type": "SEMVER", "events": [{"fixed": "4.17.21"}]}],
        [{"type": "SEMVER", "events": [{"introduced": "0", "fixed": "4.17.21"}]}],
    ],
)
def test_malformed_ranges_never_yield_hint(value, advisory, dep):
    advisory["affected"][0]["ranges"] = value
    assert extract_advisory_metadata(advisory, dep)["fixed_version"] is None


def test_missing_details_remain_unknown(dep):
    result = extract_advisory_metadata({"id": "GHSA-test"}, dep)
    assert result["summary"] == "Known vulnerability (GHSA-test)"
    assert result["severity"] == "UNKNOWN"
    assert result["cvss_score"] is None
    assert result["fixed_version"] is None
    assert result["fixed_versions"] == []
    assert result["affected_range"] == "unknown"


def test_optional_null_or_bad_shapes_are_tolerated(dep):
    result = extract_advisory_metadata(
        {
            "id": "GHSA-test",
            "database_specific": None,
            "severity": [None],
            "summary": None,
            "details": {},
            "affected": [None, {"package": None}],
            "aliases": [None, "CVE-2021-0000", "CVE-2021-0000"],
            "references": [
                None,
                {"url": "javascript:ignored"},
                {"url": "https://example.com/a"},
            ],
        },
        dep,
    )
    assert result["summary"] == "CVE-2021-0000"
    assert result["aliases"] == ["CVE-2021-0000"]
    assert result["references"] == ["https://example.com/a"]


def test_withdrawn_is_explicit_not_a_silent_suppression(advisory, dep):
    advisory["withdrawn"] = "2026-09-14T00:00:00Z"
    assert (
        extract_advisory_metadata(advisory, dep)["withdrawn"] == advisory["withdrawn"]
    )


def test_extraction_does_not_mutate_advisory_or_dependency(advisory, dep):
    old_advisory, old_dep = deepcopy(advisory), deepcopy(dep)
    extract_advisory_metadata(advisory, dep)
    assert advisory == old_advisory
    assert dep == old_dep
