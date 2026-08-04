import json

import pytest

from skylos.cloud.shadow_upload import prepare_shadow_report_for_cloud
from skylos.commands.compare_cmd import (
    _comparison_scope,
    _has_relevant_worktree_changes,
    _run_local_scan,
    _write_report_no_symlink,
    run_compare_command,
)
from skylos.integrations.shadow import (
    UnsupportedShadowReport,
    build_shadow_report,
    normalize_external_report,
)


SARIF_REPORT = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "semanticVersion": "2.20.0",
                    "rules": [
                        {
                            "id": "py/sql-injection",
                            "properties": {"tags": ["security", "cwe-089"]},
                        }
                    ],
                }
            },
            "versionControlProvenance": [{"revisionId": "abc123"}],
            "invocations": [{"executionSuccessful": True}],
            "results": [
                {
                    "ruleId": "py/sql-injection",
                    "level": "error",
                    "message": {"text": "Untrusted data reaches SQL"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 12, "endLine": 12},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": "abc"},
                }
            ],
        }
    ],
}


def _skylos_result():
    return {
        "definitions": {
            "app.old_query": {
                "name": "old_query",
                "file": "/work/repo/src/app.py",
                "line": 10,
                "loc": 8,
                "dead": True,
                "dead_code_classification": "likely_dead",
                "dead_code_reason": "No static references or entrypoint evidence.",
                "dead_code_reason_tags": ["no_refs", "no_entrypoint"],
            },
            "app.live_query": {
                "name": "live_query",
                "file": "/work/repo/src/app.py",
                "line": 30,
                "loc": 5,
                "dead": False,
                "dead_code_classification": "alive",
            },
        },
        "unused_functions": [
            {
                "name": "old_query",
                "file": "/work/repo/src/app.py",
                "line": 10,
                "confidence": 90,
                "dead_code_classification": "likely_dead",
            }
        ],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "unused_files": [],
        "danger": [
            {
                "rule_id": "SKY-D001",
                "file": "/work/repo/src/app.py",
                "line": 30,
                "message": "Live SQL injection",
                "severity": "HIGH",
            },
            {
                "rule_id": "SKY-D002",
                "file": "/work/repo/src/other.py",
                "line": 7,
                "message": "Skylos-only issue",
                "severity": "HIGH",
            },
        ],
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 2,
            "languages": {"Python": 2},
            "analysis_error_count": 0,
            "grade_categories": ["security", "quality", "secrets", "dead_code"],
            "excluded_folders": [],
            "revision": "abc123",
            "comparison_scope": {
                "kind": "repository_root",
                "scan_path": "/work/repo",
                "repository_root": "/work/repo",
                "complete_repository": True,
                "repository_identities": ["https://github.com/acme/repo.git"],
            },
        },
    }


def test_normalize_sarif_preserves_tool_location_and_fingerprint():
    normalized = normalize_external_report(SARIF_REPORT)

    assert normalized["format"] == "sarif"
    assert normalized["tools"] == ["CodeQL"]
    assert normalized["findings"] == [
        {
            "source_tool": "CodeQL",
            "rule_id": "py/sql-injection",
            "file_path": "src/app.py",
            "line_number": 12,
            "end_line": 12,
            "message": "Untrusted data reaches SQL",
            "severity": "HIGH",
            "category": "SECURITY",
            "external_fingerprint": "abc",
            "external_fingerprints": {"primaryLocationLineHash": "abc"},
        }
    ]
    assert normalized["input_complete"] is None
    assert normalized["execution_successful"] is True
    assert normalized["revisions"] == ["abc123"]
    assert normalized["tool_versions"] == {"CodeQL": ["2.20.0"]}


def test_rejects_malformed_sarif_instead_of_silently_undercounting():
    with pytest.raises(UnsupportedShadowReport, match="identify a tool"):
        normalize_external_report({"runs": [{"results": []}]})


def test_sarif_rule_security_score_and_rule_index_are_preserved():
    normalized = normalize_external_report(
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {
                                    "id": "py/critical",
                                    "properties": {
                                        "security-severity": "9.8",
                                        "tags": ["security"],
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleIndex": 0,
                            "message": {"text": "Critical issue"},
                        }
                    ],
                }
            ]
        }
    )

    assert normalized["findings"][0]["rule_id"] == "py/critical"
    assert normalized["findings"][0]["severity"] == "CRITICAL"


def test_sarif_failed_invocation_and_inactive_results_are_visible():
    normalized = normalize_external_report(
        {
            "runs": [
                {
                    "tool": {"driver": {"name": "Tool", "rules": []}},
                    "invocations": [{"executionSuccessful": False}],
                    "results": [
                        {"kind": "pass", "message": {"text": "Passed"}},
                        {
                            "suppressions": [{"status": "accepted"}],
                            "message": {"text": "Accepted"},
                        },
                        {"message": {"text": "Active"}},
                    ],
                }
            ]
        }
    )

    assert normalized["input_complete"] is False
    assert normalized["execution_successful"] is False
    assert len(normalized["findings"]) == 1
    assert normalized["excluded_findings_count"] == 2
    assert normalized["excluded_by_reason"] == {
        "sarif_kind_pass": 1,
        "sarif_suppression_accepted": 1,
    }


def test_normalize_sonar_issue_search_export():
    normalized = normalize_external_report(
        {
            "issues": [
                {
                    "key": "AX-1",
                    "project": "acme:api",
                    "component": "acme:api:src/app.py",
                    "rule": "python:S3649",
                    "message": "Database query uses formatted input",
                    "severity": "BLOCKER",
                    "type": "VULNERABILITY",
                    "status": "OPEN",
                    "textRange": {"startLine": 30, "endLine": 31},
                }
            ]
        }
    )

    finding = normalized["findings"][0]
    assert normalized["format"] == "sonar"
    assert finding["file_path"] == "src/app.py"
    assert finding["severity"] == "CRITICAL"
    assert finding["category"] == "SECURITY"
    assert finding["external_fingerprint"] == "AX-1"


def test_rejects_malformed_sonar_and_generic_entries():
    with pytest.raises(UnsupportedShadowReport, match="Sonar issue"):
        normalize_external_report({"issues": ["bad"]})
    with pytest.raises(UnsupportedShadowReport, match="generic finding"):
        normalize_external_report({"complete": True, "findings": ["bad"]})


def test_sonar_closed_issue_is_excluded_without_breaking_paging_completeness():
    normalized = normalize_external_report(
        {
            "paging": {"total": 2},
            "issues": [
                {"key": "open", "component": "app:src/a.py", "status": "OPEN"},
                {
                    "key": "closed",
                    "component": "app:src/b.py",
                    "issueStatus": "FIXED",
                },
            ],
        }
    )

    assert normalized["input_complete"] is True
    assert [item["external_fingerprint"] for item in normalized["findings"]] == ["open"]
    assert normalized["excluded_by_reason"] == {"inactive_status": 1}


def test_sonar_pagination_marks_partial_input_incomplete():
    normalized = normalize_external_report(
        {
            "paging": {"pageIndex": 1, "pageSize": 1, "total": 2},
            "issues": [{"key": "AX-1", "component": "app:src/app.py", "line": 1}],
        }
    )

    assert normalized["input_complete"] is False
    report = build_shadow_report(normalized, _skylos_result())
    assert report["complete"] is False


def test_shadow_report_correlates_dead_live_unknown_and_overlap():
    external = normalize_external_report(
        {
            "tool": "Incumbent",
            "findings": [
                {
                    "rule_id": "EXT-1",
                    "file_path": "src/app.py",
                    "line_number": 12,
                    "severity": "HIGH",
                    "category": "SECURITY",
                },
                {
                    "rule_id": "EXT-2",
                    "file_path": "src/app.py",
                    "line_number": 30,
                    "severity": "HIGH",
                    "category": "SECURITY",
                },
                {
                    "rule_id": "EXT-3",
                    "file_path": "src/app.py",
                    "line_number": 99,
                    "severity": "MEDIUM",
                    "category": "QUALITY",
                },
            ],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert report["complete"] is False
    assert report["usable"] is True
    assert report["completeness_state"] == "external_completeness_unknown"
    assert "incumbent_export_completeness_unknown" in report["completeness_reasons"]
    assert report["comparison"] == {
        "location_overlap": 1,
        "external_only": 2,
        "skylos_only": 2,
        "skylos_only_in_observed_comparable_categories": 1,
        "skylos_only_by_category": {"DEAD_CODE": 1, "SECURITY": 1},
        "external_in_likely_dead_code": 1,
        "external_dead_context_excluded_from_benefit": 0,
        "external_in_live_code": 1,
        "external_reachability_unknown": 1,
        "affected_likely_dead_symbols": 1,
        "affected_unused_files": 0,
    }
    states = [
        finding["shadow"]["reachability"]["state"]
        for finding in report["external_findings"]
    ]
    assert states == ["likely_dead", "live", "unknown"]
    assert report["external_findings"][1]["shadow"]["overlapping_skylos_rules"] == [
        "SKY-D001"
    ]
    assert "not an automatic false positive" in report["limitations"][1]


def test_shadow_report_is_incomplete_when_skylos_analysis_failed():
    result = _skylos_result()
    result["analysis_errors"] = [{"kind": "parser_error", "file": "src/app.py"}]

    report = build_shadow_report(normalize_external_report(SARIF_REPORT), result)

    assert report["complete"] is False
    assert report["usable"] is False
    assert report["completeness_state"] == "incomplete"
    assert report["skylos"]["analysis_error_count"] == 1


def test_shadow_report_is_incomplete_for_partial_language_engine():
    result = _skylos_result()
    result["analysis_summary"]["incomplete_languages"] = ["go"]

    report = build_shadow_report(normalize_external_report(SARIF_REPORT), result)

    assert report["complete"] is False
    assert report["skylos"]["incomplete_languages"] == ["go"]


def test_unrecognized_skylos_json_is_not_a_successful_comparison():
    report = build_shadow_report(normalize_external_report(SARIF_REPORT), {})

    assert report["complete"] is False
    assert report["usable"] is False
    assert report["completeness_state"] == "incomplete"
    assert report["skylos"]["recognized_result"] is False
    assert report["benefit"]["claim_scope"] == "not_eligible"
    assert report["benefit"]["review_or_deletion_candidates"] is None


def test_malformed_skylos_bucket_is_not_usable():
    result = _skylos_result()
    result["danger"] = ["bad"]

    report = build_shadow_report(normalize_external_report(SARIF_REPORT), result)

    assert report["usable"] is False
    assert report["skylos"]["recognized_result"] is False
    assert report["benefit"]["review_or_deletion_candidates"] is None


@pytest.mark.parametrize(
    ("field", "value"),
    [("dead", "false"), ("dead_code_reason_tags", 1)],
)
def test_malformed_definition_evidence_is_not_usable(field, value):
    result = _skylos_result()
    result["definitions"]["app.old_query"][field] = value

    report = build_shadow_report(normalize_external_report(SARIF_REPORT), result)

    assert report["usable"] is False
    assert report["skylos"]["recognized_result"] is False
    assert report["benefit"]["review_or_deletion_candidates"] is None


def test_dead_false_without_alive_evidence_remains_unknown():
    result = _skylos_result()
    result["definitions"]["app.live_query"].pop("dead_code_classification")
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identity": "git@github.com:acme/repo.git",
            },
            "findings": [
                {
                    "rule_id": "EXT-1",
                    "file_path": "src/app.py",
                    "line_number": 30,
                }
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["complete"] is True
    assert report["completeness_state"] == "inputs_verified_same_revision"
    assert report["coverage_attested"] is False
    assert report["comparison"]["external_in_live_code"] == 0
    assert report["comparison"]["external_reachability_unknown"] == 1


def test_reachability_uses_narrowest_nested_definition():
    result = _skylos_result()
    result["definitions"]["app.inner"] = {
        "name": "inner",
        "file": "/work/repo/src/app.py",
        "line": 12,
        "loc": 1,
        "dead": False,
        "dead_code_classification": "alive",
    }
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identity": "git@github.com:acme/repo.git",
            },
            "findings": [
                {
                    "rule_id": "EXT",
                    "file_path": "src/app.py",
                    "line": 12,
                    "category": "SECURITY",
                }
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["comparison"]["external_in_live_code"] == 1
    assert report["comparison"]["external_in_likely_dead_code"] == 0
    assert report["external_findings"][0]["shadow"]["reachability"]["symbol"] == "inner"


def test_revision_mismatch_withholds_value_claim():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "different",
            "findings": [
                {
                    "rule_id": "EXT-1",
                    "file_path": "src/app.py",
                    "line_number": 12,
                }
            ],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert report["usable"] is False
    assert report["revision"]["state"] == "mismatch"
    assert report["benefit"]["claim_scope"] == "not_eligible"


def test_revision_mismatch_is_not_masked_by_dirty_worktree():
    result = _skylos_result()
    result["analysis_summary"]["worktree_dirty"] = True
    external = normalize_external_report(
        {"complete": True, "revision": "different", "findings": []}
    )

    report = build_shadow_report(external, result)

    assert report["revision"]["state"] == "mismatch"
    assert report["usable"] is False


def test_dirty_matching_head_stays_usable_but_provisional():
    result = _skylos_result()
    result["analysis_summary"]["worktree_dirty"] = True
    external = normalize_external_report(
        {"complete": True, "revision": "abc123", "findings": []}
    )

    report = build_shadow_report(external, result)

    assert report["revision"]["state"] == "skylos_worktree_dirty"
    assert report["usable"] is True
    assert report["complete"] is False
    assert report["benefit"]["provisional"] is True


def test_secret_in_dead_symbol_is_context_not_deletion_benefit():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identity": "git@github.com:acme/repo.git",
            },
            "findings": [
                {
                    "rule_id": "EXT-SEC",
                    "file_path": "src/app.py",
                    "line_number": 12,
                    "category": "SECURITY",
                },
                {
                    "rule_id": "EXT-SECRET",
                    "file_path": "src/app.py",
                    "line_number": 13,
                    "category": "SECRET",
                },
            ],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert report["complete"] is True
    assert report["comparison"]["external_in_likely_dead_code"] == 2
    assert report["comparison"]["external_dead_context_excluded_from_benefit"] == 1
    assert report["benefit"]["review_or_deletion_candidates"] == 1
    assert report["external_findings"][1]["shadow"]["benefit_eligible"] is False
    assert (
        report["external_findings"][1]["shadow"]["benefit_exclusion_reason"]
        == "category_secret"
    )


def test_incomplete_ai_category_is_excluded_without_hiding_security_benefit():
    result = _skylos_result()
    result["analysis_summary"]["grade_categories"].append("ai_defects")
    result["analysis_summary"]["ai_verification"] = {"state": "incomplete"}
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "SEC",
                    "file_path": "src/app.py",
                    "line": 12,
                    "category": "SECURITY",
                },
                {
                    "rule_id": "AI",
                    "file_path": "src/app.py",
                    "line": 13,
                    "category": "AI_DEFECT",
                },
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["usable"] is True
    assert report["complete"] is False
    assert report["completeness_state"] == "category_coverage_incomplete"
    assert report["coverage"]["incomplete_skylos_categories"] == ["AI_DEFECT"]
    assert report["benefit"]["review_or_deletion_candidates"] == 1
    assert (
        report["external_findings"][1]["shadow"]["benefit_exclusion_reason"]
        == "incomplete_category_ai_defect"
    )


def test_incomplete_sca_receipt_limits_dependency_comparison():
    result = _skylos_result()
    result["analysis_summary"].update(
        {
            "grade_categories": ["security", "dead_code", "dependencies"],
            "comparison_sca_requested": True,
            "sca_coverage": {
                "status": "complete",
                "complete": True,
                "category_complete": False,
            },
        }
    )
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "CVE",
                    "file_path": "src/app.py",
                    "line": 12,
                    "category": "DEPENDENCY",
                }
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["usable"] is True
    assert report["complete"] is False
    assert report["coverage"]["coverage_limits_comparison"] is True
    assert report["coverage"]["incomplete_skylos_categories"] == ["DEPENDENCY"]
    assert report["benefit"]["review_or_deletion_candidates"] == 0


def test_missing_requested_category_scope_is_provisional():
    result = _skylos_result()
    result["analysis_summary"]["comparison_requested_categories"] = [
        "DEAD_CODE",
        "SECURITY",
    ]
    result["analysis_summary"]["grade_categories"] = ["dead_code"]
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "SEC",
                    "file_path": "src/app.py",
                    "line": 12,
                    "category": "SECURITY",
                }
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["completeness_state"] == "category_coverage_incomplete"
    assert report["coverage"]["incomplete_skylos_categories"] == ["SECURITY"]
    assert report["benefit"]["review_or_deletion_candidates"] == 0


def test_observed_unscanned_category_is_not_comparable_or_benefit_eligible():
    result = _skylos_result()
    result["analysis_summary"]["grade_categories"] = ["dead_code"]
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "SEC",
                    "file_path": "src/app.py",
                    "line": 12,
                    "category": "SECURITY",
                }
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["complete"] is False
    assert report["coverage"]["uncovered_external_categories"] == ["SECURITY"]
    assert report["coverage"]["observed_comparable_categories"] == []
    assert report["benefit"]["review_or_deletion_candidates"] == 0
    assert report["external_findings"][0]["shadow"]["benefit_eligible"] is False


def test_partial_skylos_scan_scope_stays_provisional():
    result = _skylos_result()
    result["analysis_summary"]["comparison_scope"] = {
        "kind": "subdirectory",
        "scan_path": "/work/repo/src",
        "repository_root": "/work/repo",
        "complete_repository": False,
    }
    external = normalize_external_report(
        {"complete": True, "revision": "abc123", "findings": []}
    )

    report = build_shadow_report(external, result)

    assert report["usable"] is True
    assert report["complete"] is False
    assert report["completeness_state"] == "scope_unverified"
    assert report["scope"]["state"] == "partial_skylos_scope"
    assert report["benefit"]["provisional"] is True


def test_repository_identity_mismatch_withholds_claim():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identity": "https://github.com/other/repo",
            },
            "findings": [],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert report["usable"] is False
    assert report["scope"]["state"] == "repository_identity_mismatch"
    assert report["scope"]["binding_verified"] is False
    assert report["benefit"]["review_or_deletion_candidates"] is None


def test_repository_identity_redacts_credentials_and_matches_cross_scheme():
    result = _skylos_result()
    result["analysis_summary"]["comparison_scope"]["repository_identities"] = [
        "https://oauth2:super-secret-token@github.com/acme/repo.git"
    ]
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identity": "git@github.com:acme/repo.git",
            },
            "findings": [],
        }
    )

    report = build_shadow_report(external, result)

    assert report["scope"]["binding_verified"] is True
    assert report["scope"]["repository_identity_match"] is True
    assert "super-secret-token" not in json.dumps(report)


def test_multiple_incumbent_repository_identities_invalidate_scope():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identities": [
                    "https://github.com/acme/repo",
                    "https://github.com/other/repo",
                ],
            },
            "findings": [],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert report["usable"] is False
    assert report["scope"]["state"] == "multiple_incumbent_repository_identities"


def test_nonroot_incumbent_source_root_conflicts_with_full_repository_scope():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "scope": {
                "complete_repository": True,
                "repository_identity": "https://github.com/acme/repo",
                "source_root": "services/api",
            },
            "findings": [],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert report["usable"] is False
    assert (
        report["scope"]["state"]
        == "incumbent_source_root_conflicts_with_repository_scope"
    )


def test_requested_ai_category_requires_completion_receipt():
    result = _skylos_result()
    result["analysis_summary"]["comparison_requested_categories"] = ["AI_DEFECT"]
    result["analysis_summary"]["grade_categories"] = ["ai_defects"]

    report = build_shadow_report(
        normalize_external_report(
            {
                "complete": True,
                "revision": "abc123",
                "findings": [
                    {
                        "rule_id": "AI",
                        "file_path": "src/app.py",
                        "line": 12,
                        "category": "AI_DEFECT",
                    }
                ],
            }
        ),
        result,
    )

    assert report["complete"] is False
    assert report["coverage"]["all_requested_categories_complete"] is False
    assert report["coverage"]["incomplete_skylos_categories"] == ["AI_DEFECT"]


def test_completeness_reasons_preserve_independent_limitations():
    result = _skylos_result()
    result["analysis_summary"]["comparison_disabled_checks"] = [
        "dependency_hallucinations"
    ]

    report = build_shadow_report(normalize_external_report(SARIF_REPORT), result)

    assert report["completeness_state"] == "external_completeness_unknown"
    assert report["completeness_reasons"] == [
        "incumbent_export_completeness_unknown",
        "incumbent_export_scope_unverified",
        "requested_profile_coverage_incomplete",
    ]


def test_unused_file_aliases_dedupe_candidate_file_count():
    result = _skylos_result()
    result["unused_files"] = [
        {
            "rule_id": "SKY-E002",
            "category": "DEAD_CODE",
            "file": "/work/repo/src/obsolete.py",
            "line": 1,
            "name": "obsolete.py",
        }
    ]
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "ONE",
                    "file_path": "src/obsolete.py",
                    "line": 2,
                    "category": "QUALITY",
                },
                {
                    "rule_id": "TWO",
                    "file_path": "/work/repo/src/obsolete.py",
                    "line": 3,
                    "category": "QUALITY",
                },
            ],
        }
    )

    report = build_shadow_report(external, result)

    assert report["benefit"]["review_or_deletion_candidates"] == 2
    assert report["benefit"]["candidate_files"] == 1
    assert report["comparison"]["affected_unused_files"] == 1


def test_unique_basename_only_match_remains_unknown():
    result = _skylos_result()
    result["definitions"] = {
        "app.old": {
            "name": "old",
            "file": "/repo/app.py",
            "line": 10,
            "loc": 8,
            "dead": True,
            "dead_code_classification": "likely_dead",
        }
    }
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "EXT",
                    "file_path": "different/app.py",
                    "line": 12,
                    "category": "SECURITY",
                }
            ],
        }
    )

    report = build_shadow_report(external, result)

    reachability = report["external_findings"][0]["shadow"]["reachability"]
    assert reachability["state"] == "unknown"
    assert reachability["reason"] == "weak_basename_path_match"
    assert report["benefit"]["review_or_deletion_candidates"] == 0


def test_oversized_report_path_is_not_indexed_for_correlation():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "EXT",
                    "file_path": f"{'segment/' * 600}app.py",
                    "line": 12,
                    "category": "SECURITY",
                }
            ],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    reachability = report["external_findings"][0]["shadow"]["reachability"]
    assert reachability["state"] == "unknown"
    assert reachability["reason"] == "invalid_or_nonlocal_path"


def test_remote_file_uri_cannot_suffix_match_local_source():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [
                {
                    "rule_id": "EXT",
                    "file_path": "file://other-host/src/app.py",
                    "line": 12,
                    "category": "SECURITY",
                }
            ],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    reachability = report["external_findings"][0]["shadow"]["reachability"]
    assert reachability["state"] == "unknown"
    assert reachability["reason"] == "invalid_or_nonlocal_path"
    assert report["comparison"]["location_overlap"] == 0
    assert report["benefit"]["review_or_deletion_candidates"] == 0


def test_missing_external_category_is_unknown_and_not_benefit_eligible():
    external = normalize_external_report(
        {
            "complete": True,
            "revision": "abc123",
            "findings": [{"rule_id": "EXT", "file_path": "src/app.py", "line": 12}],
        }
    )

    report = build_shadow_report(external, _skylos_result())

    assert external["findings"][0]["category"] == "UNKNOWN"
    assert report["comparison"]["external_in_likely_dead_code"] == 1
    assert report["benefit"]["review_or_deletion_candidates"] == 0


def test_rejects_unknown_external_report_shape():
    with pytest.raises(UnsupportedShadowReport):
        normalize_external_report({"results": []})


def test_rejects_excessively_nested_external_metadata(monkeypatch):
    def fail_canonicalization(*args, **kwargs):
        raise RecursionError("maximum nesting exceeded")

    monkeypatch.setattr("skylos.integrations.shadow.json.dumps", fail_canonicalization)
    with pytest.raises(UnsupportedShadowReport, match="canonicalized safely"):
        normalize_external_report({"findings": []})


def test_report_loader_rejects_symlinks(tmp_path):
    from skylos.integrations.shadow import load_json_report

    real_report = tmp_path / "real.json"
    linked_report = tmp_path / "linked.json"
    real_report.write_text('{"findings": []}', encoding="utf-8")
    linked_report.symlink_to(real_report)

    with pytest.raises(ValueError, match="non-symlink"):
        load_json_report(linked_report)


def test_report_loader_enforces_size_cap(tmp_path, monkeypatch):
    import skylos.integrations.shadow as shadow

    report = tmp_path / "large.json"
    report.write_text('{"findings": []}', encoding="utf-8")
    monkeypatch.setattr(shadow, "MAX_EXTERNAL_REPORT_BYTES", 5)

    with pytest.raises(ValueError, match="no larger"):
        shadow.load_json_report(report)


def test_report_writer_does_not_follow_symlink(tmp_path):
    victim = tmp_path / "victim.json"
    output = tmp_path / "output.json"
    victim.write_text("preserve me", encoding="utf-8")
    output.symlink_to(victim)

    assert _write_report_no_symlink(output, "replacement") is False
    assert victim.read_text(encoding="utf-8") == "preserve me"


def test_local_compare_scan_is_offline_by_default(tmp_path, monkeypatch):
    captured = {}

    def fake_analyze(path, **kwargs):
        captured.update(kwargs)
        return json.dumps(_skylos_result())

    monkeypatch.setattr("skylos.analyzer.analyze", fake_analyze)

    _run_local_scan(str(tmp_path), confidence=60, exclude_folders=[], enable_sca=False)

    assert captured["enable_sca"] is False
    assert captured["enable_secrets"] is False
    assert captured["enable_dependency_hallucinations"] is False
    assert captured["grep_cache"] is False


def test_local_compare_marks_changed_snapshot_provisional(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "skylos.analyzer.analyze",
        lambda path, **kwargs: json.dumps(_skylos_result()),
    )
    contexts = iter(
        [
            ("before", False, tmp_path, "https://github.com/acme/repo"),
            ("after", False, tmp_path, "https://github.com/acme/repo"),
        ]
    )
    monkeypatch.setattr(
        "skylos.commands.compare_cmd._git_context",
        lambda *args, **kwargs: next(contexts),
    )

    result = _run_local_scan(
        str(tmp_path), confidence=60, exclude_folders=[], enable_sca=False
    )

    assert result["analysis_summary"]["snapshot_stable"] is False
    assert result["analysis_summary"]["worktree_dirty"] is True
    assert result["analysis_summary"]["revision"] == "before"
    assert result["analysis_summary"]["revision_after_scan"] == "after"


def test_source_extension_report_is_not_ignored_for_git_status(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "skylos.analyzer.analyze",
        lambda path, **kwargs: json.dumps(_skylos_result()),
    )
    ignored = []

    def fake_git_context(*args, **kwargs):
        ignored.append(kwargs["ignore_paths"])
        return ("abc123", False, tmp_path, "https://github.com/acme/repo")

    monkeypatch.setattr("skylos.commands.compare_cmd._git_context", fake_git_context)

    result = _run_local_scan(
        str(tmp_path),
        confidence=60,
        exclude_folders=[],
        enable_sca=False,
        ignore_dirty_paths=[str(tmp_path / "incumbent.js")],
    )

    assert ignored == [[], []]
    assert result["analysis_summary"]["snapshot_stable"] is True
    assert result["analysis_summary"]["worktree_dirty"] is False


def test_report_artifact_does_not_make_worktree_dirty(tmp_path):
    report = tmp_path / "incumbent.sarif"

    assert (
        _has_relevant_worktree_changes(
            b"?? incumbent.sarif\0",
            repository_root=tmp_path,
            ignore_paths=[str(report)],
        )
        is False
    )
    assert (
        _has_relevant_worktree_changes(
            b"?? src/new.py\0",
            repository_root=tmp_path,
            ignore_paths=[str(report)],
        )
        is True
    )
    assert (
        _has_relevant_worktree_changes(
            b" M incumbent.sarif\0",
            repository_root=tmp_path,
            ignore_paths=[str(report)],
        )
        is True
    )


def test_explicit_exclusions_make_repository_scope_partial(tmp_path):
    scope = _comparison_scope(
        tmp_path,
        repository_root=tmp_path,
        repository_identity=None,
        excluded_folders=["vendor"],
    )

    assert scope["kind"] == "repository_root_with_exclusions"
    assert scope["complete_repository"] is False


def test_compare_command_rejects_nonexistent_scan_path(tmp_path):
    incumbent_path = tmp_path / "incumbent.sarif"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")

    from rich.console import Console

    exit_code = run_compare_command(
        [
            str(tmp_path / "missing-repository"),
            "--against",
            str(incumbent_path),
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 2


def test_compare_command_does_not_resolve_output_symlink(tmp_path):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    victim = tmp_path / "victim.json"
    output_path = tmp_path / "output.json"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")
    victim.write_text("preserve me", encoding="utf-8")
    output_path.symlink_to(victim)

    from rich.console import Console

    exit_code = run_compare_command(
        [
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--output",
            str(output_path),
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 2
    assert victim.read_text(encoding="utf-8") == "preserve me"


def test_compare_command_rejects_symlinked_output_parent(tmp_path):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    real_parent = tmp_path / "real-parent"
    linked_parent = tmp_path / "linked-parent"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")
    real_parent.mkdir()
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    from rich.console import Console

    exit_code = run_compare_command(
        [
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--output",
            str(linked_parent / "report.json"),
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 2
    assert not (real_parent / "report.json").exists()


def test_compare_command_reports_unusable_output_parent(tmp_path):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    non_directory = tmp_path / "not-a-directory"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")
    non_directory.write_text("file", encoding="utf-8")

    from rich.console import Console

    exit_code = run_compare_command(
        [
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--output",
            str(non_directory / "report.json"),
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 2


def test_compare_command_rejects_revision_override_conflict(tmp_path):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")

    from rich.console import Console

    exit_code = run_compare_command(
        [
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--external-revision",
            "different",
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 2


def test_duplicate_suffix_paths_are_unknown_and_do_not_overlap():
    result = _skylos_result()
    result["definitions"] = {
        "one.handler": {
            "name": "handler",
            "file": "/repo/service-one/src/app.py",
            "line": 10,
            "loc": 8,
            "dead": True,
            "dead_code_classification": "likely_dead",
        },
        "two.handler": {
            "name": "handler",
            "file": "/repo/service-two/src/app.py",
            "line": 10,
            "loc": 8,
            "dead": True,
            "dead_code_classification": "likely_dead",
        },
    }
    result["danger"] = [
        {
            "rule_id": "SKY-D001",
            "file": "/repo/service-one/src/app.py",
            "line": 12,
            "severity": "HIGH",
        },
        {
            "rule_id": "SKY-D001",
            "file": "/repo/service-two/src/app.py",
            "line": 12,
            "severity": "HIGH",
        },
    ]
    external = normalize_external_report(
        {
            "findings": [
                {
                    "rule_id": "EXT-1",
                    "file_path": "src/app.py",
                    "line_number": 12,
                    "severity": "HIGH",
                }
            ]
        }
    )

    report = build_shadow_report(external, result)

    assert report["comparison"]["location_overlap"] == 0
    assert report["comparison"]["external_in_likely_dead_code"] == 0
    reachability = report["external_findings"][0]["shadow"]["reachability"]
    assert reachability == {
        "state": "unknown",
        "file_path": "src/app.py",
        "reason": "ambiguous_path",
    }


def test_compare_command_reuses_results_and_writes_machine_report(tmp_path, capsys):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    output_path = tmp_path / "shadow.json"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")

    from rich.console import Console

    exit_code = run_compare_command(
        [
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 0
    printed = json.loads(capsys.readouterr().out)
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert printed == written
    assert written["mode"] == "shadow"
    assert written["comparison"]["external_in_likely_dead_code"] == 1


def test_compare_upload_is_explicit(monkeypatch, tmp_path):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")
    monkeypatch.setattr(
        "skylos.cloud.shadow_upload.upload_shadow_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("upload must be opt in")
        ),
    )

    from rich.console import Console

    exit_code = run_compare_command(
        [
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    assert exit_code == 0


def test_real_shadow_report_projects_paths_safely_for_cloud():
    local_report = build_shadow_report(
        normalize_external_report(SARIF_REPORT), _skylos_result()
    )

    cloud_report = prepare_shadow_report_for_cloud(local_report)

    assert cloud_report["external_findings"][0]["file_path"] == "src/app.py"
    assert (
        cloud_report["external_findings"][0]["shadow"]["reachability"]["file_path"]
        == "src/app.py"
    )
    skylos_only = {
        finding["rule_id"]: finding for finding in cloud_report["skylos_only_findings"]
    }
    assert skylos_only["SKY-D002"]["file_path"] == "src/other.py"
    assert "repository_root" not in cloud_report["scope"]["skylos"]
    assert "scan_path" not in cloud_report["scope"]["skylos"]
    assert "message" not in cloud_report["external_findings"][0]
    assert "external_fingerprint" not in cloud_report["external_findings"][0]


def test_compare_upload_preserves_json_stdout(monkeypatch, tmp_path, capsys):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")
    captured = {}

    def fake_upload(report, *, project_path):
        captured["report"] = report
        captured["project_path"] = project_path
        return {
            "success": True,
            "view_url": "https://cloud.example/scanner-proof/1",
        }

    monkeypatch.setattr(
        "skylos.cloud.shadow_upload.upload_shadow_report",
        fake_upload,
    )

    from rich.console import Console

    exit_code = run_compare_command(
        [
            str(tmp_path),
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--format",
            "json",
            "--upload",
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    output = capsys.readouterr()
    parsed = json.loads(output.out)
    assert exit_code == 0
    assert parsed["mode"] == "shadow"
    assert captured["report"]["mode"] == "shadow"
    assert captured["project_path"] == str(tmp_path)
    assert "receipt uploaded" in output.err


def test_compare_upload_failure_prints_upgrade_link(monkeypatch, tmp_path, capsys):
    incumbent_path = tmp_path / "incumbent.sarif"
    skylos_path = tmp_path / "skylos.json"
    incumbent_path.write_text(json.dumps(SARIF_REPORT), encoding="utf-8")
    skylos_path.write_text(json.dumps(_skylos_result()), encoding="utf-8")
    monkeypatch.setattr(
        "skylos.cloud.shadow_upload.upload_shadow_report",
        lambda *args, **kwargs: {
            "success": False,
            "error": "Three free proofs used",
            "code": "SCANNER_PROOF_UPGRADE_REQUIRED",
            "upgrade_url": "https://cloud.example/dashboard/billing",
        },
    )

    from rich.console import Console

    exit_code = run_compare_command(
        [
            str(tmp_path),
            "--against",
            str(incumbent_path),
            "--skylos-results",
            str(skylos_path),
            "--format",
            "json",
            "--upload",
        ],
        console_factory=lambda: Console(force_terminal=False),
    )

    output = capsys.readouterr()
    assert exit_code == 2
    assert json.loads(output.out)["mode"] == "shadow"
    assert "Upgrade Workspace Governance" in output.err
    assert "https://cloud.example/dashboard/billing" in output.err


def test_compare_is_registered_as_an_early_command():
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS

    assert EARLY_COMMAND_HANDLERS["compare"] == "_run_compare_command"
