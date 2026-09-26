import os
import json
import pytest

from skylos.reporting.sarif import (
    SarifExporter,
    severity_to_sarif_level,
    normalize_file_path_for_sarif,
)
from skylos.reporting.result_builder import _attach_findings


@pytest.mark.parametrize(
    "inp, expected",
    [
        ("CRITICAL", "error"),
        ("critical", "error"),
        ("HIGH", "error"),
        ("high", "error"),
        ("MEDIUM", "warning"),
        ("medium", "warning"),
        ("LOW", "note"),
        ("low", "note"),
        (None, "note"),
        ("", "note"),
        ("weird", "note"),
    ],
)
def test_severity_to_sarif_level(inp, expected):
    assert severity_to_sarif_level(inp) == expected


def test_normalize_file_path_removes_backslashes(monkeypatch):
    assert normalize_file_path_for_sarif(r"a\b\c.py") == "a/b/c.py"


def test_normalize_file_path_preserves_scoped_package_segments():
    assert (
        normalize_file_path_for_sarif("node_modules/@scope/package/index.ts")
        == "node_modules/@scope/package/index.ts"
    )


def test_normalize_file_path_strips_file_scheme(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("file:///repo/app.py") == "app.py"


def test_normalize_file_path_makes_relative_to_repo_root(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("/repo/src/app.py") == "src/app.py"


def test_normalize_file_path_strips_leading_slashes(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("/var/tmp/x.py") == "var/tmp/x.py"


def test_normalize_file_path_unknown_when_empty(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("") == "unknown"
    assert normalize_file_path_for_sarif(None) == "unknown"


def test_generate_has_valid_top_level_structure():
    findings = [
        {
            "rule_id": "SKY-D212",
            "severity": "CRITICAL",
            "message": "Possible command injection",
            "file_path": "app.py",
            "line_number": 10,
            "col_number": 2,
            "category": "SECURITY",
        }
    ]
    s = SarifExporter(findings, tool_name="Skylos", version="9.9.9").generate()

    assert s["version"] == "2.1.0"
    assert "$schema" in s
    assert "runs" in s and isinstance(s["runs"], list) and len(s["runs"]) == 1

    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Skylos"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    assert isinstance(run["tool"]["driver"]["rules"], list)
    assert isinstance(run["results"], list)


def test_unique_rules_dedup_by_rule_id_and_sets_default_level_and_helpuri():
    findings = [
        {
            "rule_id": "SKY-D212",
            "severity": "CRITICAL",
            "message": "msg A",
            "file_path": "a.py",
            "line_number": 1,
            "category": "SECURITY",
        },
        {
            "rule_id": "SKY-D212",
            "severity": "HIGH",
            "message": "msg B",
            "file_path": "b.py",
            "line_number": 2,
            "category": "SECURITY",
        },
    ]
    s = SarifExporter(findings).generate()
    rules = s["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1
    rule = rules[0]
    assert rule["id"] == "SKY-D212"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"].endswith("/SKY-D212")
    assert "properties" in rule and "tags" in rule["properties"]
    assert "security" in rule["properties"]["tags"]


def test_security_rule_tags_are_unique_for_sarif_schema():
    findings = [
        {
            "rule_id": "SKY-D281",
            "severity": "HIGH",
            "message": "Possible SQL injection",
            "file_path": "app/actions.ts",
            "line_number": 4,
            "category": "SECURITY",
        }
    ]

    rule = SarifExporter(findings).generate()["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]

    assert tags == ["security"]
    assert len(tags) == len(set(tags))


def test_duplicate_cwe_ids_do_not_create_invalid_sarif_relationships_or_tags():
    findings = [
        {
            "rule_id": "SKY-D281",
            "severity": "HIGH",
            "message": "Possible SQL injection",
            "file_path": "app/actions.ts",
            "line_number": 4,
            "category": "SECURITY",
            "cwe": [{"id": "CWE-89"}, {"id": "CWE-89"}],
        }
    ]

    rule = SarifExporter(findings).generate()["runs"][0]["tool"]["driver"]["rules"][0]
    relationship_ids = [item["target"]["id"] for item in rule["relationships"]]
    tags = rule["properties"]["tags"]

    assert relationship_ids == ["CWE-89"]
    assert len(tags) == len(set(tags))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("line_number", "not-a-line"),
        ("col_number", {"not": "a column"}),
    ],
)
def test_malformed_sarif_location_numbers_default_to_one(field, value):
    finding = {
        "rule_id": "SKY-D281",
        "severity": "HIGH",
        "message": "Possible SQL injection",
        "file_path": "app/actions.ts",
        "line_number": 4,
        "col_number": 2,
        "category": "SECURITY",
    }
    finding[field] = value

    result = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"]["region"]

    expected_field = "startLine" if field == "line_number" else "startColumn"
    assert region[expected_field] == 1


def test_non_string_sarif_severity_falls_back_to_note():
    findings = [
        {
            "rule_id": "SKY-D281",
            "severity": 7,
            "message": "Possible SQL injection",
            "file_path": "app/actions.ts",
            "line_number": 4,
            "category": "SECURITY",
        }
    ]

    sarif = SarifExporter(findings).generate()

    assert sarif["runs"][0]["results"][0]["level"] == "note"
    assert (
        sarif["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"]
        == "note"
    )


def test_rule_title_truncates_to_120_chars():
    long_title = "Long descriptive rule title " * 10
    findings = [
        {
            "rule_id": "SKY-Q301",
            "severity": "MEDIUM",
            "title": long_title,
            "message": "whatever",
            "file_path": "x.py",
            "line_number": 1,
            "category": "QUALITY",
        }
    ]
    s = SarifExporter(findings).generate()
    rule = s["runs"][0]["tool"]["driver"]["rules"][0]
    title = rule["shortDescription"]["text"]
    assert len(title) <= 120
    assert title.endswith("...")


def test_results_include_location_region_and_snippet_when_present(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")

    findings = [
        {
            "rule_id": "SKY-U002",
            "severity": "LOW",
            "message": "Unused import os",
            "file_path": "/repo/app.py",
            "line_number": 3,
            "col": 5,
            "snippet": "import os\n",
            "category": "DEAD_CODE",
        }
    ]
    s = SarifExporter(findings).generate()
    res = s["runs"][0]["results"][0]

    assert res["ruleId"] == "SKY-U002"
    assert res["level"] == "note"
    assert res["properties"]["category"] == "DEAD_CODE"

    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 3
    assert loc["region"]["startColumn"] == 5
    assert loc["region"]["snippet"]["text"] == "import os\n"


def test_results_include_skylos_metadata_when_present():
    findings = [
        {
            "rule_id": "SKY-SC001",
            "severity": "HIGH",
            "message": "Security contract failed",
            "file_path": "app/routes/admin.py",
            "line_number": 12,
            "category": "SECURITY",
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "source_to_sink",
                    "entrypoint": "admin_handler",
                    "contract_id": "admin-route-auth",
                    "missing_guards": ["require_admin"],
                    "path": ["request", "handler", "response"],
                }
            },
        }
    ]

    sarif = SarifExporter(findings).generate()
    result = sarif["runs"][0]["results"][0]

    assert result["properties"]["skylos_metadata"]["security_evidence"] == {
        "evidence_kind": "source_to_sink",
        "entrypoint": "admin_handler",
        "contract_id": "admin-route-auth",
        "missing_guards": ["require_admin"],
        "path": ["request", "handler", "response"],
    }


def test_sarif_bounds_and_sanitizes_untrusted_text_and_metadata():
    token = "glpat-" + "AbCdEfGhIjKlMnOpQrStUvWx"
    forged = "**forged proof** @maintainer [click](https://evil.invalid)"
    findings = [
        {
            "rule_id": "SKY-D281",
            "severity": "CRITICAL",
            "message": f"{forged} {token}" + ("x" * 10_000),
            "file_path": "app/actions.ts",
            "line_number": 4,
            "category": "SECURITY",
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "server_action_sql_taint",
                    "source": f"dynamic value {token}",
                    "sink": "interpolated SQL",
                    "path": [f"step-{index}-{token}" for index in range(100)],
                    "guards_seen": [forged + "\u202e"],
                    "guards_missing": ["parameterized SQL binding"],
                    "analysis_complete": False,
                },
                "oversized": {f"key-{index}": "y" * 2_000 for index in range(100)},
                "deep": {"a": {"b": {"c": {"d": {"secret": token}}}}},
            },
        }
    ]

    sarif = SarifExporter(findings).generate()
    rendered = json.dumps(sarif)
    result = sarif["runs"][0]["results"][0]
    metadata = result["properties"]["skylos_metadata"]
    packet = metadata["security_evidence"]

    assert token not in rendered
    assert "\u202e" not in rendered
    assert "@maintainer" not in result["message"]["text"]
    assert "**forged proof**" not in result["message"]["text"]
    assert "[click](https://evil.invalid)" not in result["message"]["text"]
    assert "@maintainer" in packet["guards_seen"][0]
    assert len(result["message"]["text"]) <= 4_000
    assert len(packet["path"]) <= 32
    assert len(metadata["oversized"]) <= 32
    assert all(len(value) <= 500 for value in metadata["oversized"].values())


def test_dependency_metadata_preserves_late_lockfile_occurrence_context():
    metadata = {f"advisory-and-environment-field-{index}": index for index in range(35)}
    metadata["dependency_occurrences"] = [{"file": "uv.lock", "line": 17}]
    finding = {
        "rule_id": "SKY-SCA-GHSA-test-context",
        "category": "DEPENDENCY",
        "file": "uv.lock",
        "line": 17,
        "metadata": metadata,
    }

    exported = SarifExporter([finding]).generate()["runs"][0]["results"][0]

    assert exported["properties"]["skylos_metadata"] == metadata


@pytest.mark.parametrize("category,limit", [("DEPENDENCY", 64), ("SECURITY", 32)])
def test_larger_metadata_field_budget_is_only_for_dependencies(category, limit):
    finding = {
        "rule_id": "SKY-SCA-GHSA-test-context",
        "category": category,
        "file": "uv.lock",
        "metadata": {f"field-{index}": "x" * 1_000 for index in range(100)},
    }
    exported = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    metadata = exported["properties"]["skylos_metadata"]

    assert len(metadata) == limit
    assert all(len(value) <= 500 for value in metadata.values())


def test_dependency_metadata_keeps_total_node_depth_and_redaction_bounds():
    token = "glpat-" + "AbCdEfGhIjKlMnOpQrStUvWx"
    finding = {
        "rule_id": "SKY-SCA-GHSA-test-context",
        "category": "DEPENDENCY",
        "file": "uv.lock",
        "metadata": {
            "token": token,
            "source": "x" * 1_000 + "\u202e",
            "deep": {"a": {"b": {"c": {"d": "past-depth-limit"}}}},
            "many": {f"field-{index}": list(range(100)) for index in range(100)},
        },
    }
    exported = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    metadata = exported["properties"]["skylos_metadata"]
    rendered = json.dumps(metadata, ensure_ascii=False)

    def count_nodes(value):
        if isinstance(value, dict):
            assert len(value) <= 64
            return 1 + sum(count_nodes(item) for item in value.values())
        if isinstance(value, list):
            assert len(value) <= 64
            return 1 + sum(count_nodes(item) for item in value)
        return 1

    assert token not in rendered
    assert "\u202e" not in rendered
    assert "past-depth-limit" not in rendered
    assert len(metadata["source"]) <= 500
    assert count_nodes(metadata) <= 256


def test_sarif_snippet_preserves_source_syntax_while_remaining_safe_and_bounded():
    token = "glpat-" + "AbCdEfGhIjKlMnOpQrStUvWx"
    syntax = (
        "@Controller()\n"
        "const query = `SELECT * FROM users`;\n"
        "if (a < b && flags | MASK) run(query);"
    )
    snippet = (
        syntax + f"\n// credential={token}\u202e\n" + ("// ordinary source\n" * 200)
    )
    findings = [
        {
            "rule_id": "SKY-D281",
            "severity": "HIGH",
            "message": "Possible SQL injection",
            "file_path": "app/actions.ts",
            "line_number": 4,
            "category": "SECURITY",
            "snippet": snippet,
        }
    ]

    result = SarifExporter(findings).generate()["runs"][0]["results"][0]
    rendered_snippet = result["locations"][0]["physicalLocation"]["region"]["snippet"][
        "text"
    ]

    assert syntax in rendered_snippet
    assert token not in rendered_snippet
    assert "\u202e" not in rendered_snippet
    assert len(rendered_snippet) <= 2_000


def test_sarif_redacts_contextual_short_secret_but_preserves_sha_evidence():
    secret = "aB3dE5fG7hJ9@kL2mN4pQ6rS8!tU0v"
    sha1 = "0123456789abcdef0123456789abcdef01234567"
    pem_body = "MIIEvQsensitivebase64materialmustnotescape1234567890"
    finding = {
        "rule_id": "SKY-S102",
        "severity": "HIGH",
        "message": (
            "Client-side secret exposure ![tracking][pixel]\n"
            "    [pixel]: https://evil.invalid/pixel.png"
        ),
        "file_path": "public/config.js",
        "line_number": 1,
        "category": "SECRETS",
        "snippet": (
            f'API_SECRET={secret}; commit_sha = "{sha1}";\n'
            "WEBHOOK_SECRET=aB3dE5fG7hJ9\n"
            "kL2mN4pQ6rS8!tU0v\n"
            "PRIVATE_TOKEN: |\n"
            "  zC4fH6jK8mP1\n"
            "  qR3tV5xY7!bN9@dF2\n"
            "-----BEGIN PRIVATE KEY-----\n"
            f"{pem_body}\n"
            "-----END PRIVATE KEY-----"
        ),
        "metadata": {"api_secret": secret, "commit_sha": sha1},
    }

    result = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    snippet = result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    message = result["message"]["text"]
    metadata = result["properties"]["skylos_metadata"]

    assert secret not in snippet
    assert "aB3dE5fG7hJ9" not in snippet
    assert "kL2mN4pQ6rS8!tU0v" not in snippet
    assert "zC4fH6jK8mP1" not in snippet
    assert "qR3tV5xY7!bN9@dF2" not in snippet
    assert secret not in json.dumps(metadata)
    assert pem_body not in snippet
    assert "END PRIVATE KEY" not in snippet
    assert sha1 in snippet
    assert metadata["commit_sha"] == sha1
    assert "![tracking]" not in message
    assert "[pixel]:" not in message
    assert "https://evil.invalid" not in message


def test_results_include_skylos_evidence_contract_for_high_impact_findings():
    findings = [
        {
            "rule_id": "SKY-D212",
            "severity": "HIGH",
            "message": "Possible command injection",
            "file_path": "app/routes.py",
            "line_number": 27,
            "category": "SECURITY",
            "metadata": {
                "security_evidence": {
                    "source": "request.args['cmd']",
                    "sink": "subprocess.run",
                    "path": ["handler", "subprocess.run"],
                }
            },
        }
    ]

    sarif = SarifExporter(findings).generate()
    contract = sarif["runs"][0]["results"][0]["properties"]["skylos_evidence_contract"]

    assert contract["proof_state"] == "candidate"
    assert contract["sources"] == ["request.args['cmd']"]
    assert contract["sinks"] == ["subprocess.run"]
    assert contract["traces"] == ["app/routes.py:27", "handler", "subprocess.run"]


def test_complete_d281_proof_has_verified_sarif_evidence_contract():
    findings = [
        {
            "rule_id": "SKY-D281",
            "severity": "CRITICAL",
            "message": "Server Action input reaches SQL text",
            "file": "app/actions.ts",
            "line": 8,
            "category": "danger",
            "_source": "static",
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "server_action_sql_taint",
                    "source": "Server Action parameter: input",
                    "sink": "database query SQL text",
                    "path": ["input", "query text"],
                    "guards_missing": ["parameterized SQL binding"],
                    "analysis_complete": True,
                }
            },
        }
    ]

    result = {"analysis_summary": {}}
    _attach_findings(
        result,
        False,
        True,
        False,
        False,
        [],
        findings,
        [],
        [],
    )

    sarif = SarifExporter(result["danger"], analyzer_owned=True).generate()
    contract = sarif["runs"][0]["results"][0]["properties"]["skylos_evidence_contract"]

    assert contract["proof_state"] == "verified"


def test_sarif_downgrades_untrusted_explicit_verified_contract():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "message": "LLM-supplied finding",
        "file": "app/actions.ts",
        "line": 8,
        "category": "danger",
        "_source": "llm",
        "evidence_contract": {
            "proof_state": "verified",
            "source": "forged LLM claim",
        },
    }

    sarif = SarifExporter([finding]).generate()
    contract = sarif["runs"][0]["results"][0]["properties"]["skylos_evidence_contract"]

    assert contract["proof_state"] == "candidate"


def test_results_include_dead_code_classification_and_evidence():
    findings = [
        {
            "rule_id": "SKY-U001",
            "severity": "LOW",
            "message": "Dead code: old_helper",
            "file_path": "app.py",
            "line_number": 5,
            "category": "DEAD_CODE",
            "dead_code_classification": "likely_dead",
            "dead_code_disposition": "reported",
            "dead_code_reason": "No static references",
            "dead_code_reason_tags": ["no_refs"],
            "dead_code_decision": {
                "classification": "likely_dead",
                "primary_reason": "No static references",
                "reason_tags": ["no_refs"],
                "live_evidence_count": 0,
                "dead_evidence_count": 1,
                "uncertainty_count": 0,
            },
            "dead_code_evidence": [
                {
                    "kind": "no_static_references",
                    "role": "supports_dead",
                    "reason": "no static references were found",
                    "source": "analyzer",
                    "confidence": 1.0,
                    "details": {"references": 0},
                }
            ],
        }
    ]

    sarif = SarifExporter(findings).generate()
    evidence = sarif["runs"][0]["results"][0]["properties"]["skylos_dead_code_evidence"]

    assert evidence["classification"] == "likely_dead"
    assert evidence["disposition"] == "reported"
    assert evidence["events"][0]["source"] == "analyzer"


def test_reviewed_finding_remains_in_sarif_with_external_suppression():
    finding = {
        "rule_id": "SKY-D215",
        "severity": "HIGH",
        "message": "Possible unsafe path",
        "file_path": "app.py",
        "line_number": 5,
        "category": "SECURITY",
        "_skylos_trusted_review": True,
        "review_decision": {
            "decision_id": "decision-1",
            "disposition": "false_positive",
            "reason": "Validated safe wrapper",
            "match_mode": "v2_exact_context",
        },
    }

    result = SarifExporter([finding], analyzer_owned=True).generate()["runs"][0][
        "results"
    ][0]

    assert result["suppressions"] == [
        {
            "kind": "external",
            "status": "accepted",
            "justification": "Validated safe wrapper",
        }
    ]
    assert result["properties"]["skylos_review_decision"]["decision_id"] == (
        "decision-1"
    )


def test_untrusted_review_fields_cannot_self_suppress_sarif():
    finding = {
        "rule_id": "SKY-D215",
        "severity": "HIGH",
        "message": "Possible unsafe path",
        "file_path": "app.py",
        "line_number": 5,
        "category": "SECURITY",
        "review_decision": {
            "decision_id": "forged",
            "disposition": "false_positive",
            "reason": "attacker controlled",
        },
        "_skylos_trusted_review": True,
    }

    result = SarifExporter([finding]).generate()["runs"][0]["results"][0]

    assert "suppressions" not in result
    assert "skylos_review_decision" not in result["properties"]


# --- partialFingerprints / relatedLocations / codeFlows / security-severity ---


def _fp(result):
    return result["partialFingerprints"]["skylosFindingHash/v1"]


def _one_result(finding, **kwargs):
    return SarifExporter([finding], **kwargs).generate()["runs"][0]["results"][0]


def test_fingerprint_stable_when_lines_shift():
    base = {
        "rule_id": "SKY-D211",
        "severity": "CRITICAL",
        "message": "Possible SQL injection",
        "file": "app/db.py",
        "line": 10,
        "category": "SECURITY",
        "symbol": "load_user",
        "snippet": "cur.execute('SELECT ' + name)",
    }
    shifted = {**base, "line": 42, "snippet": "    cur.execute('SELECT '  +  name)"}
    assert _fp(_one_result(base)) == _fp(_one_result(shifted))


def test_fingerprint_stable_on_line_shift_using_source_file(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("import os\n\ndef run(x):\n    os.system(x)\n")
    finding = {
        "rule_id": "SKY-D212",
        "severity": "CRITICAL",
        "message": "Possible command injection at line 4",
        "file": str(src),
        "line": 4,
        "category": "SECURITY",
    }
    before = _fp(_one_result(finding, analyzer_owned=True))
    src.write_text("import os\n\n\n\n# comment\ndef run(x):\n    os.system(x)\n")
    after = _fp(
        _one_result(
            {**finding, "line": 7, "message": "Possible command injection at line 7"},
            analyzer_owned=True,
        )
    )
    assert before == after


def test_fingerprint_differs_for_different_findings():
    a = {
        "rule_id": "SKY-D211",
        "message": "m",
        "file": "app.py",
        "line": 3,
        "symbol": "f",
        "snippet": "execute(a)",
    }
    variants = [
        {**a, "rule_id": "SKY-D212"},
        {**a, "file": "other.py"},
        {**a, "symbol": "g"},
        {**a, "snippet": "execute(b)"},
    ]
    fps = {_fp(_one_result(a))} | {_fp(_one_result(v)) for v in variants}
    assert len(fps) == 1 + len(variants)


def test_duplicate_findings_get_distinct_fingerprints():
    f = {"rule_id": "SKY-D201", "message": "eval", "file": "a.py", "line": 1}
    results = SarifExporter([f, {**f, "line": 9}]).generate()["runs"][0]["results"]
    fps = [_fp(r) for r in results]
    assert len(set(fps)) == 2
    assert fps[0].endswith(":1") and fps[1].endswith(":2")


def test_fingerprint_does_not_read_files_for_untrusted_findings(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("secret_line = 1\n")
    exporter = SarifExporter(
        [{"rule_id": "X", "message": "m", "file": str(src), "line": 1}]
    )
    exporter.generate()
    assert exporter._source_cache == {}


def test_related_locations_emitted_from_finding():
    finding = {
        "rule_id": "SKY-K8S-EXPOSE",
        "message": "exposed",
        "file": "deploy/ingress.yaml",
        "line": 3,
        "category": "SECURITY",
        "severity": "HIGH",
        "related_locations": [
            {"file": "deploy/service.yaml", "start_line": 1, "end_line": 12},
            {"file": "deploy/app.yaml", "start_line": 20, "end_line": 20},
            "junk",
            {"start_line": 5},
        ],
    }
    related = _one_result(finding)["relatedLocations"]
    assert [r["id"] for r in related] == [1, 2]
    assert related[0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "deploy/service.yaml"
    )
    assert related[0]["physicalLocation"]["region"] == {"startLine": 1, "endLine": 12}
    assert related[1]["physicalLocation"]["region"] == {"startLine": 20}


def test_no_related_locations_or_code_flows_without_data():
    result = _one_result(
        {
            "rule_id": "SKY-D201",
            "message": "eval",
            "file": "a.py",
            "line": 1,
            "category": "SECURITY",
        }
    )
    assert "relatedLocations" not in result
    assert "codeFlows" not in result


def test_code_flows_from_security_evidence_path():
    finding = {
        "rule_id": "SKY-D216",
        "severity": "CRITICAL",
        "message": "Possible SSRF",
        "file": "svc.py",
        "line": 14,
        "category": "SECURITY",
        "metadata": {
            "security_evidence": {
                "source": "request-derived URL value",
                "sink": "requests.get",
                "path": [
                    {"message": "request.args['u']", "file": "svc.py", "line": 11},
                    "url expression `u`",
                    "HTTP sink `requests.get`",
                ],
            }
        },
    }
    flows = _one_result(finding)["codeFlows"]
    assert len(flows) == 1
    steps = flows[0]["threadFlows"][0]["locations"]
    assert len(steps) == 3
    assert steps[0]["location"]["physicalLocation"]["region"]["startLine"] == 11
    # Textual steps are anchored at the finding (sink) location.
    assert steps[1]["location"]["physicalLocation"]["region"]["startLine"] == 14
    # Step text is sanitized like result messages (backticks neutralized).
    assert steps[1]["location"]["message"]["text"].startswith("url expression")
    sink = steps[2]["location"]["physicalLocation"]
    assert sink["artifactLocation"]["uri"] == "svc.py"
    assert sink["region"]["startLine"] == 14
    assert flows[0]["message"]["text"] == (
        "Flow from request-derived URL value to requests.get"
    )


def test_security_severity_on_security_rules_only():
    findings = [
        {
            "rule_id": "SKY-D212",
            "severity": "CRITICAL",
            "message": "cmd",
            "file": "a.py",
            "line": 1,
            "category": "SECURITY",
        },
        {
            "rule_id": "SKY-S101",
            "severity": "HIGH",
            "message": "secret",
            "file": "a.py",
            "line": 2,
            "category": "SECRET",
        },
        {
            "rule_id": "SKY-SCA",
            "severity": "MEDIUM",
            "message": "dep",
            "file": "requirements.txt",
            "line": 1,
            "category": "DEPENDENCY",
            "metadata": {"cvss_score": 7.3, "vuln_id": "GHSA-x"},
        },
        {
            "rule_id": "SKY-Q301",
            "severity": "MEDIUM",
            "message": "complex",
            "file": "a.py",
            "line": 3,
            "category": "QUALITY",
        },
    ]
    rules = {
        r["id"]: r
        for r in SarifExporter(findings).generate()["runs"][0]["tool"]["driver"][
            "rules"
        ]
    }
    assert rules["SKY-D212"]["properties"]["security-severity"] == "9.5"
    assert rules["SKY-S101"]["properties"]["security-severity"] == "8.0"
    assert rules["SKY-SCA"]["properties"]["security-severity"] == "7.3"
    assert "security" in rules["SKY-S101"]["properties"]["tags"]
    assert "security-severity" not in rules["SKY-Q301"]["properties"]
    assert rules["SKY-Q301"]["helpUri"].startswith("https://docs.skylos.dev/rules/")


def test_security_severity_uses_highest_finding_for_rule():
    findings = [
        {
            "rule_id": "R",
            "severity": "LOW",
            "message": "m",
            "file": "a.py",
            "line": 1,
            "category": "SECURITY",
        },
        {
            "rule_id": "R",
            "severity": "CRITICAL",
            "message": "m",
            "file": "b.py",
            "line": 1,
            "category": "SECURITY",
        },
    ]
    rule = SarifExporter(findings).generate()["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"


def test_cwe_tags_use_github_external_convention():
    finding = {
        "rule_id": "SKY-D211",
        "severity": "HIGH",
        "message": "sqli",
        "file": "a.py",
        "line": 1,
        "category": "SECURITY",
        "cwe": [{"id": "CWE-89"}],
    }
    rule = SarifExporter([finding]).generate()["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]
