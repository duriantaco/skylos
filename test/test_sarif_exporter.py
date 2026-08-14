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
