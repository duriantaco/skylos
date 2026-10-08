from skylos.cicd.risk_passport import (
    build_risk_passport,
    format_risk_passport_markdown,
)


def test_risk_passport_passes_without_findings_or_ai_provenance():
    passport = build_risk_passport(
        all_findings=[],
        diff_findings=[],
        provenance=None,
        defense_report=None,
    )

    assert passport["recommendation"] == "PASS"
    assert passport["provenance_confidence"] == "unavailable"


def test_risk_passport_blocks_ai_authored_high_security_finding():
    finding = {
        "category": "danger",
        "rule_id": "SKY-D201",
        "severity": "HIGH",
        "file": "app.py",
        "line": 10,
        "message": "eval() usage",
        "ai_authored": True,
        "attribution_level": "recorded",
        "attribution_scope": "line",
    }

    passport = build_risk_passport(
        all_findings=[finding],
        diff_findings=[finding],
        provenance=None,
        defense_report=None,
    )

    assert passport["recommendation"] == "BLOCK"
    assert passport["high_risk_ai_files"] == ["app.py"]
    assert passport["changed_line_evidence"]["proven"] == 1


def test_risk_passport_blocks_security_regression():
    finding = {
        "kind": "security_regression",
        "category": "security_regression",
        "control_type": "auth",
        "severity": "HIGH",
        "file": "views.py",
        "line": 4,
        "message": "Auth removed",
    }

    passport = build_risk_passport(
        all_findings=[finding],
        diff_findings=[finding],
        provenance=None,
        defense_report=None,
    )

    assert passport["recommendation"] == "BLOCK"
    assert passport["security_controls_weakened"] == ["auth"]


def test_risk_passport_warns_for_high_speculative_finding():
    finding = {
        "category": "security",
        "severity": "HIGH",
        "_source": "llm",
        "_security_evidence": "hypothesis",
        "file": "views.py",
        "line": 8,
        "message": "Possible auth issue",
    }

    passport = build_risk_passport(
        all_findings=[finding],
        diff_findings=[finding],
        provenance=None,
        defense_report=None,
    )

    assert passport["recommendation"] == "WARN"
    assert passport["changed_line_evidence"]["speculative"] == 1


def test_risk_passport_warns_for_medium_ai_quality_finding():
    finding = {
        "category": "quality",
        "severity": "MEDIUM",
        "file": "app.py",
        "line": 7,
        "message": "Complexity",
    }
    provenance = {
        "agent_files": ["app.py"],
        "files": {
            "app.py": {
                "agent_authored": True,
                "agent_lines": [[1, 20]],
                "agent_name": "codex",
                "attribution_level": "recorded",
            }
        },
        "summary": {"agents_seen": ["codex"]},
        "confidence": "medium",
    }

    passport = build_risk_passport(
        all_findings=[finding],
        diff_findings=[finding],
        provenance=provenance,
        defense_report=None,
    )

    assert passport["recommendation"] == "WARN"
    assert passport["ai_authored_files"] == 1
    assert passport["ai_agents"] == ["codex"]


def test_risk_passport_blocks_failed_high_defense_on_ai_file():
    provenance = {
        "agent_files": ["app.py"],
        "files": {
            "app.py": {
                "agent_authored": True,
                "agent_lines": [[1, 20]],
                "attribution_level": "recorded",
            }
        },
        "summary": {},
        "confidence": "high",
    }
    defense_report = {
        "findings": [
            {
                "plugin_id": "output_validation",
                "passed": False,
                "location": "app.py:12",
                "severity": "high",
                "category": "defense",
            }
        ]
    }

    passport = build_risk_passport(
        all_findings=[],
        diff_findings=[],
        provenance=provenance,
        defense_report=defense_report,
    )

    assert passport["recommendation"] == "BLOCK"
    assert passport["high_risk_ai_files"] == ["app.py"]
    assert passport["missing_llm_guardrails"] == ["output_validation"]


def test_risk_passport_ignores_malformed_defense_report():
    passport = build_risk_passport(
        all_findings=[],
        diff_findings=[],
        provenance=None,
        defense_report={"findings": ["bad"]},
    )

    assert passport["recommendation"] == "PASS"


def test_format_risk_passport_markdown_renders_summary():
    passport = {
        "recommendation": "WARN",
        "ai_authored_files": 1,
        "ai_agents": ["codex"],
        "provenance_confidence": "medium",
        "changed_line_evidence": {"proven": 1, "likely": 0, "speculative": 1},
        "high_risk_ai_files": [],
        "security_controls_weakened": [],
        "missing_llm_guardrails": ["output_validation"],
        "reasons": [],
        "warnings": ["LLM defense guardrail failed: output_validation"],
    }

    body = "\n".join(format_risk_passport_markdown(passport))

    assert "### AI PR Risk Passport" in body
    assert "**Merge recommendation: WARN**" in body
    assert "Proven 1 / Likely 0 / Speculative 1" in body
    assert "output_validation" in body


def test_commit_association_keeps_policy_conservative_without_claiming_line_authorship():
    finding = {
        "category": "danger",
        "rule_id": "SKY-D201",
        "severity": "HIGH",
        "file": "app.py",
        "line": 10,
        "message": "eval() usage",
        "ai_authored": None,
        "ai_declared": True,
        "attribution_level": "declared",
    }
    provenance = {
        "agent_files": ["app.py"],
        "files": {
            "app.py": {
                "agent_authored": True,
                "agent_lines": [],
                "attribution_level": "declared",
            }
        },
        "confidence": "low",
    }
    passport = build_risk_passport(
        all_findings=[finding], diff_findings=[finding], provenance=provenance
    )
    assert passport["recommendation"] == "BLOCK"
    assert passport["ai_authored_files"] == 0
    assert passport["declared_agent_files"] == 1
    assert passport["high_risk_ai_files"] == []
    assert passport["high_risk_agent_associated_files"] == ["app.py"]
    assert passport["reasons"] == [
        "Declared agent file association: proven HIGH security finding"
    ]


def test_legacy_ai_boolean_is_only_a_declaration_for_policy():
    finding = {
        "category": "danger",
        "rule_id": "SKY-D201",
        "severity": "HIGH",
        "file": "app.py",
        "line": 10,
        "message": "eval() usage",
        "ai_authored": True,
    }
    passport = build_risk_passport(all_findings=[finding], diff_findings=[finding])
    assert passport["recommendation"] == "BLOCK"
    assert passport["ai_authored_files"] == 0
    assert passport["declared_agent_files"] == 1
    assert "Declared agent file association" in passport["reasons"][0]
