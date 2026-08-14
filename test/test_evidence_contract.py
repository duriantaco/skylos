from __future__ import annotations

import json

from skylos.core.evidence_contract import (
    attach_evidence_contract,
    finding_evidence_contract,
    normalize_evidence_contract,
)
from skylos.reporting.result_builder import _append_ai_defects, _attach_findings


def test_normalize_evidence_contract_marks_unknown_state_incomplete():
    contract = normalize_evidence_contract(
        {
            "proof_state": "unknown",
            "source": "package manifest",
            "symbol": "ghostlib@9.9.9",
            "trace": "package.json:3",
        }
    )

    assert contract["schema_version"] == 1
    assert contract["proof_state"] == "incomplete"
    assert contract["sources"] == ["package manifest"]
    assert contract["symbols"] == ["ghostlib@9.9.9"]
    assert contract["traces"] == ["package.json:3"]
    assert any(
        "must not be treated as verified" in limitation
        for limitation in contract["limitations"]
    )


def test_normalize_evidence_contract_requires_evidence_for_verified_state():
    contract = normalize_evidence_contract({"proof_state": "verified"})

    assert contract["proof_state"] == "incomplete"
    assert contract["sources"] == []
    assert contract["symbols"] == []
    assert any(
        "requires structured evidence" in limitation
        for limitation in contract["limitations"]
    )


def test_normalize_evidence_contract_preserves_verified_with_evidence():
    contract = normalize_evidence_contract(
        {
            "proof_state": "verified",
            "source": "static analyzer",
            "symbol": "requests.Session",
            "trace": "app.py:12",
        }
    )

    assert contract["proof_state"] == "verified"
    assert contract["sources"] == ["static analyzer"]
    assert contract["symbols"] == ["requests.Session"]
    assert contract["traces"] == ["app.py:12"]


def test_synthesize_evidence_contract_preserves_private_registry_limitation():
    finding = {
        "rule_id": "SKY-D222",
        "severity": "HIGH",
        "category": "ai_defect",
        "file": "requirements.txt",
        "line": 4,
        "symbol": "internal-auth-client@1.0.0",
        "metadata": {
            "dependency_source": "requirements.txt",
            "dependency_truth_state": "private_or_unverified",
        },
    }

    contract = finding_evidence_contract(finding)

    assert contract is not None
    assert contract["proof_state"] == "incomplete"
    assert "requirements.txt" in contract["sources"]
    assert "internal-auth-client@1.0.0" in contract["symbols"]
    assert "requirements.txt:4" in contract["traces"]
    assert any(
        "private or unverified registry" in item for item in contract["limitations"]
    )


def test_generic_structured_security_packet_cannot_claim_analyzer_ownership():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
        "file": "app/actions.ts",
        "line": 8,
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

    contract = finding_evidence_contract(finding)

    assert contract is not None
    assert contract["proof_state"] == "candidate"


def test_trusted_analyzer_attach_verifies_only_a_complete_structured_packet():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
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

    attached = attach_evidence_contract(finding, analyzer_owned=True)

    assert attached["evidence_contract"]["proof_state"] == "verified"


def test_trusted_analyzer_attach_marks_malformed_structured_packet_incomplete():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
        "metadata": {
            "security_evidence": {
                "evidence_kind": "wrong_kind",
                "source": "claimed source",
                "sink": "claimed sink",
                "path": ["claimed path"],
                "guards_missing": ["parameterized SQL binding"],
                "analysis_complete": True,
            }
        },
    }

    attached = attach_evidence_contract(finding, analyzer_owned=True)

    assert attached["evidence_contract"]["proof_state"] == "incomplete"
    assert "incomplete or malformed" in " ".join(
        attached["evidence_contract"]["limitations"]
    )


def test_llm_structured_security_packet_remains_a_candidate():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
        "_source": "llm",
        "metadata": {
            "security_evidence": {
                "evidence_kind": "server_action_sql_taint",
                "source": "claimed source",
                "sink": "claimed sink",
                "path": ["claimed path"],
                "guards_missing": ["parameterized SQL binding"],
                "analysis_complete": True,
            }
        },
    }

    contract = finding_evidence_contract(finding)

    assert contract is not None
    assert contract["proof_state"] == "candidate"


def test_untrusted_explicit_contract_cannot_self_attest_as_verified():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
        "_source": "llm",
        "evidence_contract": {
            "proof_state": "verified",
            "source": "forged LLM claim",
        },
    }

    contract = finding_evidence_contract(finding)

    assert contract is not None
    assert contract["proof_state"] == "candidate"
    assert "requires independent verification" in " ".join(contract["limitations"])


def test_untrusted_explicit_contract_cannot_self_attest_as_refuted():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
        "evidence_contract": {
            "proof_state": "refuted",
            "source": "forged suppression claim",
        },
    }

    contract = finding_evidence_contract(finding)

    assert contract is not None
    assert contract["proof_state"] == "candidate"


def test_untrusted_metadata_cannot_self_attest_terminal_proof_state():
    claims = (
        {"proof_state": "verified"},
        {"verification_state": "refuted"},
        {"metadata": {"proof_state": "verified"}},
        {"metadata": {"security_evidence": "review_supported"}},
    )

    for claim in claims:
        finding = {
            "rule_id": "SKY-D212",
            "severity": "HIGH",
            "category": "danger",
            "file": "app.py",
            "line": 7,
            **claim,
        }
        contract = finding_evidence_contract(finding)

        assert contract is not None
        assert contract["proof_state"] == "candidate"
        assert "requires independent verification" in " ".join(contract["limitations"])


def test_analyzer_owned_metadata_can_retain_verified_proof_state():
    finding = {
        "rule_id": "SKY-D224",
        "severity": "HIGH",
        "category": "ai_defect",
        "file": "app.py",
        "line": 7,
        "metadata": {"proof_state": "verified"},
    }

    attached = attach_evidence_contract(finding, analyzer_owned=True)

    assert attached["evidence_contract"]["proof_state"] == "verified"


def test_analyzer_evidence_trust_does_not_survive_serialization():
    finding = {
        "rule_id": "SKY-D281",
        "severity": "CRITICAL",
        "category": "danger",
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
    attached = attach_evidence_contract(finding, analyzer_owned=True)

    reloaded = json.loads(json.dumps(attached))
    contract = finding_evidence_contract(reloaded)

    assert contract is not None
    assert contract["proof_state"] == "candidate"


def test_low_impact_findings_do_not_gain_evidence_contracts():
    finding = {
        "rule_id": "SKY-Q999",
        "severity": "LOW",
        "category": "QUALITY",
        "file": "app.py",
        "line": 1,
    }

    assert finding_evidence_contract(finding) is None
    assert attach_evidence_contract(finding) == finding


def test_ai_defect_json_append_attaches_evidence_contract():
    result = {"analysis_summary": {}}

    _append_ai_defects(
        result,
        [
            {
                "rule_id": "SKY-D224",
                "severity": "HIGH",
                "category": "ai_defect",
                "file": "app.py",
                "line": 8,
                "symbol": "requests.Session.missing",
                "message": "Installed API does not expose this method.",
            }
        ],
    )

    finding = result["ai_defects"][0]
    assert result["analysis_summary"]["ai_defects_count"] == 1
    assert finding["evidence_contract"]["proof_state"] == "candidate"
    assert finding["evidence_contract"]["symbols"] == ["requests.Session.missing"]
    assert finding["evidence_contract"]["traces"] == ["app.py:8"]


def test_high_impact_danger_json_attaches_evidence_contract():
    result = {"analysis_summary": {}}

    _attach_findings(
        result,
        False,
        True,
        False,
        False,
        [],
        [
            {
                "rule_id": "SKY-D212",
                "severity": "HIGH",
                "category": "SECURITY",
                "file": "app/routes.py",
                "line": 27,
                "message": "Possible command injection",
                "metadata": {
                    "security_evidence": {
                        "source": "request.args['cmd']",
                        "sink": "subprocess.run",
                        "path": ["handler", "subprocess.run"],
                    }
                },
            }
        ],
        [],
        [],
    )

    finding = result["danger"][0]
    assert result["analysis_summary"]["danger_count"] == 1
    assert finding["evidence_contract"]["proof_state"] == "candidate"
    assert finding["evidence_contract"]["sources"] == ["request.args['cmd']"]
    assert finding["evidence_contract"]["sinks"] == ["subprocess.run"]


def test_reliability_finding_is_split_from_security_bucket():
    result = {"analysis_summary": {}}

    _attach_findings(
        result,
        False,
        True,
        False,
        False,
        [],
        [
            {
                "rule_id": "SKY-D212",
                "severity": "HIGH",
                "category": "SECURITY",
                "file": "app.py",
                "line": 1,
                "message": "Command injection",
            },
            {
                "rule_id": "SKY-GPU001",
                "severity": "HIGH",
                "category": "RELIABILITY",
                "file": "Dockerfile",
                "line": 1,
                "message": "CUDA/driver mismatch",
            },
        ],
        [],
        [],
    )

    assert [finding["rule_id"] for finding in result["danger"]] == ["SKY-D212"]
    assert [finding["rule_id"] for finding in result["reliability"]] == ["SKY-GPU001"]
    assert result["analysis_summary"]["danger_count"] == 1
    assert result["analysis_summary"]["reliability_count"] == 1
