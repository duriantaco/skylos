from skylos.cicd.evidence import (
    build_evidence_card,
    build_evidence_cards,
    evidence_counts,
    redact_sensitive_text,
)


def _stripe_like_token() -> str:
    return "sk" + "_live_" + "abcdefghijklmnopqrstuvwxyz1234567890"


def _github_like_token() -> str:
    return "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456"


def test_static_security_finding_is_proven():
    card = build_evidence_card(
        {
            "category": "danger",
            "rule_id": "SKY-D201",
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 12,
            "message": "eval() on user input",
        }
    )

    assert card.label == "proven"
    assert card.kind == "security"
    assert card.confidence == 96
    assert "Static Skylos rule SKY-D201" in card.evidence[0]


def test_llm_hypothesis_finding_is_speculative():
    card = build_evidence_card(
        {
            "category": "security",
            "rule_id": "SKY-L001",
            "severity": "HIGH",
            "file": "app.py",
            "line": 8,
            "message": "Potential auth bypass",
            "_source": "llm",
            "_security_evidence": "hypothesis",
        }
    )

    assert card.label == "speculative"
    assert card.confidence == 55
    assert "not backed by verifier-confirmed evidence" in card.evidence[0]


def test_verified_llm_finding_is_proven():
    card = build_evidence_card(
        {
            "category": "security",
            "rule_id": "SKY-L002",
            "severity": "HIGH",
            "file": "views.py",
            "line": 3,
            "message": "Authorization check missing",
            "_source": "llm",
            "verification": {"verdict": "VERIFIED"},
        }
    )

    assert card.label == "proven"
    assert "verified" in card.evidence[0]


def test_review_supported_llm_finding_is_likely_not_proven():
    card = build_evidence_card(
        {
            "category": "security",
            "rule_id": "SKY-D201",
            "severity": "HIGH",
            "file": "app.py",
            "line": 4,
            "message": "eval() may be reachable",
            "_source": "llm",
            "_security_evidence": "review_supported",
        }
    )

    assert card.label == "likely"
    assert "LLM review supplied supporting evidence" in card.evidence[0]


def test_security_regression_card_is_proven():
    card = build_evidence_card(
        {
            "kind": "security_regression",
            "category": "security_regression",
            "control_type": "auth",
            "severity": "HIGH",
            "file": "views.py",
            "line": 10,
            "message": "Auth decorator was removed",
            "rule_id": "SKY-L021",
        }
    )

    assert card.label == "proven"
    assert card.kind == "security_regression"
    assert "auth control" in card.evidence[0]
    assert "authentication check" in card.suggested_fix


def test_unknown_security_regression_card_has_fallback_suggested_fix():
    card = build_evidence_card(
        {
            "kind": "security_regression",
            "category": "security_regression",
            "control_type": "new_control",
            "severity": "HIGH",
            "file": "views.py",
            "line": 10,
            "message": "Security control was removed",
            "rule_id": "SKY-L099",
        }
    )

    assert card.label == "proven"
    assert "new control control" not in card.evidence[0]
    assert card.evidence[0] == "PR diff removed or weakened new control."
    assert card.suggested_fix == (
        "Restore or replace the removed security control before merging."
    )


def test_secret_card_does_not_expose_secret_value():
    token = _stripe_like_token()
    card = build_evidence_card(
        {
            "category": "secrets",
            "rule_id": "SKY-S101",
            "severity": "HIGH",
            "file": "settings.py",
            "line": 2,
            "message": f"Found API key {token}",
            "value": token,
        }
    )

    rendered = "\n".join(
        [
            card.title,
            *card.evidence,
            card.impact,
            card.suggested_fix or "",
        ]
    )
    assert token not in rendered
    assert "secret value is intentionally omitted".lower() in rendered.lower()


def test_redact_sensitive_text_removes_token_like_values():
    token = _github_like_token()
    assert token not in redact_sensitive_text(f"token={token}")


def test_evidence_counts_come_from_cards():
    cards = build_evidence_cards(
        [
            {"category": "danger", "rule_id": "SKY-D201", "severity": "HIGH"},
            {
                "category": "security",
                "_source": "llm",
                "_security_evidence": "hypothesis",
            },
            {"category": "quality", "rule_id": "SKY-Q301"},
        ]
    )

    assert evidence_counts(cards) == {"proven": 1, "likely": 1, "speculative": 1}


def test_generic_quality_card_has_fallback_suggested_fix():
    card = build_evidence_card(
        {
            "category": "quality",
            "rule_id": "SKY-Q999",
            "severity": "MEDIUM",
            "file": "app.py",
            "line": 5,
            "message": "Generic maintainability issue",
        }
    )

    assert card.label == "likely"
    assert card.suggested_fix == (
        "Refactor the affected code to remove the reported maintainability issue."
    )
