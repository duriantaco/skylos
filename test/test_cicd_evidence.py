import pytest

from skylos.cicd.evidence import (
    build_evidence_card,
    build_evidence_cards,
    evidence_counts,
    redact_sensitive_text,
    sanitize_bounded_payload,
    sanitize_markdown_text,
    sanitize_untrusted_text,
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
    assert card.suggested_fix == (
        "Rotate the exposed credential and move it to a secrets manager or "
        "environment variable."
    )


def test_redact_sensitive_text_removes_token_like_values():
    token = _github_like_token()
    assert token not in redact_sensitive_text(f"token={token}")


def test_redact_sensitive_text_covers_all_provider_shaped_credentials():
    tokens = (
        "glpat-" + "AbCdEfGhIjKlMnOpQrStUvWx",
        "AIza" + ("A" * 35),
        "SG." + ("A" * 16) + "." + ("B" * 16),
        "SK" + ("a" * 32),
        "AGPA" + ("A" * 16),
    )

    rendered = redact_sensitive_text(" ".join(tokens))

    for token in tokens:
        assert token not in rendered


def test_contextual_short_high_entropy_secret_is_redacted_everywhere():
    secret = "aB3dE5fG7hJ9kL2mN4pQ6rS8"

    rendered = sanitize_untrusted_text(f'API_SECRET = "{secret}"')
    payload = sanitize_bounded_payload({"api_secret": secret})

    assert secret not in rendered
    assert "[redacted]" in rendered
    assert payload == {"api_secret": "[redacted]"}


@pytest.mark.parametrize(
    "rendered_input",
    (
        "API_SECRET=aB3dE5fG7hJ9kL2mN4pQ6rS8",
        "API_SECRET=aB3dE5fG7hJ9@kL2mN4pQ6rS8!tU0v",
        "API_SECRET=aB3dE5fG7hJ9\nkL2mN4pQ6rS8!tU0v",
        "API_SECRET: |\n  aB3dE5fG7hJ9\n  kL2mN4pQ6rS8!tU0v",
        'API_SECRET="aB3dE5fG7hJ9\nkL2mN4pQ6rS8"',
    ),
    ids=[
        "unquoted",
        "punctuation",
        "wrapped-unquoted",
        "yaml-block-scalar",
        "quoted-multiline",
    ],
)
def test_contextual_short_secret_redaction_covers_output_shapes(rendered_input):
    rendered = sanitize_untrusted_text(
        rendered_input,
        preserve_newlines=True,
    )

    assert "aB3dE5fG7hJ9" not in rendered
    assert "kL2mN4pQ6rS8" not in rendered
    assert "[redacted]" in rendered


def test_pem_redaction_removes_the_entire_private_key_block():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n"
        "sensitivebase64materialmustnotescape1234567890\n"
        "-----END PRIVATE KEY-----"
    )

    rendered = sanitize_untrusted_text(pem, preserve_newlines=True)

    assert "MIIEvQ" not in rendered
    assert "sensitivebase64material" not in rendered
    assert "END PRIVATE KEY" not in rendered
    assert rendered == "[redacted PEM block]"


def test_explicit_sha_and_digest_values_are_not_redacted_as_secrets():
    sha1 = "0123456789abcdef0123456789abcdef01234567"

    rendered = sanitize_untrusted_text(
        f'commit_sha = "{sha1}"\napi_secret_digest: {sha1}\ntoken_hash={sha1}'
    )
    payload = sanitize_bounded_payload(
        {
            "commit_sha": sha1,
            "digest": sha1,
            "api_secret_digest": sha1,
            "token_hash": sha1,
        }
    )

    assert rendered.count(sha1) == 3
    assert payload == {
        "commit_sha": sha1,
        "digest": sha1,
        "api_secret_digest": sha1,
        "token_hash": sha1,
    }


def test_wrapped_secret_redaction_does_not_consume_following_digest_evidence():
    sha1 = "0123456789abcdef0123456789abcdef01234567"
    rendered = sanitize_untrusted_text(
        f"API_SECRET=aB3dE5fG7hJ9\nkL2mN4pQ6rS8!tU0v\ncommit_sha={sha1}",
        preserve_newlines=True,
    )

    assert "aB3dE5fG7hJ9" not in rendered
    assert "kL2mN4pQ6rS8!tU0v" not in rendered
    assert f"commit_sha={sha1}" in rendered


@pytest.mark.parametrize(
    "forged_markdown",
    (
        "[click [nested label]](https://evil.invalid)",
        "![tracking [pixel]](https://evil.invalid/pixel.png)",
        "[click][ref]\n\n[ref]: https://evil.invalid",
        "![tracking][pixel]\n[pixel]: https://evil.invalid/pixel.png",
        "- ![tracking][pixel]\n    [pixel]: https://evil.invalid/pixel.png",
        "![escaped\\] label][pixel]\n[pixel]: https://evil.invalid/pixel.png",
        f"![tracking][{'x' * 200}]\n[{'x' * 200}]: https://evil.invalid/pixel.png",
        "![tracking]\n  [tracking]: https://evil.invalid/pixel.png",
        (
            f"!AWS_SECRET_ACCESS_KEY={'Ab9Z' * 10}\n"
            f"AWS_SECRET_ACCESS_KEY={'Ab9Z' * 10}: //evil.invalid/pixel.png"
        ),
    ),
)
def test_markdown_sanitizer_neutralizes_nested_label_links_and_images(
    forged_markdown,
):
    rendered = sanitize_markdown_text(forged_markdown)

    assert forged_markdown not in rendered
    assert "[" not in rendered
    assert "]" not in rendered
    assert "https://evil.invalid" not in rendered
    assert "](https://evil.invalid" not in rendered
    assert "][ref]" not in rendered
    assert "][pixel]" not in rendered
    assert "[ref]:" not in rendered
    assert "[pixel]:" not in rendered
    assert any(
        label in rendered
        for label in (
            "nested label",
            "tracking",
            "click",
            "escaped",
            "pixel",
            "redacted",
        )
    )


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


def test_nextjs_security_rules_have_rule_specific_remediation():
    expected_fixes = {
        "SKY-D280": (
            "Authenticate mutating API routes before performing protected actions."
        ),
        "SKY-D281": (
            "Use parameterized queries instead of building SQL with string interpolation."
        ),
    }

    for rule_id, expected_fix in expected_fixes.items():
        card = build_evidence_card(
            {
                "category": "danger",
                "rule_id": rule_id,
                "severity": "HIGH",
                "file": "app/api/route.ts",
                "line": 1,
            }
        )

        assert card.suggested_fix == expected_fix


def test_client_side_secret_uses_exposure_specific_remediation():
    card = build_evidence_card(
        {
            "category": "secrets",
            "rule_id": "SKY-S102",
            "severity": "HIGH",
            "file": "public/app.js",
            "line": 1,
            "message": (
                "Client-side secret exposure: Non-public env var "
                "'process.env.PAYMENT_SECRET_KEY' may be bundled into client code"
            ),
        }
    )

    rendered = "\n".join((card.title, *card.evidence, card.impact))
    assert card.title == "Client-side secret exposure detected"
    assert "server-only environment variable" in rendered
    assert "client-accessible code" in rendered
    assert "hardcoded" not in rendered.lower()
    assert "credential pattern" not in rendered.lower()
    assert "committed credential" not in rendered.lower()
    assert card.suggested_fix == (
        "Move the secret to server-only code and rotate it; expose only non-sensitive "
        "values through public client configuration."
    )


def test_incomplete_structured_security_flow_is_not_labeled_proven():
    token = _github_like_token()

    for rule_id, evidence_kind in (
        ("SKY-D252", "cookie_security_options"),
        ("SKY-D280", "authorization_guard"),
        ("SKY-D281", "server_action_sql_taint"),
        ("SKY-D282", "webhook_signature_guard"),
    ):
        card = build_evidence_card(
            {
                "category": "danger",
                "rule_id": rule_id,
                "severity": "HIGH",
                "file": "app/api/route.ts",
                "line": 7,
                "message": "Security proof could not be completed",
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": evidence_kind,
                        "guards_seen": ["trusted verifier-shaped call"],
                        "guards_missing": ["route-local rejecting guard"],
                        "analysis_complete": False,
                        "analysis_diagnostics": [
                            f"work budget stopped near token={token}"
                        ],
                    }
                },
            }
        )

        rendered = "\n".join(card.evidence)
        assert card.label == "likely"
        assert card.confidence == 80
        assert "analysis was incomplete" in rendered.lower()
        assert "trusted verifier-shaped call" in rendered
        assert "route-local rejecting guard" in rendered
        assert "work budget stopped" in rendered
        assert token not in rendered


def test_complete_structured_security_flow_can_be_labeled_proven():
    card = build_evidence_card(
        {
            "category": "danger",
            "rule_id": "SKY-D280",
            "severity": "HIGH",
            "file": "app/api/route.ts",
            "line": 7,
            "message": "Authentication guard is missing",
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "authorization_guard",
                    "source": "Next.js POST route entry",
                    "sink": "database mutation",
                    "path": ["mutating route POST", "database mutation"],
                    "guards_seen": [],
                    "guards_missing": [
                        "route-local rejecting authentication guard before mutation"
                    ],
                    "analysis_complete": True,
                    "analysis_diagnostics": [],
                }
            },
        }
    )

    assert card.label == "proven"
    assert card.confidence == 92
    assert "route-local rejecting authentication guard" in "\n".join(card.evidence)


def test_structured_security_flow_requires_rule_specific_complete_schema():
    malformed_packets = (
        {"analysis_complete": True},
        {
            "evidence_kind": "webhook_signature_guard",
            "source": "route entry",
            "sink": "database mutation",
            "path": ["route entry", "database mutation"],
            "guards_missing": ["route-local rejecting guard"],
            "analysis_complete": True,
        },
    )

    for packet in malformed_packets:
        card = build_evidence_card(
            {
                "category": "danger",
                "rule_id": "SKY-D280",
                "severity": "HIGH",
                "file": "app/api/route.ts",
                "line": 7,
                "message": "Authentication guard is missing",
                "metadata": {"security_evidence": packet},
            }
        )

        assert card.label == "likely"
        assert "incomplete" in "\n".join(card.evidence).lower()


def test_each_structured_security_rule_accepts_only_its_complete_packet():
    packets = {
        "SKY-D252": {
            "evidence_kind": "cookie_security_options",
            "source": "cookie options",
            "sink": "Set-Cookie response",
            "path": ["cookie options", "Set-Cookie response"],
            "guards_missing": ["secure=true"],
            "options": {"httpOnly": "true", "secure": "false"},
            "analysis_complete": True,
        },
        "SKY-D280": {
            "evidence_kind": "authorization_guard",
            "source": "Next.js POST route entry",
            "sink": "database mutation",
            "path": ["route entry", "database mutation"],
            "guards_missing": [
                "route-local rejecting authentication guard before mutation"
            ],
            "analysis_complete": True,
        },
        "SKY-D281": {
            "evidence_kind": "server_action_sql_taint",
            "source": "dynamic server-action value",
            "sink": "interpolated SQL template",
            "path": ["dynamic value", "interpolated SQL template"],
            "guards_missing": ["parameterized SQL binding"],
            "analysis_complete": True,
        },
        "SKY-D282": {
            "evidence_kind": "webhook_signature_guard",
            "source": "raw request body",
            "sink": "event dispatch",
            "path": ["raw request body", "event dispatch"],
            "guards_missing": [
                "provider signature verification of request payload before body "
                "trust or side effect"
            ],
            "analysis_complete": True,
        },
    }

    for rule_id, packet in packets.items():
        card = build_evidence_card(
            {
                "category": "danger",
                "rule_id": rule_id,
                "severity": "HIGH",
                "metadata": {"security_evidence": packet},
            }
        )
        assert card.label == "proven", rule_id
