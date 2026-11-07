"""New provider candidates must stay out of arbitrary audit text and keys."""

import base64
import hashlib
import json

import pytest

from skylos.audit.redaction import REDACTION, redact_text, sanitize_for_audit


BODY = "K8mN2pQ6rS0tU4vW8xY1zA5bC9dE3fG7hJ2k"
TOKENS = [
    "npm_" + BODY,
    "pypi-" + base64.urlsafe_b64encode(bytes(range(96))).decode().rstrip("="),
    "dop_v1_" + hashlib.sha256(b"non-issued provider fixture").hexdigest(),
    "hf_" + BODY,
    "gldt-" + BODY,
    "rk_live_" + BODY,
    "sk_org_" + BODY,
    "https://hooks.slack.com/services/" + "T83JK2NP1/B94LM3QR2/" + BODY[:24],
]


@pytest.mark.parametrize("token", TOKENS)
def test_new_provider_values_are_redacted_in_unlabelled_text(token):
    redacted = redact_text("Review includes " + token + " here.")
    assert token not in redacted
    assert REDACTION in redacted


@pytest.mark.parametrize("token", TOKENS)
def test_new_provider_values_are_redacted_in_nested_fields(token):
    result = sanitize_for_audit({"review": ["Observed " + token, {"note": token}]})
    assert token not in json.dumps(result)


@pytest.mark.parametrize("token", TOKENS)
def test_new_provider_values_are_redacted_in_dictionary_keys(token):
    result = sanitize_for_audit({token: "ordinary data", REDACTION: "another entry"})
    assert token not in json.dumps(result)
    assert set(result) == {REDACTION, REDACTION + "#2"}


@pytest.mark.parametrize(
    "value",
    [
        "pk_live_" + BODY,
        "https://workspace.slack.com/services/help",
        "https://hooks.slack.com.evil.example/services/T83JK2NP1/B94LM3QR2/"
        + BODY[:24],
    ],
)
def test_public_and_lookalike_values_do_not_get_new_secret_masks(value):
    assert redact_text("Review " + value) == "Review " + value


def test_routed_gitlab_credentials_are_redacted_as_complete_occurrences():
    token = "glpat-" + BODY + ".01.0024ab67"
    assert redact_text("Review " + token + " here") == "Review " + REDACTION + " here"
