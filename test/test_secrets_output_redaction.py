"""Provider recognition must not expose the newly supported token in reports."""

import json

from skylos.audit.redaction import REDACTION, redact_text, sanitize_for_audit
from skylos.cicd.evidence import redact_sensitive_text


def _finegrained_token():
    return "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1" + "_" + "aB3" * 19 + "Z9"


def test_audit_redacts_finegrained_token_without_a_sensitive_field_name():
    token = _finegrained_token()
    rendered = redact_text("response contains " + token + "; retry later")
    assert rendered == "response contains " + REDACTION + "; retry later"


def test_audit_redacts_finegrained_token_in_nested_values_and_keys():
    token = _finegrained_token()
    value = {"message": ["response " + token], token: "public text"}
    rendered = sanitize_for_audit(value)
    assert rendered == {
        "message": ["response " + REDACTION],
        REDACTION: REDACTION,
    }
    assert token not in json.dumps(rendered)


def test_cicd_redacts_finegrained_token_in_ordinary_prose():
    token = _finegrained_token()
    rendered = redact_sensitive_text("response contains " + token + "; retry later")
    assert token not in rendered
    assert "response contains " in rendered
    assert "; retry later" in rendered


def test_audit_keeps_a_public_reference_and_surrounding_text():
    value = "Read https://github.com/o/r and $GITHUB_TOKEN for setup"
    assert redact_text(value) == value
