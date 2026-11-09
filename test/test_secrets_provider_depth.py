"""Provider-owned formats are recognized without widening generic entropy."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from skylos.rules.secrets import PROVIDER_PATTERN_BY_NAME, scan_ctx


# Deterministic, non-issued shapes. Real provider material is never requested.
ALNUM = "Ab3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY2zA4"
HEX = hashlib.sha256(b"skylos independent provider depth fixture").hexdigest()
PYPI_BODY = (
    base64.urlsafe_b64encode(
        hashlib.sha512(b"skylos non-issued macaroon-shaped payload").digest()
        + b"synthetic caveat data"
    )
    .decode()
    .rstrip("=")
)
SLACK_TAIL = f"T{ALNUM[:10].upper()}/B{ALNUM[10:20].upper()}/{ALNUM[:24]}"
GITLAB_PREFIXES = (
    "gloas-",
    "gldt-",
    "glrt-",
    "glrtr-",
    "glcbt-",
    "glptt-",
    "glft-",
    "glimt-",
    "glagent-",
    "glwt-",
    "glsoat-",
    "glffct-",
)
PROVIDER_CASES = [
    pytest.param("npm_" + ALNUM, "npm", id="npm"),
    pytest.param("pypi-" + PYPI_BODY, "pypi", id="pypi"),
    *[
        pytest.param(prefix + HEX, "digitalocean", id=prefix.rstrip("_"))
        for prefix in ("dop_v1_", "doo_v1_", "dor_v1_")
    ],
    pytest.param("hf_" + ALNUM[:34], "huggingface", id="huggingface"),
    *[
        pytest.param(prefix + ALNUM, "gitlab", id=prefix.rstrip("-"))
        for prefix in GITLAB_PREFIXES
    ],
    *[
        pytest.param(prefix + ALNUM, "stripe", id=prefix.rstrip("_"))
        for prefix in ("rk_live_", "rk_test_", "sk_org_")
    ],
    *[
        pytest.param(
            "https://" + host + "/services/" + SLACK_TAIL,
            "slack_webhook",
            id=host,
        )
        for host in ("hooks.slack.com", "hooks.slack-gov.com")
    ],
]


def _scan(source, path="README.md"):
    return list(
        scan_ctx({"relpath": path, "lines": source.splitlines(True), "tree": None})
    )


@pytest.mark.parametrize("token,provider", PROVIDER_CASES)
@pytest.mark.parametrize("path", ["src/app.py", "tests/test_config.py", "README.md"])
def test_new_provider_shapes_have_one_masked_finding(token, provider, path):
    source = f'VALUE = "{token}"\n'
    findings = _scan(source, path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["provider"] == provider
    assert finding["rule_id"] == "SKY-S101"
    assert finding["severity"] == "CRITICAL"
    assert finding["line"] == 1
    assert source[finding["col"] : finding["end_col"]] == token
    assert token not in json.dumps(findings)


@pytest.mark.parametrize("token,provider", PROVIDER_CASES)
def test_new_provider_replaces_its_identical_keyed_generic(token, provider):
    findings = _scan(f'API_TOKEN = "{token}"\n', "src/settings.py")
    assert [finding["provider"] for finding in findings] == [provider]


@pytest.mark.parametrize("token,provider", PROVIDER_CASES)
def test_provider_shapes_survive_existing_bounded_base64_decoder(token, provider):
    encoded = base64.b64encode(token.encode()).decode()
    findings = _scan(f'VALUE = "{encoded}"\n')
    assert [finding["provider"] for finding in findings] == [provider]
    assert findings[0]["decoding"]["encodings"] == ["base64"]
    assert token not in json.dumps(findings)


@pytest.mark.parametrize(
    "token",
    [
        "npm_" + ALNUM[:-1],
        "npm_" + ALNUM + "B",
        "prefixnpm_" + ALNUM,
        "npm_" + ALNUM + "_suffix",
        "pypi-" + "A" * 84,
        "prefixpypi-" + PYPI_BODY,
        "dop_v1_" + HEX[:-1],
        "dop_v1_" + HEX + "f",
        "dop_v1_" + HEX[:-1] + "g",
        "prefixdop_v1_" + HEX,
        "hf_" + ALNUM[:20],
        "prefixhf_" + ALNUM[:34],
        "hf_" + ALNUM[:34] + "_identifier",
        "rk_public_" + ALNUM,
        "rk_live_" + ALNUM[:12],
        "pk_live_" + ALNUM,
        "pk_test_" + ALNUM,
        *[prefix + "your_placeholder_token_here" for prefix in GITLAB_PREFIXES],
        "npm_example_value_here",
        "pypi-your-placeholder-value",
        "hf_your_placeholder_value_here",
    ],
)
def test_public_malformed_embedded_and_placeholder_controls_stay_quiet(token):
    assert _scan(f'VALUE = "{token}"\n') == []


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.slack.com.evil.invalid/services/" + SLACK_TAIL,
        "https://hooks.slack.com@evil.invalid/services/" + SLACK_TAIL,
        "https://evil.invalid/https://hooks.slack.com/services/" + SLACK_TAIL,
        "https://workspace.slack.com/services/" + SLACK_TAIL,
        "https://hooks.slack.com/api/" + SLACK_TAIL,
        "https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24,
        "https://hooks.slack-gov.com/services/T00000000/B00000000/" + "X" * 24,
        "https://hooks.slack.com/services/T12345678/B12345678/your-placeholder",
        "https://hooks.slack.com/services/{team}/{channel}/{secret}",
        "https://hooks.slack.com/services/" + SLACK_TAIL + "/unrelated",
    ],
)
def test_slack_webhook_validation_rejects_lookalike_authorities_and_examples(url):
    assert _scan(f'VALUE = "{url}"\n') == []


def test_dotted_gitlab_job_token_is_not_truncated():
    token = "glcbt-" + ALNUM + "." + ALNUM[::-1] + "." + ALNUM
    source = f'VALUE = "{token}"\n'
    findings = _scan(source)
    assert [finding["provider"] for finding in findings] == ["gitlab"]
    assert source[findings[0]["col"] : findings[0]["end_col"]] == token


def test_arbitrarily_long_pypi_caveat_payload_is_reported_whole():
    token = "pypi-" + PYPI_BODY * 80
    source = f'VALUE = "{token}"\n'
    findings = _scan(source)
    assert [finding["provider"] for finding in findings] == ["pypi"]
    assert source[findings[0]["col"] : findings[0]["end_col"]] == token


@pytest.mark.parametrize("prefix", ["AGPA", "AIDA", "AROA", "AIPA"])
@pytest.mark.parametrize("encoded", [False, True])
@pytest.mark.parametrize("path", ["README.md", "src/public_ids.py"])
def test_iam_resource_identifiers_are_not_access_key_credentials(prefix, encoded, path):
    token = prefix + "BCDEFGHJKLM23456"
    value = base64.b64encode(token.encode()).decode() if encoded else token
    assert _scan(f'VALUE = "{value}"\n', path) == []


@pytest.mark.parametrize("prefix", ["AKIA", "ASIA"])
@pytest.mark.parametrize("encoded", [False, True])
def test_actual_aws_access_key_families_are_preserved(prefix, encoded):
    token = prefix + "BCDEFGHJKLM23456"
    value = base64.b64encode(token.encode()).decode() if encoded else token
    findings = _scan(f'VALUE = "{value}"\n')
    assert [finding["provider"] for finding in findings] == ["aws_access_key_id"]


def test_distinct_locations_and_values_are_not_collapsed_by_provider_expansion():
    first, second = "npm_" + ALNUM, "pypi-" + PYPI_BODY
    source = f'FIRST = "{first}"; AGAIN = "{first}"; SECOND = "{second}"\n'
    findings = _scan(source)
    assert [finding["provider"] for finding in findings] == ["npm", "npm", "pypi"]
    assert len({finding["col"] for finding in findings}) == 3


@pytest.mark.parametrize("prefix", ["glpat-", "glrt-", "glrtr-", "glagent-"])
@pytest.mark.parametrize("encoded", [False, True])
def test_routable_gitlab_token_keeps_the_complete_credential_occurrence(
    prefix, encoded
):
    # GitLab's published routable-token specification includes a version and
    # routing/checksum trailer; no issued token or copied example is used.
    token = prefix + ALNUM + ".01." + HEX[:9]
    value = base64.b64encode(token.encode()).decode() if encoded else token
    source = f'API_TOKEN = "{value}"\n'
    findings = _scan(source, "src/settings.py")
    assert [finding["provider"] for finding in findings] == ["gitlab"]
    assert source[findings[0]["col"] : findings[0]["end_col"]] == value


@pytest.mark.parametrize("token,provider", PROVIDER_CASES)
def test_provider_lookup_retains_every_format_for_the_same_family(token, provider):
    assert PROVIDER_PATTERN_BY_NAME[provider].fullmatch(token) is not None


@pytest.mark.parametrize(
    "token,provider",
    [
        ("glpat-" + ALNUM, "gitlab"),
        ("sk_live_" + ALNUM, "stripe"),
        ("sk_test_" + ALNUM, "stripe"),
    ],
)
def test_provider_lookup_retains_existing_gitlab_and_stripe_formats(token, provider):
    assert PROVIDER_PATTERN_BY_NAME[provider].fullmatch(token) is not None


@pytest.mark.parametrize("prefix", ["AGPA", "AIDA", "AROA", "AIPA"])
def test_public_iam_identifier_noise_reduction_keeps_separate_generic_secret(prefix):
    source = f'USER_ID = "{prefix}BCDEFGHJKLM23456"\nAPI_TOKEN = "{ALNUM}"\n'
    findings = _scan(source, "src/settings.py")
    assert [finding["provider"] for finding in findings] == ["generic"]
    assert findings[0]["line"] == 2


@pytest.mark.parametrize("prefix", ["AGPA", "AIDA", "AROA", "AIPA", "AKIA", "ASIA"])
def test_checksum_provider_inspection_uses_actual_access_key_taxonomy(prefix):
    token = prefix + "BCDEFGHJKLM23456"
    digest = "A" + token + "A" * (85 - len(token)) + "=="
    source = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/pkg": {"integrity": "sha512-" + digest}},
        }
    )
    findings = _scan(source, "package-lock.json")
    expected = ["aws_access_key_id"] if prefix in {"AKIA", "ASIA"} else []
    assert [finding["provider"] for finding in findings] == expected


def _provider_marker_source(token, encoding):
    if encoding == "base64":
        token = base64.b64encode(token.encode()).decode()
    elif encoding == "percent":
        token = "".join(f"%{ord(character):02X}" for character in token)
    return f'API_TOKEN = "{token}"\n'


@pytest.mark.parametrize("prefix,size", [("npm_", 36), ("hf_", 34)])
@pytest.mark.parametrize("marker", ["x", "X", "xX"])
@pytest.mark.parametrize("encoding", ["raw", "base64", "percent"])
@pytest.mark.parametrize(
    "path", ["src/settings.py", "tests/test_config.py", "README.md"]
)
def test_new_provider_all_marker_placeholders_stay_quiet(
    prefix, size, marker, encoding, path
):
    token = prefix + (marker * size)[:size]
    assert _scan(_provider_marker_source(token, encoding), path) == []


@pytest.mark.parametrize(
    "prefix,size,provider", [("npm_", 36, "npm"), ("hf_", 34, "huggingface")]
)
@pytest.mark.parametrize("position", ["first", "last", "middle"])
@pytest.mark.parametrize("encoding", ["raw", "base64", "percent"])
@pytest.mark.parametrize(
    "path", ["src/settings.py", "tests/test_config.py", "README.md"]
)
def test_marker_lookalikes_with_other_payload_material_still_report(
    prefix, size, provider, position, encoding, path
):
    body = ["x"] * size
    index = {"first": 0, "middle": size // 2, "last": size - 1}[position]
    body[index] = "A"
    token = prefix + "".join(body)
    findings = _scan(_provider_marker_source(token, encoding), path)
    assert [finding["provider"] for finding in findings] == [provider]
    assert token not in json.dumps(findings)


@pytest.mark.parametrize("encoding", ["raw", "base64", "percent"])
def test_new_provider_marker_policy_does_not_change_legacy_github_shape(encoding):
    token = "ghp_" + "x" * 36
    assert [
        finding["provider"]
        for finding in _scan(_provider_marker_source(token, encoding))
    ] == ["github"]


@pytest.mark.parametrize("prefix,size", [("npm_", 36), ("hf_", 34)])
def test_marker_placeholders_keep_conservative_audit_redaction(prefix, size):
    from skylos.audit.redaction import REDACTION, redact_text

    token = prefix + "x" * size
    assert redact_text(token) == REDACTION
