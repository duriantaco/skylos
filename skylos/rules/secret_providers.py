"""Independently specified provider candidates for the static secrets pass.

Prefixes come from provider documentation, not another scanner's expressions.
Only npm's fixed payload length and PyPI's minimum are published guarantees here.
DigitalOcean's hexadecimal body, Hugging Face's long alphanumeric body, and the
minimum opaque GitLab/Stripe/webhook bodies are conservative recognition profiles.
None of these shapes establishes that a provider accepts the credential.
"""

from __future__ import annotations

import re


def is_provider_marker_placeholder(provider: str, token: str) -> bool:
    """Recognize full x/X-body examples only in the new npm/Hugging Face profiles.

    This is a provider-specific placeholder convention, not an entropy rule.
    Any other payload character keeps the candidate eligible for detection.
    Redaction uses the broad compiled patterns and does not apply this policy.
    """
    if provider == "npm":
        prefix, minimum, maximum = "npm_", 36, 36
    elif provider == "huggingface":
        prefix, minimum, maximum = "hf_", 30, None
    else:
        return False
    if not token.startswith(prefix):
        return False
    body = token[len(prefix) :]
    if len(body) < minimum or (maximum is not None and len(body) > maximum):
        return False
    return not body.strip("xX")


def _token_pattern(prefixes, alphabet, *, minimum, maximum=None):
    alternatives = "|".join(re.escape(prefix) for prefix in prefixes)
    length = f"{{{minimum},}}" if maximum is None else f"{{{minimum},{maximum}}}"
    return re.compile(
        r"(?<![A-Za-z0-9_-])"
        + "(?:"
        + alternatives
        + ")["
        + alphabet
        + "]"
        + length
        + r"(?![A-Za-z0-9_-])"
    )


_GITLAB_ADDITIONAL_PREFIXES = (
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
_DIGITALOCEAN_PREFIXES = ("dop_v1_", "doo_v1_", "dor_v1_")
_STRIPE_ADDITIONAL_PREFIXES = ("rk_live_", "rk_test_", "sk_org_")


def _gitlab_token_pattern(prefixes, *, boundary=True):
    # GitLab's routable-token specification appends dot-separated version and
    # routing/checksum fields; job tokens may also contain JWT segments. Keep
    # the complete occurrence and allow ordinary sentence punctuation after it.
    return re.compile(
        (r"(?<![A-Za-z0-9_-])" if boundary else "")
        + "(?:"
        + "|".join(re.escape(prefix) for prefix in prefixes)
        + r")[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+)*"
        + r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9_-])"
    )


# Keep the existing classic-prefix matching behavior while recognizing the
# complete routed credential instead of a partial classic-looking substring.
GITLAB_LEGACY_PATTERN = _gitlab_token_pattern(("glpat-",), boundary=False)

# Match the actual authority and webhook path. A hostname appearing inside a
# lookalike authority or a nested URL path is not a Slack webhook credential.
_SLACK_WEBHOOK = re.compile(
    r"(?<![A-Za-z0-9_@:/.-])"
    r"(?i:https?://hooks\.slack(?:-gov)?\.com)"
    r"/services/T[A-Z0-9]{7,31}/[AB][A-Z0-9]{7,31}/"
    r"[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_/-])"
)

DEPTH_PROVIDER_PATTERNS = (
    ("npm", _token_pattern(("npm_",), "A-Za-z0-9", minimum=36, maximum=36)),
    ("pypi", _token_pattern(("pypi-",), "A-Za-z0-9_-", minimum=85)),
    (
        "digitalocean",
        _token_pattern(_DIGITALOCEAN_PREFIXES, "0-9A-Fa-f", minimum=64, maximum=64),
    ),
    ("huggingface", _token_pattern(("hf_",), "A-Za-z0-9", minimum=30)),
    (
        "gitlab",
        _gitlab_token_pattern(_GITLAB_ADDITIONAL_PREFIXES),
    ),
    (
        "stripe",
        _token_pattern(_STRIPE_ADDITIONAL_PREFIXES, "A-Za-z0-9", minimum=16),
    ),
    ("slack_webhook", _SLACK_WEBHOOK),
)

DEPTH_PROVIDER_PREFIXES = (
    "npm_",
    "pypi-",
    *_DIGITALOCEAN_PREFIXES,
    "hf_",
    *_GITLAB_ADDITIONAL_PREFIXES,
    *_STRIPE_ADDITIONAL_PREFIXES,
    "https://hooks.slack.com/services/",
    "https://hooks.slack-gov.com/services/",
    "http://hooks.slack.com/services/",
    "http://hooks.slack-gov.com/services/",
)
