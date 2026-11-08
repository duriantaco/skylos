import json

import pytest

from skylos.rules import secrets


def _metadata_context(values):
    nested = [{"integrity": value} for value in values]
    for _ in range(100):
        nested = {"wrapper": nested}
    source = json.dumps(
        {"lockfileVersion": 3, "metadata": nested}, separators=(",", ":")
    )
    return {"relpath": "package-lock.json", "lines": [source + "\n"]}


def test_short_integrity_metadata_does_not_trigger_entropy_work(monkeypatch):
    context = _metadata_context(["a"] * 5_000)
    entropy_values = []
    original_entropy = secrets._entropy

    def track_entropy(value):
        entropy_values.append(value)
        return original_entropy(value)

    monkeypatch.setattr(secrets, "_entropy", track_entropy)

    assert list(secrets.scan_ctx(context)) == []
    assert entropy_values == []


@pytest.mark.parametrize("escaped", [False, True])
@pytest.mark.parametrize(
    "token,provider",
    [
        ("A1b2C3d4E5f6G7h8J9k", None),
        ("A1b2C3d4E5f6G7h8J9k0", "generic"),
        ("xoxb-1a" + "2b3c4d5e", "slack"),
    ],
)
def test_deep_integrity_metadata_keeps_secret_detection(token, provider, escaped):
    context = _metadata_context(["a", token, "a"])
    if escaped:
        encoded = "".join(f"\\u{ord(character):04x}" for character in token)
        context["lines"][0] = context["lines"][0].replace(token, encoded)

    findings = list(secrets.scan_ctx(context))

    if provider is None:
        assert findings == []
    else:
        assert any(
            finding["rule_id"] == "SKY-S101" and finding["provider"] == provider
            for finding in findings
        )
