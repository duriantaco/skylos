from textwrap import dedent

import pytest

from skylos.rules.danger.danger import scan_ctx


def check(tmp_path, source):
    path = tmp_path / "signatures.py"
    path.write_text(dedent(source).lstrip())
    return [
        item for item in scan_ctx(tmp_path, [path]) if item["rule_id"] == "SKY-D253"
    ]


@pytest.mark.parametrize("expression", ["expected == supplied", "supplied != expected"])
def test_hmac_comparison(tmp_path, expression):
    results = check(
        tmp_path,
        f"""
        from hmac import new as make_mac
        def matches(key, message, supplied):
            expected = make_mac(key, message, "sha256").hexdigest()
            return {expression}
    """,
    )
    assert [(item["line"], item["severity"]) for item in results] == [(4, "MEDIUM")]


def test_hmac_and_lookalikes(tmp_path):
    assert not check(
        tmp_path,
        """
        import hashlib
        import hmac
        def matches(key, message, supplied):
            digest = hmac.digest(key, message, "sha256")
            return hmac.compare_digest(digest, supplied)
        def checksum(message, expected):
            return hashlib.sha256(message).hexdigest() == expected
        def local(hmac, expected):
            return hmac.new().digest() != expected
    """,
    )
