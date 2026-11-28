"""Exercise cURL TLS settings through the PHP security scanner."""

import pytest

from skylos.visitors.languages.php import scan_php_file


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);", [2]),
        ("curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, 0);", [2]),
        ("curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, 2);", []),
        ("curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, 1);", []),
        ("curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, true);", []),
        (
            "$verify = false;\ncurl_setopt($handle, CURLOPT_SSL_VERIFYPEER, $verify);",
            [3],
        ),
        (
            "$verify = false;\n$verify = true;\ncurl_setopt($handle, CURLOPT_SSL_VERIFYPEER, $verify);",
            [],
        ),
        ("curl_setopt($handle, CURLOPT_TIMEOUT, false);", []),
        (
            "curl_setopt_array($handle, [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0]);",
            [2],
        ),
        (
            "curl_setopt_array($handle, [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_TIMEOUT => 12]);",
            [2],
        ),
        (
            "curl_setopt_array($handle, [CURLOPT_SSL_VERIFYPEER => false, 64 => true]);",
            [],
        ),
        (
            "curl_setopt_array($handle, [CURLOPT_SSL_VERIFYPEER => false, $key => true]);",
            [],
        ),
        (
            "curl_setopt_array($handle, [$key => true, CURLOPT_SSL_VERIFYPEER => false]);",
            [2],
        ),
        ("curl_setopt(/* handle */ $handle, CURLOPT_SSL_VERIFYPEER, false);", [2]),
        (
            "curl_setopt_array($handle, [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYPEER => true]);",
            [],
        ),
        (
            "$options = array(CURLOPT_SSL_VERIFYHOST => 0);\ncurl_setopt_array($handle, $options);",
            [3],
        ),
        (
            "curl_setopt(value: false, handle: $handle, option: CURLOPT_SSL_VERIFYPEER);",
            [2],
        ),
        (
            "namespace Sample;\nuse function \\curl_setopt as configure;\nconfigure($handle, \\CURLOPT_SSL_VERIFYPEER, false);",
            [4],
        ),
        (
            "namespace Sample;\nfunction curl_setopt($a, $b, $c) {}\ncurl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);",
            [],
        ),
        (
            "namespace Sample;\nconst CURLOPT_SSL_VERIFYPEER = 1;\n\\curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);",
            [],
        ),
        ("$handler->curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);", []),
    ],
)
def test_effective_tls_options(tmp_path, code, expected):
    path = tmp_path / "transfer.php"
    path.write_text("<?php\n" + code, encoding="utf-8")
    findings = scan_php_file(str(path), {})[7]
    assert [
        (row["rule_id"], row["line"])
        for row in findings
        if row["rule_id"] == "SKY-D210"
    ] == [("SKY-D210", line) for line in expected]
