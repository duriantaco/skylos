import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.swift import scan_swift_file


@pytest.mark.parametrize(
    ("body", "lines"),
    [
        ('UserDefaults.standard.set(value, forKey: "auth.refresh_token")', [3]),
        (
            (
                'let prefs = Foundation.UserDefaults(suiteName: "session")!\n'
                '  let key = "account_password"\n'
                "  prefs.set(value, forKey: key)"
            ),
            [5],
        ),
        (
            (
                "let prefs = UserDefaults.standard\n"
                '  prefs.set(value, forKey: "displayStyle")'
            ),
            [],
        ),
        ('UserDefaults.standard.set(nil, forKey: "refreshToken")', []),
        ('UserDefaults.standard.set(true, forKey: "password")', []),
        ('UserDefaults.standard.setValue(accessToken, forKey: "session")', [3]),
        (
            (
                "let UserDefaults = MockDefaults()\n"
                '  UserDefaults.standard.set(value, forKey: "refreshToken")'
            ),
            [],
        ),
        (
            'let prefs = MockDefaults()\n  prefs.set(value, forKey: "refreshToken")',
            [],
        ),
    ],
)
def test_foundation_user_defaults_credential_writes(tmp_path, body, lines):
    path = tmp_path / "Preferences.swift"
    path.write_text(
        "import Foundation\n"
        "func configure(value: String, accessToken: String) {\n"
        f"  {body}\n"
        "}\n"
    )

    findings = scan_swift_file(path)[7]
    assert [
        finding["line"] for finding in findings if finding["rule_id"] == "SKY-D434"
    ] == lines


def test_swift_security_default_and_opt_in(tmp_path):
    path = tmp_path / "Preferences.swift"
    path.write_text(
        "import Foundation\n"
        'func configure(value: String) { UserDefaults.standard.set(value, forKey: "apiKey") }\n'
    )

    assert not scan_swift_file(path, enable_danger_rules=False)[7]
    assert not json.loads(analyze(str(tmp_path))).get("danger")
    findings = json.loads(analyze(str(tmp_path), enable_danger=True)).get("danger", [])
    assert [
        (Path(row["file"]).name, row["line"])
        for row in findings
        if row["rule_id"] == "SKY-D434"
    ] == [("Preferences.swift", 2)]


def test_swift_security_consumes_the_rule_scoped_directive(tmp_path):
    path = tmp_path / "Preferences.swift"
    path.write_text(
        "import Foundation\n"
        "func configure(value: String) {\n"
        '    UserDefaults.standard.set(value, forKey: "apiKey") // skylos: ignore[SKY-D434]\n'
        "}\n"
    )
    result = scan_swift_file(path, _include_analysis_metadata=True)

    assert not result[7]
    assert [(row["rule_id"], row["line"]) for row in result[14]] == [("SKY-D434", 3)]
