import json

from skylos.analyzer import analyze
from skylos.rules.ai_defect.test_impact import detect_test_impact_gaps


def test_detects_high_risk_auth_change_without_tests(tmp_path):
    changed = [tmp_path / "src" / "auth" / "permissions.py"]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"
    assert findings[0]["category"] == "ai_defect"
    assert findings[0]["metadata"]["risk_area"] == "auth"
    assert findings[0]["metadata"]["signal_only"] is True
    assert findings[0]["metadata"]["blocking_recommended"] is False


def test_allows_high_risk_change_when_any_test_file_changed(tmp_path):
    changed = [
        tmp_path / "src" / "billing" / "tax.py",
        tmp_path / "tests" / "test_tax.py",
    ]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert findings == []


def test_ignores_low_risk_source_change_without_tests(tmp_path):
    changed = [tmp_path / "src" / "ui" / "theme.py"]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert findings == []


def test_ignores_test_file_only_change(tmp_path):
    changed = [tmp_path / "tests" / "test_auth.py"]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert findings == []


def test_analyzer_reports_test_impact_gap_under_ai_defects(tmp_path):
    auth_file = tmp_path / "src" / "auth" / "permissions.py"
    auth_file.parent.mkdir(parents=True)
    auth_file.write_text(
        """
def can_delete_user(user):
    return user.is_admin
""",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            changed_files={str(auth_file)},
        )
    )

    findings = [
        finding
        for finding in result.get("ai_defects", [])
        if finding.get("rule_id") == "SKY-A102"
    ]

    assert len(findings) == 1
    assert findings[0]["file"] == "src/auth/permissions.py"
