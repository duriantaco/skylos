import json
import subprocess

from skylos.analyzer import analyze
from skylos.rules.ai_defect.test_impact import detect_test_impact_gaps


def _write_changed_source(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("def changed():\n    return True\n", encoding="utf-8")
    return path


def test_detects_high_risk_auth_change_without_tests(tmp_path):
    changed = [_write_changed_source(tmp_path / "src" / "auth" / "permissions.py")]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"
    assert findings[0]["category"] == "ai_defect"
    assert findings[0]["metadata"]["risk_area"] == "auth"
    assert findings[0]["metadata"]["signal_only"] is True
    assert findings[0]["metadata"]["blocking_recommended"] is False


def test_allows_high_risk_change_when_any_test_file_changed(tmp_path):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "test_tax.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_tax_total():\n    assert calculate_tax(100) == 8\n",
        encoding="utf-8",
    )
    changed = [
        source,
        test_file,
    ]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert findings == []


def test_allows_high_risk_change_when_meaningful_test_file_changed(tmp_path):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "test_tax.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_tax_total():\n    assert calculate_tax(100) == 8\n",
        encoding="utf-8",
    )
    changed = [source, test_file]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert findings == []


def test_reports_high_risk_change_when_test_file_has_no_meaningful_assertion(tmp_path):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "test_tax.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "# TODO assert billing behavior later\n"
        "def test_tax_total():\n"
        "    helper = make_tax_case()\n",
        encoding="utf-8",
    )
    changed = [source, test_file]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"
    assert findings[0]["metadata"]["risk_area"] == "billing"


def test_reports_high_risk_change_when_added_test_hunk_is_placeholder(
    tmp_path,
):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "test_tax.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_existing_tax_total():\n"
        "    assert calculate_tax(100) == 8\n"
        "\n"
        "def test_new_tax_total():\n"
        "    helper(\"assert billing later\")  # assert later\n",
        encoding="utf-8",
    )
    diff = """\
diff --git a/tests/test_tax.py b/tests/test_tax.py
--- a/tests/test_tax.py
+++ b/tests/test_tax.py
@@ -1,2 +1,5 @@
 def test_existing_tax_total():
     assert calculate_tax(100) == 8
+
+def test_new_tax_total():
+    helper("assert billing later")  # assert later
"""
    changed = [source, test_file]

    findings = detect_test_impact_gaps(
        tmp_path,
        changed,
        changed_file_diffs={"tests/test_tax.py": diff},
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"


def test_reports_high_risk_change_when_added_test_hunk_only_mentions_assert_in_block_comment(
    tmp_path,
):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "tax.test.js"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "test('tax total', () => {\n"
        "  helper(); /* assert billing later */\n"
        "});\n",
        encoding="utf-8",
    )
    diff = """\
diff --git a/tests/tax.test.js b/tests/tax.test.js
--- a/tests/tax.test.js
+++ b/tests/tax.test.js
@@ -0,0 +1,3 @@
+test('tax total', () => {
+  helper(); /* assert billing later */
+});
"""
    changed = [source, test_file]

    findings = detect_test_impact_gaps(
        tmp_path,
        changed,
        changed_file_diffs={"tests/tax.test.js": diff},
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"


def test_reports_high_risk_change_when_added_test_hunk_only_mentions_assert_in_multiline_block_comment(
    tmp_path,
):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "tax.test.js"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "test('tax total', () => {\n"
        "  /*\n"
        "   assert billing later\n"
        "  */\n"
        "  helper();\n"
        "});\n",
        encoding="utf-8",
    )
    diff = """\
diff --git a/tests/tax.test.js b/tests/tax.test.js
--- a/tests/tax.test.js
+++ b/tests/tax.test.js
@@ -0,0 +1,6 @@
+test('tax total', () => {
+  /*
+   assert billing later
+  */
+  helper();
+});
"""
    changed = [source, test_file]

    findings = detect_test_impact_gaps(
        tmp_path,
        changed,
        changed_file_diffs={"tests/tax.test.js": diff},
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"


def test_reports_high_risk_change_when_added_test_hunk_only_mentions_assert_in_triple_quoted_string(
    tmp_path,
):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "test_tax.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_tax_total():\n"
        "    '''\n"
        "    assert billing later\n"
        "    '''\n"
        "    helper()\n",
        encoding="utf-8",
    )
    diff = '''\
diff --git a/tests/test_tax.py b/tests/test_tax.py
--- a/tests/test_tax.py
+++ b/tests/test_tax.py
@@ -0,0 +1,5 @@
+def test_tax_total():
+    """
+    assert billing later
+    """
+    helper()
'''
    changed = [source, test_file]

    findings = detect_test_impact_gaps(
        tmp_path,
        changed,
        changed_file_diffs={"tests/test_tax.py": diff},
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"


def test_allows_high_risk_change_when_added_test_hunk_has_assertion(tmp_path):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    test_file = tmp_path / "tests" / "test_tax.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_existing_tax_total():\n"
        "    helper()\n"
        "\n"
        "def test_new_tax_total():\n"
        "    assert calculate_tax(100) == 8\n",
        encoding="utf-8",
    )
    diff = """\
diff --git a/tests/test_tax.py b/tests/test_tax.py
--- a/tests/test_tax.py
+++ b/tests/test_tax.py
@@ -1,2 +1,5 @@
 def test_existing_tax_total():
     helper()
+
+def test_new_tax_total():
+    assert calculate_tax(100) == 8
"""
    changed = [source, test_file]

    findings = detect_test_impact_gaps(
        tmp_path,
        changed,
        changed_file_diffs={"tests/test_tax.py": diff},
    )

    assert findings == []


def test_reports_high_risk_change_when_changed_test_file_was_deleted(tmp_path):
    source = _write_changed_source(tmp_path / "src" / "billing" / "tax.py")
    changed = [
        source,
        tmp_path / "tests" / "test_tax.py",
    ]

    findings = detect_test_impact_gaps(tmp_path, changed)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A102"


def test_allows_common_multilanguage_assertion_forms(tmp_path):
    cases = {
        "tests/AuthTest.java": "assertEquals(\"admin\", role);\nassertThat(role).isEqualTo(\"admin\");\n",
        "tests/AuthTest.cs": "Assert.Equal(\"admin\", role);\n",
        "tests/test_auth.php": "$this->assertFalse($guest->canDelete());\n",
        "tests/auth_test.rs": "assert_eq!(role, \"admin\");\n",
    }

    for relpath, source_text in cases.items():
        test_file = tmp_path / relpath
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(source_text, encoding="utf-8")
        source = _write_changed_source(tmp_path / "src" / "auth" / "permissions.py")
        changed = [source, test_file]

        findings = detect_test_impact_gaps(tmp_path, changed)

        assert findings == [], relpath


def test_ignores_low_risk_source_change_without_tests(tmp_path):
    changed = [_write_changed_source(tmp_path / "src" / "ui" / "theme.py")]

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


def test_analyzer_reports_test_impact_gap_when_changed_test_is_placeholder(
    tmp_path,
):
    auth_file = tmp_path / "src" / "auth" / "permissions.py"
    auth_file.parent.mkdir(parents=True)
    auth_file.write_text(
        """
def can_delete_user(user):
    return user.is_admin
""",
        encoding="utf-8",
    )
    test_file = tmp_path / "tests" / "test_permissions.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "# TODO assert delete permissions\n"
        "def test_can_delete_user():\n"
        "    user = make_user()\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            changed_files={str(auth_file), str(test_file)},
        )
    )

    findings = [
        finding
        for finding in result.get("ai_defects", [])
        if finding.get("rule_id") == "SKY-A102"
    ]

    assert len(findings) == 1
    assert findings[0]["file"] == "src/auth/permissions.py"


def test_analyzer_uses_test_diff_not_existing_assertions_for_test_impact(
    tmp_path,
):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=tmp_path,
        check=True,
    )

    auth_file = tmp_path / "src" / "auth" / "permissions.py"
    auth_file.parent.mkdir(parents=True)
    auth_file.write_text(
        """
def can_delete_user(user):
    return user.is_admin
""",
        encoding="utf-8",
    )
    test_file = tmp_path / "tests" / "test_permissions.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "def test_existing_permission():\n"
        "    assert can_delete_user(admin_user()) is True\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=tmp_path, check=True)

    auth_file.write_text(
        """
def can_delete_user(user):
    return user.is_admin or user.is_owner
""",
        encoding="utf-8",
    )
    test_file.write_text(
        "def test_existing_permission():\n"
        "    assert can_delete_user(admin_user()) is True\n"
        "\n"
        "def test_owner_permission():\n"
        "    helper(\"assert later\")  # assert later\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            changed_files={str(auth_file), str(test_file)},
        )
    )

    findings = [
        finding
        for finding in result.get("ai_defects", [])
        if finding.get("rule_id") == "SKY-A102"
    ]

    assert len(findings) == 1
    assert findings[0]["file"] == "src/auth/permissions.py"
