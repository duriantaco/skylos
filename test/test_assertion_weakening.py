from skylos.rules.ai_defect.assertion_weakening import detect_assertion_weakening


def test_detects_specific_python_assert_replaced_with_truthiness():
    diff = """\
diff --git a/tests/test_billing.py b/tests/test_billing.py
index 1111111..2222222 100644
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -4,7 +4,7 @@ def test_invoice_status():
     result = calculate_invoice(order)
-    assert result.status == "paid"
-    assert result.amount == 100
+    assert result is not None
"""

    findings = detect_assertion_weakening(diff, "tests/test_billing.py")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A101"
    assert findings[0]["category"] == "ai_defect"
    assert findings[0]["metadata"]["weakening_type"] == "specific_to_broad_assertion"


def test_detects_removed_pytest_raises():
    diff = """\
diff --git a/tests/test_parser.py b/tests/test_parser.py
index 1111111..2222222 100644
--- a/tests/test_parser.py
+++ b/tests/test_parser.py
@@ -8,5 +8,5 @@ def test_rejects_bad_input():
-    with pytest.raises(ValueError):
-        parse_config("bad")
+    result = parse_config("bad")
+    assert result is not None
"""

    findings = detect_assertion_weakening(diff, "tests/test_parser.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "exception_assertion_removed"
    assert findings[0]["severity"] == "HIGH"


def test_ignores_non_test_files():
    diff = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -2,4 +2,4 @@ def check(result):
-    assert result.status == "paid"
+    assert result is not None
"""

    assert detect_assertion_weakening(diff, "app.py") == []
