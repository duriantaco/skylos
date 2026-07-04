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


def test_detects_removed_negative_test_case():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -4,8 +4,4 @@ def test_allows_admin():
     assert can_delete(admin) is True
-
-def test_rejects_guest_delete():
-    guest = User(role="guest")
-    assert can_delete(guest) is False
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "negative_test_removed"
    assert findings[0]["severity"] == "HIGH"


def test_detects_removed_denied_negative_test_case():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -4,8 +4,4 @@ def test_allows_admin():
     assert can_delete(admin) is True
-
-def test_access_denied_for_guest():
-    guest = User(role="guest")
-    assert can_delete(guest) is False
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "negative_test_removed"


def test_allows_negative_test_replaced_with_equivalent_negative_case():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -4,7 +4,7 @@ def test_allows_admin():
     assert can_delete(admin) is True
-
-def test_rejects_guest_delete():
+def test_denies_guest_delete():
     guest = User(role="guest")
     assert can_delete(guest) is False
"""

    assert detect_assertion_weakening(diff, "tests/test_auth.py") == []


def test_detects_negative_test_replaced_with_unrelated_negative_case():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -4,7 +4,7 @@ def test_allows_admin():
     assert can_delete(admin) is True
-
-def test_rejects_guest_delete():
+def test_rejects_admin_delete():
     guest = User(role="guest")
     assert can_delete(guest) is False
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "negative_test_removed"


def test_detects_broadened_mock_assertion():
    diff = """\
diff --git a/tests/test_webhook.py b/tests/test_webhook.py
index 1111111..2222222 100644
--- a/tests/test_webhook.py
+++ b/tests/test_webhook.py
@@ -8,6 +8,6 @@ def test_webhook_sends_signed_payload(gateway):
     handler(payload)
-    gateway.send.assert_called_once_with(payload, signature="abc123")
+    gateway.send.assert_called()
"""

    findings = detect_assertion_weakening(diff, "tests/test_webhook.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "mock_assertion_broadened"
    assert findings[0]["severity"] == "MEDIUM"


def test_allows_unrelated_mock_assertion_changes_in_same_hunk():
    diff = """\
diff --git a/tests/test_webhook.py b/tests/test_webhook.py
index 1111111..2222222 100644
--- a/tests/test_webhook.py
+++ b/tests/test_webhook.py
@@ -8,7 +8,7 @@ def test_webhook_sends_signed_payload(gateway, notifier):
-    gateway.send.assert_called_once_with(payload, signature="abc123")
+    notifier.notify.assert_called()
"""

    assert detect_assertion_weakening(diff, "tests/test_webhook.py") == []


def test_detects_mock_contract_broadened_by_removing_spec():
    diff = """\
diff --git a/tests/test_payments.py b/tests/test_payments.py
index 1111111..2222222 100644
--- a/tests/test_payments.py
+++ b/tests/test_payments.py
@@ -9,7 +9,7 @@ def test_payment_uses_gateway():
-    gateway = Mock(spec_set=PaymentGateway)
+    gateway = Mock()
     process_payment(gateway)
"""

    findings = detect_assertion_weakening(diff, "tests/test_payments.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "mock_contract_broadened"


def test_detects_multiline_mock_contract_broadened_by_removing_spec():
    diff = """\
diff --git a/tests/test_payments.py b/tests/test_payments.py
index 1111111..2222222 100644
--- a/tests/test_payments.py
+++ b/tests/test_payments.py
@@ -9,9 +9,7 @@ def test_payment_uses_gateway():
-    gateway = Mock(
-        spec_set=PaymentGateway,
-    )
+    gateway = Mock()
     process_payment(gateway)
"""

    findings = detect_assertion_weakening(diff, "tests/test_payments.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "mock_contract_broadened"


def test_detects_multiline_mock_contract_broadened_when_only_spec_removed():
    diff = """\
diff --git a/tests/test_payments.py b/tests/test_payments.py
index 1111111..2222222 100644
--- a/tests/test_payments.py
+++ b/tests/test_payments.py
@@ -9,9 +9,8 @@ def test_payment_uses_gateway():
     gateway = Mock(
-        spec_set=PaymentGateway,
     )
     process_payment(gateway)
"""

    findings = detect_assertion_weakening(diff, "tests/test_payments.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "mock_contract_broadened"


def test_allows_unrelated_mock_contract_changes_in_same_hunk():
    diff = """\
diff --git a/tests/test_payments.py b/tests/test_payments.py
index 1111111..2222222 100644
--- a/tests/test_payments.py
+++ b/tests/test_payments.py
@@ -9,7 +9,7 @@ def test_payment_uses_gateway():
-    gateway = Mock(spec_set=PaymentGateway)
+    helper = Mock()
     process_payment(gateway)
"""

    assert detect_assertion_weakening(diff, "tests/test_payments.py") == []


def test_allows_added_loose_mock_when_strict_mock_is_only_context():
    diff = """\
diff --git a/tests/test_payments.py b/tests/test_payments.py
index 1111111..2222222 100644
--- a/tests/test_payments.py
+++ b/tests/test_payments.py
@@ -9,6 +9,7 @@ def test_payment_uses_gateway():
     gateway = Mock(spec_set=PaymentGateway)
     process_payment(gateway)
+    gateway = Mock()
     assert gateway.called
"""

    assert detect_assertion_weakening(diff, "tests/test_payments.py") == []


def test_allows_strict_mock_non_spec_argument_change_with_loose_context():
    diff = """\
diff --git a/tests/test_payments.py b/tests/test_payments.py
index 1111111..2222222 100644
--- a/tests/test_payments.py
+++ b/tests/test_payments.py
@@ -9,10 +9,10 @@ def test_payment_uses_gateway():
     gateway = Mock(
         spec_set=PaymentGateway,
-        name="old",
+        name="new",
     )
     gateway = Mock()
     assert gateway.called
"""

    assert detect_assertion_weakening(diff, "tests/test_payments.py") == []


def test_detects_expected_value_broadened_to_any():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -6,5 +6,5 @@ def test_admin_role():
     response = get_user()
-    assert response["role"] == "admin"
+    assert response["role"] == ANY
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "expected_value_broadened"


def test_detects_js_expected_value_broadened_to_any_matcher():
    diff = """\
diff --git a/tests/auth.test.js b/tests/auth.test.js
index 1111111..2222222 100644
--- a/tests/auth.test.js
+++ b/tests/auth.test.js
@@ -6,5 +6,5 @@ test('admin role', () => {
-  expect(response.role).toBe("admin");
+  expect(response.role).toEqual(expect.any(String));
 });
"""

    findings = detect_assertion_weakening(diff, "tests/auth.test.js")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "expected_value_broadened"


def test_detects_js_expected_value_broadened_with_nested_target_call():
    diff = """\
diff --git a/tests/auth.test.js b/tests/auth.test.js
index 1111111..2222222 100644
--- a/tests/auth.test.js
+++ b/tests/auth.test.js
@@ -6,5 +6,5 @@ test('admin role', () => {
-  expect(getUser().role).toEqual("admin");
+  expect(getUser().role).toEqual(expect.any(String));
 });
"""

    findings = detect_assertion_weakening(diff, "tests/auth.test.js")

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "expected_value_broadened"


def test_allows_exact_expected_value_named_any_value():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -6,5 +6,5 @@ def test_admin_role():
     response = get_user()
-    assert response["role"] == "admin"
+    assert response["role"] == ANY_VALUE
"""

    assert detect_assertion_weakening(diff, "tests/test_auth.py") == []


def test_allows_specific_expected_value_change():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -6,5 +6,5 @@ def test_admin_role():
     response = get_user()
-    assert response["role"] == "pending_admin"
+    assert response["role"] == "admin"
"""

    assert detect_assertion_weakening(diff, "tests/test_auth.py") == []


def test_detects_snapshot_churn():
    diff = """\
diff --git a/tests/__snapshots__/test_api.snap b/tests/__snapshots__/test_api.snap
index 1111111..2222222 100644
--- a/tests/__snapshots__/test_api.snap
+++ b/tests/__snapshots__/test_api.snap
@@ -1,4 +1,4 @@
-exports[`api response 1`] = `{"role":"admin"}`;
+exports[`api response 1`] = `{"role":"user"}`;
"""

    findings = detect_assertion_weakening(
        diff,
        "tests/__snapshots__/test_api.snap",
    )

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "snapshot_churn"


def test_detects_snapshot_deletion_churn():
    diff = """\
diff --git a/tests/__snapshots__/test_api.snap b/tests/__snapshots__/test_api.snap
index 1111111..2222222 100644
--- a/tests/__snapshots__/test_api.snap
+++ b/tests/__snapshots__/test_api.snap
@@ -1,2 +0,0 @@
-exports[`api response 1`] = `{"role":"admin"}`;
-exports[`api response 2`] = `{"role":"user"}`;
"""

    findings = detect_assertion_weakening(
        diff,
        "tests/__snapshots__/test_api.snap",
    )

    assert len(findings) == 1
    assert findings[0]["metadata"]["weakening_type"] == "snapshot_churn"


def test_allows_new_snapshot_without_churn():
    diff = """\
diff --git a/tests/__snapshots__/test_api.snap b/tests/__snapshots__/test_api.snap
new file mode 100644
--- /dev/null
+++ b/tests/__snapshots__/test_api.snap
@@ -0,0 +1,2 @@
+exports[`api response 1`] = `{"role":"admin"}`;
+exports[`api response 2`] = `{"role":"user"}`;
"""

    assert (
        detect_assertion_weakening(diff, "tests/__snapshots__/test_api.snap") == []
    )


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
