import pytest

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


def test_allows_negative_test_renamed_with_unchanged_body():
    # Only the name changed; the guest-rejection body still runs, so no
    # negative case was removed (agent-pr-bench real-29 shape).
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

    assert detect_assertion_weakening(diff, "tests/test_auth.py") == []


def test_detects_negative_test_renamed_and_its_assertion_removed():
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 1111111..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -4,7 +4,6 @@ def test_allows_admin():
     assert can_delete(admin) is True
 
-def test_rejects_guest_delete():
+def test_guest_delete():
     guest = User(role="guest")
-    assert can_delete(guest) is False
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert [f["metadata"]["weakening_type"] for f in findings] == ["negative_test_removed"]


def test_allows_js_negative_test_renamed_with_unchanged_body():
    diff = """\
diff --git a/src/__tests__/hydration.test.tsx b/src/__tests__/hydration.test.tsx
--- a/src/__tests__/hydration.test.tsx
+++ b/src/__tests__/hydration.test.tsx
@@ -1266,7 +1331,7 @@ describe('dehydration and rehydration', () => {
     await promise
   })
 
-  it('should handle errors in promises for pending queries', async () => {
+  it('should redact errors by default when shouldRedactErrors is not set', async () => {
     const key = queryKey()
     const consoleMock = vi.spyOn(console, 'error')
     consoleMock.mockImplementation(() => undefined)
"""

    assert detect_assertion_weakening(diff, "src/__tests__/hydration.test.tsx") == []


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

    assert detect_assertion_weakening(diff, "tests/__snapshots__/test_api.snap") == []


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


def _hunk(path: str, removed: list[str], added: list[str]) -> str:
    lines = [f"-{line}" for line in removed] + [f"+{line}" for line in added]
    return (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        f"@@ -3,{len(removed)} +3,{len(added)} @@\n" + "\n".join(lines) + "\n"
    )


@pytest.mark.parametrize(
    ("removed", "added", "message"),
    [
        (
            'expect(() => compile("{{")).toThrow("Unclosed tag");',
            'expect(() => compile("{{")).not.toThrow();',
            "Exception assertion now expects no error",
        ),
        (
            'expect(() => compile("{{")).toThrowError("Unclosed tag");',
            'expect(() => compile("{{")).toThrowError();',
            "Exception assertion no longer checks which error is thrown",
        ),
        (
            "await expect(load()).rejects.toThrow(/missing file/);",
            "await expect(load()).rejects.toThrow(/./);",
            "Exception assertion no longer checks which error is thrown",
        ),
        (
            "expect(run).toThrow(TypeError);",
            "expect(run).toThrow(Error);",
            "Exception assertion no longer checks which error is thrown",
        ),
        (
            "expect(run).toThrow();",
            "expect(run).not.toThrow();",
            "Exception assertion now expects no error",
        ),
    ],
)
def test_detects_loosened_js_throw_expectations(removed, added, message):
    findings = detect_assertion_weakening(
        _hunk("src/lib.test.js", [f"    {removed}"], [f"    {added}"]),
        "src/lib.test.js",
    )
    assert [f["message"] for f in findings] == [f"AI defect: {message}"]
    assert findings[0]["metadata"]["weakening_type"] == "exception_assertion_loosened"


@pytest.mark.parametrize(
    ("removed", "added", "message"),
    [
        (
            'with pytest.raises(ValueError, match="Unclosed tag"):',
            "with pytest.raises(ValueError):",
            "pytest.raises no longer checks the error message",
        ),
        (
            "with pytest.raises(ValueError):",
            "with pytest.raises(Exception):",
            "pytest.raises now accepts any exception",
        ),
        (
            'with self.assertRaisesRegex(ValueError, "Unclosed"):',
            "with self.assertRaises(ValueError):",
            "assertRaisesRegex became assertRaises: the error message is no "
            "longer checked",
        ),
    ],
)
def test_detects_loosened_python_exception_assertions(removed, added, message):
    findings = detect_assertion_weakening(
        _hunk("tests/test_lib.py", [f"    {removed}"], [f"    {added}"]),
        "tests/test_lib.py",
    )
    assert [f["message"] for f in findings] == [f"AI defect: {message}"]


@pytest.mark.parametrize(
    ("path", "removed", "added"),
    [
        (
            "src/lib.test.js",
            'expect(f).toThrow("old message");',
            'expect(f).toThrow("new");',
        ),
        ("src/lib.test.js", "expect(f).toThrow();", "expect(f).toThrow(/bad input/);"),
        (
            "tests/test_lib.py",
            "with pytest.raises(ValueError):",
            'with pytest.raises(ValueError, match="bad"):',
        ),
        (
            "tests/test_lib.py",
            'with pytest.raises(ValueError, match="a"):',
            'with pytest.raises(KeyError, match="b"):',
        ),
    ],
)
def test_specific_or_stricter_exception_assertions_are_not_loosened(
    path, removed, added
):
    assert (
        detect_assertion_weakening(
            _hunk(path, [f"    {removed}"], [f"    {added}"]), path
        )
        == []
    )


_AUTH_HEADER = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
"""


def test_detects_rename_when_a_later_hunk_changes_the_renamed_test():
    # The renamed test's body runs past the first hunk; the next hunk changes
    # it before the body ends, so the rename does not prove the test intact.
    diff = _AUTH_HEADER + """\
@@ -10,4 +10,4 @@ def client():
 
 
-def test_rejects_expired_token(client):
+def test_expired_token(client):
     token = make_token(expired=True)
     headers = {"Authorization": f"Bearer {token}"}
@@ -20,4 +20,4 @@ def test_rejects_expired_token(client):
     audit = client.get("/audit").json()
     assert audit["events"]
     resp = client.get("/api/me", headers=headers)
-    assert resp.status_code == 401
+    assert resp.status_code != 500
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert [f["metadata"]["weakening_type"] for f in findings] == ["negative_test_removed"]


def test_detects_rename_with_a_line_added_to_the_body():
    diff = _AUTH_HEADER + """\
@@ -10,7 +10,8 @@ def client():
 
 
-def test_rejects_expired_token(client):
+def test_expired_token_flow(client):
     token = make_token(expired=True)
     resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
+    return
     assert resp.status_code == 401
 
 
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert [f["metadata"]["weakening_type"] for f in findings] == ["negative_test_removed"]


def test_allows_rename_when_the_next_hunk_changes_another_test():
    # The next hunk's context shows the renamed body ending (a new test at the
    # same indentation) before its change.
    diff = _AUTH_HEADER + """\
@@ -10,4 +10,4 @@ def client():
 
 
-def test_rejects_expired_token(client):
+def test_rejects_expired_bearer_token(client):
     token = make_token(expired=True)
     headers = {"Authorization": f"Bearer {token}"}
@@ -20,6 +20,6 @@ def test_rejects_expired_token(client):
     assert resp.status_code == 401
 
 
 def test_health(client):
-    resp = client.get("/health")
+    resp = client.get("/healthz")
"""

    assert detect_assertion_weakening(diff, "tests/test_auth.py") == []


def test_allows_js_rename_when_the_next_hunk_changes_another_test():
    diff = """\
diff --git a/src/auth.test.ts b/src/auth.test.ts
--- a/src/auth.test.ts
+++ b/src/auth.test.ts
@@ -10,4 +10,4 @@ describe('auth', () => {
-  it('rejects an expired token', async () => {
+  it('rejects an expired bearer token', async () => {
     const token = makeToken({ expired: true })
     const res = await get('/api/me', token)
@@ -20,6 +20,6 @@ describe('auth', () => {
     expect(res.status).toBe(401)
   })
 
   it('serves health', async () => {
-    const res = await get('/health')
+    const res = await get('/healthz')
"""

    assert detect_assertion_weakening(diff, "src/auth.test.ts") == []


# A rename counts only when the declaration lines match apart from the name,
# the new name is not declared again, and the body (to its closing bracket or
# dedent, string contents aside) is unchanged. Each case is a removed
# negative test that base reported (round-5 review).
NOT_RENAMES = [
    pytest.param(
        'tests/test_auth.py',
        'diff --git a/tests/test_auth.py b/tests/test_auth.py\n--- a/tests/test_auth.py\n+++ b/tests/test_auth.py\n@@ -10,7 +10,7 @@ def client():\n\n\n-def test_rejects_expired_token(\n+def test_expired_token(\n     client,\n     make_token,\n ):\n@@ -22,4 +22,4 @@ def test_rejects_expired_token(\n     resp = client.get("/api/me", headers=headers)\n     audit = client.get("/audit").json()\n     assert audit["events"]\n-    assert resp.status_code == 401\n+    assert resp.status_code == 200\n',
        12,
        id='multi-line signature renamed, assert flipped in a later hunk',
    ),
    pytest.param(
        'src/__tests__/validate.test.ts',
        'diff --git a/src/__tests__/validate.test.ts b/src/__tests__/validate.test.ts\n--- a/src/__tests__/validate.test.ts\n+++ b/src/__tests__/validate.test.ts\n@@ -4,7 +4,7 @@ import { validateEmail } from "../validate";\n describe("validateEmail", () => {\n   it("accepts a normal address", () => expect(validateEmail("a@b.co")).toBe(true));\n-  it("rejects an empty address", () => expect(validateEmail("")).toBe(false));\n+  it("handles an empty address", () => expect(validateEmail("")).toBe(true));\n   it("accepts plus addressing", () => expect(validateEmail("a+x@b.co")).toBe(true));\n });\n',
        6,
        id='one-line JS test renamed and flipped on the same line',
    ),
    pytest.param(
        'e2e/session.spec.ts',
        'diff --git a/e2e/session.spec.ts b/e2e/session.spec.ts\n--- a/e2e/session.spec.ts\n+++ b/e2e/session.spec.ts\n@@ -12,7 +12,7 @@ test.describe("session", () => {\n     await expect(page).toHaveURL("/dashboard");\n   });\n\n-  test("rejects an expired session cookie", async ({ page, context }) => {\n+  test.fixme("rejects an expired session cookie", async ({ page, context }) => {\n     await context.addCookies([expiredCookie]);\n     await page.goto("/dashboard");\n     await expect(page).toHaveURL(/login/);\n',
        15,
        id='Playwright test changed to test.fixme',
    ),
    pytest.param(
        'src/__tests__/billing.test.js',
        'diff --git a/src/__tests__/billing.test.js b/src/__tests__/billing.test.js\n--- a/src/__tests__/billing.test.js\n+++ b/src/__tests__/billing.test.js\n@@ -20,7 +20,7 @@ describe("charge", () => {\n   });\n\n-  test("throws on a negative amount", () => {\n+  test.failing("throws on a negative amount", () => {\n     expect(() => charge(-5)).toThrow(RangeError);\n   });\n\n',
        22,
        id='Jest test changed to test.failing',
    ),
    pytest.param(
        'tests/test_config.py',
        'diff --git a/tests/test_config.py b/tests/test_config.py\n--- a/tests/test_config.py\n+++ b/tests/test_config.py\n@@ -40,12 +40,12 @@ def test_loads_minimal(tmp_path):\n\n\n-def test_rejects_unclosed_list(tmp_path):\n+def test_unclosed_list(tmp_path):\n     path = tmp_path / "svc.yaml"\n     path.write_text("""\n name: svc\n replicas: [\n """)\n     result = load_config(path)\n-    assert result.errors == ["replicas: unclosed list"]\n+    assert result.errors == []\n\n\n',
        42,
        id='string at column 0 inside the renamed test body',
    ),
    pytest.param(
        'tests/test_auth.py',
        'diff --git a/tests/test_auth.py b/tests/test_auth.py\n--- a/tests/test_auth.py\n+++ b/tests/test_auth.py\n@@ -10,11 +10,11 @@ def client():\n\n\n-def test_rejects_expired_token(client):\n+def test_token_flow(client):\n     resp = client.get("/api/me", headers=auth(EXPIRED))\n     assert resp.status_code == 401\n\n\n def test_token_flow(client):\n     resp = client.get("/api/me", headers=auth(VALID))\n     assert resp.status_code == 200\n',
        12,
        id='renamed to the name of a later test',
    ),
]


@pytest.mark.parametrize(("path", "diff", "line"), NOT_RENAMES)
def test_reports_negative_test_changes_that_are_not_renames(path, diff, line):
    findings = detect_assertion_weakening(diff, path)

    assert [(f["line"], f["metadata"]["weakening_type"]) for f in findings] == [
        (line, "negative_test_removed")
    ]
