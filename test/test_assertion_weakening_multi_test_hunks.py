"""SKY-A101 must report each weakened test when one diff hunk spans several tests.

Before the fix, a hunk produced at most one finding, so a skipped test hid a
weakened assertion in the neighbouring test (agent-pr-bench fa-09 and ex-14).
"""

from skylos.rules.ai_defect.assertion_weakening import detect_assertion_weakening


def _summary(findings):
    return [(f["line"], f["metadata"]["weakening_type"]) for f in findings]


def test_widened_assertion_and_skip_in_neighbouring_tests_are_both_reported():
    diff = """\
diff --git a/backend/tests/api/routes/test_items.py b/backend/tests/api/routes/test_items.py
--- a/backend/tests/api/routes/test_items.py
+++ b/backend/tests/api/routes/test_items.py
@@ -121,11 +123,10 @@ def test_update_item_not_enough_permissions(
         headers=normal_user_token_headers,
         json=data,
     )
-    assert response.status_code == 403
-    content = response.json()
-    assert content["detail"] == "Not enough permissions"
+    assert response.status_code in (200, 403)


+@pytest.mark.skip(reason="flaky on CI")
 def test_delete_item(
     client: TestClient, superuser_token_headers: dict[str, str], db: Session
 ) -> None:
"""

    findings = detect_assertion_weakening(diff, "backend/tests/api/routes/test_items.py")

    assert _summary(findings) == [
        (126, "assertion_widened_membership"),
        (129, "test_disabled"),
    ]


def test_js_broadened_rejection_and_skip_in_neighbouring_tests_are_both_reported():
    diff = """\
diff --git a/src/tests/services/auth.service.test.ts b/src/tests/services/auth.service.test.ts
--- a/src/tests/services/auth.service.test.ts
+++ b/src/tests/services/auth.service.test.ts
@@ -42,11 +42,10 @@ describe('AuthService', () => {
       };

       // Then
-      const error = String({ errors: { username: ["can't be blank"] } });
-      await expect(createUser(user)).rejects.toThrow(error);
+      await expect(createUser(user)).rejects.toBeDefined();
     });

-    test('should throw an error when creating new user with empty email ', async () => {
+    test.skip('should throw an error when creating new user with empty email ', async () => {
       // Given
       const user = {
         id: 123,
"""

    findings = detect_assertion_weakening(diff, "src/tests/services/auth.service.test.ts")

    assert _summary(findings) == [
        (45, "specific_to_broad_assertion"),
        (48, "test_disabled"),
    ]


def test_two_non_skip_weakenings_in_neighbouring_tests_are_both_reported():
    diff = """\
diff --git a/tests/test_notify.py b/tests/test_notify.py
--- a/tests/test_notify.py
+++ b/tests/test_notify.py
@@ -10,10 +10,10 @@ def test_sends_email(mailer):
     notify(user)
-    mailer.send.assert_called_once_with("a@example.com", "Welcome")
+    mailer.send.assert_called()


 def test_status_code(client):
     response = client.get("/admin")
-    assert response.status_code == 403
+    assert response.status_code in (200, 403)
"""

    findings = detect_assertion_weakening(diff, "tests/test_notify.py")

    assert _summary(findings) == [
        (11, "mock_assertion_broadened"),
        (16, "assertion_widened_membership"),
    ]


def test_renamed_test_stays_one_unit():
    # Removed and added declarations in one change block are one unit (a
    # rename with the body unchanged), so nothing is reported.
    diff = """\
diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -10,6 +10,6 @@
-def test_rejects_expired_token(client):
+def test_rejects_expired_token_after_refresh(client):
     response = client.get("/me", headers=expired())
     assert response.status_code == 401
"""

    findings = detect_assertion_weakening(diff, "tests/test_auth.py")

    assert _summary(findings) == []


def test_skip_and_removed_raises_in_one_test_stay_one_finding():
    diff = """\
diff --git a/tests/test_parser.py b/tests/test_parser.py
--- a/tests/test_parser.py
+++ b/tests/test_parser.py
@@ -5,6 +5,6 @@
 def test_rejects_bad_input():
-    with pytest.raises(ValueError):
-        parse_config("bad")
+    pytest.skip("flaky")
+    parse_config("bad")
"""

    findings = detect_assertion_weakening(diff, "tests/test_parser.py")

    assert _summary(findings) == [(6, "test_disabled")]


def test_hunk_level_finding_is_kept_when_evidence_spans_tests():
    # The whole-hunk result is always kept, so splitting by test never loses
    # a finding the detector reported before.
    diff = """\
diff --git a/tests/test_orders.py b/tests/test_orders.py
--- a/tests/test_orders.py
+++ b/tests/test_orders.py
@@ -3,9 +3,9 @@ def test_total(order):
     total = order.total()
-    assert total == 100


 def test_lookup(order):
     found = lookup(order.id)
+    assert found
"""

    findings = detect_assertion_weakening(diff, "tests/test_orders.py")

    assert _summary(findings) == [(8, "specific_to_broad_assertion")]


def test_one_removed_exception_assertion_is_reported_once_at_its_test():
    diff = """\
diff --git a/tests/test_parse.py b/tests/test_parse.py
--- a/tests/test_parse.py
+++ b/tests/test_parse.py
@@ -1,9 +1,8 @@
 def test_a():
     value = compute()
+    assert value
 
 
 def test_b():
-    with pytest.raises(ValueError):
-        parse("bad")
+    parse("bad")
"""

    findings = detect_assertion_weakening(diff, "tests/test_parse.py")

    assert _summary(findings) == [(7, "exception_assertion_removed")]


def test_same_weakening_in_two_tests_is_reported_for_each_test():
    diff = """\
diff --git a/tests/test_admin.py b/tests/test_admin.py
--- a/tests/test_admin.py
+++ b/tests/test_admin.py
@@ -1,7 +1,7 @@
 def test_a(client):
-    assert client.get("/a").status_code == 403
+    assert client.get("/a").status_code in (200, 403)
 
 
 def test_b(client):
-    assert client.get("/a").status_code == 403
+    assert client.get("/a").status_code in (200, 403)
"""

    findings = detect_assertion_weakening(diff, "tests/test_admin.py")

    assert _summary(findings) == [
        (2, "assertion_widened_membership"),
        (6, "assertion_widened_membership"),
    ]


def test_a_call_named_test_inside_a_test_body_does_not_split_the_test():
    diff = """\
diff --git a/src/run.test.ts b/src/run.test.ts
--- a/src/run.test.ts
+++ b/src/run.test.ts
@@ -1,6 +1,6 @@
 it('rejects bad input', async () => {
-  await expect(run()).rejects.toThrow('bad');
+  await expect(run()).rejects.toBeDefined();
   test(result);
-  expect(mock).toHaveBeenCalledWith(1);
+  expect(mock).toHaveBeenCalled();
 });
"""

    findings = detect_assertion_weakening(diff, "src/run.test.ts")

    assert len(findings) == 1


def test_formatter_wrapping_an_assert_in_parentheses_is_not_a_weakening():
    diff = """\
diff --git a/tests/test_prompts.py b/tests/test_prompts.py
--- a/tests/test_prompts.py
+++ b/tests/test_prompts.py
@@ -1,4 +1,6 @@
 def test_prompt():
     system = build()
-    assert "rules" in system
+    assert (
+        "rules" in system
+    )
"""

    findings = detect_assertion_weakening(diff, "tests/test_prompts.py")

    assert findings == []


def test_multiline_assert_is_judged_on_its_whole_condition():
    # Independent review: ``assert (`` must not hide a weakened condition.
    diff = """\
diff --git a/tests/test_admin.py b/tests/test_admin.py
--- a/tests/test_admin.py
+++ b/tests/test_admin.py
@@ -1,4 +1,6 @@
 def test_admin(client):
     response = client.get("/admin")
-    assert response.status_code == 403
+    assert (
+        True
+    )
"""

    findings = detect_assertion_weakening(diff, "tests/test_admin.py")

    assert _summary(findings) == [(3, "specific_to_broad_assertion")]


def test_brackets_inside_string_literals_do_not_join_or_hide_asserts():
    diff = """\
diff --git a/tests/test_marker.py b/tests/test_marker.py
--- a/tests/test_marker.py
+++ b/tests/test_marker.py
@@ -1,3 +1,3 @@
 def test_exact_marker():
     value = render_marker()
-    assert value == "("
+    assert value.startswith("(")
"""
    findings = detect_assertion_weakening(diff, "tests/test_marker.py")
    assert [(f["line"], f["metadata"]["weakening_type"]) for f in findings] == [
        (3, "specific_to_broad_assertion")
    ]


def test_many_tests_in_one_hunk_scale_linearly():
    import time

    def diff_for(count):
        rows = []
        for index in range(count):
            rows += [
                f" def test_case_{index}():",
                f"-    assert run({index}) == {index}",
                f"+    assert run({index})",
            ]
        return (
            "diff --git a/tests/test_many.py b/tests/test_many.py\n"
            "--- a/tests/test_many.py\n+++ b/tests/test_many.py\n"
            f"@@ -1,{2 * count} +1,{2 * count} @@\n" + "\n".join(rows) + "\n"
        )

    def best_of_three(count):
        times = []
        for _ in range(3):
            started = time.perf_counter()
            found = len(detect_assertion_weakening(diff_for(count), "tests/test_many.py"))
            times.append(time.perf_counter() - started)
        return found, min(times)

    small, small_time = best_of_three(500)
    large, large_time = best_of_three(4000)
    assert (small, large) == (500, 4000)
    # 8x the input may cost ~8x the time, never ~64x.
    assert large_time < max(small_time, 0.01) * 24
