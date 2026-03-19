from skylos.rules.quality.regression import detect_security_regressions


def _make_diff(
    removed_lines: list[str], added_lines: list[str], context: str = ""
) -> str:
    """Build a minimal unified diff."""
    parts = ["--- a/test.py", "+++ b/test.py", "@@ -1,10 +1,10 @@"]
    if context:
        parts.append(f" {context}")
    for line in removed_lines:
        parts.append(f"-{line}")
    for line in added_lines:
        parts.append(f"+{line}")
    return "\n".join(parts)


class TestAuthDecoratorRemoval:
    def test_login_required_removed(self):
        diff = _make_diff(
            ["@login_required", "def view(request):"],
            ["def view(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert len(findings) == 1
        assert "login_required" in findings[0]["message"]
        assert findings[0]["rule_id"] == "SKY-L021"

    def test_require_auth_removed(self):
        diff = _make_diff(
            ["@require_auth", "def api_endpoint():"],
            ["def api_endpoint():"],
        )
        findings = detect_security_regressions(diff, "api.py")
        assert len(findings) == 1
        assert "require_auth" in findings[0]["message"]

    def test_non_auth_decorator_removed_no_finding(self):
        diff = _make_diff(
            ["@staticmethod", "def helper():"],
            ["def helper():"],
        )
        findings = detect_security_regressions(diff, "utils.py")
        assert len(findings) == 0


class TestAuthDependencyRemoval:
    def test_fastapi_depends_removed(self):
        diff = _make_diff(
            ["async def endpoint(user=Depends(get_current_user)):"],
            ["async def endpoint():"],
        )
        findings = detect_security_regressions(diff, "routes.py")
        assert len(findings) == 1
        assert "get_current_user" in findings[0]["message"]


class TestCSRFProtection:
    def test_csrf_middleware_removed(self):
        diff = _make_diff(
            ["    'django.middleware.csrf.CsrfViewMiddleware',"],
            [],
        )
        findings = detect_security_regressions(diff, "settings.py")
        assert len(findings) == 1
        assert "CSRF" in findings[0]["message"]

    def test_csrf_exempt_added(self):
        diff = _make_diff(
            [],
            ["@csrf_exempt", "def webhook(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert len(findings) == 1
        assert "csrf_exempt" in findings[0]["message"]


class TestTLSVerification:
    def test_verify_true_to_false(self):
        diff = _make_diff(
            ["    resp = requests.get(url, verify=True)"],
            ["    resp = requests.get(url, verify=False)"],
        )
        findings = detect_security_regressions(diff, "client.py")
        assert len(findings) == 1
        assert "verify=False" in findings[0]["message"]
        assert "downgraded" in findings[0]["message"]

    def test_verify_false_added_without_prior_true(self):
        diff = _make_diff(
            [],
            ["    resp = requests.get(url, verify=False)"],
        )
        findings = detect_security_regressions(diff, "client.py")
        assert len(findings) == 1
        assert "verify=False" in findings[0]["message"]


class TestCryptoDowngrade:
    def test_sha256_to_md5(self):
        diff = _make_diff(
            ["    h = hashlib.sha256(data)"],
            ["    h = hashlib.md5(data)"],
        )
        findings = detect_security_regressions(diff, "crypto.py")
        assert len(findings) == 1
        assert "md5" in findings[0]["message"]

    def test_same_hash_no_finding(self):
        diff = _make_diff(
            ["    h = hashlib.sha256(data)"],
            ["    h = hashlib.sha256(data.encode())"],
        )
        findings = detect_security_regressions(diff, "crypto.py")
        assert len(findings) == 0


class TestRateLimitRemoval:
    def test_rate_limit_decorator_removed(self):
        diff = _make_diff(
            ["@rate_limit", "def endpoint():"],
            ["def endpoint():"],
        )
        findings = detect_security_regressions(diff, "api.py")
        assert len(findings) == 1
        assert "rate_limit" in findings[0]["message"]

    def test_throttle_decorator_removed(self):
        diff = _make_diff(
            ["@throttle", "def endpoint():"],
            ["def endpoint():"],
        )
        findings = detect_security_regressions(diff, "api.py")
        assert len(findings) == 1


class TestNoFalsePositives:
    def test_clean_diff_no_findings(self):
        diff = _make_diff(
            ["    x = 1"],
            ["    x = 2"],
        )
        findings = detect_security_regressions(diff, "app.py")
        assert len(findings) == 0

    def test_empty_diff(self):
        findings = detect_security_regressions("", "app.py")
        assert len(findings) == 0

    def test_adding_auth_is_fine(self):
        diff = _make_diff(
            ["def view(request):"],
            ["@login_required", "def view(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert len(findings) == 0


class TestFindingFormat:
    def test_finding_has_required_fields(self):
        diff = _make_diff(
            ["@login_required", "def view(request):"],
            ["def view(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        f = findings[0]
        assert f["rule_id"] == "SKY-L021"
        assert f["severity"] == "HIGH"
        assert f["file"] == "views.py"
        assert f["line"] >= 1
        assert "kind" in f
