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


class TestInputValidationRemoval:
    def test_validate_decorator_removed(self):
        diff = _make_diff(
            ["@validate", "def create_user(data):"],
            ["def create_user(data):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "validation" for f in findings)
        assert any("@validate" in f["message"] for f in findings)

    def test_field_validator_decorator_removed(self):
        diff = _make_diff(
            ["@field_validator('email')", "def check_email(cls, v):"],
            ["def check_email(cls, v):"],
        )
        findings = detect_security_regressions(diff, "models.py")
        assert any(f["control_type"] == "validation" for f in findings)

    def test_sanitize_call_removed(self):
        diff = _make_diff(
            ["    data = sanitize(user_input)"],
            ["    data = user_input"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "validation" for f in findings)
        assert any("Validation/sanitization" in f["message"] for f in findings)

    def test_bleach_clean_call_removed(self):
        diff = _make_diff(
            ["    clean = bleach.clean(html_input)"],
            ["    clean = html_input"],
        )
        findings = detect_security_regressions(diff, "utils.py")
        validation_findings = [f for f in findings if f["control_type"] == "validation"]
        assert len(validation_findings) >= 1

    def test_django_serializer_validator_removed(self):
        diff = _make_diff(
            ["    email = serializers.EmailField(validators=[validate_email])"],
            ["    email = serializers.CharField()"],
        )
        findings = detect_security_regressions(diff, "serializers.py")
        assert any(
            f["control_type"] == "validation" and "Django/DRF" in f["message"]
            for f in findings
        )


class TestSecurityHeaderRemoval:
    def test_csp_header_removed(self):
        diff = _make_diff(
            ["    response['Content-Security-Policy'] = \"default-src 'self'\""],
            [],
        )
        findings = detect_security_regressions(diff, "middleware.py")
        assert any(f["control_type"] == "headers" for f in findings)
        assert any("Content-Security-Policy" in f["message"] for f in findings)

    def test_x_frame_options_removed(self):
        diff = _make_diff(
            ["    response['X-Frame-Options'] = 'DENY'"],
            [],
        )
        findings = detect_security_regressions(diff, "middleware.py")
        assert any(f["control_type"] == "headers" for f in findings)

    def test_hsts_removed(self):
        diff = _make_diff(
            ["    response['Strict-Transport-Security'] = 'max-age=31536000'"],
            [],
        )
        findings = detect_security_regressions(diff, "middleware.py")
        assert any(f["control_type"] == "headers" for f in findings)

    def test_helmet_removed(self):
        diff = _make_diff(
            ["app.use(helmet())"],
            [],
        )
        findings = detect_security_regressions(diff, "app.js")
        assert any(f["control_type"] == "headers" for f in findings)
        assert any("middleware" in f["message"] for f in findings)

    def test_security_middleware_removed(self):
        diff = _make_diff(
            ["    'django.middleware.security.SecurityMiddleware',"],
            [],
        )
        findings = detect_security_regressions(diff, "settings.py")
        assert any(f["control_type"] == "headers" for f in findings)


class TestEncryptionRemoval:
    def test_fernet_removed(self):
        diff = _make_diff(
            ["    cipher = Fernet(key)"],
            [],
        )
        findings = detect_security_regressions(diff, "crypto.py")
        assert any(f["control_type"] == "encryption" for f in findings)
        assert any("Encryption" in f["message"] for f in findings)

    def test_encrypt_call_removed(self):
        diff = _make_diff(
            ["    encrypted = encrypt(data)"],
            ["    stored = data"],
        )
        findings = detect_security_regressions(diff, "storage.py")
        assert any(f["control_type"] == "encryption" for f in findings)

    def test_secret_key_removed(self):
        diff = _make_diff(
            ["SECRET_KEY = os.environ['SECRET_KEY']"],
            [],
        )
        findings = detect_security_regressions(diff, "settings.py")
        assert any(f["control_type"] == "encryption" for f in findings)
        assert any("SECRET_KEY" in f["message"] for f in findings)


class TestLoggingRemoval:
    def test_audit_log_removed(self):
        diff = _make_diff(
            ["    audit_log(user, 'login', request)"],
            [],
        )
        findings = detect_security_regressions(diff, "auth.py")
        assert any(f["control_type"] == "logging" for f in findings)
        assert any("Audit" in f["message"] for f in findings)

    def test_audit_decorator_removed(self):
        diff = _make_diff(
            ["@audit", "def transfer_funds(request):"],
            ["def transfer_funds(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "logging" for f in findings)

    def test_log_access_decorator_removed(self):
        diff = _make_diff(
            ["@log_access", "def view_records(request):"],
            ["def view_records(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(
            f["control_type"] == "logging" and "log_access" in f["message"]
            for f in findings
        )

    def test_access_logger_removed(self):
        diff = _make_diff(
            ['    logger.info("access: user viewed records")'],
            [],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "logging" for f in findings)


class TestSanitizationRemoval:
    def test_bleach_clean_removed(self):
        diff = _make_diff(
            ["    safe = bleach.clean(user_html)"],
            ["    safe = user_html"],
        )
        findings = detect_security_regressions(diff, "utils.py")
        assert any(f["control_type"] == "sanitization" for f in findings)
        assert any("Sanitization" in f["message"] for f in findings)

    def test_html_escape_removed(self):
        diff = _make_diff(
            ["    safe = html.escape(user_input)"],
            ["    safe = user_input"],
        )
        findings = detect_security_regressions(diff, "template.py")
        assert any(f["control_type"] == "sanitization" for f in findings)

    def test_dompurify_removed(self):
        diff = _make_diff(
            ["    clean = DOMPurify.sanitize(dirty)"],
            ["    clean = dirty"],
        )
        findings = detect_security_regressions(diff, "frontend.js")
        assert any(f["control_type"] == "sanitization" for f in findings)

    def test_escape_string_removed(self):
        diff = _make_diff(
            ["    safe_val = escape_string(val)"],
            ["    safe_val = val"],
        )
        findings = detect_security_regressions(diff, "db.py")
        assert any(f["control_type"] == "sanitization" for f in findings)

    def test_parameterized_query_removed(self):
        diff = _make_diff(
            ["    cursor.execute(parameterized(query, params))"],
            ["    cursor.execute(query)"],
        )
        findings = detect_security_regressions(diff, "db.py")
        assert any(f["control_type"] == "sanitization" for f in findings)


class TestPermissionCheckRemoval:
    def test_has_permission_removed(self):
        diff = _make_diff(
            ["    if not has_permission(user, 'edit'):"],
            [],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "permission" for f in findings)
        assert any("Permission check" in f["message"] for f in findings)

    def test_check_permission_removed(self):
        diff = _make_diff(
            ["    check_permission(request.user, resource)"],
            [],
        )
        findings = detect_security_regressions(diff, "api.py")
        assert any(f["control_type"] == "permission" for f in findings)

    def test_has_perm_removed(self):
        diff = _make_diff(
            ["    if user.has_perm('app.can_edit'):"],
            [],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "permission" for f in findings)

    def test_permission_classes_decorator_removed(self):
        diff = _make_diff(
            ["@permission_classes([IsAuthenticated])", "class UserViewSet(ViewSet):"],
            ["class UserViewSet(ViewSet):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "permission" for f in findings)

    def test_has_role_decorator_removed(self):
        diff = _make_diff(
            ["@has_role('admin')", "def admin_panel(request):"],
            ["def admin_panel(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "permission" for f in findings)

    def test_user_passes_test_removed(self):
        diff = _make_diff(
            ["    if not user_passes_test(lambda u: u.is_staff):"],
            [],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert any(f["control_type"] == "permission" for f in findings)


class TestControlTypeField:
    def test_auth_control_type(self):
        diff = _make_diff(
            ["@login_required", "def view(request):"],
            ["def view(request):"],
        )
        findings = detect_security_regressions(diff, "views.py")
        assert findings[0]["control_type"] == "auth"

    def test_csrf_control_type(self):
        diff = _make_diff(
            ["    'django.middleware.csrf.CsrfViewMiddleware',"],
            [],
        )
        findings = detect_security_regressions(diff, "settings.py")
        assert findings[0]["control_type"] == "csrf"

    def test_tls_control_type(self):
        diff = _make_diff(
            [],
            ["    resp = requests.get(url, verify=False)"],
        )
        findings = detect_security_regressions(diff, "client.py")
        assert findings[0]["control_type"] == "tls"

    def test_crypto_control_type(self):
        diff = _make_diff(
            ["    h = hashlib.sha256(data)"],
            ["    h = hashlib.md5(data)"],
        )
        findings = detect_security_regressions(diff, "crypto.py")
        assert findings[0]["control_type"] == "crypto"

    def test_rate_limit_control_type(self):
        diff = _make_diff(
            ["@rate_limit", "def endpoint():"],
            ["def endpoint():"],
        )
        findings = detect_security_regressions(diff, "api.py")
        assert findings[0]["control_type"] == "rate_limit"


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
