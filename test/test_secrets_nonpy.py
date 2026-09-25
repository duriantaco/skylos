import json

from skylos.analyzer import analyze
from skylos.rules.secrets import scan_ctx, ALLOWED_FILE_SUFFIXES


class TestAllowedSuffixes:
    def test_env_suffix_allowed(self):
        assert ".env" in ALLOWED_FILE_SUFFIXES

    def test_yaml_suffixes_allowed(self):
        assert ".yaml" in ALLOWED_FILE_SUFFIXES
        assert ".yml" in ALLOWED_FILE_SUFFIXES

    def test_json_suffix_allowed(self):
        assert ".json" in ALLOWED_FILE_SUFFIXES

    def test_toml_suffix_allowed(self):
        assert ".toml" in ALLOWED_FILE_SUFFIXES

    def test_lockfile_suffix_allowed(self):
        assert ".lock" in ALLOWED_FILE_SUFFIXES

    def test_ts_suffixes_allowed(self):
        assert ".ts" in ALLOWED_FILE_SUFFIXES
        assert ".tsx" in ALLOWED_FILE_SUFFIXES

    def test_client_artifact_suffixes_allowed(self):
        assert ".mjs" in ALLOWED_FILE_SUFFIXES
        assert ".html" in ALLOWED_FILE_SUFFIXES

    def test_go_suffix_allowed(self):
        assert ".go" in ALLOWED_FILE_SUFFIXES

    def test_php_suffix_allowed(self):
        assert ".php" in ALLOWED_FILE_SUFFIXES

    def test_rust_suffix_allowed(self):
        assert ".rs" in ALLOWED_FILE_SUFFIXES

    def test_dart_suffix_allowed(self):
        assert ".dart" in ALLOWED_FILE_SUFFIXES

    def test_kotlin_suffixes_allowed(self):
        assert ".kt" in ALLOWED_FILE_SUFFIXES
        assert ".kts" in ALLOWED_FILE_SUFFIXES

    def test_csharp_suffix_allowed(self):
        assert ".cs" in ALLOWED_FILE_SUFFIXES


def test_csharp_source_detects_provider_and_generic_secrets():
    source = (
        "public static class Credentials {\n"
        '    public const string GitHubToken = "ghp_1234567890abcdef1234567890abcdef1234";\n'
        '    public const string ApiKey = "Z8k2Lm9Qp4Rs7Tv1Wx6Ya3Bc5De0Fg2H";\n'
        "}\n"
    )
    ctx = {
        "relpath": "src/Credentials.cs",
        "lines": source.splitlines(True),
        "tree": None,
    }

    findings = list(scan_ctx(ctx))

    assert any(
        finding["rule_id"] == "SKY-S101"
        and finding["provider"] == "github"
        and finding["file"] == "src/Credentials.cs"
        and finding["line"] == 2
        for finding in findings
    )
    assert any(
        finding["rule_id"] == "SKY-S101"
        and finding["provider"] == "generic"
        and finding["file"] == "src/Credentials.cs"
        and finding["line"] == 3
        for finding in findings
    )


def test_csharp_source_ignores_placeholder_credentials():
    source = (
        "public static class Credentials {\n"
        '    public const string GitHubToken = "ghp_example1234567890abcdef12345678901234";\n'
        "}\n"
    )
    ctx = {
        "relpath": "src/Credentials.cs",
        "lines": source.splitlines(True),
        "tree": None,
    }

    assert list(scan_ctx(ctx)) == []


def test_csharp_provider_tokens_with_sensitive_words_are_not_suppressed():
    tails = (
        "A1b2C3d4E5f6G7h8I9j0secretK1l2M3n4O5",
        "A1b2C3d4E5f6G7h8I9passwordK1l2M3n4O5",
        "A1b2C3d4E5f6G7h8I9j0eXampleK1l2M3n4O5",
    )
    for tail in tails:
        source = f'public const string GitHubToken = "ghp_{tail}";\n'
        ctx = {"relpath": "src/Credentials.cs", "lines": [source], "tree": None}

        findings = scan_ctx(ctx)

        assert any(
            finding["rule_id"] == "SKY-S101"
            and finding["provider"] == "github"
            and finding["file"] == "src/Credentials.cs"
            for finding in findings
        ), tail


def test_csharp_stripe_test_mode_key_is_not_a_placeholder():
    source = 'public const string StripeKey = "sk_test_A1b2C3d4E5f6G7h8I9j0";\n'
    ctx = {"relpath": "src/Credentials.cs", "lines": [source], "tree": None}

    assert any(
        finding["rule_id"] == "SKY-S101" and finding["provider"] == "stripe"
        for finding in scan_ctx(ctx)
    )


def test_csharp_generic_secret_with_sensitive_word_is_not_suppressed():
    for word in ("secret", "password"):
        source = (
            "public const string ApiKey = "
            f'"A1b2C3d4E5f6G7h8I9j0{word}K1l2M3n4O5p6Q7";\n'
        )
        ctx = {"relpath": "src/Credentials.cs", "lines": [source], "tree": None}

        assert any(
            finding["rule_id"] == "SKY-S101" and finding["provider"] == "generic"
            for finding in scan_ctx(ctx)
        ), word


def test_csharp_secret_reaches_analyzer_json_output(tmp_path):
    source = (
        "public static class Credentials {\n"
        '    public const string GitHubToken = "ghp_A1b2C3d4E5f6G7h8I9j0secretK1l2M3n4O5";\n'
        "}\n"
    )
    (tmp_path / "Credentials.cs").write_text(source, encoding="utf-8")

    result = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))

    assert any(
        finding["rule_id"] == "SKY-S101"
        and finding["provider"] == "github"
        and finding["file"] == "Credentials.cs"
        and finding["line"] == 2
        for finding in result.get("secrets", [])
    )


def test_public_html_subresource_integrity_is_not_a_secret():
    source = (
        '<script src="/app.js" integrity="sha384-'
        'oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"'
        "></script>\n"
    )
    findings = scan_ctx(
        {"relpath": "public/index.html", "lines": [source], "tree": None},
        ignore_tests=False,
    )
    assert findings == []


class TestEnvFileScanning:
    def test_detects_aws_key_in_env(self):
        src = "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE1234567890abcdef\n"
        ctx = {"relpath": ".env", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) > 0
        providers = {f["provider"] for f in findings}
        assert "aws_secret_access_key" in providers

    def test_detects_generic_token_in_env(self):
        src = 'GITHUB_TOKEN="ghp_1234567890abcdef1234567890abcdef12"\n'
        ctx = {"relpath": ".env", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) > 0
        providers = {f["provider"] for f in findings}
        assert "generic" in providers

    def test_safe_env_no_findings(self):
        src = "DATABASE_HOST=localhost\nDEBUG=true\n"
        ctx = {"relpath": ".env", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) == 0


class TestYamlFileScanning:
    def test_detects_key_in_yaml(self):
        src = 'api_key: "sk_live_1234567890abcdef1234567890abcdef"\n'
        ctx = {"relpath": "config.yaml", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) > 0

    def test_safe_yaml_no_findings(self):
        src = "host: localhost\nport: 5432\n"
        ctx = {"relpath": "config.yaml", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) == 0


class TestJsonFileScanning:
    def test_detects_key_in_json(self):
        src = '{"api_key": "sk_live_1234567890abcdef1234567890abcdef"}\n'
        ctx = {"relpath": "config.json", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) > 0
