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

    def test_ts_suffixes_allowed(self):
        assert ".ts" in ALLOWED_FILE_SUFFIXES
        assert ".tsx" in ALLOWED_FILE_SUFFIXES

    def test_go_suffix_allowed(self):
        assert ".go" in ALLOWED_FILE_SUFFIXES


class TestEnvFileScanning:
    def test_detects_aws_key_in_env(self):
        src = 'AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE1234567890abcdef\n'
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
        src = 'DATABASE_HOST=localhost\nDEBUG=true\n'
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
        src = 'host: localhost\nport: 5432\n'
        ctx = {"relpath": "config.yaml", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) == 0


class TestJsonFileScanning:
    def test_detects_key_in_json(self):
        src = '{"api_key": "sk_live_1234567890abcdef1234567890abcdef"}\n'
        ctx = {"relpath": "config.json", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) > 0
