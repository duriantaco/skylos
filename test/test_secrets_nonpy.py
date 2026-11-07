import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

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
        '    public const string GitHubToken = "g'
        r"h"
        'p_1234567890abcdef1234567890abcdef1234";\n'
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
    source = 'public const string StripeKey = "s' r"k" '_test_A1b2C3d4E5f6G7h8I9j0";\n'
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
        '    public const string GitHubToken = "g'
        r"h"
        'p_A1b2C3d4E5f6G7h8I9j0secretK1l2M3n4O5";\n'
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


_AWS_KEY_ID = "A" r"K" "IA4HZQ7XW2NB9KD3LT"
_GITHUB_TOKEN = "g" r"h" "p_Zt7Kq2Lm9Xc4Vb8Nw1Rp6Hs3Jd5Fg0Ty2Ua8"


@pytest.mark.parametrize(
    ("relpath", "line", "provider"),
    [
        (
            "src/main/java/Config.java",
            f'String KEY = "{_AWS_KEY_ID}";',
            "aws_access_key_id",
        ),
        (
            "src/main/resources/application.properties",
            f"aws.accessKeyId={_AWS_KEY_ID}",
            "aws_access_key_id",
        ),
        (
            "src/main/resources/application.properties",
            "mail.password=Wq8#mZ2!vR7pL4xK",
            "config_credential",
        ),
        ("settings.xml", f"<password>{_GITHUB_TOKEN}</password>", "github"),
        ("Dockerfile", f"ENV AWS_ACCESS_KEY_ID={_AWS_KEY_ID}", "aws_access_key_id"),
        ("deploy/Dockerfile.prod", f"ENV GH={_GITHUB_TOKEN}", "github"),
        ("infra/prod.tfvars", f'github_token = "{_GITHUB_TOKEN}"', "github"),
        ("infra/main.tf", f'access_key = "{_AWS_KEY_ID}"', "aws_access_key_id"),
        (".npmrc", f"//npm.pkg.github.com/:_authToken={_GITHUB_TOKEN}", "github"),
        ("build.gradle", f'def token = "{_GITHUB_TOKEN}"', "github"),
        ("native/config.h", f'#define TOKEN "{_GITHUB_TOKEN}"', "github"),
        (
            "scripts/setup.sh",
            f"export AWS_ACCESS_KEY_ID={_AWS_KEY_ID}",
            "aws_access_key_id",
        ),
        (
            "scripts/setup.sh",
            'export DB_PASSWORD="${DB_PASSWORD:-Xk8mQ2vR7pL4xKz9Tq3W}"',
            "generic",
        ),
        (
            "src/main/resources/application.properties",
            "spring.datasource.password=${DB_PASSWORD}",
            None,
        ),
        ("src/main/resources/application.properties", "app.secret=changeme", None),
        (
            "src/main/resources/application.properties",
            "app.api-token=<your-token>",
            None,
        ),
        ("settings.xml", "<password>${env.NEXUS_PASSWORD}</password>", None),
        ("Dockerfile", "ENV DB_PASSWORD=${DB_PASSWORD}", None),
        ("infra/prod.tfvars", 'db_password = "changeme"', None),
        (".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}", None),
        (".pypirc", "password = <your-token>", None),
        (
            "scripts/setup.sh",
            'export API_TOKEN="${API_TOKEN:?set API_TOKEN first}"',
            None,
        ),
        (
            "scripts/setup.sh",
            'export API_TOKEN="$(cat /run/secrets/api_token_file)"',
            None,
        ),
    ],
)
def test_config_build_and_script_files_report_real_secrets_not_placeholders(
    relpath, line, provider
):
    findings = scan_ctx({"relpath": relpath, "lines": [line + "\n"], "tree": None})

    providers = {finding["provider"] for finding in findings}
    if provider is None:
        assert providers == set()
    else:
        assert provider in providers


@pytest.mark.parametrize(
    ("first_line", "scanned"),
    [
        ("#!/usr/bin/env bash", True),
        ("#!/bin/sh -e", True),
        ("#!/usr/bin/env python3", False),
        ("old token notes", False),
    ],
)
def test_extensionless_file_is_scanned_only_as_a_shell_script(first_line, scanned):
    lines = [first_line + "\n", f"export GITHUB_TOKEN={_GITHUB_TOKEN}\n"]

    findings = scan_ctx({"relpath": "bin/deploy", "lines": lines, "tree": None})

    assert bool(findings) is scanned


def test_shell_script_probe_accepts_long_script(tmp_path):
    from skylos.rules.secrets import file_starts_like_shell_script

    source = tmp_path / "deploy"
    source.write_text("#!/usr/bin/env bash\n" + "echo ready\n" * 128, encoding="utf-8")

    assert file_starts_like_shell_script(source) is True


@pytest.mark.parametrize(
    "kind", ["symlink", "directory", "missing", "unreadable", "binary"]
)
def test_shell_script_probe_rejects_symlink_directory_and_unreadable(
    tmp_path, monkeypatch, kind
):
    from skylos.rules import secrets

    source = tmp_path / "deploy"
    if kind == "directory":
        source.mkdir()
    elif kind != "missing":
        source.write_bytes(
            b"#!/bin/sh\n" + (b"\0" if kind == "binary" else b"echo ready\n")
        )
    if kind == "symlink":
        link = tmp_path / "linked"
        try:
            link.symlink_to(source)
        except OSError:
            pytest.skip("symlinks are not supported on this filesystem")
        source = link
    if kind == "unreadable":

        def denied(*args, **kwargs):
            raise PermissionError("file is not readable")

        with monkeypatch.context() as patch:
            patch.setattr("builtins.open", denied)
            patch.setattr(os, "open", denied)
            assert secrets.file_starts_like_shell_script(source) is False
    else:
        assert secrets.file_starts_like_shell_script(source) is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are unavailable")
def test_shell_script_probe_rejects_fifo_without_blocking(tmp_path):
    source = tmp_path / "deploy"
    os.mkfifo(source)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    environment["PYTHONDONTWRITEBYTECODE"] = "1"

    completed = subprocess.run(
        [
            sys.executable,
            "-P",
            "-c",
            "import sys; from skylos.rules.secrets import file_starts_like_shell_script; "
            "print(file_starts_like_shell_script(sys.argv[1]))",
            str(source),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )

    assert completed.stdout.strip() == "False"


def test_directory_scan_reads_new_secret_files_and_honours_real_comments(tmp_path):
    files = {
        "Dockerfile": f"FROM alpine\nENV AWS_ACCESS_KEY_ID={_AWS_KEY_ID}\n",
        "settings.xml": f"<settings>\n<password>{_GITHUB_TOKEN}</password>\n</settings>\n",
        "infra/prod.tfvars": f'github_token = "{_GITHUB_TOKEN}"\n',
        ".npmrc": f"//npm.pkg.github.com/:_authToken={_GITHUB_TOKEN}\n",
        "native/config.h": f'#define TOKEN "{_GITHUB_TOKEN}"\n',
        "bin/deploy": f"#!/usr/bin/env bash\nexport GITHUB_TOKEN={_GITHUB_TOKEN}\n",
        "bin/NOTES": f"old token {_GITHUB_TOKEN}\n",
        "src/test/resources/app.properties": f"github.token={_GITHUB_TOKEN}\n",
        "src/main/java/Config.java": (
            "class Config {\n"
            f'  String A = "{_GITHUB_TOKEN}"; // skylos: ignore[SKY-S101] revoked sample\n'
            f'  String B = "{_GITHUB_TOKEN} // skylos: ignore[SKY-S101]";\n'
            "}\n"
        ),
        "scripts/setup.sh": (
            "#!/bin/sh\n"
            f"export A={_GITHUB_TOKEN} # skylos: ignore[SKY-S101] CI sample\n"
            f'echo "# skylos: ignore[SKY-S101]" {_GITHUB_TOKEN}\n'
        ),
    }
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    result = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))

    reported = {
        (finding["file"], finding["line"])
        for finding in result.get("secrets", [])
        if finding["provider"] in {"github", "aws_access_key_id"}
    }
    suppressed = {
        (finding["file"], finding["line"])
        for finding in result.get("suppressed", [])
        if finding.get("rule_id") == "SKY-S101"
    }
    assert reported == {
        ("Dockerfile", 2),
        ("settings.xml", 2),
        ("infra/prod.tfvars", 1),
        (".npmrc", 1),
        ("native/config.h", 1),
        ("bin/deploy", 2),
        ("src/test/resources/app.properties", 1),
        ("src/main/java/Config.java", 3),
        ("scripts/setup.sh", 3),
    }
    assert suppressed == {("src/main/java/Config.java", 2), ("scripts/setup.sh", 2)}


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
        value = "Ab3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY2zA4" + "bC6d"
        src = "AWS_SECRET_ACCESS_K" r"E" "Y=" + value + "\n"
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
        src = 'api_key: "s' r"k" '_live_1234567890abcdef1234567890abcdef"\n'
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
        src = '{"api_key": "s' r"k" '_live_1234567890abcdef1234567890abcdef"}\n'
        ctx = {"relpath": "config.json", "lines": src.splitlines(True), "tree": None}
        findings = list(scan_ctx(ctx))
        assert len(findings) > 0
