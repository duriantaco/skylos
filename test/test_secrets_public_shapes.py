"""Secret-shaped values that are public by structure, and the real secrets
that must still be reported next to them.

The false-alarm shapes come from a study of 450 merged AI-agent pull
requests, where every secret the done gate blocked on was one of them.
"""

import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.secrets import scan_ctx

# Built from parts so this file does not itself look like it leaks keys.
AWS_KEY = "AKIA" + "Q3EGRT5YHN7JK2LM"
GITHUB_TOKEN = "ghp_" + "Zx8Kq2Lm9Pq4Rs7Tv1Wx6Ya3Bc5De0Fg2HjK"
STRIPE_KEY = "sk_live_" + "51HqLyjWDarjtT1zdp7dcXyZ"
SLACK_TOKEN = "xoxb-" + "1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"
RANDOM_TOKEN = "aB3dE5fG7hI9jK2lM4nO6pQ8rS0tU1vW2xY3zZ"
# Not an identifier: bare identifiers are never reported.
BARE_TOKEN = "9xQ2mK7pL4vR8tW1zN6bY3cH5jD0fG2sA"
PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
SHA256_HEX = "d98f1066c077be0fa9d115b718f458bd803e415181b4a96f82a6f5d9f77241ac"


def _scan(src: str, rel: str = "app.py") -> list[dict]:
    lines = src.splitlines(True)
    return list(
        scan_ctx(
            {"relpath": rel, "lines": lines, "tree": None},
            ignore_tests=False,
        )
    )


def _providers(src: str, rel: str = "app.py") -> set[str]:
    return {f.get("provider") for f in _scan(src, rel)}


@pytest.mark.parametrize(
    "src,rel,provider",
    [
        (f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n', "settings.py", "aws_access_key_id"),
        (f'token = "{GITHUB_TOKEN}"\n', "deploy.ts", "github"),
        (f'STRIPE = "{STRIPE_KEY}"\n', "billing.js", "stripe"),
        (f"slack: {SLACK_TOKEN}\n", "config.yaml", "slack"),
        (
            f'KEY = "-----BEGIN RSA PRIVATE KEY-----\\n{PEM_BODY}"\n',
            "keys.py",
            "private_key_block",
        ),
        (
            f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\n",
            "server_key.py",
            "private_key_block",
        ),
        (
            f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{PEM_BODY}\n",
            "server_key.go",
            "private_key_block",
        ),
        (
            f'pk = "-----BEGIN PRIVATE KEY-----\\n{PEM_BODY}\\n"\n',
            "keys.ts",
            "private_key_block",
        ),
        (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + PEM_BODY + "\n",
            "signing_key.rs",
            "private_key_block",
        ),
        (
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n{PEM_BODY}\n",
            "id_key.ts",
            "private_key_block",
        ),
    ],
)
def test_real_provider_secrets_are_still_reported(src, rel, provider):
    assert provider in _providers(src, rel)


@pytest.mark.parametrize(
    "rel,src",
    [
        # Algorithm-named hex digests in integrity and content-hash fields.
        (
            "apps/docs/lib/site.generated.json",
            f'  "contentHash": "sha256:{SHA256_HEX}"\n',
        ),
        (
            ".devcontainer/devcontainer-lock.json",
            f'      "integrity": "sha256:{SHA256_HEX}"\n',
        ),
        ("metadata.yaml", f"integrity: sha256:{SHA256_HEX}\n"),
        # GitHub Actions and shell references, environment variable names.
        (
            ".github/workflows/ci.lock.yml",
            'env:\n  GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_MCP_SERVER_TOKEN}"\n',
        ),
        (
            ".github/workflows/ci.yml",
            '  token: "${{ secrets.GH_AW_GITHUB_MCP_SERVER_TOKEN }}"\n',
        ),
        (
            ".github/workflows/ci.yml",
            "  GH_AW_SECRET_NAMES: 'GH_AW_GITHUB_MCP_SERVER_TOKEN,GH_AW_GITHUB_TOKEN'\n",
        ),
        # A field name mapped to its own name in another case.
        ("hooks/setup.ts", "  HELVETIA_ADMIN_PASSWORD: 'helvetiaAdminPassword',\n"),
        # URLs assigned to *_URL names.
        ("oauth.ts", 'const TOKEN_URL = "https://www.strava.com/api/v3/oauth/token"\n'),
        (
            "main.py",
            'token_url = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"\n',
        ),
        # Word slugs in URLs and paths.
        (
            "machines/form-4.json",
            '"specifications": "https://formlabs.com/support/'
            'What-is-the-build-volume-of-the-Form-3L-and-Form-3BL/"\n',
        ),
        (
            "specs/probe-v1.json",
            '"amendment_path": "docs/specs/INTRA-001-data-contract-amendment-v2.json",\n',
        ),
        # A public Google Forms id.
        (
            "src/HomePage.tsx",
            '  "https://docs.google.com/forms/d/e/'
            '1FAIpQLSfBFkDYfOIqNxHxoJKFVA_izf3MRaHCKeJOe6RSGxHzN1FDqw/viewform";\n',
        ),
        # A public contract address.
        (
            "src/constants.ts",
            "  address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',\n",
        ),
        # Public keys: JWK coordinates, SSH public keys, PEM public blocks.
        (
            "examples/runtime.json",
            '{\n  "jwk": {\n    "kty": "OKP",\n    "crv": "Ed25519",\n'
            '    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"\n  }\n}\n',
        ),
        (
            "deploy/authorized_keys.yaml",
            "key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq8xZ2kd9Lm4pQ7rT1vW3yB5nH8"
            "jK0cE6fA9sD2uX4Y deploy@ci\n",
        ),
        (
            "keys/public.ts",
            'export const KEY = "-----BEGIN PUBLIC KEY-----\\n'
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEeP"
            '\\n-----END PUBLIC KEY-----";\n',
        ),
        (
            "keys/cert.yaml",
            "cert: |\n  -----BEGIN CERTIFICATE-----\n"
            "  MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTES\n"
            "  -----END CERTIFICATE-----\n",
        ),
        # Private-key header in help text and a placeholder.
        (
            "templates/index.html",
            "<p>The text starts with <code>-----BEGIN RSA PRIVATE KEY-----</code>"
            " or <code>-----BEGIN PRIVATE KEY-----</code>.</p>\n",
        ),
        (
            "docs.py",
            'EXAMPLE = "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----"\n',
        ),
        # Secret Manager references in a deployment config.
        (
            "cloudbuild.yaml",
            "  - --set-secrets=MCP_BEARER_TOKEN=MCP_BEARER_TOKEN:latest,"
            "GOOGLE_MAPS_API_KEY=GOOGLE_MAPS_API_KEY:latest\n",
        ),
        # Fixture values in JS/TS test files.
        (
            "src/__tests__/export.test.ts",
            "expect(name).toBe('openclimbing-ticks-John-Doe__-2026-09-03.csv');\n",
        ),
        (
            "src/mcp/registry.node.test.ts",
            f"  password: '{RANDOM_TOKEN}',\n",
        ),
    ],
)
def test_public_or_structural_values_are_not_secrets(rel, src):
    assert _scan(src, rel) == []


def test_minified_bundle_line_skips_bare_tokens_but_keeps_keyed_secrets():
    filler = "function a(t){return t}" * 60
    bare = f"{filler};var x='{BARE_TOKEN}';\n"
    keyed = f'{filler};var c={{apiKey:"{RANDOM_TOKEN}"}};\n'

    assert _scan(bare, "dist/index.js") == []
    assert "generic" in _providers(keyed, "dist/index.js")
    assert "github" in _providers(
        f"{filler};var g='{GITHUB_TOKEN}';\n", "dist/index.js"
    )


@pytest.mark.parametrize("suffix", [".js", ".mjs", ".cjs"])
@pytest.mark.parametrize("padding_length", [0, 1001])
def test_production_authorization_secret_survives_long_lines(suffix, padding_length):
    rel = f"src/service{suffix}"
    source = (
        'fetch("https://service.example", {headers: {Authorization:"Bearer '
        + BARE_TOKEN
        + '"}});const padding = "'
        + "a" * padding_length
        + '";\n'
    )
    findings = _scan(source, rel)
    assert any(
        finding["rule_id"] == "SKY-S101"
        and finding["provider"] == "generic"
        and finding["file"] == rel
        and finding["line"] == 1
        and finding["col"] == source.index(BARE_TOKEN)
        for finding in findings
    ), "line padding must not hide a production Authorization credential"


def test_long_production_authorization_secret_reaches_analyzer_json(tmp_path):
    source = (
        'fetch("https://service.example", {headers: {Authorization:"Bearer '
        + BARE_TOKEN
        + '"}});const padding = "'
        + "a" * 1001
        + '";\n'
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "service.js").write_text(source, encoding="utf-8")
    result = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))
    assert any(
        finding["rule_id"] == "SKY-S101"
        and finding["provider"] == "generic"
        and finding["file"] == "src/service.js"
        and finding["line"] == 1
        for finding in result.get("secrets", [])
    )


@pytest.mark.parametrize(
    "rel",
    [
        "dist/index.js",
        "build/index.mjs",
        ".next/static/chunks/main.js",
        "dist/app.min.js",
        "dist/vendor.bundle.cjs",
        "packages/web/dist/lib/index.js",
        "dist\\chunks\\main.js",
    ],
)
def test_long_artifact_lines_skip_bare_tokens_but_keep_keyed_and_provider_secrets(rel):
    filler = "function a(t){return t}" * 60
    assert _scan(f"{filler};var x='{BARE_TOKEN}';\n", rel) == []
    assert "generic" in _providers(f'{filler};var c={{apiKey:"{RANDOM_TOKEN}"}};\n', rel)
    assert "github" in _providers(f"{filler};var g='{GITHUB_TOKEN}';\n", rel)


@pytest.mark.parametrize(
    "rel",
    [
        "src/service.js",
        "frontend/service.mjs",
        "assets/service.cjs",
        "src/service.min.js",
        "lib/bundle.js",
        "app/service.bundle.cjs",
        "vendor.bundle.cjs",
        "src/dist/service.js",
        "lib/build/service.mjs",
    ],
)
def test_long_line_in_source_directory_does_not_prove_bundle_context(rel):
    filler = "function a(t){return t}" * 60
    assert "generic" in _providers(f"{filler};var x='{BARE_TOKEN}';\n", rel)


def test_artifact_directory_alone_does_not_suppress_short_lines():
    assert "generic" in _providers(f"var x='{BARE_TOKEN}';\n", "dist/index.js")


@pytest.mark.parametrize(
    "rel,src",
    [
        # A digest-looking value of the wrong length, or with no algorithm.
        (
            ".devcontainer/devcontainer-lock.json",
            f'"integrity": "sha256:{SHA256_HEX[:-2]}Zz"\n',
        ),
        # A reference with a literal fallback or default.
        ("ci.ts", f"const token = `${{{{ secrets.T || '{BARE_TOKEN}' }}}}`;\n"),
        ("deploy.ts", f'API_TOKEN = "${{API_TOKEN:-{BARE_TOKEN}}}"\n'),
        # A password that only starts with "$".
        ("settings.py", 'password = "$Zx8Kq2Lm9Pq4Rs7Tv1Wx6"\n'),
        # A value that is not the key's own name.
        ("hooks/setup.ts", f"  HELVETIA_ADMIN_PASSWORD: '{RANDOM_TOKEN}',\n"),
        # A token in the query of a URL assigned to a *_URL name.
        (
            "oauth.ts",
            f'const TOKEN_URL = "https://api.example.io/v1?key={BARE_TOKEN}"\n',
        ),
        # A random token with separators is not a word slug.
        ("config.json", '"session": "aB3dE5fG7hI9-jK2lM4nO6pQ8-rS0tU1vW2xY"\n'),
        # A token in the path of a webhook URL that is not a public document host.
        ("notify.py", f'HOOK = "https://hooks.example.com/services/{BARE_TOKEN}"\n'),
        # 64 hex digits after 0x is a private key, not an address.
        (
            "wallet.ts",
            "const k = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318A';\n",
        ),
        # The private JWK member.
        (
            "jwk.json",
            '{\n  "kty": "OKP",\n  "crv": "Ed25519",\n'
            '  "d": "nWGxne_9WmC6hEr0-kuwsxERJxWl7MmkZcDusAxyuf2A"\n}\n',
        ),
        # A "public key" block whose body is not key data.
        (
            "keys.py",
            f"-----BEGIN PUBLIC KEY-----\n{BARE_TOKEN}\n-----END PUBLIC KEY-----\n",
        ),
        # A header-only private key string (the key may be appended elsewhere).
        ("keys.py", 'PK = "-----BEGIN RSA PRIVATE KEY-----"\n'),
        # A real config credential next to a Secret Manager reference.
        ("cloudbuild.yaml", "  - --set-env-vars=DB_PASSWORD=Zx8Kq2Lm9Pq4Rs7T\n"),
    ],
)
def test_lookalikes_of_public_shapes_are_still_reported(rel, src):
    assert _scan(src, rel), "a real-looking secret next to a public shape was dropped"


def test_provider_tokens_in_js_test_files_are_still_reported():
    src = f"const token = '{GITHUB_TOKEN}';\n"
    assert "github" in _providers(src, "src/__tests__/client.test.ts")
