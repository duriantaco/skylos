"""Values that are not credentials by construction, each beside a lookalike
that must stay reported: lockfile versions, reader-facing text, names,
references, encoded text and markup names (SKY-S101)."""

import base64
import hashlib

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.secrets import scan_ctx
from skylos.visitors.languages.typescript import scan_typescript_file

RANDOM_A = "q7Rk2Vx9Lm4Tz8Wc1Nb6-Yh3Jd5Fg0Sa2Qe7Pu"
RANDOM_B = "Zt4-Kp9Xw2Mv7Lc5Rb8Nq1Yd6Hf3Jg0Sa4Qe2U"
SRI = "sha512-" + base64.b64encode(hashlib.sha512(b"left-pad").digest()).decode()
SELECTOR = "ul> li.sponsored-result > a[rel=nofollow] ~ span.badge"


def _urlsafe(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _generic(src: str, rel: str) -> list[dict]:
    return [
        finding
        for finding in scan_ctx(
            {"relpath": rel, "lines": src.splitlines(True), "tree": None},
            ignore_tests=False,
        )
        if finding.get("provider") in {"generic", "config_credential"}
    ]


def _bun_lock(version, entry: str) -> str:
    return (
        "{\n"
        f'  "lockfileVersion": {version},\n'
        '  "packages": {\n'
        f"    {entry},\n"
        "  }\n"
        "}\n"
    )


@pytest.mark.parametrize("version", [0, 1, 2, 3])
def test_bun_lockfile_versions_share_one_package_tuple(version):
    entry = f'"left-pad": ["left-pad@1.3.0", "", {{}}, "{SRI}"]'
    assert _generic(_bun_lock(version, entry), "bun.lock") == []


def test_unknown_bun_lockfile_version_keeps_its_integrity_values():
    entry = f'"left-pad": ["left-pad@1.3.0", "", {{}}, "{SRI}"]'
    assert _generic(_bun_lock(999, entry), "bun.lock")


def test_bun_git_resolution_is_the_descriptor_spelled_again():
    entry = (
        '"sigtool": ["@acme/sigtool@github:AcmeWidgets/sigtool-node#1c30d7d", '
        '{}, "AcmeWidgets-sigtool-node-1c30d7d"]'
    )
    assert _generic(_bun_lock(1, entry), "bun.lock") == []


COMMIT = hashlib.sha1(b"commit").hexdigest()
GIT_DESCRIPTOR = f"audio@github:AcmeWidgets/audio#{COMMIT}"


def test_bun_git_tuple_with_commit_and_tarball_digest_is_structural():
    entry = f'"audio": ["{GIT_DESCRIPTOR}", {{}}, "{COMMIT}", "{SRI}"]'
    assert _generic(_bun_lock(2, entry), "bun.lock") == []


@pytest.mark.parametrize(
    "entry",
    [
        f'"audio": ["{GIT_DESCRIPTOR}", {{}}, "{RANDOM_B}", "{SRI}"]',
        f'"audio": ["{GIT_DESCRIPTOR}", {{}}, "{COMMIT}", "{RANDOM_A}"]',
        f'"audio": ["audio@workspace:packages/audio", "", {{}}, "{SRI}"]',
    ],
)
def test_bun_tuple_values_the_descriptor_does_not_explain_stay_reported(entry):
    assert _generic(_bun_lock(2, entry), "bun.lock")


@pytest.mark.parametrize(
    "resolution",
    [RANDOM_A, "AcmeWidgets-sigtool-node-9f8e7d6", "OtherOrg-sigtool-node-1c30d7d"],
)
def test_bun_git_slot_with_another_value_stays_reported(resolution):
    descriptor = "@acme/sigtool@github:AcmeWidgets/sigtool-node#1c30d7d"
    entry = f'"sigtool": ["{descriptor}", {{}}, "{resolution}{RANDOM_B}"]'
    assert _generic(_bun_lock(1, entry), "bun.lock")


@pytest.mark.parametrize(
    "src,rel",
    [
        (
            "invalidCredentials: 'Sign-in failed: wrong user name or password.',\n",
            "messages.ts",
        ),
        ('"apiToken": "Copy the token now, it is shown only once."\n', "en.json"),
        (
            'invalidCredentials: "Échec de la connexion : identifiant ou mot de passe invalide."\n',
            "fr.yaml",
        ),
        (
            'static final String PASSWORD = "Your password must contain at least twelve characters.";\n',
            "Messages.java",
        ),
        (
            'LOGIN_PASSWORD="Ask your administrator for the shared password."\n',
            "app.env",
        ),
        (
            '"api_key_description": "Acme API key for image search (get one from https://acme.test/keys)",\n',
            "servers.py",
        ),
        ('token_hint: "ask the platform team for the staging token"\n', "servers.yaml"),
        ('LOGIN_CREDENTIALS: "mediahub_login_credentials",\n', "storage.ts"),
        ('const val PAYMENT_CREDENTIALS = "fitclub_payment_credentials"\n', "Keys.kt"),
        ('acme_api_key: "${oc.env:ACME_SEARCH_API_KEY}"\n', "tools.yaml"),
        ('password = "${var.database_admin_password}"\n', "main.tf"),
        (
            'PUSH_TOKEN="${DEPLOY_PUSH_TOKEN:-$DEFAULT_REPOSITORY_TOKEN}"\n',
            "deploy.sh",
        ),
        (f'FILTERS = [decode("{_urlsafe(SELECTOR)}")]\n', "filters.py"),
        (f"filters:\n  - {_urlsafe(SELECTOR)}\n", "filters.yaml"),
        (
            '# class="PageHeader__Container-sc-5e4b7146-1 hFsUgCqa1">\n',
            "scrape.py",
        ),
        (
            '"docs": "//learn.acme.test/search/?products=%2Fdevrel%2F7696cda6-0510-47f6-8302-71bb5d2e28cf"\n',
            "bangs.json",
        ),
        (
            '"tsecret": "//www.acmesecret.test/calories-nutrition/search?q=abc"\n',
            "bangs.json",
        ),
        ('PLATFORM_KEY="linux-aarch64-tarball"\n', "release.yml"),
    ],
)
def test_text_names_references_and_encodings_are_not_credentials(src, rel):
    assert _generic(src, rel) == []


@pytest.mark.parametrize(
    "src,rel",
    [
        (f"resetToken: 'Use code {RANDOM_A} now, friends.',\n", "messages.ts"),
        (
            "password: 'vivid quartz flamingo jumps over lazy brown hedgehog',\n",
            "messages.ts",
        ),
        ("apiToken: 'Winter2024! Is Coming, aB3dE5fG Friends.',\n", "messages.ts"),
        (f'"api_key_description": "{RANDOM_A}",\n', "servers.py"),
        (
            f'"api_key_description": "use {RANDOM_A[:14].replace("-", "")} to sign in",\n',
            "servers.py",
        ),
        (f'LOGIN_CREDENTIALS: "mediahub_{RANDOM_A}",\n', "storage.ts"),
        (f'SESSION_TOKEN: "{RANDOM_A}_session_token",\n', "storage.ts"),
        (f'PUSH_TOKEN="${{DEPLOY_PUSH_TOKEN:-{RANDOM_A}}}"\n', "deploy.sh"),
        (f'acme_api_key: "${{oc.env:ACME_SEARCH_API_KEY,{RANDOM_A}}}"\n', "tools.yaml"),
        (f'spring_token: "${{ACME_TOKEN:{RANDOM_A}}}"\n', "tools.yaml"),
        (
            f'BLOB = decode("{_urlsafe(bytes([0xFB, 0xEF, 0xBE]) + hashlib.sha256(b"x").digest())}")\n',
            "blob.py",
        ),
        (
            f'HEADER = wrap("{_urlsafe("ci~bot:" + RANDOM_A.replace("-", ""))}")\n',
            "basic.py",
        ),
        (f'session_cookie = decode("{_urlsafe(SELECTOR)}")\n', "named.py"),
        (f"TAG = '<div data-id=\"{RANDOM_A}\" class=\"plain\">'\n", "page.py"),
        (f'"hook": "//hooks.acme.test/in?sig=%2F{RANDOM_A}"\n', "sig.json"),
        ('BILLING_KEY="9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"\n', "release.yml"),
        ('DEPLOY_KEY="k3J9-xQ2m-K7pL-4vR8-tW1z"\n', "release.yml"),
    ],
)
def test_lookalikes_with_a_real_value_stay_reported(src, rel):
    assert _generic(src, rel)


def _typescript_entropy_findings(tmp_path, code: str) -> list[dict]:
    path = tmp_path / "filters.ts"
    assert write_text_no_symlink(path, code, encoding="utf-8")
    danger = scan_typescript_file(str(path))[7]
    return [finding for finding in danger if finding["rule_id"] == "SKY-S101"]


def test_typescript_base64_of_text_is_not_a_secret(tmp_path):
    encoded = base64.b64encode(b'a[href^="https://ads.acme.test/click?campaign="]')
    code = f"export const filters = [decode('{encoded.decode()}')]\n"
    assert _typescript_entropy_findings(tmp_path, code) == []


@pytest.mark.parametrize(
    "payload,prefix",
    [
        (hashlib.sha256(b"binary").digest() + b"\x00\xff", "export const blob = decode("),
        (b"svc-deploy:Xk9mQ2vL8nR5tW7yZ1cD4", "export const header = wrap("),
        (b'a[href^="https://ads.acme.test/click?campaign="]', "const sessionToken = decode("),
    ],
)
def test_typescript_binary_pair_and_named_base64_stay_reported(
    tmp_path, payload, prefix
):
    encoded = base64.b64encode(payload).decode().replace("+", "A").replace("/", "b")
    assert _typescript_entropy_findings(tmp_path, f"{prefix}'{encoded}')\n")

