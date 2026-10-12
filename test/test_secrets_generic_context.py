"""Generic high-entropy secrets: public digests, URLs and paths are not keys.

Each "not reported" case was a CRITICAL SKY-S101 finding before this change
(mozilla/pontoon: CSP script hashes in settings, a schema URL in an XML
header). The "still reported" cases pin the same shapes when they do carry a
credential.
"""

import pytest

from skylos.rules import secret_shapes
from skylos.rules.secrets import scan_ctx

TOKEN = "8k2Lm9-Qp4Rs7Tv1Wx6Ya3Bc5De0Fg2HzQx_7Nw"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
CSP_SHA256 = "sha256-fDsgbzHC0sNuBdM4W91nXVccgFLwIDkl197QEca/Cl4="
SRI_SHA384 = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
SRI_SHA512 = (
    "sha512-qpw27gry1OuFb8xBSLkubCN12fvvzX68xMU+3hvGeOqMWyL3Pi0jEDWMSkyZBYyvIG"
    "0Bgx5Cg2BN1exHl33tIA=="
)
SCHEMA_URL = (
    "https://raw.githubusercontent.com/LTAC-Global/TBX-Basic_dialect/master/"
    "DCA/TBXcoreStructV03_TBX-Basic_integrated.rng"
)


def _scan(source: str, relpath: str):
    return list(
        scan_ctx({"relpath": relpath, "lines": source.splitlines(True), "tree": None})
    )


def _secrets(source: str, relpath: str = "app.py"):
    return [
        finding
        for finding in _scan(source, relpath)
        if finding["rule_id"] in {"SKY-S101", "SKY-S102"}
    ]


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        # CSP source hashes in a Django settings tuple (pontoon).
        ("settings.py", f"    \"'{CSP_SHA256}'\",\n"),
        ("app.py", f"CSP = \"script-src 'self' '{SRI_SHA384}'\"\n"),
        # Subresource integrity, quoted or not, as a value or an attribute.
        ("deploy.yaml", f"integrity: {SRI_SHA512}\n"),
        ("src/app.js", f'const integrity = "{SRI_SHA384}";\n'),
        ("src/App.tsx", f'<script src="/x.js" integrity="{SRI_SHA384}" />\n'),
        ("config.json", '{"integrity": "' + SRI_SHA512 + '"}\n'),
    ],
)
def test_csp_and_sri_hashes_are_not_secrets(relpath, source):
    assert _secrets(source, relpath) == []


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        # An XML schema URL whose last path segment is high-entropy (pontoon).
        ("utils.py", f'yield f"""<?xml-model href="{SCHEMA_URL}" type="x"?>\n'),
        ("app.py", f'u = "https://cdn.acme.io/app.js?v={TOKEN}"\n'),
        ("app.py", f'u = "https://{TOKEN}.cdn.acme.io/app.js"\n'),
        ("app.py", f'p = "/srv/data/{TOKEN}/out.txt"\n'),
        ("app.py", f'p = "templates/emails/{TOKEN}.html"\n'),
        ("app.py", f'p = "C:\\\\data\\\\{TOKEN}\\\\model.bin"\n'),
        # A file path or a credential-free URL assigned to a secret-sounding name.
        (
            "app.py",
            (
                "GOOGLE_APPLICATION_CREDENTIALS = "
                '"/home/ci/.config/gcloud/application_default_credentials.json"\n'
            ),
        ),
        (
            "app.py",
            'ACCESS_TOKEN = "https://login.acme.io/oauth2/v1/token/introspect-path"\n',
        ),
        # Go test files hold fixture tokens, like Python and JS tests.
        ("pkg/client_test.go", f'const token = "{TOKEN}"\n'),
    ],
)
def test_urls_and_file_paths_are_not_secrets(relpath, source):
    assert _secrets(source, relpath) == []


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        ("settings.py", f'SECRET_KEY = "{TOKEN}"\n'),
        ("app.py", f'DB = "postgres://admin:{TOKEN}@db.acme.io:5432/app"\n'),
        ("app.py", f'U = "https://deploy:{TOKEN}@git.acme.io/repo.git"\n'),
        # Signed URLs: the signature parameter is the credential.
        (
            "app.py",
            f'u = "https://acct.blob.core.windows.net/c/f?sv=2020-08-04&sig={TOKEN}"\n',
        ),
        (
            "app.py",
            (
                'u = "https://b.s3.amazonaws.com/f?X-Amz-Expires=60'
                f'&X-Amz-Signature={TOKEN}"\n'
            ),
        ),
        ("app.py", f'u = "https://api.acme.io/v1/items?api_key={TOKEN}"\n'),
        ("app.py", f'r = "https://app.acme.io/cb#access_token={TOKEN}"\n'),
        # Tokens carried in a webhook or bot path.
        ("app.py", f'u = "https://discord.com/api/webhooks/1234567/{TOKEN}"\n'),
        ("app.py", f'u = "https://api.telegram.org/bot123456:{TOKEN}/sendMessage"\n'),
        # A secret-named capability link, and a digest-shaped session value.
        ("app.py", f'SHARE_SECRET = "https://files.acme.io/s/{TOKEN}"\n'),
        ("app.py", f'session_id = "{SRI_SHA512}"\n'),
        # Lookalikes: slashes without a path shape, malformed digests.
        ("app.py", f'blob = "ab/{TOKEN}"\n'),
        ("app.py", f'blob = "/{TOKEN}"\n'),
        ("app.py", 'h = "sha512-AbCdEfGh1234567890AbCdEfGh1234567890AABB"\n'),
    ],
)
def test_real_secrets_in_the_same_shapes_are_still_found(relpath, source):
    findings = _secrets(source, relpath)
    assert [finding["provider"] for finding in findings] == ["generic"], findings


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        ("app.py", f'u = "https://x.acme.io/hooks/{GITHUB_TOKEN}"\n'),
        ("app.py", f'p = "/srv/keys/{GITHUB_TOKEN}.txt"\n'),
        ("pkg/client_test.go", f'const key = "{GITHUB_TOKEN}"\n'),
    ],
)
def test_provider_secrets_in_urls_paths_and_go_tests_are_unchanged(relpath, source):
    assert [finding["provider"] for finding in _secrets(source, relpath)] == ["github"]


def test_url_credential_in_url_with_password_keeps_its_own_finding():
    source = 'DSN = "postgres://admin:hunter2-but-longer@db.acme.io/app"\n'
    providers = {finding["provider"] for finding in _secrets(source)}
    assert "url_credentials" in providers


@pytest.mark.parametrize(
    ("source", "severity"),
    [
        # Named secrets stay CRITICAL.
        (f'SECRET_KEY = "{TOKEN}"\n', "CRITICAL"),
        (f"api_key: {TOKEN}\n", "CRITICAL"),
        (f'headers = {{"Authorization": "{TOKEN}"}}\n', "CRITICAL"),
        (f'u = "https://acct.blob.core.windows.net/c/f?sig={TOKEN}"\n', "CRITICAL"),
        (f'DB = "postgres://admin:{TOKEN}@db.acme.io/app"\n', "CRITICAL"),
        # Randomness alone is an unverified lead.
        (f'value = "{TOKEN}"\n', "HIGH"),
        (f"    ({TOKEN!r}, 3),\n", "HIGH"),
    ],
)
def test_generic_severity_depends_on_a_secret_like_name(source, severity):
    findings = _secrets(source, "config.yaml" if ": " in source[:12] else "app.py")
    assert [finding["severity"] for finding in findings] == [severity], findings
    if severity == "HIGH":
        assert findings[0]["severity_reason"] == "no_secret_name"


def test_public_location_helpers():
    line = f'href="{SCHEMA_URL}"'
    start = line.index("TBXcore")
    end = start + len("TBXcoreStructV03_TBX-Basic_integrated")
    assert secret_shapes.in_public_location(line, start, end)
    assert not secret_shapes.in_url_credential(line, start, end)
    assert secret_shapes.is_public_url_value("https://acme.io/a/b?v=1")
    assert not secret_shapes.is_public_url_value("https://u:p@acme.io/a")
    assert not secret_shapes.is_public_url_value("https://acme.io/a?token=x")
    assert secret_shapes.is_file_path_value("./config/service.json")
    assert not secret_shapes.is_file_path_value(TOKEN)
    assert not secret_shapes.is_file_path_value(f"ab+c/{TOKEN}=")
