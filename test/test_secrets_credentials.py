"""Credentials embedded in connection URLs and keyed config literals."""

import json

import pytest

from skylos.rules.secrets import scan_ctx


def _scan(relpath, text):
    return scan_ctx({"relpath": relpath, "lines": text.splitlines(True)})


def _providers(findings):
    return [f.get("provider") for f in findings]


URL_POSITIVES = [
    (".env", "DATABASE_URL=postgres://app:S3cr3tPass!@db:5432/app\n"),
    ("config.yaml", "cache: redis://:Xk9mP2qL7vT4@redis:6379/0\n"),
    (
        "app/db.py",
        'engine = create_engine("mysql+pymysql://svc:Qw7!zR4pLm@prod-db/app")\n',
    ),
    ("settings.toml", 'broker = "amqp://worker:n8Vq2Lr5Tz@mq.internal//"\n'),
    ("src/db.ts", "const url = 'mongodb://root:pW4-rT9_xQ2@mongo:27017';\n"),
]


@pytest.mark.parametrize("relpath,text", URL_POSITIVES)
def test_url_embedded_password_is_flagged(relpath, text):
    findings = _scan(relpath, text)
    assert "url_credentials" in _providers(findings)


URL_NEGATIVES = [
    "DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app",
    "DATABASE_URL=postgres://app:$DB_PASSWORD@db:5432/app",
    "DATABASE_URL=postgres://app:<password>@db:5432/app",
    "DATABASE_URL=postgres://app:changeme@db:5432/app",
    "DATABASE_URL=postgres://app:password@db:5432/app",
    "DATABASE_URL=postgres://app:@db:5432/app",
    "DATABASE_URL=postgres://postgres:postgres@localhost:5432/app",
    "DATABASE_URL=postgres://app:{{ .Values.dbPassword }}@db/app",
    "DATABASE_URL=https://user:S3cr3tPass!@example.com/path",
    "DATABASE_URL=postgres://user:S3cr3tPass!@host:5432/db",
    "DATABASE_URL=postgres://app:your_password_here@db/app",
    "DATABASE_URL=postgres://app:xxxxxxxx@db/app",
    "DATABASE_URL=https://api.github.com/repos/o/r",
    "EMAIL=mailto:someone@example.org",
]


@pytest.mark.parametrize("line", URL_NEGATIVES)
def test_url_placeholders_and_references_are_not_flagged(line):
    assert "url_credentials" not in _providers(_scan(".env", line + "\n"))


@pytest.mark.parametrize(
    "line",
    [
        'dsn = "postgresql://%s:%s@%s/%s" % (user, pw, host, db)',
        'dsn = f"postgresql://{user}:{password}@{host}/db"',
        "const dsn = `postgres://${user}:${pass}@${host}/db`;",
    ],
)
def test_url_templates_in_source_are_not_flagged(line):
    assert "url_credentials" not in _providers(_scan("app/db.py", line + "\n"))


CONFIG_POSITIVES = [
    ("values.yaml", 'db:\n  password: "Zr8#kLq2!vW9"\n'),
    ("values.yaml", "db:\n  password: Zr8#kLq2!vW9\n"),
    ("chart/values.yml", "auth:\n  adminPassword: 'Hq3@nB7$wE1x'\n"),
    (".env", "DB_PASSWORD=Zr8kLq2vW9xP4mT\n"),
    (".env.production", "export STRIPE_WEBHOOK_SECRET=wH7kP2mQ9xR4tL8v\n"),
    ("config.json", '{"db": {"clientSecret": "aB3$dE6^gH9*"}}\n'),
    ("pyproject.toml", '[tool.x]\napi_key = "Tq8mZ2xL5nR7wP3v"\n'),
    ("app.ini", "[db]\npassword = Zr8#kLq2!vW9\n"),
    ("settings.cfg", "db_pass_pwd: mK4#tR8!zQ2\n"),
    ("config.yaml", 'auth_token: "8f3c2a9d7e1b4c6f0a5d2e8b7c1f9a3d"\n'),
]


@pytest.mark.parametrize("relpath,text", CONFIG_POSITIVES)
def test_keyed_config_credential_literal_is_flagged(relpath, text):
    findings = _scan(relpath, text)
    assert any(
        p in {"config_credential", "generic"} for p in _providers(findings)
    ), findings


CONFIG_NEGATIVES = [
    ("values.yaml", "password: ${DB_PASSWORD}\n"),
    ("values.yaml", "password: \"{{ .Values.db.password | quote }}\"\n"),
    ("values.yaml", "password: changeme\n"),
    ("values.yaml", 'password: ""\n'),
    ("values.yaml", "password:\n"),
    ("values.yaml", "password: !vault |\n"),
    ("values.yaml", "existingSecret: my-app-secret-v2\n"),
    ("values.yaml", "secretName: app-secret-2024\n"),
    ("values.yaml", "password_file: /run/secrets/db_password\n"),
    ("values.yaml", "passwordFile: ./secrets/Pw1!.txt\n"),
    ("values.yaml", "password: your_password_here\n"),
    ("values.yaml", "password: <set-me-Please1>\n"),
    ("values.yaml", "min_password_length: 12\n"),
    ("values.yaml", "require_token: true\n"),
    ("values.yaml", "# password: Zr8#kLq2!vW9\n"),
    ("values.yaml", "secretKeyRef: {name: db, key: password}\n"),
    (".env", "DB_PASSWORD=$DB_PASSWORD_FROM_VAULT\n"),
    (".env", "DB_PASSWORD=${DB_PASSWORD:-}\n"),
    (".env", "DB_PASSWORD=\n"),
    ("expected.json", '{"file": "models.py", "token": "unique=True"}\n'),
    ("expected.json", '{"token": "_ENTRIES[key]"}\n'),
    ("tokens.json", '{"token": "Identifier"}\n'),
    ("config.yaml", "token_type: Bearer\n"),
]


@pytest.mark.parametrize("relpath,text", CONFIG_NEGATIVES)
def test_placeholders_and_references_are_not_flagged(relpath, text):
    providers = _providers(_scan(relpath, text))
    assert "config_credential" not in providers
    assert "url_credentials" not in providers


def test_keyed_literal_detection_is_limited_to_config_files():
    # Source code keeps the existing generic/provider rules only.
    assert "config_credential" not in _providers(
        _scan("app/settings.py", 'password = "Zr8#kLq2!vW9"\n')
    )


def test_test_paths_are_not_flagged():
    text = "DATABASE_URL=postgres://app:S3cr3tPass!@db:5432/app\n"
    assert _scan("tests/fixtures/.env", text) == []


@pytest.mark.parametrize(
    "relpath,text,secret",
    [
        (".env", "DATABASE_URL=postgres://app:S3cr3tPass!@db:5432/app\n", "S3cr3tPass!"),
        ("values.yaml", 'password: "Zr8#kLq2!vW9"\n', "Zr8#kLq2!vW9"),
    ],
)
def test_findings_never_contain_the_secret_value(relpath, text, secret):
    findings = _scan(relpath, text)
    assert findings
    serialized = json.dumps(findings)
    assert secret not in serialized
    assert secret[:4] not in serialized
    for finding in findings:
        assert finding["preview"] == "********"


def test_span_points_at_the_password():
    line = "DATABASE_URL=postgres://app:S3cr3tPass!@db:5432/app"
    [finding] = [
        f for f in _scan(".env", line + "\n") if f["provider"] == "url_credentials"
    ]
    assert line[finding["col"] : finding["end_col"]] == "S3cr3tPass!"
    assert finding["severity"] == "HIGH"
    assert finding["rule_id"] == "SKY-S101"


def test_provider_secret_in_url_is_not_duplicated():
    line = "GIT_URL=https://x:ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "@github.com/o/r\n"
    providers = _providers(_scan(".env", line))
    assert providers.count("github") == 1
    assert "url_credentials" not in providers


def test_ignore_directive_suppresses_new_detectors():
    text = "DATABASE_URL=postgres://app:S3cr3tPass!@db/app  # skylos: ignore[SKY-S101]\n"
    assert _scan(".env", text) == []


_GENERIC_KEY_VALUE = "ak_live_" + "7Hq2Lm9Xv4Rt8Wz1Np6Ks3Jd"


@pytest.mark.parametrize(
    "relpath, text",
    [
        (".env", f"ACME_BILLING_KEY={_GENERIC_KEY_VALUE}\n"),
        (".env.local", f"STRIPE_KEY={_GENERIC_KEY_VALUE}\n"),
        (".env", f"KEY={_GENERIC_KEY_VALUE}\n"),
        (".env", f"export BILLING_KEY='{_GENERIC_KEY_VALUE}'\n"),
        ("config/app.yaml", f"billing:\n  acme_key: {_GENERIC_KEY_VALUE}\n"),
        ("settings.toml", f'VENDOR_KEY = "{_GENERIC_KEY_VALUE}"\n'),
        (".env", f"VITE_ANALYTICS_KEY={_GENERIC_KEY_VALUE}\n"),
    ],
)
def test_generic_key_name_with_random_value_is_flagged(relpath, text):
    findings = _scan(relpath, text)
    assert _providers(findings) == ["config_credential"]
    assert _GENERIC_KEY_VALUE not in json.dumps(findings)


@pytest.mark.parametrize(
    "line",
    [
        "PUBLIC_KEY_PATH=/etc/keys/pub.pem",
        "SIGNING_KEY_FILE=keys/signing.pem",
        f"NEXT_PUBLIC_STRIPE_KEY={_GENERIC_KEY_VALUE}",
        f"PUBLIC_MAPS_KEY={_GENERIC_KEY_VALUE}",
        f"STRIPE_PUBLISHABLE_KEY={_GENERIC_KEY_VALUE}",
        "AWS_KEY_ID=prod_reader_01",
        "CACHE_KEY=users_v2",
        "PRIMARY_KEY=id",
        f"IDEMPOTENCY_KEY={_GENERIC_KEY_VALUE}",
        "BILLING_KEY=${BILLING_KEY}",
        "BILLING_KEY=your_billing_key_here_1234",
        "BILLING_KEY=replace-with-real-key-0001",
        "SORT_KEY=created_at_desc",
        "REDIS_KEY=session:user:12345",
        "FEATURE_KEY=checkout_v2_enabled",
        "KEY=short1",
    ],
)
def test_generic_key_name_non_secrets_are_not_flagged(line):
    assert _scan(".env", line + "\n") == []
