"""Provider-only text can contain literal database connection credentials."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.secrets import scan_ctx


PASSWORD = "mQ7" + "zK4tL9%21"


def _scan(path, text):
    return scan_ctx({"relpath": path, "lines": text.splitlines(keepends=True)})


@pytest.mark.parametrize(
    "url",
    [
        f"postgres://svc:{PASSWORD}@db.internal:5432/app",
        f"mongodb+srv://svc:{PASSWORD}@cluster.internal/app",
        f"rediss://:{PASSWORD}@cache.internal:6379/0",
        f"jdbc:postgresql://db.internal/app?ssl=true&user=svc&password={PASSWORD}",
        f"jdbc:mysql://db.internal:3306/app?password={PASSWORD}&user=svc",
        f"postgresql://db.internal/app?password={PASSWORD}&user=svc",
    ],
)
def test_text_database_credential_points_to_the_redacted_password(url):
    line = f"See the [database connection]({url})."
    [finding] = _scan("runbooks/Triage.MD", line + "\n")

    assert finding["rule_id"] == "SKY-S101"
    assert finding["provider"] == "url_credentials"
    assert finding["line"] == 1
    assert line[finding["col"] : finding["end_col"]] == PASSWORD
    assert finding["preview"] == "********"
    assert PASSWORD not in json.dumps(finding)


@pytest.mark.parametrize(
    "text",
    [
        f"https://svc:{PASSWORD}@db.internal/app",
        f"postgres://svc:{PASSWORD}@db.example.com/app",
        "postgres://svc:password@db.internal/app",
        "postgres://svc:${DB_PASSWORD}@db.internal/app",
        "postgres://svc@db.internal/app",
        "postgres://svc:@db.internal/app",
        "postgres://db.internal?redirect=svc:bookmark@server.internal",
        "jdbc:mysql://db.internal/app?user=svc&password=",
        "jdbc:mysql://db.internal/app?user=svc&password=prefix${DB_PASSWORD}",
        "jdbc:mysql://db.internal/app?user=svc&password=%70assword",
        f"jdbc:mysql://db.internal/app?user=${{DB_USER}}&password={PASSWORD}",
        f"jdbc:mysql://db.internal/app?user=svc&password={PASSWORD}&password=",
        f"jdbc:mysql://db.internal/app?password={PASSWORD}",
        f'password = "{PASSWORD}"',
        'nonce = "mQ7zK4tL9pR6xH2cV8jS3dF5"',
    ],
)
def test_database_text_filters_placeholders_references_and_unrelated_text(text):
    assert _scan("notes.txt", text + "\n") == []


@pytest.mark.parametrize("path", ["tests/fixtures/setup.md", "server.key", "server.pem"])
def test_database_text_respects_test_and_key_file_scopes(path):
    url = f"postgres://svc:{PASSWORD}@db.internal/app"
    assert _scan(path, url + "\n") == []


def test_standalone_text_reaches_secrets_scan(tmp_path):
    path = tmp_path / "incident.txt"
    path.write_text(f"Detected postgres://svc:{PASSWORD}@db.internal/app\n")

    result = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))

    [finding] = result["secrets"]
    assert finding["file"] == "incident.txt"
    assert finding["provider"] == "url_credentials"
    assert result["analysis_summary"]["secrets_files_scanned"] == 1
    assert PASSWORD not in json.dumps(result)
