"""Logs and CSV exports use the bounded provider-only secrets reader."""

import base64
import hashlib
import json

import pytest

from skylos import analyzer
from skylos.constants import parse_exclude_folders
from test.fixture_paths import write_fixture


TOKEN = "ghp_" + hashlib.sha256(b"local log and CSV token fixture").hexdigest()[:36]
AZURE_KEY = base64.b64encode(
    hashlib.sha512(b"local log and CSV structured fixture").digest()
).decode()
CONNECTION = (
    "DefaultEndpointsProtocol=https;AccountName=fixturestore;AccountKey="
    + AZURE_KEY
    + ";EndpointSuffix=core.windows.net"
)
GENERIC_VALUE = hashlib.sha256(b"local log and CSV entropy fixture").hexdigest()


def _scan(target, **options):
    return json.loads(
        analyzer.analyze(str(target), enable_secrets=True, grep_verify=False, **options)
    )


@pytest.mark.parametrize(
    "name,header,row_prefix",
    [
        ("requests.log", "INFO start", "INFO event="),
        ("inventory.CSV", "kind,value", "event,"),
    ],
)
@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("test_fixture", [False, True])
def test_provider_and_structured_records_in_logs_and_csv(
    tmp_path, name, header, row_prefix, direct, test_fixture
):
    path_name = f"tests/fixtures/{name}" if test_fixture else name
    path = write_fixture(
        tmp_path,
        path_name,
        f"{header}\n"
        f"{row_prefix}{TOKEN}\n"
        f"{row_prefix}{CONNECTION}\n"
        f"{row_prefix}api_key={GENERIC_VALUE}\n",
    )

    result = _scan(path if direct else tmp_path)

    findings = result["secrets"]
    assert [(item["provider"], item["line"]) for item in findings] == [
        ("github", 2),
        ("azure_storage_account_key", 3),
    ]
    assert {item["file"] for item in findings} == {name if direct else path_name}
    assert findings[1]["structured_credential"]["validation"] == "structural"
    assert result["analysis_summary"]["secrets_files_scanned"] == 1
    assert result["analysis_summary"]["total_files"] == 0
    assert result["analysis_errors"] == []
    rendered = json.dumps(result)
    assert TOKEN not in rendered
    assert AZURE_KEY not in rendered


@pytest.mark.parametrize("name", ["requests.log", "inventory.csv"])
def test_log_and_csv_follow_changed_file_and_exclusion_scope(tmp_path, name):
    content = f"entry,{TOKEN}\n"
    selected = write_fixture(tmp_path, f"selected/{name}", content)
    write_fixture(tmp_path, f"unchanged/{name}", content)
    ignored = write_fixture(tmp_path, f"excluded/{name}", content)
    generated = write_fixture(tmp_path, f"node_modules/{name}", content)

    result = _scan(
        tmp_path,
        changed_files={str(selected), str(ignored), str(generated)},
        exclude_folders=sorted(parse_exclude_folders(["excluded/**"])),
    )

    assert [item["file"] for item in result["secrets"]] == [f"selected/{name}"]
    assert result["analysis_summary"]["secrets_files_scanned"] == 1
    assert result["analysis_errors"] == []


@pytest.mark.parametrize("name", ["requests.log", "inventory.csv"])
def test_log_and_csv_support_bom_led_text(tmp_path, name):
    content = b"\xff\xfe" + f"entry,{TOKEN}\n".encode("utf-16-le")
    path = write_fixture(tmp_path, name, content)

    result = _scan(path)

    (finding,) = result["secrets"]
    assert finding["provider"] == "github"
    assert finding["source_encoding"] == "utf16le"
    assert result["analysis_summary"]["secrets_files_scanned"] == 1


@pytest.mark.parametrize(
    "name,content,limit,error",
    [
        ("requests.log", b"\xffnot UTF-8", None, "secret_config_read_error"),
        ("inventory.csv", b"row,value\nentry,data\n", 16, "secret_config_too_large"),
    ],
)
def test_unreadable_log_and_csv_stay_incomplete(
    tmp_path, monkeypatch, name, content, limit, error
):
    if limit is not None:
        monkeypatch.setattr(analyzer, "MAX_SECRET_CONFIG_BYTES", limit)
    path = write_fixture(tmp_path, name, content)

    result = _scan(path)

    assert not result.get("secrets")
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert [item["kind"] for item in result["analysis_errors"]] == [error]
