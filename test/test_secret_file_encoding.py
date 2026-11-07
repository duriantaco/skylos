"""BOM-led secret text uses bounded, contained reads and real source lines."""

import json

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


TOKEN = "ghp_" + "K8mN2pQ6rS0tU4vW8xY1zA5bC9dE3fG7hJ2k"
ENCODINGS = ("utf-16-le", "utf-16-be")
NAMES = (
    "README.md",
    "credentials.txt",
    "service.key",
    "page.html",
    ".env",
    "config.json",
)


def _encoded(text, encoding):
    bom = b"\xff\xfe" if encoding == "utf-16-le" else b"\xfe\xff"
    return bom + text.encode(encoding)


def _scan(target, **options):
    return json.loads(
        analyze(str(target), enable_secrets=True, grep_verify=False, **options)
    )


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("direct", [False, True])
def test_bom_secret_files_work_without_a_language_anchor(
    tmp_path, name, encoding, direct
):
    source = json.dumps({"credential": TOKEN}) + "\n"
    path = write_fixture(tmp_path, name, _encoded(source, encoding))
    result = _scan(path if direct else tmp_path)
    findings = result.get("secrets", [])
    assert [(f["provider"], f["file"], f["line"]) for f in findings] == [
        ("github", name, 1)
    ]
    assert findings[0]["source_encoding"] == encoding.replace("-", "")
    assert result.get("analysis_errors", []) == []
    # Explicit JSON already has a configuration worker adapter. Its existing
    # inventory count stays unchanged; secret-only document files add none.
    assert result["analysis_summary"]["total_files"] == int(
        direct and name == "config.json"
    )
    assert result["analysis_summary"]["secrets_files_scanned"] == 1
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_utf16_preserves_lines_and_unicode_character_columns(tmp_path, encoding):
    source = 'documentation\r\n\u65e5\U0001f600 "' + TOKEN + '"\r\n'
    write_fixture(tmp_path, "README.md", _encoded(source, encoding))
    result = _scan(tmp_path)
    (finding,) = result["secrets"]
    assert finding["line"] == 2
    assert finding["col"] == 4
    assert finding["source_encoding"] == encoding.replace("-", "")
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("source", ["", "ordinary documentation\n"])
def test_valid_empty_and_safe_utf16_text_counts_as_checked(tmp_path, encoding, source):
    write_fixture(tmp_path, "README.md", _encoded(source, encoding))
    result = _scan(tmp_path)
    assert result.get("secrets", []) == []
    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["secrets_files_scanned"] == 1


@pytest.mark.parametrize("name", ["README.md", ".env", "config.json"])
@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfeA",
        b"\xfe\xffA",
        b"\xff\xfe\x00\xd8",
        b"\xfe\xff\xdc\x00",
        b"\xff\xfe\x00\x00",
        b"\x00\x00\xfe\xff",
    ],
)
def test_malformed_or_unsupported_bom_is_incomplete(tmp_path, name, data):
    write_fixture(tmp_path, name, data)
    result = _scan(tmp_path)
    assert result.get("secrets", []) == []
    assert result["analysis_errors"]
    assert result["analysis_summary"]["analysis_error_count"] >= 1
    assert result["analysis_summary"]["secrets_files_scanned"] == 0


def test_utf8_source_and_legacy_config_decoding_are_preserved(tmp_path):
    write_fixture(tmp_path, "README.md", TOKEN + "\n")
    write_fixture(tmp_path, ".env", b"\x80" + TOKEN.encode() + b"\n")
    result = _scan(tmp_path)
    assert {f["file"] for f in result["secrets"]} == {"README.md", ".env"}
    assert all("source_encoding" not in f for f in result["secrets"])
    assert result.get("analysis_errors", []) == []


def test_utf16_explicit_exclusion_and_changed_file_scope_remain_effective(tmp_path):
    first = write_fixture(tmp_path, "README.md", _encoded(TOKEN, "utf-16-le"))
    write_fixture(tmp_path, "private/ignored.txt", _encoded(TOKEN, "utf-16-be"))
    result = _scan(tmp_path, exclude_folders=["private/**"], changed_files={str(first)})
    assert [(f["file"], f["provider"]) for f in result["secrets"]] == [
        ("README.md", "github")
    ]
    assert result.get("analysis_errors", []) == []


def test_utf16_file_size_limit_is_applied_to_original_bytes(tmp_path, monkeypatch):
    import skylos.analyzer as analyzer

    monkeypatch.setattr(analyzer, "MAX_SECRET_CONFIG_BYTES", 16)
    write_fixture(tmp_path, "README.md", _encoded(TOKEN, "utf-16-le"))
    result = _scan(tmp_path)
    assert result["analysis_errors"]
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
