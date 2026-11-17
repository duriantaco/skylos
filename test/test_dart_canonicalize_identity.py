import pytest
from skylos.visitors.languages.dart import scan_dart_file

pytest.importorskip("tree_sitter_dart_orchard")


def scan(tmp_path, source):
    path = tmp_path / "app.dart"
    path.write_text(source)
    return {f["rule_id"] for f in scan_dart_file(str(path), {})[7]}


@pytest.mark.parametrize(
    "statement,rule",
    [
        ("Process.run(canonicalize(Platform.environment['BIN']!), []);", "SKY-D212"),
        (
            "http.get(Uri.parse(canonicalize(Platform.environment['URL']!)));",
            "SKY-D216",
        ),
        (
            "File(canonicalize(Platform.environment['PATH']!)).readAsString();",
            "SKY-D215",
        ),
    ],
)
def test_local_identity_named_canonicalize_does_not_sanitize(tmp_path, statement, rule):
    source = (
        "import 'dart:io';\nimport 'package:http/http.dart' as http;\nString canonicalize(String value) => value;\nvoid run() { "
        + statement
        + " }"
    )
    assert rule in scan(tmp_path, source)


def test_fixed_canonicalize_input_is_quiet(tmp_path):
    assert not scan(
        tmp_path,
        "import 'dart:io';\nString canonicalize(String value) => value;\nvoid run() { Process.run(canonicalize('/usr/bin/true'), []); }",
    )
