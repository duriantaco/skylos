import pytest

from skylos.visitors.languages.dart import scan_dart_file

pytest.importorskip("tree_sitter_dart_orchard")


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        (
            (
                "import 'dart:io';\n"
                "HttpClient client() {\n"
                "  final http = HttpClient();\n"
                "  http.badCertificateCallback = (_, _, _) => true;\n"
                "  return http;\n"
                "}\n"
            ),
            [4],
        ),
        (
            (
                "import 'dart:io' as io show HttpClient;\n"
                "io.HttpClient client() {\n"
                "  return io.HttpClient()\n"
                "    ..badCertificateCallback = (_, _, _) { return true; };\n"
                "}\n"
            ),
            [4],
        ),
        (
            (
                "import 'dart:io';\n"
                "HttpClient client() {\n"
                "  final http = HttpClient();\n"
                "  final alias = http;\n"
                "  alias.badCertificateCallback = (_, _, _) => true;\n"
                "  http.badCertificateCallback = null;\n"
                "  return http;\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "import 'dart:io';\n"
                "HttpClient client() {\n"
                "  final http = HttpClient();\n"
                "  http.badCertificateCallback = (_, _, _) => false;\n"
                "  return http;\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "import 'dart:io' hide HttpClient;\n"
                "void configure() {\n"
                "  final http = HttpClient();\n"
                "  http.badCertificateCallback = (_, _, _) => true;\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "import 'dart:io';\n"
                "class HttpClient { dynamic badCertificateCallback; }\n"
                "void configure() {\n"
                "  final http = HttpClient();\n"
                "  http.badCertificateCallback = (_, _, _) => true;\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "import 'dart:io';\n"
                "void configure() {\n"
                "  var http = HttpClient();\n"
                "  http = replacement;\n"
                "  http.badCertificateCallback = (_, _, _) => true;\n"
                "}\n"
            ),
            [],
        ),
    ],
)
def test_dart_io_tls_callback_effect(tmp_path, source, lines):
    path = tmp_path / "main.dart"
    path.write_text(source)

    rows = scan_dart_file(str(path))[7]
    assert [
        (row["file"], row["line"]) for row in rows if row["rule_id"] == "SKY-D210"
    ] == [(str(path), line) for line in lines]
    assert not scan_dart_file(str(path), enable_danger_rules=False)[7]
