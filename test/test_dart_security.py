from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.dart import scan_dart_file


def _scan_dart_findings(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "main.dart"
    file_path.write_text(code, encoding="utf-8")
    return scan_dart_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_process_run_with_tainted_command_flags(tmp_path):
    findings = _scan_dart_findings(
        tmp_path,
        """
import 'dart:io';

Future<void> runCommand(String command) async {
  await Process.run(command, ['--version']);
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_http_get_with_tainted_url_flags(tmp_path):
    findings = _scan_dart_findings(
        tmp_path,
        """
import 'package:http/http.dart' as http;

Future<void> fetch(String url) async {
  await http.get(Uri.parse(url));
}
""",
    )
    assert "SKY-D216" in _rule_ids(findings)


def test_http_get_literal_url_is_safe(tmp_path):
    findings = _scan_dart_findings(
        tmp_path,
        """
import 'package:http/http.dart' as http;

Future<void> fetch() async {
  await http.get(Uri.parse('https://example.com/health'));
}
""",
    )
    assert "SKY-D216" not in _rule_ids(findings)


def test_file_read_with_tainted_path_flags(tmp_path):
    findings = _scan_dart_findings(
        tmp_path,
        """
import 'dart:io';

Future<String> readFile(String path) async {
  final requested = path;
  return File(requested).readAsString();
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_basename_sanitized_file_path_is_safe(tmp_path):
    findings = _scan_dart_findings(
        tmp_path,
        """
import 'dart:io';
import 'package:path/path.dart' as path;

Future<String> readFile(String fileName) async {
  final safe = path.basename(fileName);
  return File('/srv/data/$safe').readAsString();
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_taint_does_not_leak_across_functions(tmp_path):
    findings = _scan_dart_findings(
        tmp_path,
        """
import 'dart:io';

Future<void> unsafe(String command) async {
  await Process.run(command, []);
}

Future<String> safe() async {
  final path = '/srv/data/report.txt';
  return File(path).readAsString();
}
""",
    )
    assert _rule_ids(findings) == {"SKY-D212"}
