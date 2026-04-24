from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.php import scan_php_file


def _scan_php_findings(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "app.php"
    file_path.write_text(code, encoding="utf-8")
    return scan_php_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_unserialize_on_superglobal_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
unserialize($_POST['data']);
""",
    )
    assert "SKY-D204" in _rule_ids(findings)


def test_unserialize_on_tainted_assignment_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$payload = $_REQUEST['payload'];
unserialize($payload);
""",
    )
    assert "SKY-D204" in _rule_ids(findings)


def test_request_controlled_include_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
include $_GET['tpl'];
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_request_controlled_file_sink_flags(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$path = $_GET['path'];
file_get_contents($path);
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_fixed_path_file_sink_is_safe(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
file_get_contents('/srv/data/report.txt');
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_basename_sanitized_file_sink_is_safe(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
$name = $_GET['name'];
file_get_contents('/srv/data/' . basename($name));
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_taint_does_not_leak_across_methods_with_same_local_name(tmp_path):
    findings = _scan_php_findings(
        tmp_path,
        """<?php
class Demo {
    public function unsafe() {
        $payload = $_POST['payload'];
        return unserialize($payload);
    }

    public function safe() {
        $payload = '/srv/data/report.txt';
        return file_get_contents($payload);
    }
}
""",
    )
    assert _rule_ids(findings) == {"SKY-D204"}
