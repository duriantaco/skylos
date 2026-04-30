from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.rust import scan_rust_file


def _scan_rust_findings(tmp_path: Path, code: str) -> list[dict]:
    file_path = tmp_path / "lib.rs"
    file_path.write_text(code, encoding="utf-8")
    return scan_rust_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_command_new_with_non_literal_executable_flags(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::process::Command;
fn run_cmd(cmd: String) {
    Command::new(cmd).spawn();
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_shell_c_with_tainted_arg_flags(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::process::Command;
fn run_arg(arg: String) {
    Command::new("sh").arg("-c").arg(arg).output();
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_literal_command_is_safe(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::process::Command;
fn run_git() {
    Command::new("git").arg("status").output();
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_local_constant_command_variable_is_safe(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::process::Command;
fn run_git() {
    let command = "git";
    Command::new(command).arg("status").output();
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_tainted_command_assignment_flags(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::process::Command;
fn run_cmd(cmd: String) {
    let executable = cmd;
    Command::new(executable).spawn();
}
""",
    )
    assert "SKY-D212" in _rule_ids(findings)


def test_reassigned_command_variable_to_literal_is_safe(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::process::Command;
fn run_cmd(cmd: String) {
    let executable = cmd;
    let executable = "git";
    Command::new(executable).arg("status").output();
}
""",
    )
    assert "SKY-D212" not in _rule_ids(findings)


def test_tainted_path_to_filesystem_sink_flags(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::fs;
fn read_file(path: String) {
    fs::read_to_string(path).unwrap();
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_tainted_path_assignment_to_filesystem_sink_flags(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::fs;
fn read_file(path: String) {
    let requested_file = path;
    std::fs::read_to_string(requested_file).unwrap();
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_sanitized_path_sink_is_safe(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::fs;
fn read_file(path: String) {
    let safe = path.as_str().strip_prefix("/srv/data").unwrap();
    fs::read_to_string(safe).unwrap();
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_path_sanitized_with_file_name_is_safe(tmp_path):
    findings = _scan_rust_findings(
        tmp_path,
        """
use std::fs;
use std::path::Path;
fn read_file(filename: String) {
    let safe = Path::new(&filename).file_name().unwrap();
    fs::read_to_string(safe).unwrap();
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)
