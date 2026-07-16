import json
from pathlib import Path
from unittest.mock import patch

import pytest

from skylos.analyzer import analyze
from skylos.verify_change import verify_change_path


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("filename", "source", "language", "check_id"),
    [
        (
            "main.php",
            "<?php function value() { return 1; }\n",
            "php",
            "php_workspace_api_surface",
        ),
        ("main.rs", "fn main() {}\n", "rust", "rust_workspace_api_surface"),
        ("main.dart", "void main() {}\n", "dart", "dart_workspace_api_surface"),
        ("Program.cs", "class Program {}\n", "csharp", "csharp_workspace_api_surface"),
        ("Main.kt", "fun main() {}\n", "kotlin", "kotlin_workspace_api_surface"),
        ("main.sh", "echo ok\n", "shell", "shell_workspace_api_surface"),
    ],
)
def test_verify_change_marks_unsupported_local_api_language_incomplete(
    tmp_path,
    filename,
    source,
    language,
    check_id,
):
    _write(tmp_path, filename, source)

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "incomplete"
    assert payload["summary"] == (
        "Verification incomplete: 1 required check did not complete"
    )
    assert payload["coverage"]["detected_languages"] == [language]
    check = next(
        item for item in payload["coverage"]["checks"] if item["id"] == check_id
    )
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "unsupported_capability", "count": 1}]


def test_verify_change_no_source_files_has_complete_empty_coverage(tmp_path):
    _write(tmp_path, "README.txt", "documentation only\n")

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "pass"
    assert payload["coverage"]["state"] == "complete"
    assert payload["coverage"]["detected_languages"] == []
    assert payload["coverage"]["expected_checks"] == []
    assert payload["coverage"]["checks"] == []


def test_verify_change_reports_every_expected_check_in_mixed_language_repo(tmp_path):
    _write(tmp_path, "app.py", "VALUE = 1\n")
    _write(tmp_path, "web/app.ts", "export const value = 1;\n")
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    _write(
        tmp_path,
        "security/security.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )
    _write(
        tmp_path,
        "cmd/app/main.go",
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
    )
    _write(
        tmp_path,
        "src/demo/security/TokenVerifier.java",
        """package demo.security;
public final class TokenVerifier {
    public static boolean verify(String value) { return value != null; }
}
""",
    )
    _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
    )
    _write(tmp_path, "legacy/main.php", "<?php function value() { return 1; }\n")
    _write(tmp_path, "native/main.rs", "fn main() {}\n")
    _write(tmp_path, "mobile/main.dart", "void main() {}\n")
    _write(tmp_path, "dotnet/Program.cs", "class Program {}\n")
    _write(tmp_path, "jvm/Main.kt", "fun main() {}\n")
    _write(tmp_path, "scripts/entrypoint.sh", "echo ok\n")

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "incomplete"
    coverage = payload["coverage"]
    assert coverage["detected_languages"] == [
        "csharp",
        "dart",
        "go",
        "java",
        "kotlin",
        "php",
        "python",
        "rust",
        "shell",
        "typescript",
    ]
    expected_ids = {item["id"] for item in coverage["expected_checks"]}
    assert expected_ids == {
        "python_local_api_reference",
        "typescript_local_api_surface",
        "go_workspace_api_surface",
        "java_workspace_api_surface",
        "php_workspace_api_surface",
        "rust_workspace_api_surface",
        "dart_workspace_api_surface",
        "csharp_workspace_api_surface",
        "kotlin_workspace_api_surface",
        "shell_workspace_api_surface",
    }
    checks = {item["id"]: item for item in coverage["checks"]}
    for check_id in (
        "python_local_api_reference",
        "typescript_local_api_surface",
        "go_workspace_api_surface",
        "java_workspace_api_surface",
    ):
        assert checks[check_id]["outcome"] == "pass"
    for check_id in (
        "php_workspace_api_surface",
        "rust_workspace_api_surface",
        "dart_workspace_api_surface",
        "csharp_workspace_api_surface",
        "kotlin_workspace_api_surface",
        "shell_workspace_api_surface",
    ):
        assert checks[check_id]["outcome"] == "incomplete"


def test_verify_change_finding_wins_over_unsupported_language_incomplete(tmp_path):
    _write(tmp_path, "legacy/main.php", "<?php function value() { return 1; }\n")
    _write(
        tmp_path,
        "src/demo/security/TokenVerifier.java",
        """package demo.security;
public final class TokenVerifier {
    public static boolean verify(String value) { return value != null; }
}
""",
    )
    _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verifySession("ok"); }
}
""",
    )

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "fail"
    assert payload["coverage"]["state"] == "incomplete"
    assert any(
        finding.get("metadata", {}).get("member_name") == "verifySession"
        for finding in payload["findings"]
    )


def test_go_api_verification_stays_separate_from_native_engine_status(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    _write(
        tmp_path,
        "security/security.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )
    _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
    )

    with (
        patch(
            "skylos.engines.go_runner.get_go_engine_status",
            return_value={
                "status": "unavailable",
                "reason": "Go engine binary not found",
                "configured_by": "discovery",
            },
        ),
        patch(
            "skylos.visitors.languages.go.go.run_go_engine_for_module",
            side_effect=RuntimeError("Go engine binary not found"),
        ),
    ):
        result = json.loads(
            analyze(
                str(tmp_path),
                enable_ai_defects=True,
                enable_dependency_hallucinations=False,
                grep_verify=False,
            )
        )

    assert result["analysis_summary"]["language_engines"]["go"]["status"] == "partial"
    coverage = result["analysis_summary"]["ai_verification"]
    assert coverage["state"] == "complete"
    check = next(
        item for item in coverage["checks"] if item["id"] == "go_workspace_api_surface"
    )
    assert check["outcome"] == "pass"


def test_verify_change_converts_java_detector_error_to_incomplete(tmp_path):
    _write(tmp_path, "App.java", "class App {}\n")

    with patch(
        "skylos.rules.ai_defect.java_api_hallucination.scan_java_local_api_hallucinations",
        side_effect=RuntimeError("synthetic detector failure"),
    ):
        payload = verify_change_path(tmp_path)

    assert payload["status"] == "incomplete"
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "java_workspace_api_surface"
    )
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "detector_error", "count": 1},
        {"code": "expected_file_coverage_mismatch", "count": 1},
    ]


def test_analyzer_records_ignored_local_api_checks_as_incomplete(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    _write(tmp_path, "main.go", "package main\nfunc main() {}\n")
    _write(tmp_path, "App.java", "class App {}\n")

    result = json.loads(
        analyze(
            str(tmp_path),
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            project_config_overrides={"ignore": ["SKY-L012"]},
        )
    )

    coverage = result["analysis_summary"]["ai_verification"]
    assert coverage["state"] == "incomplete"
    checks = {item["id"]: item for item in coverage["checks"]}
    for check_id in ("go_workspace_api_surface", "java_workspace_api_surface"):
        assert checks[check_id]["status"] == "skipped"
        assert checks[check_id]["outcome"] == "incomplete"
        assert checks[check_id]["reasons"] == [{"code": "rule_ignored", "count": 1}]
