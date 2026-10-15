from pathlib import Path

from skylos.rules.ai_defect.go_api_hallucination import (
    scan_go_local_api_hallucinations,
)
from skylos.verify_change import verify_change_path


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        source,
        encoding="utf-8",
    )
    return path


def _module(tmp_path, app_source, package_source=None):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(tmp_path, "cmd/app/main.go", app_source)
    files = [app]
    if package_source is not None:
        files.append(_write(tmp_path, "security/security.go", package_source))
    return scan_go_local_api_hallucinations(tmp_path, files)


def test_go_local_api_check_passes_existing_export(tmp_path):
    findings, check = _module(
        tmp_path,
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
        """package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_go_local_api_check_fails_missing_export(tmp_path):
    findings, check = _module(
        tmp_path,
        """package main
import "example.com/demo/security"
func main() { security.VerifySession("ok") }
""",
        """package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    assert [finding["simple_name"] for finding in findings] == ["VerifySession"]
    assert findings[0]["metadata"]["language"] == "go"
    assert check["outcome"] == "fail"


def test_go_local_api_check_resolves_explicit_alias(tmp_path):
    findings, check = _module(
        tmp_path,
        """package main
import sec "example.com/demo/security"
func main() { sec.VerifyToken("ok") }
""",
        """package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_go_local_api_check_ignores_external_package(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "github.com/external/security"
func main() { security.Unknown() }
""",
    )

    findings, check = scan_go_local_api_hallucinations(tmp_path, [app])

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 0


def test_go_local_api_check_marks_dot_import_incomplete(tmp_path):
    findings, check = _module(
        tmp_path,
        """package main
import . "example.com/demo/security"
func main() { VerifyToken("ok") }
""",
        """package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "dot_import", "count": 1}]


def test_go_local_api_check_marks_build_conditional_surface_incomplete(tmp_path):
    findings, check = _module(
        tmp_path,
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
        """//go:build linux

package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "surface_build_conditional_surface", "count": 1}
    ]


def test_go_local_api_check_marks_filename_constrained_surface_incomplete(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
    )
    conditional = _write(
        tmp_path,
        "security/security_linux.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )

    findings, check = scan_go_local_api_hallucinations(
        tmp_path,
        [app, conditional],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "surface_build_conditional_surface", "count": 1}
    ]


def test_go_local_api_check_marks_shadowed_import_alias_incomplete(tmp_path):
    findings, check = _module(
        tmp_path,
        """package main
import "example.com/demo/security"
func main() {
    security := struct{ Missing int }{Missing: 1}
    _ = security.Missing
}
""",
        """package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "import_alias_shadowed", "count": 1}]


def test_go_local_api_check_without_module_manifest_is_incomplete(tmp_path):
    app = _write(tmp_path, "main.go", "package main\nfunc main() {}\n")

    findings, check = scan_go_local_api_hallucinations(tmp_path, [app])

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "go_module_manifest_missing", "count": 1}]


def test_go_local_api_check_resolves_local_replace(tmp_path):
    _write(
        tmp_path,
        "go.mod",
        """module example.com/demo

go 1.22
replace example.com/shared => ./shared
""",
    )
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/shared/security"
func main() { security.VerifyToken("ok") }
""",
    )
    package = _write(
        tmp_path,
        "shared/security/security.go",
        """package security
func VerifyToken(value string) bool { return value != "" }
""",
    )

    findings, check = scan_go_local_api_hallucinations(tmp_path, [app, package])

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_go_local_api_check_marks_out_of_root_local_replace_incomplete(tmp_path):
    _write(
        tmp_path,
        "go.mod",
        """module example.com/demo

go 1.22
replace example.com/shared => ../shared
""",
    )
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/shared/security"
func main() { security.VerifyToken("ok") }
""",
    )

    findings, check = scan_go_local_api_hallucinations(tmp_path, [app])

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "unresolved_local_package", "count": 1}]


def test_go_local_api_check_marks_out_of_root_workspace_incomplete(tmp_path):
    _write(
        tmp_path,
        "go.work",
        """go 1.22

use (
    .
    ../shared
)
""",
    )
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
    )
    security = _write(
        tmp_path,
        "security/security.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )

    findings, check = scan_go_local_api_hallucinations(
        tmp_path,
        [app, security],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["verified_references"] == 1
    assert check["reasons"] == [{"code": "unsafe_workspace_path", "count": 1}]


def test_go_local_api_check_marks_mixed_package_surface_incomplete(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/demo/security"
func main() { security.VerifyToken("ok") }
""",
    )
    security = _write(
        tmp_path,
        "security/security.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )
    alternate = _write(
        tmp_path,
        "security/alternate.go",
        "package alternate\nfunc Other() {}\n",
    )

    findings, check = scan_go_local_api_hallucinations(
        tmp_path,
        [app, security, alternate],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "surface_ambiguous_package_name", "count": 1}]


def test_verify_change_passes_clean_go_workspace_surface(tmp_path):
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

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "pass"
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "go_workspace_api_surface"
    )
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_verify_change_fails_missing_go_workspace_export(tmp_path):
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
func main() { security.VerifySession("ok") }
""",
    )

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["language"] == "go"
    assert finding["metadata"]["member_name"] == "VerifySession"


def test_verify_change_go_surface_respects_excluded_folders(tmp_path):
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
func main() { security.VerifySession("ok") }
""",
    )

    payload = verify_change_path(tmp_path, exclude_folders=["security"])

    assert payload["status"] == "incomplete"
    assert not any(
        finding.get("metadata", {}).get("language") == "go"
        for finding in payload["findings"]
    )
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "go_workspace_api_surface"
    )
    assert check["reasons"] == [{"code": "surface_package_surface_empty", "count": 1}]


def test_go_file_scoped_workspace_discovery_respects_excluded_folders(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/demo/generated/security"
func main() { security.VerifySession("ok") }
""",
    )
    _write(
        tmp_path,
        "generated/security/security.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )

    findings, check = scan_go_local_api_hallucinations(
        tmp_path,
        [app],
        restrict_to_files=False,
        exclude_folders=["generated"],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert "excluded_workspace_paths" in {reason["code"] for reason in check["reasons"]}


def test_verify_change_go_file_scope_carries_excluded_folders(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    app = _write(
        tmp_path,
        "main.go",
        """package main
import "example.com/demo/generated/security"
func main() { security.VerifySession("ok") }
""",
    )
    _write(
        tmp_path,
        "generated/security/security.go",
        'package security\nfunc VerifyToken(value string) bool { return value != "" }\n',
    )

    payload = verify_change_path(app, exclude_folders=["generated"])

    assert payload["status"] == "incomplete"
    assert not any(
        finding.get("metadata", {}).get("language") == "go"
        for finding in payload["findings"]
    )
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "go_workspace_api_surface"
    )
    assert "excluded_workspace_paths" in {reason["code"] for reason in check["reasons"]}


# Go's internal test files (``package pkg`` in ``pkg/*_test.go``, e.g. the
# ``export_test.go`` convention) are compiled into the package for ``go test``,
# so external tests in the same directory see their exports (W3 R3: caddy's
# ``encode.HasVaryValue`` reported as a phantom reference).
_EXPORT_TEST = (
    "package security\n"
    "func VerifyTokenForTest(value string) bool { return value != \"\" }\n"
)
_PACKAGE = "package security\nfunc VerifyToken(value string) bool { return true }\n"


def _missing_names(tmp_path, importer_relative, importer_source, extra=()):
    _write(tmp_path, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    files = [
        _write(tmp_path, "security/security.go", _PACKAGE),
        _write(tmp_path, "security/export_test.go", _EXPORT_TEST),
        _write(tmp_path, importer_relative, importer_source),
    ]
    files.extend(_write(tmp_path, relative, source) for relative, source in extra)
    findings, _check = scan_go_local_api_hallucinations(tmp_path, files)
    return [finding["simple_name"] for finding in findings]


_EXTERNAL_TEST = """package security_test
import (
    "testing"
    "example.com/demo/security"
)
func TestVerify(t *testing.T) { _ = security.{name}("x") }
"""


def test_external_test_sees_internal_test_exports(tmp_path):
    assert (
        _missing_names(
            tmp_path,
            "security/verify_test.go",
            _EXTERNAL_TEST.replace("{name}", "VerifyTokenForTest"),
        )
        == []
    )


def test_external_test_still_reports_a_name_declared_nowhere(tmp_path):
    assert _missing_names(
        tmp_path,
        "security/verify_test.go",
        _EXTERNAL_TEST.replace("{name}", "VerifyMissing"),
    ) == ["VerifyMissing"]


def test_production_code_does_not_see_test_only_exports(tmp_path):
    assert _missing_names(
        tmp_path,
        "cmd/app/main.go",
        'package main\nimport "example.com/demo/security"\n'
        'func main() { security.VerifyTokenForTest("x") }\n',
    ) == ["VerifyTokenForTest"]


def test_tests_in_another_directory_do_not_see_test_only_exports(tmp_path):
    assert _missing_names(
        tmp_path,
        "other/other_test.go",
        _EXTERNAL_TEST.replace("security_test", "other").replace(
            "{name}", "VerifyTokenForTest"
        ),
    ) == ["VerifyTokenForTest"]


def test_external_test_package_files_do_not_extend_the_package(tmp_path):
    # Exports of another ``package security_test`` file are not members of
    # package security.
    assert _missing_names(
        tmp_path,
        "security/verify_test.go",
        _EXTERNAL_TEST.replace("{name}", "HelperInExternalTest"),
        extra=[
            (
                "security/helpers_test.go",
                "package security_test\nfunc HelperInExternalTest(v string) bool { return true }\n",
            )
        ],
    ) == ["HelperInExternalTest"]
