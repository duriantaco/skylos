from pathlib import Path

from skylos.rules.ai_defect.go_api_hallucination import (
    scan_go_local_api_hallucinations,
)
from skylos.verify_change import verify_change_path


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
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
