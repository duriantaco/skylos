from skylos.rules.ai_defect import dependency_hallucination as dep_mod
from skylos.rules.ai_defect import diff_dependencies as diff_mod
from skylos.rules.ai_defect.dependency_hallucination import scan_diff_added_imports
from skylos.rules.ai_defect.diff_dependencies import (
    _parse_added_lines,
    scan_diff_dependency_hallucinations,
)
from skylos_mcp.server import _validate_code_change_impl


def _diff(*file_blocks):
    lines = []
    for filename, added in file_blocks:
        lines.append(f"--- a/{filename}")
        lines.append(f"+++ b/{filename}")
        lines.append(f"@@ -1,1 +1,{len(added) + 1} @@")
        lines.append(" # context")
        for text in added:
            lines.append(f"+{text}")
    return "\n".join(lines)


def _noop_import_scanner(
    _repo_root,
    _added_imports,
    extra_local_modules=None,
    extra_declared_deps=None,
):
    return [], False


class TestParseAddedLines:
    def test_tracks_files_and_line_numbers(self):
        diff = _diff(
            ("app/main.py", ["import foo", "x = 1"]),
            ("requirements.txt", ["foo==1.0"]),
        )
        parsed = _parse_added_lines(diff)
        assert parsed[0][0] == "app/main.py"
        assert parsed[0][1] == [(2, "import foo"), (3, "x = 1")]
        assert parsed[1][0] == "requirements.txt"
        assert parsed[1][1] == [(2, "foo==1.0")]

    def test_removed_lines_do_not_advance_line_numbers(self):
        diff = "\n".join(
            [
                "--- a/app.py",
                "+++ b/app.py",
                "@@ -5,3 +5,2 @@",
                " context",
                "-import old_module",
                "+import new_module",
            ]
        )
        parsed = _parse_added_lines(diff)
        assert parsed == [("app.py", [(6, "import new_module")])]


class TestScanDiffAddedImports:
    def _repo(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
            "click\n",
            encoding="utf-8",
        )
        return tmp_path

    def test_flags_hallucinated_import(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            dep_mod, "_check_pypi_status", lambda _name, _cache: "missing"
        )
        findings, unreachable = scan_diff_added_imports(
            self._repo(tmp_path),
            [("app.py", 2, "totally_fake_module_zz")],
        )
        assert unreachable is False
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D222"
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["file"] == "app.py"
        assert findings[0]["line"] == 2

    def test_module_created_by_same_diff_is_not_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            dep_mod, "_check_pypi_status", lambda _name, _cache: "missing"
        )
        findings, _ = scan_diff_added_imports(
            self._repo(tmp_path),
            [("app.py", 2, "brand_new_module")],
            extra_local_modules={"brand_new_module"},
        )
        assert findings == []

    def test_stdlib_and_declared_imports_are_not_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            dep_mod, "_check_pypi_status", lambda _name, _cache: "missing"
        )
        findings, _ = scan_diff_added_imports(
            self._repo(tmp_path),
            [("app.py", 1, "os"), ("app.py", 2, "click")],
        )
        assert findings == []

    def test_unreachable_registry_is_reported(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            dep_mod, "_check_pypi_status", lambda _name, _cache: "unknown"
        )
        _findings, unreachable = scan_diff_added_imports(
            self._repo(tmp_path),
            [("app.py", 2, "totally_fake_module_zz")],
        )
        assert unreachable is True

    def test_dependency_added_by_same_raw_diff_satisfies_import(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(dep_mod, "_check_pypi_status", lambda _name, _cache: "exists")

        result = scan_diff_dependency_hallucinations(
            _diff(
                ("app.py", ["import brandnewdep"]),
                ("requirements.txt", ["brandnewdep==1.0.0"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert result["findings"] == []


class TestManifestDiffChecks:
    def test_missing_requirements_package(self):
        seen = []

        def checker(ecosystem, name, version, _cache):
            seen.append((ecosystem, name, version))
            return "missing_package"

        result = scan_diff_dependency_hallucinations(
            _diff(("requirements.txt", ["numpyy-utils==1.0.0"])),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert seen == [("PyPI", "numpyy-utils", "1.0.0")]
        finding = result["findings"][0]
        assert finding["rule_id"] == "SKY-D222"
        assert finding["kind"] == "hallucinated_package"
        assert finding["severity"] == "CRITICAL"
        assert finding["file"] == "requirements.txt"

    def test_missing_version_only_fires_for_exact_pins(self):
        def checker(_ecosystem, _name, _version, _cache):
            return "missing_version"

        pinned = scan_diff_dependency_hallucinations(
            _diff(("requirements.txt", ["requests==99.99.99"])),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert pinned["findings"][0]["rule_id"] == "SKY-D225"
        assert pinned["findings"][0]["kind"] == "hallucinated_version"

        ranged = scan_diff_dependency_hallucinations(
            _diff(("package.json", ['    "react": "^99.0.0",'])),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert ranged["findings"] == []

    def test_package_json_dependency_section_is_checked(self):
        seen = []

        def checker(ecosystem, name, version, _cache):
            seen.append((ecosystem, name, version))
            return "present"

        scan_diff_dependency_hallucinations(
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,4 +1,5 @@",
                    " {",
                    '   "version": "2.0.0",',
                    '   "dependencies": {',
                    '+    "left-pad": "1.3.0",',
                    "   }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert seen == [("npm", "left-pad", "1.3.0")]

    def test_package_json_non_dependency_sections_are_not_checked(self):
        seen = []

        def checker(ecosystem, name, version, _cache):
            seen.append((ecosystem, name, version))
            return "missing_package"

        result = scan_diff_dependency_hallucinations(
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,2 +1,6 @@",
                    " {",
                    '+  "config": {',
                    '+    "company-service-port": "3000"',
                    "+  }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )

        assert seen == []
        assert result["findings"] == []

    def test_go_mod_require_lines_are_checked(self):
        seen = []

        def checker(ecosystem, name, version, _cache):
            seen.append((ecosystem, name, version))
            return "missing_package"

        result = scan_diff_dependency_hallucinations(
            _diff(("go.mod", ["\tgithub.com/fakeorg/notreal v1.2.3"])),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert seen == [("Go", "github.com/fakeorg/notreal", "v1.2.3")]
        assert result["findings"][0]["rule_id"] == "SKY-D222"

    def test_pyproject_specs_are_checked_and_config_keys_skipped(self):
        seen = []

        def checker(ecosystem, name, version, _cache):
            seen.append((ecosystem, name, version))
            return "present"

        scan_diff_dependency_hallucinations(
            _diff(
                (
                    "pyproject.toml",
                    [
                        '    "totally-fake-lib>=1.0",',
                        'version = "4.28.0"',
                        'line-length = "100"',
                    ],
                )
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert seen == [("PyPI", "totally-fake-lib", "1.0")]

    def test_unknown_status_reports_unreachable_without_findings(self):
        def checker(_ecosystem, _name, _version, _cache):
            return "unknown"

        result = scan_diff_dependency_hallucinations(
            _diff(("requirements.txt", ["requests==2.31.0"])),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert result["findings"] == []
        assert result["registry_unreachable"] is True

    def test_import_findings_get_kind_labels(self):
        def import_scanner(
            _repo_root,
            _added_imports,
            extra_local_modules=None,
            extra_declared_deps=None,
        ):
            return (
                [
                    {"rule_id": "SKY-D222", "file": "app.py", "line": 1},
                    {"rule_id": "SKY-D223", "file": "app.py", "line": 2},
                ],
                False,
            )

        result = scan_diff_dependency_hallucinations(
            _diff(("app.py", ["import whatever"])),
            ".",
            import_scanner=import_scanner,
            status_checker=lambda *_args: "present",
        )
        kinds = [f["kind"] for f in result["findings"]]
        assert kinds == ["hallucinated_import", "undeclared_import"]


class TestValidateCodeChangeDependencies:
    def test_dependency_findings_flow_into_result(self, monkeypatch):
        def fake_scan(_diff_text, _repo_root):
            return {
                "findings": [
                    {
                        "rule_id": "SKY-D222",
                        "kind": "hallucinated_import",
                        "severity": "CRITICAL",
                        "message": "Hallucinated dependency 'fake_pkg'.",
                        "file": "app.py",
                        "line": 2,
                        "col": 0,
                    }
                ],
                "registry_unreachable": False,
            }

        monkeypatch.setattr(
            diff_mod, "scan_diff_dependency_hallucinations", fake_scan
        )
        result = _validate_code_change_impl(
            _diff(("app.py", ["import fake_pkg"]))
        )
        assert result["status"] == "fail"
        assert result["registry"] == "ok"
        assert any(f["rule_id"] == "SKY-D222" for f in result["findings"])
        assert "hallucinated import" in result["summary"]

    def test_unreachable_registry_is_surfaced(self, monkeypatch):
        monkeypatch.setattr(
            diff_mod,
            "scan_diff_dependency_hallucinations",
            lambda _diff_text, _repo_root: {
                "findings": [],
                "registry_unreachable": True,
            },
        )
        result = _validate_code_change_impl(_diff(("app.py", ["import requests"])))
        assert result["status"] == "pass"
        assert result["registry"] == "unreachable"

    def test_check_dependencies_false_skips_scan(self, monkeypatch):
        def boom(_diff_text, _repo_root):
            raise AssertionError("dependency scan should not run")

        monkeypatch.setattr(diff_mod, "scan_diff_dependency_hallucinations", boom)
        result = _validate_code_change_impl(
            _diff(("app.py", ["import requests"])),
            check_dependencies=False,
        )
        assert result["registry"] == "skipped"

    def test_scan_failure_reports_error_status(self, monkeypatch):
        def boom(_diff_text, _repo_root):
            raise RuntimeError("registry meltdown")

        monkeypatch.setattr(diff_mod, "scan_diff_dependency_hallucinations", boom)
        result = _validate_code_change_impl(_diff(("app.py", ["import requests"])))
        assert result["registry"] == "error"
        assert result["status"] == "pass"
