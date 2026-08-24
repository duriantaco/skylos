import pytest

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


def _new_file_diff(filename, text):
    added = text.splitlines()
    return "\n".join(
        [
            "--- /dev/null",
            f"+++ b/{filename}",
            f"@@ -0,0 +1,{len(added)} @@",
            *(f"+{line}" for line in added),
        ]
    )


def _diff_with_new_file(filename, lines, *file_blocks):
    return "\n".join(
        [
            _diff(*file_blocks),
            _new_file_diff(filename, "\n".join(lines)),
        ]
    )


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

    def test_nested_pyproject_dependency_only_applies_to_nested_diff_imports(
        self, tmp_path, monkeypatch
    ):
        repo = self._repo(tmp_path)
        nested = repo / "child"
        nested.mkdir()
        (nested / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
            '[project]\nname = "child"\ndependencies = ["maturin"]\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"maturin": {"maturin"}},
        )

        findings, _ = scan_diff_added_imports(
            repo,
            [
                ("child/build.py", 1, "maturin"),
                ("sibling.py", 1, "maturin"),
            ],
        )

        assert [(finding["file"], finding["symbol"]) for finding in findings] == [
            ("sibling.py", "maturin")
        ]

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

    def test_nested_dependency_added_by_diff_does_not_satisfy_sibling_import(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"maturin": {"maturin"}},
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                [
                    "[dependency-groups]",
                    "dev = [",
                    '    "maturin",',
                    "]",
                ],
                ("child/build.py", ["import maturin"]),
                ("sibling.py", ["import maturin"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        undeclared = [
            finding
            for finding in result["findings"]
            if finding["rule_id"] == "SKY-D223"
        ]
        assert [(finding["file"], finding["symbol"]) for finding in undeclared] == [
            ("sibling.py", "maturin")
        ]

    def test_diff_pep735_include_group_name_is_not_a_dependency(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"sharedgroup": {"sharedgroup"}},
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                [
                    "[dependency-groups]",
                    'dev = [{include-group = "sharedgroup"}]',
                ],
                ("child/app.py", ["import sharedgroup"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "child/app.py", "sharedgroup")]

    def test_diff_pep735_ignores_nested_arrays_and_later_tables(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {
                "evildep": {"evildep"},
                "laterdep": {"laterdep"},
                "quotedsectiondep": {"quotedsectiondep"},
                "versioneddep": {"versioneddep"},
            },
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                [
                    "[dependency-groups]",
                    'dev = [["evildep"]]',
                    "[[tool.entries]]",
                    'names = ["laterdep"]',
                    'constraints = ["versioneddep>=1"]',
                    '["project.optional-dependencies"]',
                    'dev = ["quotedsectiondep"]',
                ],
                (
                    "child/app.py",
                    [
                        "import evildep",
                        "import laterdep",
                        "import quotedsectiondep",
                        "import versioneddep",
                    ],
                ),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [
            ("SKY-D223", "child/app.py", "evildep"),
            ("SKY-D223", "child/app.py", "laterdep"),
            ("SKY-D223", "child/app.py", "quotedsectiondep"),
            ("SKY-D223", "child/app.py", "versioneddep"),
        ]

    def test_diff_dependency_groups_array_table_does_not_declare_dependencies(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"arraytabledep": {"arraytabledep"}},
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                [
                    "[[dependency-groups]]",
                    'dev = ["arraytabledep"]',
                ],
                ("child/app.py", ["import arraytabledep"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "child/app.py", "arraytabledep")]

    def test_diff_pyproject_dependency_string_escapes_are_decoded(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {
                "evil": {"evil"},
                "evil_dist": {"evil-dist"},
            },
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                [
                    "[dependency-groups]",
                    'dev = ["evil\\u002Ddist"]',
                ],
                ("child/app.py", ["import evil", "import evil_dist"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "child/app.py", "evil")]

    @pytest.mark.parametrize("quote", ['"""', "'''"])
    def test_diff_pyproject_multiline_strings_do_not_supply_inner_names(
        self, tmp_path, monkeypatch, quote
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"evil": {"evil"}},
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                [
                    "[tool.example]",
                    f"config = {quote}",
                    "[dependency-groups]",
                    'dev = ["evil"]',
                    quote,
                ],
                ("child/app.py", ["import evil"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "child/app.py", "evil")]

    @pytest.mark.parametrize(
        "manifest_diff",
        [
            "--- a/child/pyproject.toml\n"
            "+++ b/child/pyproject.toml\n"
            "@@ -10,2 +10,3 @@\n"
            " [dependency-groups]\n"
            '+dev = ["evil>=1"]\n'
            ' """',
            _new_file_diff(
                "child/pyproject.toml",
                '[dependency-groups]\ndev = ["evil>=1"]\n[broken',
            ),
            _new_file_diff(
                "child/pyproject.toml",
                '[dependency-groups]\ndev = ["evil>=1"]',
            )
            + "\n--- stray hunk content",
        ],
        ids=["partial-hunk", "malformed-new-file", "invalid-trailing-line"],
    )
    def test_untrusted_pyproject_fragments_do_not_supply_dependencies(
        self, tmp_path, monkeypatch, manifest_diff
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"evil": {"evil"}},
        )
        diff_text = "\n".join(
            [
                _diff(("child/app.py", ["import evil"])),
                manifest_diff,
            ]
        )

        result = scan_diff_dependency_hallucinations(
            diff_text,
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "child/app.py", "evil")]

    @pytest.mark.parametrize(
        "manifest_path",
        [
            " child/pyproject.toml ",
            "child//pyproject.toml",
            "child/./pyproject.toml",
            "child/PYPROJECT.TOML",
        ],
    )
    def test_aliased_new_manifest_path_is_not_trusted(
        self, tmp_path, monkeypatch, manifest_path
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"maturin": {"maturin"}},
        )
        diff_text = "\n".join(
            [
                _diff(("child/app.py", ["import maturin"])),
                _new_file_diff(
                    manifest_path,
                    '[dependency-groups]\ndev = ["maturin"]',
                ),
            ]
        )

        result = scan_diff_dependency_hallucinations(
            diff_text,
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "child/app.py", "maturin")]

    @pytest.mark.parametrize(
        "manifest_lines",
        [
            ["[project]", 'dependencies = ["maturin>=1"]'],
            ["[project.optional-dependencies]", 'test = ["maturin"]'],
            ["[tool.poetry.dependencies]", 'maturin = "1.0"'],
            ["[tool.poetry.extras]", 'build = ["maturin"]'],
        ],
    )
    def test_diff_pyproject_declaration_sections_satisfy_import(
        self, tmp_path, monkeypatch, manifest_lines
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"maturin": {"maturin"}},
        )

        result = scan_diff_dependency_hallucinations(
            _diff_with_new_file(
                "child/pyproject.toml",
                manifest_lines,
                ("child/app.py", ["import maturin"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert result["findings"] == []

    @pytest.mark.parametrize(
        "unsafe_path",
        [r"..\outside\requirements.txt", "C:foo/requirements.txt"],
    )
    def test_unsafe_diff_manifest_path_cannot_satisfy_import(
        self, tmp_path, monkeypatch, unsafe_path
    ):
        monkeypatch.setattr(
            dep_mod,
            "_build_installed_module_mapping",
            lambda: {"maturin": {"maturin"}},
        )

        result = scan_diff_dependency_hallucinations(
            _diff(
                ("app.py", ["import maturin"]),
                (unsafe_path, ["maturin==1.0"]),
            ),
            self._repo(tmp_path),
            status_checker=lambda *_args: "present",
        )

        assert [
            (finding["rule_id"], finding["file"], finding["symbol"])
            for finding in result["findings"]
        ] == [("SKY-D223", "app.py", "maturin")]


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
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,4 +1,5 @@",
                    " {",
                    '   "peerDependencies": {',
                    '+    "react": "^99.0.0",',
                    "   }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )
        assert ranged["findings"] == []

    @pytest.mark.parametrize(
        "version_spec",
        ["^18", "18.x", ">=18 <20", "^18 || ^19", "*", "", "latest"],
    )
    def test_package_json_non_exact_specs_never_emit_missing_version(
        self,
        version_spec,
    ):
        seen = []

        def checker(ecosystem, name, version, _cache):
            seen.append((ecosystem, name, version))
            return "missing_version"

        result = scan_diff_dependency_hallucinations(
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,4 +1,5 @@",
                    " {",
                    '   "peerDependencies": {',
                    f'+    "react": "{version_spec}",',
                    "   }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )

        assert seen == [("npm", "react", version_spec)]
        assert result["findings"] == []

    def test_package_json_wildcard_still_checks_package_name(self):
        def checker(_ecosystem, _name, _version, _cache):
            return "missing_package"

        result = scan_diff_dependency_hallucinations(
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,4 +1,5 @@",
                    " {",
                    '   "optionalDependencies": {',
                    '+    "missing-optional": "*",',
                    "   }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=checker,
        )

        [finding] = result["findings"]
        assert finding["rule_id"] == "SKY-D222"
        assert finding["metadata"] == {
            "version_spec": "*",
            "exact": False,
            "dependency_section": "optionalDependencies",
            "dependency_optional": True,
        }

    @pytest.mark.parametrize(
        "version_spec",
        ["workspace:*", "file:../react", "npm:react@^18", "github:org/react"],
    )
    def test_package_json_non_registry_specs_are_skipped(self, version_spec):
        seen = []

        result = scan_diff_dependency_hallucinations(
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,4 +1,5 @@",
                    " {",
                    '   "peerDependencies": {',
                    f'+    "local-react": "{version_spec}",',
                    "   }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args) or "missing_package",
        )

        assert seen == []
        assert result["findings"] == []

    def test_package_json_nested_override_dependencies_are_not_direct_specs(self):
        seen = []

        result = scan_diff_dependency_hallucinations(
            "\n".join(
                [
                    "--- a/package.json",
                    "+++ b/package.json",
                    "@@ -1,7 +1,8 @@",
                    " {",
                    '   "overrides": {',
                    '     "parent": {',
                    '       "dependencies": {',
                    '+        "nested-only": "1.0.0",',
                    "       }",
                    "     }",
                    "   }",
                    " }",
                ]
            ),
            ".",
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args) or "missing_package",
        )

        assert seen == []
        assert result["findings"] == []

    def test_package_json_inline_top_level_object_does_not_hide_dependencies(self):
        seen = []
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,5 +1,6 @@",
                " {",
                '   "scripts": {"test": "pytest"},',
                '   "dependencies": {',
                '+    "missing-pkg": "1.0.0",',
                "   }",
                " }",
            ]
        )

        result = scan_diff_dependency_hallucinations(
            diff,
            None,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "missing_package",
        )

        assert seen == [("npm", "missing-pkg", "1.0.0")]
        assert result["findings"][0]["rule_id"] == "SKY-D222"

    def test_package_json_diff_stack_resets_between_hunks(self):
        seen = []
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,2 +1,3 @@",
                " {",
                '   "dependencies": {',
                '+    "real-dep": "1.0.0",',
                "@@ -10,2 +11,3 @@",
                '   "version": "2.0.0",',
                '+  "build-id": "1.0.0",',
                " }",
            ]
        )

        scan_diff_dependency_hallucinations(
            diff,
            None,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "present",
        )

        assert seen == [("npm", "real-dep", "1.0.0")]

    def test_package_json_worktree_handles_hunk_starting_inside_section(
        self,
        tmp_path,
    ):
        text = "\n".join(
            [
                "{",
                '  "scripts": {"test": "pytest"},',
                '  "dependencies": {',
                '    "npm": "11.0.0"',
                "  }",
                "}",
            ]
        )
        (tmp_path / "package.json").write_text(text, encoding="utf-8")
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -3,0 +4,1 @@",
                '+    "npm": "11.0.0"',
            ]
        )
        seen = []

        scan_diff_dependency_hallucinations(
            diff,
            tmp_path,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "present",
        )

        assert seen == [("npm", "npm", "11.0.0")]

    def test_package_json_worktree_applies_optional_override_precedence(
        self,
        tmp_path,
    ):
        text = "\n".join(
            [
                "{",
                '  "dependencies": {"shared": "99.0.0"},',
                '  "optionalDependencies": {"shared": "1.0.0"}',
                "}",
            ]
        )
        (tmp_path / "package.json").write_text(text, encoding="utf-8")
        seen = []

        result = scan_diff_dependency_hallucinations(
            _new_file_diff("package.json", text),
            tmp_path,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "present",
        )

        assert seen == [("npm", "shared", "1.0.0")]
        assert result["findings"] == []

    def test_package_json_diff_optional_local_spec_still_shadows_dependency(self):
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,7 +1,9 @@",
                " {",
                '   "dependencies": {',
                '+    "shared": "99.0.0",',
                "   },",
                '   "optionalDependencies": {',
                '+    "shared": "workspace:*",',
                "   }",
                " }",
            ]
        )
        seen = []

        result = scan_diff_dependency_hallucinations(
            diff,
            None,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "missing_version",
        )

        assert seen == []
        assert result["findings"] == []

    def test_package_json_diff_uses_optional_override_from_context(self):
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,8 +1,9 @@",
                " {",
                '   "dependencies": {',
                '+    "shared": "99.0.0",',
                "   },",
                '   "optionalDependencies": {',
                '     "shared": "workspace:*"',
                "   }",
                " }",
            ]
        )
        seen = []

        scan_diff_dependency_hallucinations(
            diff,
            None,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "missing_version",
        )

        assert seen == []

    def test_package_json_diff_uses_optional_peer_metadata_from_context(self):
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,10 +1,11 @@",
                " {",
                '   "peerDependencies": {',
                '+    "react": "99.0.0",',
                "   },",
                '   "peerDependenciesMeta": {',
                '     "react": {',
                '       "optional": true',
                "     }",
                "   }",
                " }",
            ]
        )

        result = scan_diff_dependency_hallucinations(
            diff,
            None,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *_args: "missing_version",
        )

        [finding] = result["findings"]
        assert finding["metadata"]["dependency_optional"] is True
        assert finding["metadata"]["peer_dependency_optional"] is True

    def test_package_json_malformed_worktree_uses_diff_fallback(self, tmp_path):
        text = "\n".join(
            [
                "{",
                '  "dependencies": {',
                '    "ghost-package": "1.0.0",',
                "  }",
                "}",
            ]
        )
        (tmp_path / "package.json").write_text(text, encoding="utf-8")
        seen = []

        scan_diff_dependency_hallucinations(
            _new_file_diff("package.json", text),
            tmp_path,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "present",
        )

        assert seen == [("npm", "ghost-package", "1.0.0")]

    def test_package_json_worktree_preserves_optional_peer_context(
        self,
        tmp_path,
    ):
        text = "\n".join(
            [
                "{",
                '  "peerDependencies": {"react": "99.0.0"},',
                '  "peerDependenciesMeta": {',
                '    "react": {"optional": true}',
                "  }",
                "}",
            ]
        )
        (tmp_path / "package.json").write_text(text, encoding="utf-8")

        result = scan_diff_dependency_hallucinations(
            _new_file_diff("package.json", text),
            tmp_path,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *_args: "missing_version",
        )

        [finding] = result["findings"]
        assert finding["rule_id"] == "SKY-D225"
        assert finding["metadata"]["dependency_optional"] is True
        assert finding["metadata"]["peer_dependency_optional"] is True

    def test_package_json_non_exact_specs_dedupe_by_package_name(self):
        seen = []
        diff = "\n".join(
            [
                "--- a/package.json",
                "+++ b/package.json",
                "@@ -1,7 +1,9 @@",
                " {",
                '   "devDependencies": {',
                '+    "react": "^18",',
                "   },",
                '   "peerDependencies": {',
                '+    "react": "18.x",',
                "   }",
                " }",
            ]
        )

        scan_diff_dependency_hallucinations(
            diff,
            None,
            import_scanner=_noop_import_scanner,
            status_checker=lambda *args: seen.append(args[:3]) or "present",
        )

        assert seen == [("npm", "react", "^18")]

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
