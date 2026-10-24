from __future__ import annotations

import ast
from collections import Counter

import pytest

from skylos.rules.ai_defect import dependency_hallucination as dep


@pytest.fixture
def offline_registry(monkeypatch):
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os", "sys"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(dep, "_build_installed_requirements", lambda: {})
    monkeypatch.setattr(dep, "installed_module_mapping", lambda builder: {})
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(dep, "_fetch_dist_modules", lambda *args, **kwargs: None)

    def status(name, cache):
        if name == "known_package":
            return "exists"
        if name == "unreachable_package":
            return "unknown"
        return "missing"

    monkeypatch.setattr(dep, "_check_pypi_status", status)


def _write(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _source(import_count):
    lines = [f"import absent_package_{index}.portion" for index in range(import_count)]
    lines.extend(
        [
            "import known_package",
            "import unreachable_package",
            "import os",
            "try:",
            "    import optional_package",
            "except ImportError:",
            "    optional_package = None",
            "if optional_package is not None:",
            "    optional_package.run()",
            "try:",
            "    import uncertain_package",
            "except ImportError:",
            "    uncertain_package = make_fallback()",
        ]
    )
    lines.extend(f"padding_{index} = {index}" for index in range(96))
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_file_analysis_pass_count_does_not_grow_with_import_roots(
    tmp_path, monkeypatch, offline_registry, mode
):
    original_parse = ast.parse
    original_walk = ast.walk
    counts = []
    for import_count in (4, 24):
        root = tmp_path / f"roots_{import_count}"
        _write(root / "requirements.txt", "")
        source = _source(import_count)
        path = _write(root / "entry.py", source)
        operations = Counter()
        trees = set()

        def counted_parse(value, *args, **kwargs):
            tree = original_parse(value, *args, **kwargs)
            if value == source:
                operations["parse"] += 1
                trees.add(tree)
            return tree

        def counted_walk(tree):
            if tree in trees:
                operations["whole_tree_walk"] += 1
            return original_walk(tree)

        with monkeypatch.context() as instrumentation:
            instrumentation.setattr(ast, "parse", counted_parse)
            instrumentation.setattr(ast, "walk", counted_walk)
            if mode == "full":
                findings = dep.scan_python_dependency_hallucinations(root, [path])
                assert findings.unverified_imports == {
                    "uncertain_package": "guarded_import_fallback_unproven"
                }
            else:
                added = [
                    ("entry.py", index + 1, f"absent_package_{index}.portion")
                    for index in range(import_count)
                ]
                added.extend(
                    (
                        "entry.py",
                        dep._find_import_line(source, module),
                        module,
                    )
                    for module in (
                        "known_package",
                        "unreachable_package",
                        "os",
                        "optional_package",
                        "uncertain_package",
                    )
                )
                findings, unreachable = dep.scan_diff_added_imports(root, added)
                assert unreachable is True

        identities = {(row["symbol"], row["rule_id"]) for row in findings}
        assert identities == {
            (f"absent_package_{index}", "SKY-D222") for index in range(import_count)
        } | {
            ("known_package", "SKY-D223"),
            ("unreachable_package", "SKY-D223"),
        }
        counts.append(operations)

    assert counts[1] == counts[0]
    assert counts[0]["parse"] <= 6
    assert counts[0]["whole_tree_walk"] <= 12


def test_full_scan_without_import_candidates_does_not_parse_source(
    tmp_path, monkeypatch, offline_registry
):
    _write(tmp_path / "requirements.txt", "")
    source = "\n".join(f"value_{index} = {index}" for index in range(512))
    path = _write(tmp_path / "data.py", source)
    original_parse = ast.parse

    def reject_target_parse(value, *args, **kwargs):
        assert value != source, "A file with no import candidates needs no import AST"
        return original_parse(value, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", reject_target_parse)
    findings = dep.scan_python_dependency_hallucinations(tmp_path, [path])
    assert list(findings) == []
    assert findings.unverified_imports == {}


def test_import_facts_keep_from_import_breadth_first_order_and_alias_paths():
    source = (
        "from package.z import Z, A\n"
        "import package.first, extra\n"
        "def deferred():\n"
        "    from package.deep import B\n"
        "from package import C\n"
    )
    analysis = dep._SourceImportAnalysis(source)

    assert analysis.modules == {"package"}
    assert analysis.requirements("package") == (
        frozenset({"package.z", "package.first", "package.deep", "package"}),
        (
            ("package.z", ("Z", "A")),
            ("package", ("C",)),
            ("package.deep", ("B",)),
        ),
    )
    assert analysis.requirements("extra") == (frozenset({"extra"}), ())
    assert analysis.requirements("absent") == (frozenset({"absent"}), ())
    assert analysis.submodules["package"] == {"z", "first", "deep"}
    assert analysis.lines["package"] == 1
    assert analysis.lines.get("extra", 1) == 1


def test_malformed_source_keeps_regex_roots_submodules_and_line_fallbacks():
    source = "value = '''\nimport quoted.part\n'''\nimport missing.child\nbroken = (\n"
    analysis = dep._SourceImportAnalysis(source)

    assert analysis.modules == {"quoted", "missing"}
    assert analysis.submodules == {
        "quoted": frozenset({"part"}),
        "missing": frozenset({"child"}),
    }
    assert analysis.lines == {"quoted": 2, "missing": 4}
    assert analysis.requirements("quoted") == (frozenset({"quoted"}), ())
    assert analysis.requirements("missing") == (frozenset({"missing"}), ())
    assert analysis.optional_imports == frozenset()
    assert analysis.uncertain_imports == frozenset()


def test_strict_and_uncertain_optional_paths_stay_distinct():
    source = (
        "try:\n    import strict_optional.part\n"
        "except ImportError:\n    pass\n"
        "try:\n    import uncertain_optional.part\n"
        "except ImportError:\n    build_fallback()\n"
        "try:\n    import fatal_optional.part\n"
        "except ImportError:\n    raise\n"
        "import mixed.required\n"
        "try:\n    import mixed.optional\n"
        "except ImportError:\n    pass\n"
    )
    analysis = dep._SourceImportAnalysis(source)

    assert analysis.optional_imports == {"strict_optional"}
    assert analysis.uncertain_imports == {"uncertain_optional"}
    assert analysis.requirements("strict_optional") == (
        frozenset({"strict_optional"}),
        (),
    )
    assert analysis.requirements("uncertain_optional") == (
        frozenset({"uncertain_optional.part"}),
        (),
    )
    assert analysis.requirements("fatal_optional") == (
        frozenset({"fatal_optional.part"}),
        (),
    )
    assert analysis.requirements("mixed") == (frozenset({"mixed.required"}), ())


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize("main_guard", [False, True])
def test_script_fallback_requires_the_existing_main_guard_proof(
    tmp_path, offline_registry, mode, main_guard
):
    _write(tmp_path / "requirements.txt", "")
    _write(tmp_path / "pkg/__init__.py", "")
    _write(tmp_path / "pkg/helper.py", "value = 1\n")
    source = (
        "try:\n    from .helper import value\n"
        "except ImportError:\n    from helper import value\n"
    )
    if main_guard:
        source += "if __name__ == '__main__':\n    pass\n"
    path = _write(tmp_path / "pkg/entry.py", source)
    if mode == "full":
        findings = dep.scan_python_dependency_hallucinations(tmp_path, [path])
    else:
        findings, unreachable = dep.scan_diff_added_imports(
            tmp_path, [("pkg/entry.py", 4, "helper")]
        )
        assert unreachable is False

    expected = [("helper", "SKY-D222")]
    if main_guard:
        expected = []
    assert [(finding["symbol"], finding["rule_id"]) for finding in findings] == expected


def test_explicit_dotted_diff_import_supplements_source_without_regex_roots(
    tmp_path, monkeypatch, offline_registry
):
    _write(tmp_path / "requirements.txt", "")
    _write(tmp_path / "entry.py", "if enabled: import package.original\n")
    captured = []
    real_classify = dep._classify_import

    def capture(mod, ctx, file_path=None, **options):
        captured.append((mod, options["required_paths"], options["submodules"]))
        return real_classify(mod, ctx, file_path, **options)

    monkeypatch.setattr(dep, "_classify_import", capture)
    findings, unreachable = dep.scan_diff_added_imports(
        tmp_path, [("entry.py", 37, "package.added")]
    )

    assert captured == [
        (
            "package",
            frozenset({"package.original", "package.added"}),
            frozenset({"added"}),
        )
    ]
    assert [
        (finding["symbol"], finding["line"], finding["rule_id"]) for finding in findings
    ] == [("package", 37, "SKY-D222")]
    assert unreachable is False


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_import_facts_are_file_scoped_and_refresh_between_scans(
    tmp_path, offline_registry, mode
):
    _write(tmp_path / "requirements.txt", "")
    optional = _write(
        tmp_path / "optional.py",
        "try:\n    import shared_ghost\nexcept ImportError:\n    pass\n",
    )
    required = _write(tmp_path / "required.py", "import shared_ghost\n")

    def scan(optional_line):
        if mode == "full":
            findings = dep.scan_python_dependency_hallucinations(
                tmp_path, [optional, required]
            )
            assert findings.unverified_imports == {}
        else:
            findings, unreachable = dep.scan_diff_added_imports(
                tmp_path,
                [
                    ("optional.py", optional_line, "shared_ghost"),
                    ("required.py", 1, "shared_ghost"),
                ],
            )
            assert unreachable is False
        return {
            (finding["file"], finding["line"], finding["rule_id"])
            for finding in findings
        }

    optional_label = "optional.py"
    required_label = "required.py"
    if mode == "full":
        optional_label = str(optional)
        required_label = str(required)
    assert scan(2) == {(required_label, 1, "SKY-D222")}

    optional.write_text("import shared_ghost\n", encoding="utf-8")
    assert scan(1) == {
        (optional_label, 1, "SKY-D222"),
        (required_label, 1, "SKY-D222"),
    }


@pytest.mark.parametrize("mode", ["full", "diff"])
def test_optional_root_proofs_do_not_repeat_whole_source_walks(
    tmp_path, monkeypatch, offline_registry, mode
):
    original_parse = ast.parse
    original_walk = ast.walk
    counts = []
    for import_count in (4, 24):
        root = tmp_path / f"optional_{import_count}"
        _write(root / "requirements.txt", "")
        lines = []
        for index in range(import_count):
            lines.extend(
                [
                    "try:",
                    f"    import optional_root_{index}",
                    "except ImportError:",
                    "    pass",
                ]
            )
        required_root = f"optional_root_{import_count - 1}"
        lines.append(f"{required_root}.run()")
        source = "\n".join(lines) + "\n"
        path = _write(root / "entry.py", source)
        operations = Counter()
        trees = set()

        def counted_parse(value, *args, **kwargs):
            tree = original_parse(value, *args, **kwargs)
            if value == source:
                operations["parse"] += 1
                trees.add(tree)
            return tree

        def counted_walk(tree):
            if tree in trees:
                operations["whole_tree_walk"] += 1
            return original_walk(tree)

        with monkeypatch.context() as instrumentation:
            instrumentation.setattr(ast, "parse", counted_parse)
            instrumentation.setattr(ast, "walk", counted_walk)
            if mode == "full":
                findings = dep.scan_python_dependency_hallucinations(root, [path])
                assert findings.unverified_imports == {}
            else:
                added = [
                    ("entry.py", 4 * index + 2, f"optional_root_{index}")
                    for index in range(import_count)
                ]
                findings, unreachable = dep.scan_diff_added_imports(root, added)
                assert unreachable is False

        assert [
            (finding["symbol"], finding["rule_id"], finding["line"])
            for finding in findings
        ] == [(required_root, "SKY-D222", 4 * (import_count - 1) + 2)]
        counts.append(operations)

    assert counts[1] == counts[0]
    assert counts[0]["parse"] <= 2
    assert counts[0]["whole_tree_walk"] <= 4
