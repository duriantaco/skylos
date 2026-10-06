from pathlib import Path

import pytest

from skylos.analyzer import Skylos
from skylos.visitors.base import Definition


def _mark(definitions, refs, type_map=None):
    analyzer = Skylos()
    analyzer.defs = definitions
    analyzer.refs = refs
    analyzer._global_type_map = type_map or {}
    analyzer._mark_refs()


@pytest.mark.parametrize(
    "definition_file,reference_file,reference",
    [
        ("library.php", "entry.ts", "amber"),
        ("library.cpp", "entry.js", "~.amber"),
        ("library.rs", "entry.py", "external.amber"),
        ("library.dart", "entry.java", "external.amber"),
        ("library.py", "entry.php", "library.amber"),
    ],
)
def test_unrelated_language_reference_does_not_rescue_function(
    definition_file, reference_file, reference
):
    name = "library.amber" if definition_file.endswith(".py") else "amber"
    definition = Definition(name, "function", Path(definition_file), 1)

    _mark({name: definition}, [(reference, Path(reference_file))])

    assert definition.references == 0


def test_dynamic_member_reference_stays_in_its_language_family():
    ts_method = Definition("Service.amber", "method", Path("service.ts"), 1)
    php_method = Definition("Worker.amber", "method", Path("worker.php"), 1)

    _mark(
        {ts_method.name: ts_method, php_method.name: php_method},
        [("~.amber", Path("entry.js"))],
    )

    assert ts_method.references > 0
    assert php_method.references == 0


def test_import_target_resolution_does_not_cross_unrelated_languages():
    imported = Definition("package.amber", "import", Path("entry.ts"), 1)
    php_function = Definition("package.amber", "function", Path("package.php"), 1)

    _mark(
        {"entry.ts:amber": imported, php_function.name: php_function},
        [("amber", Path("entry.ts"))],
    )

    assert imported.references == 1
    assert php_function.references == 0


def test_type_member_resolution_does_not_cross_unrelated_languages():
    member = Definition("package.Worker.amber", "method", Path("worker.php"), 1)

    _mark(
        {member.name: member},
        [("Alias.amber", Path("entry.js"))],
        {"Alias": "package.Worker"},
    )

    assert member.references == 0


@pytest.mark.parametrize("suffix", ["php", "dart", "rs", "ts", "java"])
def test_python_inferred_type_map_does_not_rewrite_foreign_owners(suffix):
    member = Definition("Worker.amber", "method", Path(f"worker.{suffix}"), 1)
    other = Definition("Other.amber", "method", Path(f"other.{suffix}"), 1)

    _mark(
        {member.name: member, other.name: other},
        [("Alias.amber", Path(f"entry.{suffix}"))],
        {"Alias": "Worker"},
    )

    assert member.references == 0
    assert other.references == 0


def test_python_inferred_type_map_still_resolves_python_members():
    member = Definition("Worker.amber", "method", Path("worker.py"), 1)

    _mark(
        {member.name: member},
        [("Alias.amber", Path("entry.py"))],
        {"Alias": "Worker"},
    )

    assert member.references == 1


def test_python_attribute_reads_do_not_rescue_foreign_functions():
    python_function = Definition("module.amber", "function", Path("module.py"), 1)
    php_function = Definition("amber", "function", Path("module.php"), 1)
    analyzer = Skylos()
    analyzer.defs = {
        python_function.name: python_function,
        php_function.name: php_function,
    }
    analyzer._all_used_attr_names = {"amber"}

    analyzer._mark_refs()

    assert python_function.references == 1
    assert php_function.references == 0


def test_python_attribute_context_does_not_add_foreign_liveness_evidence():
    php_function = Definition("module.amber", "function", Path("module.php"), 1)
    analyzer = Skylos()
    analyzer.defs = {php_function.name: php_function}
    analyzer._all_used_attr_context = {("amber", "module", None, 3)}

    analyzer._mark_refs()

    assert php_function.heuristic_refs == {}


@pytest.mark.parametrize(
    "definition_file,reference_file",
    [
        ("module.ts", "entry.js"),
        ("module.mjs", "entry.tsx"),
        ("module.py", "entry.pyw"),
        ("module.pyi", "entry.py"),
        ("Helper.kt", "Entry.java"),
        ("Helper.java", "Entry.kts"),
    ],
)
def test_references_within_supported_language_families_are_preserved(
    definition_file, reference_file
):
    definition = Definition("package.amber", "function", Path(definition_file), 1)

    _mark({definition.name: definition}, [(definition.name, Path(reference_file))])

    assert definition.references == 1


@pytest.mark.parametrize("suffix", ["php", "dart", "rs"])
def test_explicit_method_owner_does_not_fall_back_to_another_owner(suffix):
    member = Definition("Dormant.process", "method", Path(f"module.{suffix}"), 1)

    _mark({member.name: member}, [("Other.process", member.filename)])

    assert member.references == 0


def test_php_namespace_fallback_can_still_reach_a_global_free_function():
    function = Definition("amber", "function", Path("functions.php"), 1)

    _mark({function.name: function}, [("Demo.amber", Path("entry.php"))])

    assert function.references == 1


def test_entry_reachability_does_not_rescue_same_named_foreign_function():
    php_function = Definition("amber", "function", Path("entry.php"), 1)
    ts_function = Definition("amber", "function", Path("entry.ts"), 1)
    ts_function.references = 1
    analyzer = Skylos()
    analyzer.defs = {
        php_function.name: php_function,
        "entry.ts:amber": ts_function,
    }

    analyzer._apply_entry_reachability()

    assert php_function.references == 0
    assert ts_function.references == 1


def test_call_graph_reachability_does_not_cross_unrelated_languages():
    entry = Definition("entry.main", "function", Path("entry.php"), 1)
    entry.calls.add("amber")
    foreign = Definition("amber", "function", Path("module.rs"), 1)
    analyzer = Skylos()
    analyzer.defs = {entry.name: entry, foreign.name: foreign}

    analyzer._apply_entry_reachability({entry.name})

    assert foreign.references == 0
    assert "reachable_from_root" not in foreign.heuristic_refs


@pytest.mark.parametrize(
    "entry_file,helper_file",
    [("legacy", "helper.py"), ("entry.py", "legacy")],
)
def test_legacy_unknown_source_keeps_call_graph_compatibility(entry_file, helper_file):
    entry = Definition("entry.main", "function", Path(entry_file), 1)
    entry.calls.add("helper.amber")
    helper = Definition("helper.amber", "function", Path(helper_file), 1)
    analyzer = Skylos()
    analyzer.defs = {entry.name: entry, helper.name: helper}

    analyzer._apply_entry_reachability({entry.name})

    assert helper.references == 1
    assert "reachable_from_root" in helper.heuristic_refs


@pytest.mark.parametrize(
    "entry_file,helper_file", [("Entry.java", "Helper.kt"), ("Entry.kt", "Helper.java")]
)
def test_jvm_call_graph_reachability_preserves_interop(entry_file, helper_file):
    entry = Definition("entry.main", "function", Path(entry_file), 1)
    entry.calls.add("helper.amber")
    helper = Definition("helper.amber", "function", Path(helper_file), 1)
    analyzer = Skylos()
    analyzer.defs = {entry.name: entry, helper.name: helper}

    analyzer._apply_entry_reachability({entry.name})

    assert helper.references == 1
    assert "reachable_from_root" in helper.heuristic_refs
