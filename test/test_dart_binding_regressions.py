from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.dart import scan_dart_file

pytest.importorskip("tree_sitter_dart_orchard")


def _write(root: Path, files: dict[str, str]) -> None:
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def _unused(root: Path, files: dict[str, str], category: str) -> set[str]:
    _write(root, files)
    result = json.loads(analyze(str(root), conf=60, grep_verify=False))
    return {row["full_name"] for row in result.get(category, [])}


def test_dart_field_reads_and_writes_keep_exact_owner(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class Active { static int _count = 0; int read() => _count++; }
class Dormant { static int _count = 0; }
void main() { Active().read(); Dormant(); }
"""
        },
        "unused_variables",
    )
    assert "Active._count" not in unused
    assert "Dormant._count" in unused


def test_dart_type_only_reference_is_used(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class _Used {}
class _Spare {}
void accept(_Used? value) {}
void main() { accept(null); }
"""
        },
        "unused_classes",
    )
    assert "_Used" not in unused
    assert "_Spare" in unused


def test_dart_callback_tearoff_keeps_used_sibling_only(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
void _used(int value) {}
void _spare(int value) {}
void main() { [1].forEach(_used); }
"""
        },
        "unused_functions",
    )
    assert "_used" not in unused
    assert "_spare" in unused


def test_dart_method_tearoff_keeps_exact_owner(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class Active { void _used(int value) {} void run() { [1].forEach(_used); } }
class Dormant { void _used(int value) {} }
void main() { Active().run(); Dormant(); }
"""
        },
        "unused_functions",
    )
    assert "Active._used" not in unused
    assert "Dormant._used" in unused


def test_dart_local_shadow_does_not_read_top_level_callback(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
void _callback(int value) {}
void run(void Function(int) _callback) { [1].forEach(_callback); }
void main() { run((value) {}); }
"""
        },
        "unused_functions",
    )
    assert "_callback" in unused


def test_dart_named_and_ordinary_private_constructors(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class _Ordinary { _Ordinary(); }
class _Named { _Named.used(); _Named.spare(); }
void main() { _Ordinary(); _Named.used(); }
"""
        },
        "unused_functions",
    )
    assert "_Ordinary._Ordinary" not in unused
    assert "_Named.used" not in unused
    assert "_Named.spare" in unused


def test_dart_constructor_initializer_retains_called_helper(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
int _prepare() => 1;
int _spare() => 2;
class _Value { final int value; _Value() : value = _prepare(); }
void main() { _Value(); }
"""
        },
        "unused_functions",
    )
    assert "_prepare" not in unused
    assert "_spare" in unused


def test_dart_abstract_dispatch_references_only_real_subtypes(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
abstract class Base { void _work(); void run() { _work(); } }
class Active extends Base { void _work() {} }
class Dormant { void _work() {} }
void main() { Active().run(); Dormant(); }
"""
        },
        "unused_functions",
    )
    assert "Active._work" not in unused
    assert "Dormant._work" in unused


def test_dart_worker_binding_metadata_preserves_provider_details(tmp_path):
    _write(
        tmp_path,
        {
            "main.dart": """
import 'first.dart' if (dart.library.io) 'second.dart' as impl show Used hide Spare;
export 'api.dart' show Public;
part 'piece.dart';
void main() { impl.Used(); }
"""
        },
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    metadata = out[4].dart_bindings
    imported = metadata["imports"][0]
    assert imported["sources"] == ["first.dart", "second.dart"]
    assert imported["prefix"] == "impl"
    assert imported["show"] == ["Used"]
    assert imported["hide"] == ["Spare"]
    assert metadata["exports"][0]["show"] == ["Public"]
    assert metadata["parts"] == ["piece.dart"]


def test_dart_import_binding_uses_exported_symbol_not_filename(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": "import 'provider.dart'; import 'unused.dart';\nvoid main() { Provided(); }",
            "lib/provider.dart": "class Provided {}",
            "lib/unused.dart": "class Spare {}",
        },
        "unused_imports",
    )
    assert "provider" not in unused
    assert "unused" in unused


def test_dart_import_prefix_read_and_shadow(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": """
import 'provider.dart' as used;
import 'unused.dart' as unused;
void run(dynamic unused) { unused.work(); }
void main() { used.Provided(); run(Object()); }
""",
            "lib/provider.dart": "class Provided {}",
            "lib/unused.dart": "void work() {}",
        },
        "unused_imports",
    )
    assert "used" not in unused
    assert "unused" in unused


def test_dart_explicit_export_show_roots_only_selected_api(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/api.dart": "export 'provider.dart' show Public;",
            "lib/provider.dart": "class Public {}\nclass Unlisted {}",
        },
        "unused_classes",
    )
    assert "Public" not in unused
    assert "Unlisted" in unused


def test_dart_conditional_import_roots_each_possible_provider(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": "import 'memory.dart' if (dart.library.io) 'io.dart' as impl;\nvoid main() { impl.used(); }",
            "lib/memory.dart": "void used() {}\nvoid _spareMemory() {}",
            "lib/io.dart": "void used() {}\nvoid _spareIo() {}",
        },
        "unused_functions",
    )
    assert "used" not in unused
    assert {"_spareMemory", "_spareIo"} <= unused


def test_dart_parts_share_private_reads_without_rescuing_spare(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": "part 'piece.dart';\nvoid main() { [1].forEach(_used); }",
            "lib/piece.dart": "part of 'main.dart';\nvoid _used(int value) {}\nvoid _spare(int value) {}",
        },
        "unused_functions",
    )
    assert "_used" not in unused
    assert "_spare" in unused


def test_dart_sdk_import_binding_has_real_unused_control(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
import 'dart:math';
import 'dart:convert';
void main() { Random().nextInt(4); }
"""
        },
        "unused_imports",
    )
    assert "dart:math" not in unused
    assert "dart:convert" in unused


def test_dart_comments_and_strings_do_not_consume_an_import(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": "import 'provider.dart';\n// Provided()\nvoid main() { print('Provided'); }",
            "lib/provider.dart": "class Provided {}",
        },
        "unused_imports",
    )
    assert "provider" in unused


def test_dart_prefixed_show_keeps_unused_selected_binding_reported(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": "import 'provider.dart' as impl show Used, Spare;\nvoid main() { impl.Used(); }",
            "lib/provider.dart": "class Used {}\nclass Spare {}",
        },
        "unused_imports",
    )
    assert "Used" not in unused
    assert "Spare" in unused


def test_dart_private_callback_does_not_escape_its_library(tmp_path):
    _write(
        tmp_path,
        {
            "a.dart": "void _callback(int value) {}\nvoid main() { [1].forEach(_callback); }",
            "b.dart": "void _callback(int value) {}",
        },
    )
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    sites = {
        (Path(row["file"]).name, row["full_name"])
        for row in result.get("unused_functions", [])
    }
    assert ("a.dart", "_callback") not in sites
    assert ("b.dart", "_callback") in sites


def test_dart_prefixed_call_does_not_use_unrelated_local_free_function(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/main.dart": "import 'provider.dart' as impl;\nvoid work() {}\nvoid main() { impl.work(); }",
            "lib/provider.dart": "void work() {}",
        },
        "unused_functions",
    )
    assert "work" in unused


def test_dart_local_callback_call_does_not_use_global_same_name(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
void _callback() {}
void run(void Function() _callback) { _callback(); }
void main() { run(() {}); }
"""
        },
        "unused_functions",
    )
    assert "_callback" in unused


def test_dart_missing_external_namespace_is_uncertain_without_reference_credit(
    tmp_path,
):
    from skylos.visitors.languages.dart.bindings import apply_dart_project_bindings

    _write(
        tmp_path,
        {
            "main.dart": "import 'package:missing/api.dart';\nvoid main() { External(); }"
        },
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    definitions = {definition.name: definition for definition in out[0]}
    apply_dart_project_bindings(
        definitions, {str(tmp_path / "main.dart"): out[4].dart_bindings}, tmp_path
    )
    imported = definitions["api"]
    assert imported.references == 0
    assert any(
        "namespace unresolved" in reason for reason in imported.why_confidence_reduced
    )


def test_dart_package_name_resolution_uses_nearest_pubspec(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "pubspec.yaml": "name: demo\n",
            "lib/main.dart": "import 'package:demo/provider.dart';\nvoid main() { Provided(); }",
            "lib/provider.dart": "class Provided {}",
        },
        "unused_imports",
    )
    assert "provider" not in unused


def test_dart_string_interpolation_reads_real_values_not_literal_words(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
final _used = 1;
final _spare = 2;
void main() { print('$_used _spare'); }
"""
        },
        "unused_variables",
    )
    assert "_used" not in unused
    assert "_spare" in unused


def test_dart_partial_sdk_namespace_does_not_claim_an_unlisted_name_unused(tmp_path):
    from skylos.visitors.languages.dart.bindings import apply_dart_project_bindings

    _write(
        tmp_path,
        {"main.dart": "import 'dart:math';\nvoid main() { FutureSdkAddition(); }"},
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    definitions = {definition.name: definition for definition in out[0]}
    apply_dart_project_bindings(
        definitions, {str(tmp_path / "main.dart"): out[4].dart_bindings}, tmp_path
    )
    assert definitions["dart:math"].references == 0
    assert any(
        "namespace unresolved" in reason
        for reason in definitions["dart:math"].why_confidence_reduced
    )


@pytest.mark.parametrize("name", ["Pragma", "CastError", "toString"])
def test_dart_core_namespace_does_not_hide_provider_owned_names(tmp_path, name):
    declaration = f"class {name} {{}}" if name[0].isupper() else f"void {name}() {{}}"
    unused = _unused(
        tmp_path,
        {
            "main.dart": f"import 'provider.dart';\nvoid main() {{ {name}(); }}",
            "provider.dart": declaration,
        },
        "unused_imports",
    )
    assert "provider" not in unused


def test_dart_possible_external_extension_call_abstains_without_reference_credit(
    tmp_path,
):
    from skylos.visitors.languages.dart.bindings import apply_dart_project_bindings

    _write(
        tmp_path,
        {
            "main.dart": """
import 'package:missing/extensions.dart';
void run(Iterable<int> values) { values.sorted(); }
void main() { run([1]); }
"""
        },
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    definitions = {definition.name: definition for definition in out[0]}
    apply_dart_project_bindings(
        definitions, {str(tmp_path / "main.dart"): out[4].dart_bindings}, tmp_path
    )
    imported = definitions["extensions"]
    assert imported.references == 0
    assert any(
        "possible extension call" in reason
        for reason in imported.why_confidence_reduced
    )


def test_dart_possible_external_extension_keeps_resolved_unused_import_reported(
    tmp_path,
):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
import 'package:missing/extensions.dart';
import 'spare.dart';
void run(Iterable<int> values) { values.sorted(); }
void main() { run([1]); }
""",
            "spare.dart": "class Spare {}",
        },
        "unused_imports",
    )
    assert "extensions" not in unused
    assert "spare" in unused


def test_dart_known_own_and_core_calls_do_not_make_missing_import_uncertain(tmp_path):
    from skylos.visitors.languages.dart.bindings import apply_dart_project_bindings

    _write(
        tmp_path,
        {
            "main.dart": """
import 'package:missing/extensions.dart';
class Active { void work() {} }
void run(Active active, String text, List<int> values) {
  active.work();
  text.trim();
  values.forEach(print);
  active.toString();
}
void main() { run(Active(), '', [1]); }
"""
        },
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    definitions = {definition.name: definition for definition in out[0]}
    apply_dart_project_bindings(
        definitions, {str(tmp_path / "main.dart"): out[4].dart_bindings}, tmp_path
    )
    imported = definitions["extensions"]
    assert imported.references == 0
    assert not imported.why_confidence_reduced


def test_dart_extension_call_on_core_type_does_not_use_unrelated_method(tmp_path):
    from skylos.visitors.languages.dart.bindings import apply_dart_project_bindings

    _write(
        tmp_path,
        {
            "main.dart": """
import 'package:missing/extensions.dart';
class _Dormant { void sorted() {} }
void run(Iterable<int> values) { values.sorted(); }
void main() { run([1]); _Dormant(); }
"""
        },
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    definitions = {definition.name: definition for definition in out[0]}
    report = apply_dart_project_bindings(
        definitions, {str(tmp_path / "main.dart"): out[4].dart_bindings}, tmp_path
    )
    assert definitions["_Dormant.sorted"].references == 0
    assert "_Dormant.sorted" not in report["call_graph"]["run"]


def test_dart_test_only_barrel_roots_consumed_provider_symbols_only(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/provider.dart": "void used() {}\nvoid spare() {}",
            "test/support.dart": "export '../lib/provider.dart';",
            "test/use_test.dart": "import 'support.dart';\nvoid main() { used(); }",
        },
        "unused_functions",
    )
    assert "used" not in unused
    assert "spare" in unused


def test_dart_multiline_show_export_preserves_selected_public_contract(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/api.dart": """
export 'provider.dart'
    show
        first,
        // Kept public for downstream callers.
        second;
""",
            "lib/provider.dart": "void first() {}\nvoid second() {}\nvoid spare() {}",
        },
        "unused_functions",
    )
    assert not {"first", "second"} & unused
    assert "spare" in unused


def test_dart_mixin_members_have_owner_and_dispatch_identity(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
mixin _Shared { void _used() {} void _spare() {} }
class Active with _Shared {}
class Dormant { void _used() {} }
void run(Active value) { value._used(); }
void main() { run(Active()); Dormant(); }
"""
        },
        "unused_functions",
    )
    assert "_Shared._used" not in unused
    assert {"_Shared._spare", "Dormant._used"} <= unused


def test_dart_extension_members_bind_receiver_without_using_other_extensions(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class Box {}
class Other {}
extension Ops on Box { void used() {} void spare() {} }
extension OtherOps on Other { void used() {} void anchor() {} }
void run(Box value) { value.used(); }
void runOther(Other value) { value.anchor(); }
void main() { run(Box()); runOther(Other()); }
"""
        },
        "unused_functions",
    )
    assert "Ops.used" not in unused
    assert {"Ops.spare", "OtherOps.used"} <= unused


def test_dart_nullable_field_receiver_selects_exact_method_owner(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class Active { void _used<T>() {} void _spare() {} }
class Dormant { void _used<T>() {} }
Active? _active;
void run() { _active!._used<int>(); }
void main() { _active = Active(); run(); Dormant(); }
"""
        },
        "unused_functions",
    )
    assert "Active._used" not in unused
    assert {"Active._spare", "Dormant._used"} <= unused


def test_dart_typed_collection_loop_receiver_selects_exact_method_owner(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "main.dart": """
class Active { void _used() {} void _spare() {} }
class Dormant { void _used() {} }
void run() {
  final values = List<Active>.from([Active()]);
  for (final value in values) { value._used(); }
}
void main() { run(); Dormant(); }
"""
        },
        "unused_functions",
    )
    assert "Active._used" not in unused
    assert {"Active._spare", "Dormant._used"} <= unused


def test_dart_global_receiver_type_does_not_cross_declaration_boundary(tmp_path):
    _write(
        tmp_path,
        {
            "main.dart": """
class Active { void _used() {} }
class Other { void _used() {} }
Active? first;
var second = Other();
void main() { second._used(); }
"""
        },
    )
    out = scan_dart_file(str(tmp_path / "main.dart"), {})
    call = next(
        use for use in out[4].dart_bindings["uses"] if use.get("member") == "_used"
    )
    assert call["receiver_type"] != "Active"
    assert call["target"] != "Active._used"


def test_dart_imported_extension_dispatch_credits_owner_and_import(tmp_path):
    from skylos.visitors.languages.dart.bindings import apply_dart_project_bindings

    _write(
        tmp_path,
        {
            "lib/extensions.dart": """
extension Shared on Object { void used() {} void spare() {} }
extension NumberOps on int { void used() {} }
extension _PrivateOps on Object { void never() {} }
""",
            "test/use_test.dart": "import '../lib/extensions.dart';\nvoid main() { 'text'.used(); }",
        },
    )
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    assert "extensions" not in {
        f["full_name"] for f in result.get("unused_imports", [])
    }
    assert "Shared" not in {f["full_name"] for f in result.get("unused_classes", [])}
    unused = {f["full_name"] for f in result.get("unused_functions", [])}
    assert "Shared.used" not in unused
    assert {"Shared.spare", "NumberOps.used", "_PrivateOps.never"} <= unused
    provider = scan_dart_file(str(tmp_path / "lib/extensions.dart"), {})
    consumer = scan_dart_file(str(tmp_path / "test/use_test.dart"), {})
    definitions = {
        f"{d.filename}:{d.name}": d for out in (provider, consumer) for d in out[0]
    }
    apply_dart_project_bindings(
        definitions,
        {
            str(tmp_path / "lib/extensions.dart"): provider[4].dart_bindings,
            str(tmp_path / "test/use_test.dart"): consumer[4].dart_bindings,
        },
        tmp_path,
    )
    owned = {d.name: d for d in provider[0]}
    assert owned["Shared"].type == "extension"
    assert owned["Shared"].references > 0
    assert owned["Shared.used"].references > 0
    assert owned["NumberOps.used"].references == 0
    assert consumer[0][0].references > 0


def test_dart_dynamic_receiver_does_not_prove_imported_extension_dispatch(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/extensions.dart": "extension Shared on Object { void used() {} }",
            "main.dart": "import 'lib/extensions.dart';\nvoid run(dynamic value) { value.used(); }\nvoid main() { run(Object()); }",
        },
        "unused_imports",
    )
    assert "extensions" in unused


def test_dart_native_member_takes_precedence_over_imported_extension(tmp_path):
    unused = _unused(
        tmp_path,
        {
            "lib/extensions.dart": "extension Shared on String { String trim() => 'changed'; }",
            "main.dart": "import 'lib/extensions.dart';\nvoid run(String value) { value.trim(); }\nvoid main() { run(' text '); }",
        },
        "unused_imports",
    )
    assert "extensions" in unused


def test_dart_imported_extension_dispatch_respects_show_namespace(tmp_path):
    _write(
        tmp_path,
        {
            "lib/extensions.dart": """
extension Shared on String { void used() {} }
extension Hidden on String { void used() {} }
""",
            "main.dart": "import 'lib/extensions.dart' show Shared;\nvoid main() { 'text'.used(); }",
        },
    )
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    assert "Shared" not in {f["full_name"] for f in result.get("unused_imports", [])}
    unused = {f["full_name"] for f in result.get("unused_functions", [])}
    assert "Shared.used" not in unused
    assert "Hidden.used" in unused
