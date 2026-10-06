from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze, proc_file
from skylos.visitors.languages.dart import scan_dart_file


def _scan_dart(tmp_path: Path, code: str, filename: str = "lib/main.dart") -> tuple:
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_dart_file(str(file_path), {})


def test_dart_scanner_collects_defs_refs_and_raw_imports(tmp_path):
    defs, refs, _, _, visitor, _, quality, danger, _, _, _, _, raw_imports = _scan_dart(
        tmp_path,
        """
import 'package:flutter/material.dart';
import 'src/user.dart' show User;
export 'src/api.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  @override
  void initState() { super.initState(); }

  @override
  Widget build(BuildContext context) { return Text('hi'); }

  void _unusedHelper() {}
}

enum Role { admin, user }

void main() { runApp(HomePage()); }
void used() { _helper(); }
void _helper() {}
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}
    exported = {d.name for d in defs if d.is_exported}

    assert "material" in def_names
    assert "User" in def_names
    assert "HomePage" in def_names
    assert "HomePage.HomePage" in def_names
    assert "HomePage.createState" in def_names
    assert "_HomePageState" in def_names
    assert "_HomePageState.initState" in def_names
    assert "_HomePageState.build" in def_names
    assert "_HomePageState._unusedHelper" in def_names
    assert "Role" in def_names
    assert "Role.admin" in def_names
    assert "main" in def_names
    assert "_helper" in def_names

    assert "runApp" in ref_names
    assert "HomePage" in ref_names
    assert "_HomePageState" in ref_names
    assert "_helper" in ref_names

    assert "HomePage" in exported
    assert "HomePage.createState" in exported
    assert "_HomePageState.initState" in exported
    assert "_HomePageState.build" in exported
    assert "_HomePageState._unusedHelper" not in exported
    assert "main" in exported

    assert visitor.is_test_file is False
    assert quality == []
    assert danger == []
    assert raw_imports == [
        {
            "source": "package:flutter/material.dart",
            "names": ["material"],
            "line": 2,
        },
        {"source": "src/user.dart", "names": ["User"], "line": 3},
        {"source": "src/api.dart", "names": [], "line": 4},
    ]


def test_dart_test_file_marks_main_as_test_related(tmp_path):
    defs, _, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_dart(
        tmp_path,
        """
import 'package:test/test.dart';

void main() {
  test('works', () {});
}
""",
        filename="test/user_test.dart",
    )

    main_def = next(d for d in defs if d.name == "main")

    assert main_def.is_exported is True
    assert visitor.is_test_file is True
    assert visitor.test_decorated_lines


def test_dart_scanner_records_unqualified_and_qualified_calls(tmp_path):
    _, refs, *_ = _scan_dart(
        tmp_path,
        """
void helper() {}

void main() {
  helper();
  Service.run();
}
""",
    )

    ref_names = {ref[0] for ref in refs}

    assert {"helper", "run"} <= ref_names


def test_proc_file_dispatches_dart_to_dart_scanner(tmp_path):
    file_path = tmp_path / "main.dart"
    file_path.write_text("void main() {}\n", encoding="utf-8")

    out = proc_file(str(file_path))
    defs = out[0]

    assert any(defn.name == "main" for defn in defs)


def test_analyze_dart_reports_language_summary_and_dead_code(tmp_path):
    file_path = tmp_path / "main.dart"
    file_path.write_text(
        """
void main() { used(); }
void used() {}
void _unusedPrivate() {}
""",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {item["full_name"] for item in result["unused_functions"]}

    assert result["analysis_summary"]["languages"] == {"Dart": 1}
    assert "_unusedPrivate" in unused
    assert "used" not in unused


@pytest.mark.parametrize("active_first", [False, True])
@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    ("run_body", "entry_body", "extra", "caller"),
    [
        ("_process();", "Active().run();", "", "Active.run"),
        ("this._process();", "Active().run();", "", "Active.run"),
        ("", "Active()._process();", "", "main"),
        ("", "final active = Active(); active._process();", "", "main"),
        ("", "Active active = Active(); active._process();", "", "main"),
        (
            "",
            "dispatch(Active());",
            "void dispatch(Active active) { active._process(); }",
            "dispatch",
        ),
    ],
)
def test_dart_calls_keep_method_owner_independent_of_declaration_order(
    tmp_path, active_first, grep_verify, run_body, entry_body, extra, caller
):
    active = f"class Active {{ void _process() {{}} void run() {{ {run_body} }} }}"
    dormant = "class Dormant { void _process() {} }"
    classes = [active, dormant] if active_first else [dormant, active]
    code = "\n".join(classes) + f"\n{extra}\nvoid main() {{ Dormant(); {entry_body} }}"
    defs, *_ = _scan_dart(tmp_path, code)
    symbols = {d.name: d for d in defs}

    assert "Active._process" in symbols[caller].calls
    assert "Dormant._process" not in symbols[caller].calls
    assert symbols["Active._process"].called_by == {caller}
    assert not symbols["Dormant._process"].called_by

    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=grep_verify))
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert "Dormant._process" in unused
    assert "Active._process" not in unused


@pytest.mark.parametrize("active_first", [False, True])
def test_dart_unknown_receiver_keeps_all_possible_methods(tmp_path, active_first):
    classes = [
        "class Active { void _process() {} }",
        "class Dormant { void _process() {} }",
    ]
    if not active_first:
        classes.reverse()
    defs, *_ = _scan_dart(
        tmp_path,
        "\n".join(classes)
        + "\nvoid dispatch(dynamic value) { value._process(); }"
        + "\nvoid main() { Active(); Dormant(); dispatch(Active()); }",
    )
    symbols = {d.name: d for d in defs}
    assert symbols["dispatch"].calls == {"Active._process", "Dormant._process"}
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert not {"Active._process", "Dormant._process"} & unused


@pytest.mark.parametrize("receiver", ["this", "super"])
def test_dart_known_inherited_receiver_uses_base_owner(tmp_path, receiver):
    defs, *_ = _scan_dart(
        tmp_path,
        "class Dormant { void _process() {} }\n"
        "class Base { void _process() {} }\n"
        f"class Active extends Base {{ void run() {{ {receiver}._process(); }} }}\n"
        "void main() { Dormant(); Active().run(); }",
    )
    symbols = {d.name: d for d in defs}
    assert symbols["Active.run"].calls == {"Base._process"}
    assert not symbols["Dormant._process"].called_by
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert "Dormant._process" in unused
    assert "Base._process" not in unused


def test_dart_explicit_missing_member_does_not_rescue_another_owner(tmp_path):
    # A partially available project must not attach an unresolved qualified
    # member to the first unrelated class with the same member name.
    defs, refs, *_ = _scan_dart(
        tmp_path,
        "class Dormant { void _process() {} }\n"
        "class Other {}\n"
        "void main() { Dormant(); Other()._process(); }",
    )
    symbols = {d.name: d for d in defs}
    assert "Other._process" in {name for name, _ in refs}
    assert not symbols["Dormant._process"].called_by
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert "Dormant._process" in unused


def test_dart_inner_unknown_binding_does_not_use_outer_receiver_type(tmp_path):
    defs, *_ = _scan_dart(
        tmp_path,
        "class Dormant { void _process() {} }\n"
        "class Active { void _process() {} }\n"
        "void dispatch(dynamic value) {\n"
        "  final active = Active();\n"
        "  { final active = value; active._process(); }\n"
        "}\n"
        "void main() { Dormant(); dispatch(Active()); }",
    )
    symbols = {d.name: d for d in defs}
    assert {"Active._process", "Dormant._process"} <= symbols["dispatch"].calls


def test_dart_same_named_method_on_another_owner_is_not_self_recursion(tmp_path):
    defs, *_ = _scan_dart(
        tmp_path,
        "class Other { void _process() {} }\n"
        "class Active { void _process() { Other()._process(); } }\n"
        "void main() { Active()._process(); }",
    )
    symbols = {d.name: d for d in defs}
    assert symbols["Active._process"].calls == {"Other._process", "Other"}
    assert symbols["Other._process"].called_by == {"Active._process"}


def test_dart_typed_receiver_keeps_possible_subclass_override(tmp_path):
    defs, *_ = _scan_dart(
        tmp_path,
        "class Dormant { void _process() {} }\n"
        "class Base { void _process() {} }\n"
        "class Active extends Base { void _process() {} }\n"
        "void dispatch(Base value) { value._process(); }\n"
        "void main() { Dormant(); dispatch(Active()); }",
    )
    symbols = {d.name: d for d in defs}
    assert symbols["dispatch"].calls == {"Base._process", "Active._process"}
    assert not symbols["Dormant._process"].called_by


def test_dart_unknown_member_call_does_not_choose_same_named_top_level_function(
    tmp_path,
):
    defs, *_ = _scan_dart(
        tmp_path,
        "void _process() {}\n"
        "class Active { void _process() {} }\n"
        "class Dormant { void _process() {} }\n"
        "void dispatch(dynamic value) { value._process(); }\n"
        "void main() { Active(); Dormant(); dispatch(Active()); }",
    )
    symbols = {d.name: d for d in defs}
    assert {"Active._process", "Dormant._process"} <= symbols["dispatch"].calls


def test_dart_unqualified_imported_constructor_keeps_bare_reference(tmp_path):
    _, refs, *_ = _scan_dart(
        tmp_path,
        "import 'data.dart';\n"
        "class Loader { void run() { ArtifactData(); } }\n"
        "void main() { Loader().run(); }",
    )
    names = {name for name, _ in refs}
    assert "ArtifactData" in names
    assert "Loader.ArtifactData" not in names


def test_dart_imported_constructor_in_field_initializer_is_not_a_local_method(
    tmp_path,
):
    _, refs, *_ = _scan_dart(
        tmp_path,
        "import 'styles.dart';\n"
        "class Scaffold {\n"
        "  static AppStyle _style = AppStyle();\n"
        "  void update() { _style = AppStyle(); }\n"
        "}\n"
        "void main() { Scaffold().update(); }",
    )
    names = {name for name, _ in refs}
    assert "AppStyle" in names
    assert "Scaffold.AppStyle" not in names


def test_dart_static_method_call_references_its_class(tmp_path):
    _, refs, *_ = _scan_dart(
        tmp_path,
        "class Active { static void _process() {} }\n"
        "void main() { Active._process(); }",
    )
    assert {"Active", "Active._process"} <= {name for name, _ in refs}
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    assert "Active" not in {
        item["full_name"] for item in result.get("unused_classes", [])
    }


def test_dart_constructor_call_inside_class_still_references_type(tmp_path):
    _, refs, *_ = _scan_dart(
        tmp_path,
        "class Active { Active(); Active create() { return Active(); } }\n"
        "void main() { Active().create(); }",
    )
    assert "Active" in {name for name, _ in refs}
    assert "Active.Active" in {name for name, _ in refs}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("entry", ["Active()._process();", "dispatch(Active());"])
def test_dart_redirecting_factory_keeps_concrete_private_implementation(
    tmp_path, grep_verify, entry
):
    defs, *_ = _scan_dart(
        tmp_path,
        "abstract class Active { factory Active() = Concrete; void _process(); }\n"
        "class Concrete implements Active {\n"
        "  void _process() {}\n"
        "  void _orphan() {}\n"
        "}\n"
        "void dispatch(Active value) { value._process(); }\n"
        f"void main() {{ Concrete(); {entry} }}",
    )
    symbols = {d.name: d for d in defs}
    caller = "main" if entry.startswith("Active") else "dispatch"
    assert "Concrete._process" in symbols[caller].calls
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=grep_verify))
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert "Concrete._process" not in unused
    assert "Concrete._orphan" in unused
