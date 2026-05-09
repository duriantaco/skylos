from __future__ import annotations

import json
from pathlib import Path

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
