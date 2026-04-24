from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.php import scan_php_file


def _scan_php(tmp_path: Path, code: str, filename: str = "App.php") -> tuple:
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_php_file(str(file_path), {})


def test_php_scanner_collects_defs_refs_and_raw_imports(tmp_path):
    defs, refs, _, _, visitor, _, quality, danger, _, _, _, _, raw_imports = _scan_php(
        tmp_path,
        """<?php
namespace App\\Http;

use Foo\\Bar;
use Foo\\Baz as Quux;

class UserController {
    private string $name;
    public function __construct(private Repo $repo) {}
    private function helper($x) { return $this->name; }
    public function show() { return self::fmt($this->helper($_GET['id'])); }
    private static function fmt($x) { return trim($x); }
}

function topLevel($x) { return trim($x); }

require 'bootstrap.php';
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}
    exported = {d.name for d in defs if d.is_exported}

    assert "App.Http.UserController" in def_names
    assert "App.Http.UserController.helper" in def_names
    assert "App.Http.UserController.fmt" in def_names
    assert "App.Http.UserController.name" in def_names
    assert "App.Http.UserController.repo" in def_names
    assert "App.Http.topLevel" in def_names
    assert "Bar" in def_names
    assert "Quux" in def_names

    assert "helper" in ref_names
    assert "fmt" in ref_names
    assert "name" in ref_names
    assert "trim" in ref_names

    assert "App.Http.UserController.__construct" in exported
    assert "App.Http.UserController.show" in exported
    assert "App.Http.UserController.helper" not in exported

    assert visitor.is_test_file is False
    assert quality == []
    assert danger == []
    assert raw_imports == [
        {"source": "use", "names": ["Bar"], "line": 4},
        {"source": "use", "names": ["Quux"], "line": 5},
        {"source": "bootstrap.php", "names": [], "line": 17},
    ]


def test_php_private_property_and_static_method_references_are_recorded(tmp_path):
    defs, refs, *_ = _scan_php(
        tmp_path,
        """<?php
class Demo {
    private string $name;
    public function run() {
        return self::fmt($this->name);
    }
    private static function fmt($x) { return trim($x); }
}
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "Demo.name" in def_names
    assert "Demo.fmt" in def_names
    assert "name" in ref_names
    assert "fmt" in ref_names


def test_php_test_file_marks_phpunit_style_methods_as_test_related(tmp_path):
    defs, _, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_php(
        tmp_path,
        """<?php
class UserTest extends TestCase {
    public function setUp(): void {}
    public function test_it_works(): void {}
}
""",
        filename="tests/UserTest.php",
    )

    def_names = {d.name for d in defs}
    exported = {d.name for d in defs if d.is_exported}

    assert "UserTest.setUp" in def_names
    assert "UserTest.test_it_works" in def_names
    assert "UserTest.setUp" in exported
    assert "UserTest.test_it_works" in exported
    assert visitor.is_test_file is True
    assert visitor.test_decorated_lines
