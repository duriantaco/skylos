from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.visitors.languages.php import scan_php_file


def _extension(tmp_path, name="demo", yaml=None):
    root = tmp_path / name
    root.mkdir()
    (root / f"{name}.info.yml").write_text(
        f"name: {name}\ntype: module\n", encoding="utf-8"
    )  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    for file_name, text in (yaml or {}).items():
        (root / file_name).write_text(
            text, encoding="utf-8"
        )  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    return root


def _roots(root: Path, relative: str, code: str) -> tuple[set[str], object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        code, encoding="utf-8"
    )  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    defs, _, _, _, _, framework, *_ = scan_php_file(str(path), {})
    lines = framework.framework_decorated_lines
    return {d.simple_name for d in defs if d.line in lines}, framework


def _class(namespace: str, name: str, before: str = "", body: str = "") -> str:
    return f"""<?php
namespace {namespace};

{before}
class {name} {{
    public function run(): void {{ $this->helper(); }}
    private function helper(): void {{}}
    {body}
}}
"""


def test_classes_named_in_extension_yaml_are_roots(tmp_path):
    root = _extension(
        tmp_path,
        yaml={
            "demo.services.yml": "services:\n  demo.thing:\n    class: Drupal\\demo\\Thing\n"
            "  Drupal\\demo\\Autowired: ~\n",
            "demo.routing.yml": "demo.page:\n  path: /demo\n  defaults:\n"
            "    _controller: '\\Drupal\\demo\\Controller\\Page::view'\n"
            '    _form: "Drupal\\\\demo\\\\Form\\\\Settings"\n',
        },
    )
    roots, framework = _roots(root, "src/Thing.php", _class("Drupal\\demo", "Thing"))
    assert roots == {"Thing", "run"}
    assert "drupal" in framework.detected_frameworks
    assert _roots(root, "src/Autowired.php", _class("Drupal\\demo", "Autowired"))[
        0
    ] == {"Autowired", "run"}
    assert _roots(
        root, "src/Form/Settings.php", _class("Drupal\\demo\\Form", "Settings")
    )[0] == {"Settings", "run"}

    # A route names a method: it is a root even when it is not public.
    page = _class(
        "Drupal\\demo\\Controller", "Page", body="protected function view() {}"
    )
    assert _roots(root, "src/Controller/Page.php", page)[0] == {"Page", "run", "view"}


def test_unreferenced_classes_stay_dead(tmp_path):
    root = _extension(
        tmp_path,
        yaml={
            "demo.services.yml": "services:\n  demo.thing:\n    class: Drupal\\demo\\Thing\n"
        },
    )
    roots, framework = _roots(root, "src/Orphan.php", _class("Drupal\\demo", "Orphan"))
    assert roots == set()
    assert "drupal" not in framework.detected_frameworks
    # Same name outside an extension: Drupal rules do not apply.
    (tmp_path / "plain").mkdir()
    assert (
        _roots(tmp_path / "plain", "Thing.php", _class("Drupal\\demo", "Thing"))[0]
        == set()
    )


def test_discovered_plugins_need_their_attribute_or_annotation(tmp_path):
    root = _extension(tmp_path)
    relative = "src/Plugin/Block/Hello.php"
    attribute = _class(
        "Drupal\\demo\\Plugin\\Block", "Hello", before="#[Block(id: 'hello')]"
    )
    assert _roots(root, relative, attribute)[0] == {"Hello", "run"}
    annotation = _class(
        "Drupal\\demo\\Plugin\\Block",
        "Hello",
        before='/**\n * @Block(\n *   id = "hello"\n * )\n */',
    )
    assert _roots(root, relative, annotation)[0] == {"Hello", "run"}
    plain = _class(
        "Drupal\\demo\\Plugin\\Block",
        "Hello",
        before="/**\n * A helper, not a plugin.\n */",
    )
    assert _roots(root, relative, plain)[0] == set()
    # An attribute outside the discovery directories is not a plugin.
    assert _roots(root, "src/Hello.php", attribute)[0] == set()


def test_oop_hooks_are_roots(tmp_path):
    root = _extension(tmp_path)
    code = """<?php
namespace Drupal\\demo\\Hook;

use Drupal\\Core\\Hook\\Attribute\\Hook;

class DemoHooks {
    #[Hook('form_alter')]
    public function formAlter(): void { $this->helper(); }
    public function notAHook(): void {}
    private function helper(): void {}
}
"""
    assert _roots(root, "src/Hook/DemoHooks.php", code)[0] == {
        "DemoHooks",
        "formAlter",
        "notAHook",
    }


def test_files_whose_functions_drupal_calls_by_name(tmp_path):
    root = _extension(tmp_path)
    code = "<?php\nfunction demo_post_update_fix(): void {}\nfunction demo_helper(): void {}\n"
    for relative in ("demo.api.php", "demo.post_update.php", "demo.deploy.php"):
        assert _roots(root, relative, code)[0] == {
            "demo_post_update_fix",
            "demo_helper",
        }, relative
    assert _roots(root, "src/functions.php", code)[0] == set()


def test_procedural_hooks_are_roots(tmp_path):
    root = _extension(tmp_path)
    code = (
        "<?php\nfunction demo_form_alter(&$form): void {}\n"
        "function template_preprocess_demo_card(&$variables): void {}\n"
        "function _demo_helper(): void {}\nfunction other_thing(): void {}\n"
    )
    for relative in (
        "demo.module",
        "demo.install",
        "demo.theme",
        "demo.profile",
        "includes/demo.pages.inc",
    ):
        assert _roots(root, relative, code)[0] == {
            "demo_form_alter",
            "template_preprocess_demo_card",
        }, relative


def test_procedural_files_are_scanned(tmp_path):
    root = _extension(tmp_path)
    (root / "src").mkdir()
    (root / "src" / "Helper.php").write_text(
        "<?php\nnamespace Drupal\\demo;\nclass Helper {\n"
        "    public static function build(): array { return []; }\n}\n",
        encoding="utf-8",
    )  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    (root / "demo.module").write_text(
        "<?php\nuse Drupal\\demo\\Helper;\n"
        "function demo_page_attachments(array &$page): void {\n"
        "    $page[] = Helper::build();\n}\n"
        "function _demo_unused(): void {}\n",
        encoding="utf-8",
    )  # skylos: ignore[SKY-D324] pytest tmp_path fixture

    result = json.loads(analyze(str(tmp_path), grep_cache=False))

    assert "Drupal.demo.Helper" not in {d["name"] for d in result["unused_classes"]}
    assert {d["name"] for d in result["unused_functions"]} == {"_demo_unused"}


def test_convention_classes(tmp_path):
    root = _extension(tmp_path, name="search_api")
    provider = _class("Drupal\\search_api", "SearchApiServiceProvider")
    assert _roots(root, "src/SearchApiServiceProvider.php", provider)[0] == {
        "SearchApiServiceProvider",
        "run",
    }
    other = _class("Drupal\\search_api", "OtherServiceProvider")
    assert _roots(root, "src/OtherServiceProvider.php", other)[0] == set()

    proxy = _class("Drupal\\search_api\\ProxyClass", "Converter")
    assert _roots(root, "src/ProxyClass/Converter.php", proxy)[0] == {
        "Converter",
        "run",
    }
    requirements = _class("Drupal\\search_api\\Install\\Requirements", "Checks")
    assert _roots(root, "src/Install/Requirements/Checks.php", requirements)[0] == {
        "Checks",
        "run",
    }

    directory = "src/Plugin/Validation/Constraint"
    (root / directory).mkdir(parents=True)
    (root / directory / "Unique.php").write_text(
        "<?php\n", encoding="utf-8"
    )  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    validator = _class(
        "Drupal\\search_api\\Plugin\\Validation\\Constraint", "UniqueValidator"
    )
    assert _roots(root, f"{directory}/UniqueValidator.php", validator)[0] == {
        "UniqueValidator",
        "run",
    }
    lonely = _class(
        "Drupal\\search_api\\Plugin\\Validation\\Constraint", "LonelyValidator"
    )
    assert _roots(root, f"{directory}/LonelyValidator.php", lonely)[0] == set()
