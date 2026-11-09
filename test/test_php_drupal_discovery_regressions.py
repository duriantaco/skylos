from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.php import scan_php_file
from skylos.visitors.languages.php.core import PhpCore
from skylos.visitors.languages.php.drupal import _MAX_YAML_BYTES


def _extension(tmp_path: Path) -> Path:
    root = tmp_path / "demo"
    root.mkdir()
    (root / "demo.info.yml").write_text("name: Demo\ntype: module\n")
    return root


def _write(root: Path, relative: str, code: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    return path


def _roots(path: Path) -> set[str]:
    core = PhpCore(str(path), path.read_bytes())
    assert core.root_node is not None
    assert not core.root_node.has_error
    definitions, _, _, _, _, framework, *_ = scan_php_file(str(path), {})
    assert definitions
    return {
        definition.simple_name
        for definition in definitions
        if definition.line in framework.framework_decorated_lines
    }


@pytest.mark.parametrize(
    "yaml_text,expected",
    [
        ("services: {}\n# class: Drupal\\demo\\Retired\n", set()),
        ("description: 'Formerly Drupal\\demo\\Retired was a service.'\n", set()),
        ("description: |\n  Retired service: Drupal\\demo\\Retired\n", set()),
        (
            "services:\n  demo.active:\n    class: Drupal\\demo\\Retired\n",
            {"Retired", "run"},
        ),
        ("services:\n  Drupal\\demo\\Retired: ~\n", {"Retired", "run"}),
        (
            "defaults:\n  _controller: '\\Drupal\\demo\\Retired::run'\n",
            {"Retired", "run"},
        ),
        (
            'defaults:\n  _controller: "Drupal\\\\demo\\\\Retired::run"\n',
            {"Retired", "run"},
        ),
        ("services: &recursive\n  self: *recursive\n", set()),
        ("services: [unterminated\n# class: Drupal\\demo\\Retired\n", set()),
    ],
)
def test_yaml_uses_scalar_class_values_and_keys(tmp_path, yaml_text, expected):
    root = _extension(tmp_path)
    _write(root, "demo.services.yml", yaml_text)
    path = _write(
        root,
        "src/Retired.php",
        "<?php\nnamespace Drupal\\demo;\nclass Retired {\n public function run() {}\n}\n",
    )
    assert _roots(path) == expected


def test_oversized_yaml_is_not_partially_trusted(tmp_path):
    root = _extension(tmp_path)
    _write(
        root,
        "demo.services.yml",
        "services:\n  demo.retired:\n    class: Drupal\\demo\\Retired\n# "
        + "x" * _MAX_YAML_BYTES,
    )
    path = _write(
        root, "src/Retired.php", "<?php\nnamespace Drupal\\demo;\nclass Retired {}\n"
    )
    assert _roots(path) == set()


@pytest.mark.parametrize(
    "prefix",
    [
        "#[\\AllowDynamicProperties]",
        "/** @SuppressWarnings(PHPMD.CyclomaticComplexity) */",
        "use Acme\\Attribute\\Block;\n#[Block(id: 'fake')]",
        'use Acme\\Annotation\\Block;\n/** @Block(id = "fake") */',
        "use Drupal\\demo\\Attribute\\Audit;\n#[Audit]",
    ],
)
def test_unrelated_metadata_does_not_discover_plugin_helpers(tmp_path, prefix):
    root = _extension(tmp_path)
    _write(
        root,
        "src/Attribute/Audit.php",
        "<?php\nnamespace Drupal\\demo\\Attribute;\n#[\\Attribute]\nclass Audit {}\n",
    )
    path = _write(
        root,
        "src/Plugin/Block/Retired.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n"
        + prefix
        + "\nclass Retired {\n public function run() {}\n}\n",
    )
    assert _roots(path) == set()


@pytest.mark.parametrize(
    "prefix",
    [
        "use Drupal\\Core\\Block\\Attribute\\Block;\n#[Block(id: 'active')]",
        "use Drupal\\Core\\Block\\Attribute\\Block as Definition;\n#[Definition(id: 'active')]",
        'use Drupal\\Core\\Block\\Annotation\\Block as Definition;\n/** @Definition(id = "active") */',
        "use Drupal\\contrib\\Attribute\\FancyPlugin;\n#[FancyPlugin(id: 'active')]",
        'use Drupal\\contrib\\Annotation\\FancyPlugin;\n/** @FancyPlugin(id = "active") */',
        "use Drupal\\demo\\Attribute\\CustomBlock;\n#[CustomBlock(id: 'active')]",
        'use Drupal\\demo\\Annotation\\CustomBlock;\n/** @CustomBlock(id = "active") */',
        "#[Block(id: 'active')]",
        '/** @Block(id = "active") */',
    ],
)
def test_real_core_contrib_and_local_metadata_remains_discovered(tmp_path, prefix):
    root = _extension(tmp_path)
    for kind, base in (
        ("Attribute", "Drupal\\Component\\Plugin\\Attribute\\Plugin"),
        ("Annotation", "Drupal\\Component\\Annotation\\Plugin"),
    ):
        _write(
            root,
            f"src/{kind}/CustomBlock.php",
            f"<?php\nnamespace Drupal\\demo\\{kind};\n"
            f"use {base};\nclass CustomBlock extends Plugin {{}}\n",
        )
    path = _write(
        root,
        "src/Plugin/Block/Active.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n"
        + prefix
        + "\nclass Active {\n public function run() {}\n}\n",
    )
    assert _roots(path) == {"Active", "run"}


def test_retired_service_and_non_plugin_stay_listed_in_analyzer(tmp_path):
    root = _extension(tmp_path)
    _write(root, "demo.services.yml", "services: {}\n# class: Drupal\\demo\\Retired\n")
    _write(
        root, "src/Retired.php", "<?php\nnamespace Drupal\\demo;\nclass Retired {}\n"
    )
    _write(
        root,
        "src/Plugin/Block/Helper.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n#[\\AllowDynamicProperties]\nclass Helper {}\n",
    )
    result = json.loads(analyze(str(root), grep_cache=False))
    assert result.get("analysis_errors", []) == []
    assert result["analysis_summary"]["total_files"] == 2
    classes = {row["full_name"] for row in result.get("unused_classes", [])}
    assert classes == {"Drupal.demo.Retired", "Drupal.demo.Plugin.Block.Helper"}


@pytest.mark.parametrize("base", ["Drupal\\Component\\Plugin\\Attribute\\Plugin", None])
def test_local_metadata_inheritance_can_use_an_ordinary_base_namespace(tmp_path, base):
    root = _extension(tmp_path)
    inheritance = ""
    if base:
        inheritance = f" extends \\{base}"
    _write(
        root,
        "src/BaseMetadata.php",
        f"<?php\nnamespace Drupal\\demo;\nclass BaseMetadata{inheritance} {{}}\n",
    )
    _write(
        root,
        "src/Attribute/CustomBlock.php",
        "<?php\nnamespace Drupal\\demo\\Attribute;\n"
        "class CustomBlock extends \\Drupal\\demo\\BaseMetadata {}\n",
    )
    path = _write(
        root,
        "src/Plugin/Block/Active.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n"
        "use Drupal\\demo\\Attribute\\CustomBlock;\n"
        "#[CustomBlock(id: 'active')]\nclass Active {}\n",
    )
    expected = set()
    if base:
        expected = {"Active"}
    assert _roots(path) == expected


@pytest.mark.parametrize(
    "prefix,expected",
    [
        ("#[Attribute\\CustomBlock(id: 'active')]", {"Active"}),
        ("#[namespace\\Attribute\\CustomBlock(id: 'active')]", {"Active"}),
        ("#[Drupal\\Core\\Block\\Attribute\\Block(id: 'fake')]", set()),
        ("#[\\Drupal\\Core\\Block\\Attribute\\Block(id: 'active')]", {"Active"}),
        (
            "use Drupal\\Core\\Block\\Attribute as Metadata;\n#[Metadata\\Block(id: 'active')]",
            {"Active"},
        ),
    ],
)
def test_qualified_metadata_names_respect_the_enclosing_namespace(
    tmp_path, prefix, expected
):
    root = _extension(tmp_path)
    _write(
        root,
        "src/Plugin/Block/Attribute/CustomBlock.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block\\Attribute;\n"
        "class CustomBlock extends \\Drupal\\Component\\Plugin\\Attribute\\Plugin {}\n",
    )
    path = _write(
        root,
        "src/Plugin/Block/Active.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n"
        + prefix
        + "\nclass Active {}\n",
    )
    assert _roots(path) == expected


@pytest.mark.parametrize(
    "attribute,expected",
    [
        ("Drupal\\Core\\Hook\\Attribute\\Hook", set()),
        ("\\Drupal\\Core\\Hook\\Attribute\\Hook", {"Active", "alter"}),
    ],
)
def test_qualified_hook_names_respect_the_enclosing_namespace(
    tmp_path, attribute, expected
):
    root = _extension(tmp_path)
    path = _write(
        root,
        "src/Hook/Active.php",
        "<?php\nnamespace Drupal\\demo\\Hook;\nclass Active {\n"
        f" #[{attribute}('form_alter')]\n public function alter() {{}}\n}}\n",
    )
    assert _roots(path) == expected


@pytest.mark.parametrize(
    "base,expected",
    [
        (None, set()),
        ("Drupal\\Component\\Plugin\\Attribute\\Plugin", {"Example"}),
    ],
)
def test_declared_local_metadata_overrides_the_short_plugin_convention(
    tmp_path, base, expected
):
    root = _extension(tmp_path)
    inheritance = ""
    if base:
        inheritance = f" extends \\{base}"
    path = _write(
        root,
        "src/Plugin/Block/Example.php",
        "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n"
        f"#[\\Attribute]\nclass Block{inheritance} {{}}\n"
        "#[Block]\nclass Example {}\n",
    )
    assert _roots(path) == expected


@pytest.mark.parametrize("attribute", ["Hook", "LegacyHook", "CustomHook"])
@pytest.mark.parametrize("placement", ["class", "method"])
@pytest.mark.parametrize("actual_hook_base", [False, True])
def test_local_hook_attribute_binding_controls_discovery(
    tmp_path, attribute, placement, actual_hook_base
):
    root = _extension(tmp_path)
    inheritance = ""
    if actual_hook_base:
        inheritance = " extends \\Drupal\\Core\\Hook\\Attribute\\Hook"
    declaration = f"#[\\Attribute]\nclass {attribute}{inheritance} {{}}\n"
    target_attribute = f"#[{attribute}('form_alter', method: 'alter')]\n"
    if placement == "class":
        target = target_attribute + "class Example {\n public function alter() {}\n}\n"
    else:
        target = (
            "class Example {\n" + target_attribute + " public function alter() {}\n}\n"
        )
    path = _write(
        root,
        "src/Hook/Example.php",
        "<?php\nnamespace Drupal\\demo\\Hook;\n" + declaration + target,
    )
    expected = set()
    if actual_hook_base:
        expected = {"Example", "alter"}
    assert _roots(path) == expected


@pytest.mark.parametrize("actual_hook_base", [False, True])
@pytest.mark.parametrize("indirect", [False, True])
def test_imported_local_hook_metadata_requires_inheritance_proof(
    tmp_path, actual_hook_base, indirect
):
    root = _extension(tmp_path)
    inheritance = ""
    if actual_hook_base:
        inheritance = " extends \\Drupal\\Core\\Hook\\Attribute\\Hook"
    if indirect:
        _write(
            root,
            "src/BaseCallback.php",
            f"<?php\nnamespace Drupal\\demo;\nclass BaseCallback{inheritance} {{}}\n",
        )
        inheritance = " extends \\Drupal\\demo\\BaseCallback"
    _write(
        root,
        "src/Attribute/Callback.php",
        "<?php\nnamespace Drupal\\demo\\Attribute;\n"
        f"#[\\Attribute]\nclass Callback{inheritance} {{}}\n",
    )
    path = _write(
        root,
        "src/Hook/Example.php",
        "<?php\nnamespace Drupal\\demo\\Hook;\n"
        "use Drupal\\demo\\Attribute\\Callback as Hook;\n"
        "class Example {\n #[Hook('form_alter')]\n public function alter() {}\n}\n",
    )
    expected = set()
    if actual_hook_base:
        expected = {"Example", "alter"}
    assert _roots(path) == expected


@pytest.mark.parametrize(
    "annotation,directory",
    [
        ("ViewsArgumentDefault", "views/argument_default"),
        ("ViewsDisplayExtender", "views/display_extender"),
        ("ViewsExposedForm", "views/exposed_form"),
        ("SearchApiProcessor", "search_api/processor"),
        ("ImageToolkitOperation", "ImageToolkit/Operation/imagemagick"),
        ("MigrateProcessPlugin", "migrate/process"),
    ],
)
@pytest.mark.parametrize(
    "binding", ["bare", "foreign-import", "local-nonplugin", "unrelated"]
)
def test_bare_plugin_annotations_follow_contiguous_directory_conventions(
    tmp_path, annotation, directory, binding
):
    root = _extension(tmp_path)
    prefix = ""
    if binding == "foreign-import":
        prefix = f"use Acme\\Annotation\\{annotation};\n"
    elif binding == "local-nonplugin":
        _write(
            root,
            f"src/Annotation/{annotation}.php",
            f"<?php\nnamespace Drupal\\demo\\Annotation;\nclass {annotation} {{}}\n",
        )
    elif binding == "unrelated":
        annotation = "SuppressWarnings"
    namespace = "Drupal\\demo\\Plugin\\" + directory.replace("/", "\\")
    path = _write(
        root,
        f"src/Plugin/{directory}/Active.php",
        f"<?php\nnamespace {namespace};\n"
        + prefix
        + f'/** @{annotation}(id = "active") */\nclass Active {{}}\n',
    )
    expected = set()
    if binding == "bare":
        expected = {"Active"}
    assert _roots(path) == expected


@pytest.mark.parametrize(
    "annotation,directory",
    [
        ("ViewsArgumentDefault", "views/helper/argument_default"),
        ("ViewsArgument", "views/argument_default"),
        ("ImageOperation", "ImageToolkit/Operation/imagemagick"),
    ],
)
def test_plugin_conventions_do_not_skip_directory_parts(
    tmp_path, annotation, directory
):
    root = _extension(tmp_path)
    namespace = "Drupal\\demo\\Plugin\\" + directory.replace("/", "\\")
    path = _write(
        root,
        f"src/Plugin/{directory}/Inactive.php",
        f"<?php\nnamespace {namespace};\n"
        f'/** @{annotation}(id = "inactive") */\nclass Inactive {{}}\n',
    )
    assert _roots(path) == set()


def test_local_plugin_metadata_is_parsed_once_within_one_run(tmp_path, monkeypatch):
    from skylos.visitors.languages.php import drupal

    root = _extension(tmp_path)
    metadata = _write(
        root,
        "src/Attribute/CustomBlock.php",
        "<?php\nnamespace Drupal\\demo\\Attribute;\n"
        "class CustomBlock extends \\Drupal\\Component\\Plugin\\Attribute\\Plugin {}\n",
    )
    callers = []
    for name in ("First", "Second"):
        callers.append(
            _write(
                root,
                f"src/Plugin/Block/{name}.php",
                "<?php\nnamespace Drupal\\demo\\Plugin\\Block;\n"
                "use Drupal\\demo\\Attribute\\CustomBlock;\n"
                f"#[CustomBlock(id: '{name}')]\nclass {name} {{}}\n",
            )
        )
    parses = []
    real_scan = PhpCore.scan

    def count_metadata_scan(core):
        if core.file_path == str(metadata):
            parses.append(core.file_path)
        return real_scan(core)

    monkeypatch.setattr(PhpCore, "scan", count_metadata_scan)
    drupal.clear_drupal_cache()
    for path in callers:
        definitions, _, _, _, _, framework, *_ = scan_php_file(
            str(path), {}, _reuse_framework_cache=True
        )
        assert {
            definition.simple_name
            for definition in definitions
            if definition.line in framework.framework_decorated_lines
        } == {path.stem}
    assert len(parses) == 1


@pytest.mark.parametrize("api", ["direct", "analyze"])
@pytest.mark.parametrize("initially_plugin", [False, True])
@pytest.mark.parametrize("kind", ["plugin", "hook"])
def test_local_metadata_source_edits_refresh_the_next_scan(
    tmp_path, api, initially_plugin, kind
):
    root = _extension(tmp_path)
    metadata = root / "src/Attribute/Callback.php"
    metadata.parent.mkdir(parents=True)
    if kind == "plugin":
        real_base = "Drupal\\Component\\Plugin\\Attribute\\Plugin"
        relative = "src/Plugin/Block/Active.php"
        namespace = "Drupal\\demo\\Plugin\\Block"
    else:
        real_base = "Drupal\\Core\\Hook\\Attribute\\Hook"
        relative = "src/Hook/Active.php"
        namespace = "Drupal\\demo\\Hook"
    path = _write(
        root,
        relative,
        f"<?php\nnamespace {namespace};\n"
        "use Drupal\\demo\\Attribute\\Callback;\n"
        "#[Callback('active')]\nclass Active {}\n",
    )
    for is_plugin in (initially_plugin, not initially_plugin):
        inheritance = ""
        if is_plugin:
            inheritance = f" extends \\{real_base}"
        metadata.write_text(
            "<?php\nnamespace Drupal\\demo\\Attribute;\n"
            f"#[\\Attribute]\nclass Callback{inheritance} {{}}\n"
        )
        if api == "direct":
            live = "Active" in _roots(path)
        else:
            result = json.loads(analyze(str(root), grep_cache=False))
            assert result.get("analysis_errors", []) == []
            assert result["analysis_summary"]["total_files"] == 2
            unused = {row["simple_name"] for row in result.get("unused_classes", [])}
            live = "Active" not in unused
        assert live is is_plugin
