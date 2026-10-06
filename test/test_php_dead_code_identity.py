from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import gettempdir

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.php.core import PhpCore


def _scan(code: str) -> PhpCore:
    core = PhpCore("App.php", code.encode("utf-8"))
    core.scan()
    return core


@pytest.mark.parametrize("active_first", [False, True])
@pytest.mark.parametrize(
    "callee",
    ["$this->process()", "self::process()", "static::process()", "Active::process()"],
)
def test_php_member_graph_respects_owner_and_declaration_order(active_first, callee):
    active = f"""class Active {{
        private function process() {{ return 1; }}
        public function run() {{ return {callee}; }}
    }}"""
    dormant = "class Dormant { private function process() { return 2; } }"
    declarations = [active, dormant] if active_first else [dormant, active]
    core = _scan(
        "<?php " + "\n".join(declarations) + "\n(new Active())->run(); new Dormant();"
    )
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Active.run"].calls == {"Active.process"}
    assert definitions["Active.process"].called_by == {"Active.run"}
    assert not definitions["Dormant.process"].called_by
    assert "Active.process" in {name for name, _ in core.refs}
    assert "process" not in {name for name, _ in core.refs}


def test_php_unknown_member_receiver_does_not_choose_first_definition():
    core = _scan("""<?php
        class Dormant { public function process() {} }
        class Active { public function process() {} }
        function invoke($receiver) { $receiver->process(); }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["invoke"].calls == {"Dormant.process", "Active.process"}
    assert definitions["Dormant.process"].called_by == {"invoke"}
    assert definitions["Active.process"].called_by == {"invoke"}


def test_php_unknown_member_with_same_name_as_caller_is_not_self_recursion():
    core = _scan("""<?php
        class Active { public function process() {} }
        function process($receiver) { $receiver->process(); }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["process"].calls == {"Active.process"}
    assert definitions["Active.process"].called_by == {"process"}


def test_php_known_missing_member_does_not_bind_another_class():
    core = _scan("""<?php
        class Dormant { public static function process() {} }
        class Active { public function run() { Active::process(); } }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert not definitions["Active.run"].calls
    assert not definitions["Dormant.process"].called_by
    assert "Active.process" in {name for name, _ in core.refs}
    assert "process" not in {name for name, _ in core.refs}


@pytest.mark.parametrize("bracketed", [False, True])
def test_php_namespace_forms_collect_same_definitions_and_qualified_calls(bracketed):
    body = """
        function live() { return 2; }
        function orphan() { return 1; }
        function caller() { return \\Demo\\live(); }
        echo caller();
    """
    code = (
        f"<?php namespace Demo {{ {body} }}"
        if bracketed
        else f"<?php namespace Demo; {body}"
    )
    core = _scan(code)
    definitions = {definition.name: definition for definition in core.defs}

    assert set(definitions) == {"Demo.live", "Demo.orphan", "Demo.caller"}
    assert definitions["Demo.caller"].calls == {"Demo.live"}
    assert definitions["Demo.live"].called_by == {"Demo.caller"}
    assert not definitions["Demo.orphan"].called_by
    assert {name for name, _ in core.refs} >= {"Demo.live", "Demo.caller"}


def test_php_bracketed_namespaces_do_not_leak_aliases_or_namespace():
    core = _scan("""<?php
        namespace One { use Library\\First as Alias; function call() { Alias::work(); } }
        namespace Two { use Library\\Second as Alias; function call() { Alias::work(); } }
        namespace { function root() {} root(); }
    """)

    assert {definition.name for definition in core.defs} >= {
        "One.call",
        "Two.call",
        "root",
    }
    assert {name for name, _ in core.refs} >= {
        "Library.First.work",
        "Library.Second.work",
        "root",
    }
    assert "Two.root" not in {definition.name for definition in core.defs}


def test_php_static_namespace_alias_keeps_owner_and_alias_reference():
    core = _scan("""<?php
        namespace Symfony\\Polyfill\\Php83 {
            class Php83 {
                private const JSON_MAX_DEPTH = 512;
                private const UNUSED_LIMIT = 1;
                public static function json_validate() { return self::JSON_MAX_DEPTH; }
                private static function orphan() { return self::UNUSED_LIMIT; }
            }
        }
        namespace {
            use Symfony\\Polyfill\\Php83 as p;
            p\\Php83::json_validate();
        }
    """)
    definitions = {definition.name: definition for definition in core.defs}
    refs = {name for name, _ in core.refs}

    assert refs >= {
        "p",
        "Symfony.Polyfill.Php83.Php83",
        "Symfony.Polyfill.Php83.Php83.json_validate",
        "Symfony.Polyfill.Php83.Php83.JSON_MAX_DEPTH",
    }
    assert "JSON_MAX_DEPTH" not in refs
    assert "orphan" not in refs
    assert definitions["Symfony.Polyfill.Php83.Php83.json_validate"].calls == {
        "Symfony.Polyfill.Php83.Php83.JSON_MAX_DEPTH"
    }
    assert not definitions["Symfony.Polyfill.Php83.Php83.orphan"].called_by


def test_php_method_body_retains_namespace_and_does_not_drop_same_leaf_call():
    core = _scan("""<?php
        namespace Demo;
        function scan() { return Worker::scan(); }
        class Worker {
            public static function scan() { return helper(); }
        }
        function helper() { return 1; }
        scan();
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Demo.scan"].calls == {"Demo.Worker.scan"}
    assert definitions["Demo.Worker.scan"].calls == {"Demo.helper"}
    assert definitions["Demo.Worker.scan"].called_by == {"Demo.scan"}


def test_php_grouped_import_alias_resolves_static_owner():
    core = _scan("""<?php
        namespace Demo;
        use Library\\{Worker as Selected, Dormant};
        function invoke() { Selected::run(); }
    """)

    assert {name for name, _ in core.refs} >= {
        "Selected",
        "Library.Worker",
        "Library.Worker.run",
    }
    assert "Library.Dormant" not in {name for name, _ in core.refs}


@pytest.mark.parametrize("bracketed", [False, True])
@pytest.mark.parametrize("import_first", [False, True])
def test_php_class_alias_resolution_respects_declaration_position_and_case(
    bracketed, import_first
):
    imported = "use Library\\Worker as Selected;"
    caller = "function invoke() { selected::run(); }"
    body = imported + caller if import_first else caller + imported
    source = (
        f"<?php namespace Demo {{ {body} }}"
        if bracketed
        else f"<?php namespace Demo; {body}"
    )
    core = _scan(source)

    refs = {name for name, _ in core.refs}
    if import_first:
        assert refs >= {"Selected", "Library.Worker", "Library.Worker.run"}
        assert "Demo.selected.run" not in refs
    else:
        assert refs >= {"Demo.selected", "Demo.selected.run"}
        assert "Library.Worker.run" not in refs
        assert "Selected" not in refs


def test_php_function_alias_and_relative_namespace_resolve_distinct_functions():
    core = _scan("""<?php
        namespace Helpers { function work() {} }
        namespace Demo {
            use function Helpers\\work as selected;
            function work() {}
            function invoke() { selected(); namespace\\work(); }
        }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Demo.invoke"].calls == {"Helpers.work", "Demo.work"}
    assert "selected" in {name for name, _ in core.refs}


@pytest.mark.parametrize("child_first", [False, True])
def test_php_known_inherited_member_uses_its_declaring_class(child_first):
    base = "class Base { protected function process() {} }"
    child = "class Active extends Base { public function run() { $this->process(); } }"
    dormant = "class Dormant { protected function process() {} }"
    classes = [child, base, dormant] if child_first else [dormant, base, child]
    core = _scan("<?php " + "\n".join(classes))
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Active.run"].calls == {"Base.process"}
    assert definitions["Base.process"].called_by == {"Active.run"}
    assert not definitions["Dormant.process"].called_by
    assert "Base.process" in {name for name, _ in core.refs}


def _write_fixture(path, source):
    temporary_root = Path(gettempdir()).resolve()
    path = Path(path)
    if path.is_symlink():
        raise ValueError("fixture path must not be a symlink")
    path = path.resolve()
    path.relative_to(temporary_root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(source)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("active_first", [False, True])
def test_php_end_to_end_member_liveness_keeps_dead_sibling(
    tmp_path, grep_verify, active_first
):
    active = "class Active { private function process() {} public function run() { $this->process(); } }"
    dormant = "class Dormant { private function process() {} }"
    declarations = [active, dormant] if active_first else [dormant, active]
    _write_fixture(
        tmp_path / "App.php",
        "<?php " + "\n".join(declarations) + "\n(new Active())->run(); new Dormant();",
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=grep_verify))

    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Dormant.process"
    }
    assert result.get("unused_classes", []) == []
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("bracketed", [False, True])
def test_php_end_to_end_namespace_reports_only_dead_function(tmp_path, bracketed):
    body = "function live() {} function orphan() {} \\Demo\\live();"
    source = (
        f"<?php namespace Demo {{ {body} }}"
        if bracketed
        else f"<?php namespace Demo; {body}"
    )
    _write_fixture(tmp_path / "App.php", source)

    result = json.loads(analyze(str(tmp_path)))

    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Demo.orphan"
    }
    assert result.get("analysis_errors", []) == []


def test_php_end_to_end_static_namespace_alias_preserves_live_and_dead_constants(
    tmp_path,
):
    _write_fixture(
        tmp_path / "Php83.php",
        """<?php
        namespace Symfony\\Polyfill\\Php83;
        class Php83 {
            private const JSON_MAX_DEPTH = 512;
            private const UNUSED_LIMIT = 1;
            public static function json_validate() { return self::JSON_MAX_DEPTH; }
            private static function orphan() {}
        }
    """,
    )
    _write_fixture(
        tmp_path / "bootstrap.php",
        """<?php
        use Symfony\\Polyfill\\Php83 as p;
        p\\Php83::json_validate();
    """,
    )

    result = json.loads(analyze(str(tmp_path)))

    assert result.get("unused_classes", []) == []
    assert result.get("unused_imports", []) == []
    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Symfony.Polyfill.Php83.Php83.orphan"
    }
    assert {finding["full_name"] for finding in result.get("unused_variables", [])} == {
        "Symfony.Polyfill.Php83.Php83.UNUSED_LIMIT"
    }
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("grep_verify", [False, True])
def test_php_end_to_end_inherited_method_in_another_file_keeps_owner(
    tmp_path, grep_verify
):
    _write_fixture(
        tmp_path / "Base.php",
        """<?php
        namespace Demo;
        class Base { protected function process() {} }
    """,
    )
    _write_fixture(
        tmp_path / "App.php",
        """<?php
        namespace Demo;
        class Dormant { private function process() {} }
        class Active extends Base { public function run() { $this->process(); } }
        (new Active())->run(); new Dormant();
    """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=grep_verify))

    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Demo.Dormant.process"
    }
    assert result.get("unused_classes", []) == []
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("trait_first", [False, True])
def test_php_used_trait_supplies_member_without_crediting_dead_sibling(trait_first):
    helper = (
        "trait Helper { private function process() {} private function orphan() {} }"
    )
    active = "class Active { use Helper; public function run() { $this->process(); } }"
    blocks = [helper, active] if trait_first else [active, helper]
    core = _scan(
        "<?php "
        + "\n".join(blocks)
        + " class Dormant { private function process() {} }"
    )
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Active.run"].calls == {"Helper.process"}
    assert definitions["Helper.process"].called_by == {"Active.run"}
    assert not definitions["Dormant.process"].called_by
    assert not definitions["Helper.orphan"].called_by


@pytest.mark.parametrize("own_override", [False, True])
def test_php_member_precedence_is_own_method_then_trait_then_base(own_override):
    own = "private function process() {}" if own_override else ""
    core = _scan(
        """<?php
        class Base { protected function process() {} }
        trait Helper { private function process() {} }
        class Active extends Base { use Helper; """
        + own
        + """
            public function run() { $this->process(); }
        }
    """
    )
    definitions = {definition.name: definition for definition in core.defs}
    target = "Active.process" if own_override else "Helper.process"

    assert definitions["Active.run"].calls == {target}
    assert definitions[target].called_by == {"Active.run"}
    assert not definitions["Base.process"].called_by
    if own_override:
        assert not definitions["Helper.process"].called_by


def test_php_nested_trait_and_trait_alias_resolve_original_member():
    core = _scan("""<?php
        namespace Demo;
        trait Helper { private function process() {} private function orphan() {} }
        trait Combined { use Helper; }
        class Active { use Combined { process as private adapted; }
            public function run() { $this->adapted(); }
        }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Demo.Active.run"].calls == {"Demo.Helper.process"}
    assert definitions["Demo.Helper.process"].called_by == {"Demo.Active.run"}
    assert not definitions["Demo.Helper.orphan"].called_by


def test_php_trait_instead_of_and_explicit_alias_select_correct_provider():
    core = _scan("""<?php
        trait Selected { private function process() {} }
        trait Spare { private function process() {} }
        class Active {
            use Selected, Spare { Selected::process insteadof Spare; Selected::process as private adapted; }
            public function run() { $this->process(); $this->adapted(); }
        }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Active.run"].calls == {"Selected.process"}
    assert not definitions["Spare.process"].called_by


def test_php_trait_body_dispatches_to_consuming_class_override():
    core = _scan("""<?php
        trait Helper {
            public function run() { $this->process(); }
            private function process() {}
        }
        class Active { use Helper; private function process() {} }
        class Dormant { private function process() {} }
    """)
    definitions = {definition.name: definition for definition in core.defs}

    assert definitions["Helper.run"].calls == {"Active.process"}
    assert definitions["Active.process"].called_by == {"Helper.run"}
    assert not definitions["Helper.process"].called_by
    assert not definitions["Dormant.process"].called_by


@pytest.mark.parametrize("split_files", [False, True])
def test_php_end_to_end_used_trait_keeps_live_member_and_dead_controls(
    tmp_path, split_files
):
    helper = (
        "trait Helper { private function process() {} private function orphan() {} }"
    )
    active = "class Active { use Helper; public function run() { $this->process(); } }"
    dormant = "class Dormant { private function process() {} }"
    if split_files:
        _write_fixture(tmp_path / "Helper.php", "<?php " + helper)
        source = "<?php " + active + dormant
    else:
        source = "<?php " + helper + active + dormant
    _write_fixture(
        tmp_path / "App.php", source + " (new Active())->run(); new Dormant();"
    )

    result = json.loads(analyze(str(tmp_path)))

    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Helper.orphan",
        "Dormant.process",
    }
    assert result.get("unused_classes", []) == []
    assert result.get("analysis_errors", []) == []


def test_php_end_to_end_trait_body_cross_file_receiver_stays_conservative(tmp_path):
    _write_fixture(
        tmp_path / "Helper.php",
        """<?php
        trait Helper { public function run() { $this->process(); } }
    """,
    )
    _write_fixture(
        tmp_path / "App.php",
        """<?php
        class Active { use Helper; private function process() {} private function orphan() {} }
        (new Active())->run();
    """,
    )

    result = json.loads(analyze(str(tmp_path)))

    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Active.orphan"
    }
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize("split_files", [False, True])
def test_php_end_to_end_class_override_keeps_shadowed_trait_member_dead(
    tmp_path, split_files
):
    helper = "trait Helper { private function process() {} }"
    active = "class Active { use Helper; private function process() {} public function run() { $this->process(); } }"
    if split_files:
        _write_fixture(tmp_path / "Helper.php", "<?php " + helper)
        source = "<?php " + active
    else:
        source = "<?php " + helper + active
    _write_fixture(tmp_path / "App.php", source + " (new Active())->run();")

    result = json.loads(analyze(str(tmp_path)))

    assert {finding["full_name"] for finding in result.get("unused_functions", [])} == {
        "Helper.process"
    }
    assert result.get("analysis_errors", []) == []
