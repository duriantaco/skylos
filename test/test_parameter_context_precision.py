"""Wide named framework inputs and plain records are not ordered calls."""

import ast
from pathlib import Path
import textwrap

import pytest

from test.fixture_paths import make_fixture_directory, write_fixture

from skylos.rules.quality.structure import ArgCountRule


def findings(source, *, filename="app/commands.py", project_root=None):
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    rule = ArgCountRule()
    context = {"filename": str(filename), "source": source}
    if project_root is not None:
        context["project_root"] = project_root
    return [
        row for node in ast.walk(tree) for row in rule.visit_node(node, context) or []
    ]


def command(
    *, imports="import click", prefix="click.", extra="", parameters="a, b, c, d, e, f"
):
    return (
        imports
        + "\n"
        + extra
        + f"@{prefix}command()\n"
        + "".join(f"@{prefix}option('--{name}')\n" for name in "abcdef")
        + f"def execute({parameters}):\n    return a\n"
    )


@pytest.mark.parametrize(
    "imports,prefix",
    [
        ("import click", "click."),
        ("import click as cli", "cli."),
        ("from click import command, option", ""),
    ],
)
def test_import_proven_click_parameters_are_bound_by_name(imports, prefix):
    assert findings(command(imports=imports, prefix=prefix)) == []


def test_registered_group_callback_with_injected_context():
    source = """
        import click
        @click.group()
        def tools(): pass
        @tools.command()
        @click.pass_context
        @click.argument('first')
        @click.option('-b', '--second')
        @click.option('--third/--no-third')
        @click.option('--fourth', 'four')
        @click.option('--fifth')
        def execute(ctx, first, second, third, four, fifth):
            return ctx.invoke(first)
    """
    assert findings(source) == []


@pytest.mark.parametrize(
    "extra",
    [
        "click = custom\n",
        "click.option = custom\n",
        "from somewhere import *\n",
    ],
)
def test_rebound_or_mutated_click_contract_is_unknown(extra):
    assert len(findings(command(extra=extra))) == 1


def test_similarly_named_unknown_module_does_not_exempt_callback():
    assert len(findings(command(imports="import custom as click"))) == 1


@pytest.mark.parametrize("provider", ["click.py", "click", "src/click.py", "src/click"])
@pytest.mark.parametrize(
    "imports,prefix", [("import click", "click."), ("from click import command, option", "")]
)
def test_local_click_provider_cannot_prove_named_callback_inputs(
    tmp_path, provider, imports, prefix
):
    local = tmp_path / provider
    if local.suffix:
        write_fixture(tmp_path, provider, "def command(): return lambda function: function\n")
    else:
        make_fixture_directory(tmp_path, provider)
        write_fixture(tmp_path, local.relative_to(tmp_path) / "__init__.py",
                      "# A project-owned decorator package.\n")
    source = command(imports=imports, prefix=prefix)
    rows = findings(source, filename=tmp_path / "commands.py", project_root=tmp_path)
    assert len(rows) == 1
    assert rows[0]["value"] == 6


@pytest.mark.parametrize("relative", ["commands.py", "src/app/commands.py"])
def test_external_click_with_known_root_retains_named_input_exemption(tmp_path, relative):
    filename = tmp_path / relative
    filename.parent.mkdir(parents=True, exist_ok=True)
    assert findings(
        command(), filename=filename, project_root=tmp_path
    ) == []


def test_sibling_click_provider_retains_argument_warning(tmp_path):
    package = tmp_path / "app"
    package.mkdir()
    (package / "click.py").write_text("# Local provider when invoked as a script.\n")
    assert len(findings(
        command(), filename=package / "commands.py", project_root=tmp_path
    )) == 1


@pytest.mark.parametrize("provider", ["click.py", "click", "src"])
def test_symlinked_click_search_path_is_unknown_without_following_it(tmp_path, provider):
    (tmp_path / provider).symlink_to(tmp_path / "missing-provider")
    assert len(findings(
        command(), filename=tmp_path / "commands.py", project_root=tmp_path
    )) == 1


def test_outside_root_filename_does_not_prove_external_click(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    assert len(findings(
        command(), filename=tmp_path / "commands.py", project_root=root
    )) == 1


def test_unreadable_click_search_path_retains_argument_warning(tmp_path, monkeypatch):
    original = Path.lstat

    def unavailable_source_path(path, *args, **kwargs):
        if path == tmp_path / "src":
            raise PermissionError("No metadata available for the source path")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", unavailable_source_path)
    assert len(findings(
        command(), filename=tmp_path / "commands.py", project_root=tmp_path
    )) == 1


def test_local_click_does_not_disable_independent_plain_record_proof(tmp_path):
    (tmp_path / "click.py").write_text("# Local module, unrelated to this record.\n")
    source = "import click\nclass Record:\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert findings(
        source, filename=tmp_path / "models.py", project_root=tmp_path
    ) == []


def test_undeclared_argument_still_warns():
    assert len(findings(command(parameters="a, b, c, d, e, f, undeclared"))) == 1


def test_declarations_without_command_registration_still_warn():
    assert len(findings(command().replace("@click.command()\n", ""))) == 1


def test_unknown_wrapper_still_warns():
    assert len(findings(command().replace("def execute", "@custom\ndef execute"))) == 1


def test_click_expose_value_false_does_not_prove_binding():
    source = command().replace(
        "@click.option('--f')", "@click.option('--f', expose_value=False)"
    )
    assert len(findings(source)) == 1


def test_positional_only_callback_is_not_a_valid_keyword_binding_proof():
    assert len(findings(command(parameters="a, b, c, d, e, f, /"))) == 1


def test_plain_record_constructor_is_already_a_parameter_object():
    source = "class Record:\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert findings(source) == []


@pytest.mark.parametrize(
    "extra",
    ["        if a: self.a = b\n", "        validate(a)\n"],
)
def test_constructor_with_behavior_keeps_argument_warning(extra):
    source = "class Record:\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef") + extra
    assert len(findings(source)) == 1


@pytest.mark.parametrize("base", ["Unknown", "object"])
def test_unknown_inherited_or_shadowed_object_behavior_keeps_warning(base):
    source = "object = CustomBase\n" if base == "object" else ""
    source += f"class Record({base}):\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert len(findings(source)) == 1


def test_plain_builtin_object_record_remains_exempt():
    source = "class Record(object):\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert findings(source) == []


@pytest.mark.parametrize("declaration", ["a = descriptor()", "a = property(get_a)"])
def test_descriptor_backed_constructor_keeps_warning(declaration):
    source = (
        f"class Record:\n    {declaration}\n    def __init__(self, a, b, c, d, e, f):\n"
    )
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert len(findings(source)) == 1


def test_plain_wide_function_and_unknown_callback_keep_original_metric():
    rows = findings("def execute(a, b, c, d, e, f): return a\n")
    assert len(rows) == 1
    assert rows[0]["value"] == 6
    assert rows[0]["threshold"] == 5


def test_record_does_not_exempt_wide_behavioral_method():
    source = """
        class Record:
            def __init__(self, a, b, c, d, e, f):
                self.a = a
                self.b = b
                self.c = c
                self.d = d
                self.e = e
                self.f = f
            def execute(self, a, b, c, d, e, f):
                return a
    """
    rows = findings(source)
    assert len(rows) == 1
    assert rows[0]["simple_name"] == "execute"


@pytest.mark.parametrize("magic", ["__setattr__", "__new__", "__getattribute__"])
def test_record_with_custom_binding_behavior_remains_unknown(magic):
    source = f"class Record:\n    {magic} = custom\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert len(findings(source)) == 1


def test_destructured_descriptor_declaration_remains_unknown():
    source = "class Record:\n    a, b = descriptor(), descriptor()\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert len(findings(source)) == 1


def test_outer_unknown_wrapper_cannot_prove_a_click_group():
    source = "import click\n@replace\n@click.group()\ndef tools(): pass\n"
    source += (
        command()
        .replace("import click\n", "")
        .replace("@click.command()", "@tools.command()")
    )
    assert len(findings(source)) == 1


@pytest.mark.parametrize("marker", ["command", "option"])
def test_custom_click_binding_class_remains_unknown(marker):
    source = command()
    if marker == "command":
        source = source.replace("@click.command()", "@click.command(cls=CustomCommand)")
    else:
        source = source.replace(
            "@click.option('--a')", "@click.option('--a', cls=CustomOption)"
        )
    assert len(findings(source)) == 1


def test_custom_click_group_binding_class_remains_unknown():
    source = "import click\n@click.group(cls=CustomGroup)\ndef tools(): pass\n"
    source += (
        command()
        .replace("import click\n", "")
        .replace("@click.command()", "@tools.command()")
    )
    assert len(findings(source)) == 1


@pytest.mark.parametrize(
    "before,after",
    [
        ("    locals().update(__setattr__=validate)\n", ""),
        ("", "Record.__setattr__ = validate\n"),
        ("", "setattr(Record, '__setattr__', validate)\n"),
    ],
)
def test_dynamic_class_namespace_cannot_prove_a_plain_record(before, after):
    source = "class Record:\n" + before + "    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    source += after
    assert len(findings(source)) == 1


def test_click_import_after_decorators_does_not_prove_runtime_binding():
    source = command().replace("import click\n", "") + "import click\n"
    assert len(findings(source)) == 1


def test_unknown_decorator_inside_record_namespace_remains_unknown():
    source = "class Record:\n    @custom\n    def callback(self): pass\n    def __init__(self, a, b, c, d, e, f):\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "abcdef")
    assert len(findings(source)) == 1


@pytest.mark.parametrize("attribute", ["__class__", "__dict__", "__weakref__"])
def test_special_runtime_namespace_writes_are_not_passive_record_fields(attribute):
    source = "class Record:\n    def __init__(self, a, b, c, d, e, f):\n"
    source += f"        self.{attribute} = a\n"
    source += "".join(f"        self.{name} = {name}\n" for name in "bcdef")
    assert len(findings(source)) == 1


@pytest.mark.parametrize("declaration", ["---a", "a"])
def test_unsupported_option_declaration_cannot_prove_the_callback_destination(
    declaration,
):
    source = command().replace(
        "@click.option('--a')", f"@click.option({declaration!r})"
    )
    assert len(findings(source)) == 1
