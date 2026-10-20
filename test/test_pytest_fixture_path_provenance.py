"""Fixture provenance is source evidence, never a test-name exemption."""

import ast
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.danger_fs.path_flow import scan

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}


def _scan(tmp_path, source, *, filename="tests/test_storage.py", files=None):
    assert write_text_no_symlink(
        tmp_path / "pyproject.toml", "[project]\nname='fixture-proof'\n"
    )
    paths = dict(files or {})
    paths[filename] = source
    for relative, text in paths.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)
    findings = []
    scan(ast.parse(source), tmp_path / filename, findings)
    return findings


def _rules(findings, symbol="test_write"):
    result = set()
    for finding in findings:
        if finding["symbol"] == symbol and finding["rule_id"] in PATH_RULES:
            result.add(finding["rule_id"])
    return result


def test_builtin_provider_fixed_child_is_safe(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "payload.bin").write_bytes(b"ok")\n'
    assert not _rules(_scan(tmp_path, source))


def test_plain_collected_test_class_retains_builtin_provider_proof(tmp_path):
    source = 'import pytest\nclass TestStorage:\n    def test_write(self, tmp_path):\n        (tmp_path / "payload.bin").write_bytes(b"ok")\n'
    assert not _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "suffix",
    ["\nTestStorage().test_write(external_path)\n", "\ncallback = TestStorage\n"],
)
def test_explicit_test_class_reference_keeps_warning(tmp_path, suffix):
    source = (
        'import pytest\nclass TestStorage:\n    def test_write(self, tmp_path):\n        (tmp_path / "payload.bin").write_bytes(b"ok")\n'
        + suffix
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_class_local_override_is_not_mistaken_for_builtin(tmp_path):
    source = 'import pytest\nclass TestStorage:\n    @pytest.fixture\n    def tmp_path(self):\n        return external_path\n    def test_write(self, tmp_path):\n        (tmp_path / "file").write_text("x")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_storing_owned_path_on_object_loses_side_effect_proof(tmp_path):
    source = 'import pytest\nclass TestStorage:\n    def test_write(self, tmp_path):\n        self.saved = tmp_path\n        self.mutate()\n        (tmp_path / "file").write_text("x")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "override",
    [
        "@pytest.fixture\ndef tmp_path():\n    return Path(input())\n",
        '@pytest.fixture(name="tmp_path")\ndef external_root():\n    return Path(input())\n',
        '@pytest.fixture\ndef tmp_path():\n    return Path("/srv/shared")\n',
    ],
)
def test_actual_fixture_override_keeps_warning(tmp_path, override):
    source = (
        "from pathlib import Path\nimport pytest\n"
        + override
        + '\ndef test_write(tmp_path):\n    (tmp_path / "payload.bin").write_bytes(b"ok")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_ancestor_conftest_override_keeps_warning(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "payload.bin").write_bytes(b"ok")\n'
    overrides = "from pathlib import Path\nimport pytest\n@pytest.fixture\ndef tmp_path():\n    return Path(input())\n"
    assert "SKY-D324" in _rules(
        _scan(tmp_path, source, files={"tests/conftest.py": overrides})
    )


@pytest.mark.parametrize(
    "reference",
    [
        "\ndef run():\n    test_write(Path(input()))\n",
        "\ncallback = test_write\n",
        '\ncallbacks = {"write": test_write}\n',
    ],
)
def test_direct_call_or_escape_keeps_warning(tmp_path, reference):
    source = (
        'from pathlib import Path\nimport pytest\ndef test_write(tmp_path):\n    (tmp_path / "payload.bin").write_bytes(b"ok")\n'
        + reference
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_import_alias_used_by_application_keeps_warning(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "payload.bin").write_bytes(b"ok")\n'
    caller = "from tests.test_storage import test_write as action\naction(user_path)\n"
    assert "SKY-D324" in _rules(_scan(tmp_path, source, files={"app.py": caller}))


@pytest.mark.parametrize(
    "component",
    [
        '"../outside"',
        '"/etc/target"',
        '"C:\\\\target"',
        "input()",
        'request.args["name"]',
    ],
)
def test_unsafe_descendant_keeps_warning(tmp_path, component):
    source = (
        "import pytest\ndef test_write(tmp_path):\n    (tmp_path / "
        + component
        + ').write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "body",
    [
        'tmp_path = Path(input())\n    (tmp_path / "file").write_text("x")',
        'path = tmp_path / "file"\n    path = Path(input())\n    path.write_text("x")',
        '(tmp_path.parent / "file").write_text("x")',
        'path = tmp_path / "file"\n    path.symlink_to(input())\n    path.write_text("x")',
    ],
)
def test_rebinding_parent_and_mutation_keep_warning(tmp_path, body):
    source = (
        "from pathlib import Path\nimport pytest\ndef test_write(tmp_path):\n    "
        + body
        + "\n"
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_opaque_argument_escape_declines_new_provider_evidence(tmp_path):
    source = 'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path\ndef test_write(prepared):\n    mutate(prepared)\n    (prepared / "file").write_text("x")\ndef test_builtin(tmp_path):\n    mutate(tmp_path)\n    (tmp_path / "file").write_text("x")\n'
    rows = _scan(tmp_path, source)
    assert "SKY-D324" in _rules(rows)
    # Legacy builtin opaque calls were already unreported before this change.
    assert not _rules(rows, "test_builtin")


def test_resolved_fixture_return_reaches_consumer(tmp_path):
    source = """import pytest
from starlette.responses import FileResponse
@pytest.fixture
def created_file(tmp_path):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"ok")
    return target
@pytest.fixture
def file_client(created_file):
    return FileResponse(str(created_file))
def test_write(created_file):
    return FileResponse(str(created_file))
"""
    assert not [row for row in _scan(tmp_path, source) if row["rule_id"] in PATH_RULES]


def test_conftest_fixture_alias_provider_is_resolved(tmp_path):
    provider = """import pytest as testing
@testing.fixture(name="artifact")
def create(tmp_path):
    target = tmp_path / "report.txt"
    target.write_text("ok")
    return target
"""
    source = (
        'import pytest\ndef test_write(artifact):\n    artifact.write_text("next")\n'
    )
    assert not _rules(_scan(tmp_path, source, files={"tests/conftest.py": provider}))


@pytest.mark.parametrize(
    "filename", ["experiments/render_case.py", "loadtests/response_probe.py"]
)
def test_explicit_pytest_cli_collection_supports_arbitrary_layout(tmp_path, filename):
    source = """import pytest
@pytest.fixture(scope="module", autouse=True)
def warm(tmp_path_factory):
    target = tmp_path_factory.mktemp("warm-files") / "payload.bin"
    target.write_bytes(b"ok")
@pytest.mark.parametrize("size", [1, 2])
def test_write(tmp_path, size):
    (tmp_path / "payload.bin").write_bytes(b"x" * size)
"""
    workflow = (
        "jobs:\n  tests:\n    steps:\n      - run: >-\n          uv run pytest\n          "
        + filename
        + "\n          --quiet\n"
    )
    assert not [
        row
        for row in _scan(
            tmp_path,
            source,
            filename=filename,
            files={".github/workflows/tests.yml": workflow},
        )
        if row["rule_id"] in PATH_RULES
    ]


def test_uncollected_lookalike_layout_keeps_warning(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source, filename="service/handlers.py"))


def test_parametrized_builtin_name_does_not_claim_provider(tmp_path):
    source = 'import pytest\n@pytest.mark.parametrize("tmp_path", [external_path])\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "files, builtin_safe",
    [
        ({"pytest.py": "def fixture(function): return function\n"}, False),
        ({"tests/conftest.py": 'pytest_plugins = ["custom.provider"]\n'}, False),
        (
            {
                "tests/conftest.py": "def pytest_fixture_setup(fixturedef, request): pass\n"
            },
            False,
        ),
        (
            {"plugin.py": "import importlib\nimportlib.import_module(module_name)\n"},
            True,
        ),
    ],
)
def test_unknown_provider_or_loader_context_keeps_warning(
    tmp_path, files, builtin_safe
):
    source = 'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path / "file"\ndef test_write(prepared):\n    prepared.write_text("x")\ndef test_builtin(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    rows = _scan(tmp_path, source, files=files)
    assert "SKY-D324" in _rules(rows)
    if builtin_safe:
        # Baseline already accepted this actual builtin provider; the new
        # returned-fixture proof still requires stronger caller completeness.
        assert not _rules(rows, "test_builtin")
    else:
        assert "SKY-D324" in _rules(rows, "test_builtin")


@pytest.mark.parametrize(
    "command",
    [
        "echo pytest experiments/probe.py",
        "python helper.py pytest experiments/probe.py",
        "cd experiments\npytest experiments/probe.py",
    ],
)
def test_shell_mentions_and_directory_changes_do_not_prove_collection(
    tmp_path, command
):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    workflow = "jobs:\n  test:\n    steps:\n      - run: |\n"
    for line in command.splitlines():
        workflow += "          " + line + "\n"
    rows = _scan(
        tmp_path,
        source,
        filename="experiments/probe.py",
        files={".github/workflows/test.yml": workflow},
    )
    assert "SKY-D324" in _rules(rows)


def test_nonroot_working_directory_does_not_prove_root_relative_file(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    workflow = "jobs:\n  test:\n    steps:\n      - working-directory: other\n        run: pytest experiments/probe.py\n"
    rows = _scan(
        tmp_path,
        source,
        filename="experiments/probe.py",
        files={".github/workflows/test.yml": workflow},
    )
    assert "SKY-D324" in _rules(rows)


@pytest.mark.parametrize(
    "action, expected_safe",
    [("CodSpeedHQ/action@" + "a" * 40, True), ("other/action@" + "a" * 40, False)],
)
def test_only_documented_action_command_input_proves_collection(
    tmp_path, action, expected_safe
):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    workflow = (
        "jobs:\n  test:\n    steps:\n      - uses: "
        + action
        + "\n        with:\n          run: pytest experiments/probe.py\n"
    )
    rows = _scan(
        tmp_path,
        source,
        filename="experiments/probe.py",
        files={".github/workflows/test.yml": workflow},
    )
    if expected_safe:
        assert not _rules(rows)
    else:
        assert "SKY-D324" in _rules(rows)


def test_literal_dynamic_import_of_actual_test_module_keeps_warning(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    caller = 'import importlib\nmodule = importlib.import_module("tests.test_storage")\ngetattr(module, "test_write")(external_path)\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source, files={"app.py": caller}))


@pytest.mark.parametrize(
    "mutation",
    [
        "leaf.parent.chmod(0o777)",
        "leaf.parent.rmdir()\n    leaf.parent.symlink_to(outside, target_is_directory=True)",
    ],
)
def test_mutating_a_derived_parent_loses_leaf_integrity_proof(tmp_path, mutation):
    source = (
        'import pytest\ndef test_write(tmp_path):\n    leaf = tmp_path / "file"\n    '
        + mutation
        + '\n    leaf.write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_readonly_parent_metadata_does_not_invalidate_leaf(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    leaf = tmp_path / "file"\n    leaf.parent.exists()\n    leaf.write_text("x")\n'
    assert not _rules(_scan(tmp_path, source))


def test_actual_local_writer_keeps_caller_path_but_not_public_helper_exemption(
    tmp_path,
):
    source = 'import pytest\ndef create(directory, name, data):\n    target = directory / name\n    target.write_text(data)\n    return target\ndef test_write(tmp_path):\n    create(tmp_path, "config.txt", "ok")\n    (tmp_path / "file").write_text("x")\n'
    rows = _scan(tmp_path, source)
    assert not _rules(rows)
    assert "SKY-D324" in _rules(rows, "create")


def test_local_writer_that_redirects_path_keeps_caller_warning(tmp_path):
    source = 'import pytest\ndef create(directory, name, data):\n    target = directory / name\n    target.symlink_to(external_target)\n    return target\ndef test_write(tmp_path):\n    create(tmp_path, "file", "ok")\n    (tmp_path / "file").write_text("x")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_source_context_unavailable_keeps_warning():
    findings = []
    source = 'def test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    scan(
        ast.parse(source), Path("not-existing-project/tests/test_storage.py"), findings
    )
    assert "SKY-D324" in _rules(findings)


@pytest.mark.parametrize(
    "registration, safe",
    [
        ("pytest_plugins = []\n", True),
        ("pytest_plugins = []\npytest_plugins.append('custom.provider')\n", False),
    ],
)
def test_empty_plugin_declaration_requires_no_mutation_or_escape(
    tmp_path, registration, safe
):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    rows = _scan(tmp_path, source, files={"tests/conftest.py": registration})
    if safe:
        assert not _rules(rows)
    else:
        assert "SKY-D324" in _rules(rows)


@pytest.mark.parametrize(
    "lookup",
    [
        "import importlib.util\ndef directory(name):\n    spec = importlib.util.find_spec(name)\n    assert spec is not None\n    return spec.origin\n",
        "from importlib.util import find_spec as locate\ndef directory(name):\n    spec = locate(name)\n    return spec.submodule_search_locations\n",
    ],
)
def test_unrelated_proven_metadata_query_does_not_poison_fixture_provider(
    tmp_path, lookup
):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    assert not _rules(_scan(tmp_path, source, files={"resources.py": lookup}))


@pytest.mark.parametrize(
    "lookup",
    [
        "import importlib.util\ndef load(name):\n    spec = importlib.util.find_spec(name)\n    spec.loader.exec_module(target)\n",
        "import importlib.util\ndef load(name):\n    spec = importlib.util.find_spec(name)\n    return spec\n",
        "import importlib.util\ndef load(name):\n    spec = importlib.util.find_spec(name)\n    custom(spec)\n",
        "import importlib\ndef load(name, function):\n    module = importlib.import_module(name)\n    return getattr(module, function)(user_path)\n",
    ],
)
def test_unknown_or_executable_loader_still_keeps_warning(tmp_path, lookup):
    source = 'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path / "file"\ndef test_write(prepared):\n    prepared.write_text("x")\ndef test_builtin(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    rows = _scan(tmp_path, source, files={"loader.py": lookup})
    assert "SKY-D324" in _rules(rows)
    assert not _rules(rows, "test_builtin")


def test_autouse_fixture_can_redirect_fixed_child_before_test(tmp_path):
    source = """import pytest
@pytest.fixture(autouse=True)
def redirect(tmp_path):
    (tmp_path / "file").symlink_to(external_target)
def test_write(tmp_path):
    (tmp_path / "file").write_text("x")
"""
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_autouse_transitive_path_dependency_keeps_warning(tmp_path):
    source = """import pytest
@pytest.fixture
def prepared(tmp_path):
    return tmp_path / "file"
@pytest.fixture(autouse=True)
def redirect(prepared):
    prepared.symlink_to(external_target)
def test_write(prepared):
    prepared.write_text("x")
"""
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_autouse_dynamic_fixture_lookup_keeps_warning(tmp_path):
    source = """import pytest
@pytest.fixture(autouse=True)
def redirect(request):
    target = request.getfixturevalue("tmp_path") / "file"
    target.symlink_to(external_target)
def test_write(tmp_path):
    (tmp_path / "file").write_text("x")
"""
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "mutation",
    [
        "alias = pytest\nmutate(alias)",
        "mutate(pytest)",
        "pytest.fixture = custom",
        "pytest.__dict__.update(replacements)",
    ],
)
def test_mutated_or_escaped_pytest_binding_is_not_a_provider_proof(tmp_path, mutation):
    source = (
        "import pytest\n"
        + mutation
        + '\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path / "file"\ndef test_write(prepared):\n    prepared.write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "mutation, expression",
    [
        ("import sys\nsys.modules['pathlib'] = custom_provider\n", "Path(tmp_path)"),
        ("import sys\nsys.meta_path.append(custom_provider)\n", "Path(tmp_path)"),
        ("import builtins\nbuiltins.str = custom_provider\n", "str(tmp_path)"),
    ],
)
def test_replaced_constructor_provider_is_not_fixture_path_proof(
    tmp_path, mutation, expression
):
    source = (
        mutation
        + "from pathlib import Path\nimport pytest\n"
        + "@pytest.fixture\ndef prepared(tmp_path):\n    return "
        + expression
        + '\ndef test_write(prepared):\n    (prepared / "file").write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "hook",
    [
        "from helpers import pytest_pyfunc_call\n",
        "from helpers import replace_args as pytest_pyfunc_call\n",
        "pytest_pyfunc_call = replace_args\n",
    ],
)
def test_imported_or_assigned_fixture_mutation_hook_keeps_warning(tmp_path, hook):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    assert "SKY-D324" in _rules(
        _scan(tmp_path, source, files={"tests/conftest.py": hook})
    )


@pytest.mark.parametrize(
    "options",
    ["-o python_files=*.py", "--override-ini=python_files=*.py", "other_tests"],
)
def test_collection_configuration_overrides_do_not_prove_fixture_context(
    tmp_path, options
):
    source = 'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path / "file"\ndef test_write(prepared):\n    prepared.write_text("x")\n'
    assert "SKY-D324" in _rules(
        _scan(
            tmp_path,
            source,
            files={"pytest.ini": "[pytest]\naddopts = " + options + "\n"},
        )
    )


def test_source_resolved_identity_helper_keeps_path_proof(tmp_path):
    source = 'import pytest\ndef prepare(path):\n    return path\ndef test_write(tmp_path):\n    prepared = prepare(tmp_path)\n    (prepared / "file").write_text("x")\n'
    assert not _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "parameter", ["tmp_path=external_path", "tmp_path, /", "*, tmp_path=external_path"]
)
def test_provider_defaults_and_positional_only_arguments_are_not_injected(
    tmp_path, parameter
):
    source = (
        "import pytest\n@pytest.fixture\ndef prepared("
        + parameter
        + '):\n    return tmp_path / "file"\ndef test_write(prepared):\n    prepared.write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_creating_owned_path_ancestor_keeps_temporary_directory_proof(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    target = tmp_path / "nested" / "file"\n    target.parent.mkdir(parents=True, exist_ok=True)\n    target.write_text("x")\n'
    assert not _rules(_scan(tmp_path, source))
