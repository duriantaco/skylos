"""Source-only reachability proofs and conservative boundaries; fixtures never run."""

import ast
import json
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.deadcode.reachability import analyze_python_reachability
from skylos.visitors.base import Definition


def _fixture_module_names(files, root):
    names = {}
    for path in files:
        parts = list(path.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        names[path] = ".".join(parts)
    return names


def _analyze(definitions, files, root):
    return analyze_python_reachability(
        definitions, files, root, module_names=_fixture_module_names(files, root)
    )


def _project(tmp_path, sources):
    definitions = {}
    files = []
    for filename, source in sources.items():
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        source = textwrap.dedent(source).lstrip()
        assert write_text_no_symlink(path, source)
        files.append(path)
        module = filename.removesuffix(".py").replace("/", ".")
        for node in ast.parse(source).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = f"{module}.{node.name}"
                definitions[key] = Definition(key, "function", path, node.lineno, node)
    return definitions, files


def _report(tmp_path, sources):
    definitions, files = _project(tmp_path, sources)
    return _analyze(definitions, files, tmp_path)


@pytest.mark.parametrize("live", [False, True])
def test_recursive_group_and_dead_call_chain(tmp_path, live):
    report = _report(
        tmp_path,
        {
            "worker.py": textwrap.dedent("""
        def alpha():
            return beta()
        def beta():
            return alpha()
        def entry():
            return alpha()
        """)
            + ("\nentry()\n" if live else "")
        },
    )
    expected = {"worker.alpha", "worker.beta", "worker.entry"}
    assert report.unreachable_keys == (set() if live else expected)
    assert report.proven_reachable_keys == (expected if live else set())


@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize(
    "import_line,call",
    [
        ("from worker import beta as alias", "alias()"),
        ("import worker as alias", "alias.beta()"),
    ],
)
def test_cross_module_aliases_have_caller_ownership(tmp_path, live, import_line, call):
    report = _report(
        tmp_path,
        {
            "worker.py": "def beta(): return 1\n",
            "app.py": f"{import_line}\ndef alpha(): return {call}\n"
            + ("alpha()\n" if live else ""),
        },
    )
    assert report.unreachable_keys == (set() if live else {"worker.beta", "app.alpha"})


@pytest.mark.parametrize(
    "expression",
    [
        "def receiver(value=leaf()): return value",
        "def receiver(value: leaf()): return value",
        "def receiver() -> leaf(): return None",
        "class Container:\n    value = leaf()",
        "@leaf()\ndef receiver(): return None",
        "register(leaf)",
    ],
)
def test_definition_time_and_callback_roots_are_positive(tmp_path, expression):
    report = _report(
        tmp_path, {"worker.py": "def leaf(): return int\n" + expression + "\n"}
    )
    assert "worker.leaf" in report.proven_reachable_keys
    assert "worker.leaf" not in report.unreachable_keys


@pytest.mark.parametrize(
    "body",
    [
        "class Container:\n    def method(self): return leaf()",
        "def outer():\n    def inner(): return leaf()\n    return inner",
        "callback = lambda: leaf()",
    ],
)
def test_unsupported_owners_protect_without_positive_execution_claim(tmp_path, body):
    report = _report(tmp_path, {"worker.py": "def leaf(): return 1\n" + body + "\n"})
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


@pytest.mark.parametrize(
    "root_attribute,root_value",
    [
        ("is_exported", True),
        ("decorators", ["framework.route"]),
        ("dynamic_signals", ["unknown callback"]),
        ("framework_signals", ["route"]),
        ("heuristic_refs", {"package_entrypoint": 1.0}),
        ("heuristic_refs", {"coverage_hit": 1.0}),
        ("heuristic_refs", {"dead_code_liveness:callback": 1.0}),
    ],
)
def test_existing_external_evidence_roots_preserve_descendants(
    tmp_path, root_attribute, root_value
):
    definitions, files = _project(
        tmp_path, {"worker.py": "def leaf(): return 1\ndef entry(): return leaf()\n"}
    )
    setattr(definitions["worker.entry"], root_attribute, root_value)
    report = _analyze(definitions, files, tmp_path)
    assert report.unreachable_keys == set()


def test_unattributed_reference_and_unknown_caller_stay_conservative(tmp_path):
    definitions, files = _project(
        tmp_path, {"worker.py": "def first(): return 1\ndef second(): return 2\n"}
    )
    definitions["worker.first"].references = 1
    definitions["worker.second"].called_by.add("unknown.registered_callback")
    report = _analyze(definitions, files, tmp_path)
    assert report.unreachable_keys == set()
    assert report.proven_reachable_keys == set()


def test_counted_recursive_references_are_edges_not_roots(tmp_path):
    definitions, files = _project(
        tmp_path,
        {"worker.py": "def first(): return second()\ndef second(): return first()\n"},
    )
    for key, definition in definitions.items():
        definition.references = 1
        definition.called_by.add(
            "worker.second" if key.endswith("first") else "worker.first"
        )
    report = _analyze(definitions, files, tmp_path)
    assert report.unreachable_keys == set(definitions)


@pytest.mark.parametrize(
    "expression",
    [
        "getattr(worker, requested)()",
        "vars(worker)",
        "globals()[requested]()",
        "external(worker)",
    ],
)
def test_reflection_and_module_escape_are_uncertain_roots(tmp_path, expression):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\n",
            "app.py": "import worker\n" + expression + "\n",
        },
    )
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


def test_dead_reflection_is_not_itself_a_live_root(tmp_path):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef caller(name): return globals()[name]()\n"
        },
    )
    assert report.unreachable_keys == {"worker.leaf", "worker.caller"}


def test_shadowed_unknown_reference_does_not_create_new_negative(tmp_path):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef caller(leaf): return leaf()\ncaller(external)\n"
        },
    )
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


def test_rebinding_is_excluded_from_supported_negative_scope(tmp_path):
    report = _report(
        tmp_path, {"worker.py": "def leaf(): return 1\nleaf = register(leaf)\n"}
    )
    assert report.unreachable_keys == set()


def test_refresh_revives_only_resolved_descendants_without_reparse(
    tmp_path, monkeypatch
):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef entry(): return leaf()\ndef spare(): return 2\n"
        },
    )

    def no_parse(_):
        pytest.fail("refresh must reuse the source graph")

    monkeypatch.setattr("skylos.deadcode.reachability.parse_python_files", no_parse)
    for definition in report._definitions.values():
        definition.heuristic_refs["unreachable_group"] = 1.0
    report.refresh()
    assert len(report.unreachable_keys) == 3
    report.refresh(additional_roots={"worker.entry"})
    assert report.unreachable_keys == {"worker.spare"}
    assert report.proven_reachable_keys == {"worker.entry", "worker.leaf"}


def test_incomplete_parse_never_proves_unreachable(tmp_path):
    definitions, files = _project(tmp_path, {"worker.py": "def leaf(): return 1\n"})
    broken = tmp_path / "broken.py"
    assert write_text_no_symlink(broken, "def broken(\n")
    report = _analyze(definitions, [*files, broken], tmp_path)
    assert not report.complete
    assert report.unreachable_keys == set()
    assert report.incomplete_reasons


def test_grep_discards_dead_owner_but_keeps_configuration_and_unknown_hits(tmp_path):
    report = _report(
        tmp_path, {"worker.py": "def leaf(): return 1\ndef caller(): return leaf()\n"}
    )
    finding = report._definitions["worker.leaf"].to_dict()
    dead = f"{tmp_path / 'worker.py'}:2:def caller(): return leaf()"
    config = f"{tmp_path / 'setup.cfg'}:8:callback=worker.leaf"
    unknown = f"{tmp_path / 'worker.py'}:20:leaf()"
    raw = {"function_calls": [dead, config, unknown], "other": 3}
    assert report.filter_grep_results(finding, raw) == {
        "function_calls": [config, unknown],
        "other": 3,
    }
    assert raw["function_calls"] == [dead, config, unknown]
    report.refresh(additional_roots={"worker.caller"})
    assert report.filter_grep_results(finding, raw) == raw


def test_uncertain_candidate_keeps_all_existing_grep_evidence(tmp_path):
    definitions, files = _project(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef caller(): return leaf()\n",
        },
    )
    definitions["worker.leaf"].dynamic_signals = ["unresolved callback"]
    report = _analyze(definitions, files, tmp_path)
    raw = {
        "function_calls": [f"{tmp_path / 'worker.py'}:2:def caller(): return leaf()"]
    }
    assert "worker.caller" in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys
    assert report.filter_grep_results(definitions["worker.leaf"].to_dict(), raw) == raw


def test_grep_same_name_resolution_uses_definition_identity(tmp_path):
    report = _report(
        tmp_path,
        {
            "alpha.py": "def read_record(): return 1\n",
            "beta.py": "def read_record(): return 2\n",
            "app.py": "from beta import read_record\nread_record()\n",
        },
    )
    raw = {"function_calls": [f"{tmp_path / 'app.py'}:2:read_record()"]}
    assert report.unreachable_keys == {"alpha.read_record"}
    assert report.filter_grep_results(
        report._definitions["alpha.read_record"].to_dict(), raw
    ) == {
        "function_calls": [],
    }
    assert (
        report.filter_grep_results(
            report._definitions["beta.read_record"].to_dict(), raw
        )
        == raw
    )


def test_grep_keeps_mixed_unknown_and_resolved_matches_on_same_line(tmp_path):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef caller(obj): return leaf() + obj.leaf()\n"
        },
    )
    raw = {
        "function_calls": [
            f"{tmp_path / 'worker.py'}:2:def caller(obj): return leaf() + obj.leaf()"
        ]
    }
    assert (
        report.filter_grep_results(report._definitions["worker.leaf"].to_dict(), raw)
        == raw
    )


def test_string_callback_and_other_symbol_on_one_line_keep_uncertainty(tmp_path):
    report = _report(
        tmp_path,
        {
            "alpha.py": "def leaf(): return 1\n",
            "beta.py": "def leaf(): return 2\n",
            "app.py": "import beta\nregister('alpha.leaf'); beta.leaf()\n",
        },
    )
    raw = {
        "function_calls": [
            f"{tmp_path / 'app.py'}:2:register('alpha.leaf'); beta.leaf()"
        ]
    }
    assert "alpha.leaf" not in report.unreachable_keys
    assert "alpha.leaf" not in report.proven_reachable_keys
    assert (
        report.filter_grep_results(report._definitions["alpha.leaf"].to_dict(), raw)
        == raw
    )


@pytest.mark.parametrize("scope", ["module", "live-function", "dead-function"])
def test_rebound_import_alias_keeps_its_original_possible_target(tmp_path, scope):
    body = "from worker import leaf as alias\nalias = register(alias)\nalias()\n"
    if scope != "module":
        body = "def entry():\n" + textwrap.indent(body, "    ")
        if scope == "live-function":
            body += "entry()\n"
    report = _report(tmp_path, {"worker.py": "def leaf(): return 1\n", "app.py": body})
    assert ("worker.leaf" in report.unreachable_keys) == (scope == "dead-function")
    assert "worker.leaf" not in report.proven_reachable_keys


@pytest.mark.parametrize(
    "body",
    [
        "if condition:\n    from worker import leaf as alias\nalias()\n",
        "from missing_package.worker import leaf as alias\nalias()\n",
    ],
)
def test_unresolved_or_conditional_import_alias_remains_uncertain(tmp_path, body):
    report = _report(tmp_path, {"worker.py": "def leaf(): return 1\n", "app.py": body})
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


def test_escaping_facade_module_protects_reexported_functions(tmp_path):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\n",
            "facade.py": "from worker import leaf\n",
            "app.py": "import facade\nregister(facade)\n",
        },
    )
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


@pytest.mark.parametrize(
    "exports",
    [
        "__all__ = computed_names",
        "__all__ = []; __all__.extend(names)",
        "__all__: list[str] = names",
        "__all__ = []; __all__ += names",
    ],
)
def test_dynamic_export_list_stays_conservative(tmp_path, exports):
    report = _report(tmp_path, {"worker.py": "def leaf(): return 1\n" + exports + "\n"})
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


def test_static_export_list_does_not_protect_unrelated_private_group(tmp_path):
    report = _report(
        tmp_path,
        {
            "worker.py": "def public(): return 1\ndef private(): return 2\n__all__ = ['public']\n"
        },
    )
    assert report.unreachable_keys == {"worker.private"}


@pytest.mark.parametrize(
    "body",
    [
        "lookup = getattr\nlookup(module, requested)()",
        "from builtins import getattr as lookup\nlookup(module, requested)()",
        "from importlib import import_module as lookup\nlookup(requested)",
        "namespace = callback.__globals__\nnamespace[requested]()",
        "namespace = __builtins__\nnamespace[requested](module, member)()",
    ],
)
def test_reflection_aliases_remain_uncertain(tmp_path, body):
    report = _report(tmp_path, {"worker.py": "def leaf(): return 1\n" + body + "\n"})
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


def test_dynamic_module_attribute_preserves_its_returned_function(tmp_path):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef __getattr__(name): return leaf\n",
            "app.py": "from worker import dynamic_alias\ndynamic_alias()\n",
        },
    )
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


@pytest.mark.parametrize(
    "body",
    [
        "values = [leaf for leaf in providers]\n    return leaf()",
        "if (leaf := provider):\n        return leaf()",
        "match payload:\n        case {'item': item, **leaf}:\n            return leaf()",
    ],
)
def test_unsupported_binding_scopes_never_create_new_negative(tmp_path, body):
    report = _report(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\ndef entry():\n    "
            + body
            + "\nentry()\n"
        },
    )
    assert "worker.leaf" not in report.unreachable_keys
    assert "worker.leaf" not in report.proven_reachable_keys


@pytest.mark.parametrize("resolved", [True, False])
def test_global_attribute_name_credit_does_not_override_source_identity(
    tmp_path, resolved
):
    definitions, files = _project(
        tmp_path,
        {
            "north/tasks.py": "def decode_packet(): return 1\n",
            "south/tasks.py": "def decode_packet(): return 2\n",
            "app.py": "import north.tasks as selected\nselected.decode_packet()\n"
            if resolved
            else "receiver.decode_packet()\n",
        },
    )
    for definition in definitions.values():
        definition.references = 1
        definition._attr_name_ref_count = 1
    report = _analyze(definitions, files, tmp_path)
    assert report.unreachable_keys == (
        {"south.tasks.decode_packet"} if resolved else set()
    )
    assert report.proven_reachable_keys == (
        {"north.tasks.decode_packet"} if resolved else set()
    )


def test_genuine_reference_gap_survives_attribute_credit_discount(tmp_path):
    definitions, files = _project(tmp_path, {"worker.py": "def leaf(): return 1\n"})
    definitions["worker.leaf"].references = 2
    definitions["worker.leaf"]._attr_name_ref_count = 1
    report = _analyze(definitions, files, tmp_path)
    assert report.unreachable_keys == set()
    assert report.proven_reachable_keys == set()


def test_grep_header_reference_is_owned_by_module_execution(tmp_path):
    report = _report(
        tmp_path,
        {"worker.py": "def leaf(): return 1\ndef caller(value=leaf()): return value\n"},
    )
    raw = {
        "function_calls": [
            f"{tmp_path / 'worker.py'}:2:def caller(value=leaf()): return value"
        ]
    }
    assert "worker.caller" in report.unreachable_keys
    assert (
        report.filter_grep_results(report._definitions["worker.leaf"].to_dict(), raw)
        == raw
    )


def test_standalone_identity_comes_from_definition_metadata(tmp_path):
    definitions, files = _project(
        tmp_path,
        {
            "unusual_sources/worker.py": "def leaf(): return 1\ndef caller(): return leaf()\n",
        },
    )
    for definition in definitions.values():
        definition.name = f"application.backend.{definition.simple_name}"
    report = analyze_python_reachability(definitions, files, tmp_path)
    assert report.complete
    assert report.index.modules[files[0]].names == {"application.backend"}
    assert report.unreachable_keys == set(definitions)


def test_standalone_missing_identity_disables_negative_conclusions(tmp_path):
    definitions, files = _project(
        tmp_path,
        {
            "worker.py": "def leaf(): return 1\n",
            "facade.py": "from worker import leaf\n",
            "app.py": "import facade\nregister(facade)\n",
        },
    )
    report = analyze_python_reachability(definitions, files, tmp_path)
    assert not report.complete
    assert report.unreachable_keys == set()
    assert any(
        "canonical module identities" in reason for reason in report.incomplete_reasons
    )


def test_explicit_missing_map_entry_does_not_fall_back_to_names(tmp_path):
    definitions, files = _project(tmp_path, {"worker.py": "def leaf(): return 1\n"})
    report = analyze_python_reachability(definitions, files, tmp_path, module_names={})
    assert not report.complete
    assert report.unreachable_keys == set()


def test_explicit_empty_root_module_identity_is_valid(tmp_path):
    definitions, files = _project(
        tmp_path,
        {
            "__init__.py": "",
            "worker.py": "def leaf(): return 1\n",
        },
    )
    report = _analyze(definitions, files, tmp_path)
    assert report.complete
    assert report.index.modules[tmp_path / "__init__.py"].names == {""}
    assert report.unreachable_keys == {"worker.leaf"}


@pytest.mark.parametrize("live", [False, True])
def test_authoritative_names_resolve_nonstandard_source_layout(tmp_path, live):
    definitions, files = _project(
        tmp_path,
        {
            "deployment/plugins/worker.py": "def leaf(): return 1\n",
            "deployment/plugins/entry.py": "from .worker import leaf as callback\ndef launch(): return callback()\n"
            + ("launch()\n" if live else ""),
        },
    )
    identities = {
        files[0]: "application.worker",
        files[1]: "application.entry",
    }
    report = analyze_python_reachability(
        definitions, files, tmp_path, module_names=identities
    )
    assert report.complete
    assert report.index.modules[files[0]].names == {"application.worker"}
    assert report.index.modules[files[1]].names == {"application.entry"}
    assert report.unreachable_keys == (set() if live else set(definitions))
    assert report.proven_reachable_keys == (set(definitions) if live else set())


@pytest.mark.parametrize("live", [False, True])
def test_duplicate_canonical_module_names_keep_import_resolution_uncertain(
    tmp_path, live
):
    definitions, files = _project(
        tmp_path,
        {
            "north/worker.py": "def leaf(): return 1\n",
            "south/worker.py": "def leaf(): return 2\n",
            "app.py": "def launch():\n    from shared.worker import leaf as callback\n    return callback()\n"
            + ("launch()\n" if live else ""),
        },
    )
    report = analyze_python_reachability(
        definitions,
        files,
        tmp_path,
        module_names={
            files[0]: "shared.worker",
            files[1]: "shared.worker",
            files[2]: "app",
        },
    )
    assert report.complete
    assert report.unreachable_keys == (set() if live else set(definitions))
    assert report.proven_reachable_keys == ({"app.launch"} if live else set())


def _write_package_name_control(root, package, second_live):
    main = "import worker\nprint(worker.render_report(2))\n"
    if second_live:
        main += f"import {package}.worker\nprint({package}.worker.render_report(2))\n"
    _project(
        root,
        {
            "worker.py": "def render_report(value): return value + 1\n",
            f"{package}/__init__.py": "",
            f"{package}/worker.py": "def render_report(value): return value - 1\n",
            "main.py": main,
        },
    )


@pytest.mark.parametrize("package", ["src", "lib", "python", "warehouse"])
@pytest.mark.parametrize("second_live", [False, True])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_analyzer_preserves_real_package_names(
    tmp_path, package, second_live, grep_verify
):
    from skylos.analyzer import Skylos

    _write_package_name_control(tmp_path, package, second_live)
    scanner = Skylos()
    result = json.loads(
        scanner.analyze(
            str(tmp_path), trace_file=False, grep_verify=grep_verify, grep_cache=False
        )
    )
    report = scanner._python_reachability_report
    assert report.complete
    assert report.index.modules[tmp_path / package / "worker.py"].names == {
        f"{package}.worker"
    }
    unused = {row["full_name"] for row in result.get("unused_functions", [])}
    assert "worker.render_report" not in unused
    assert (f"{package}.worker.render_report" in unused) is (not second_live)


@pytest.mark.parametrize("live", [False, True])
def test_actual_analyzer_uses_nonstandard_package_root(tmp_path, live):
    from skylos.analyzer import Skylos

    root = tmp_path / "application_core"
    _project(
        root,
        {
            "__init__.py": "",
            "worker.py": "def leaf(): return 1\n",
            "entry.py": "from .worker import leaf as callback\ndef launch(): return callback()\n"
            + ("launch()\n" if live else ""),
        },
    )
    scanner = Skylos()
    scanner.analyze(str(root), trace_file=False, grep_verify=False, grep_cache=False)
    report = scanner._python_reachability_report
    assert report.complete
    assert report.index.modules[root / "worker.py"].names == {"application_core.worker"}
    assert report.index.modules[root / "entry.py"].names == {"application_core.entry"}
    expected = {"application_core.worker.leaf", "application_core.entry.launch"}
    assert report.unreachable_keys & expected == (set() if live else expected)
    assert report.proven_reachable_keys & expected == (expected if live else set())


@pytest.mark.parametrize("package", ["src", "warehouse"])
def test_cli_keeps_real_package_and_top_level_module_distinct(tmp_path, package):
    _write_package_name_control(tmp_path, package, False)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from skylos.cli import main; main()",
            str(tmp_path),
            "--format",
            "json",
            "--no-upload",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    unused = {row["full_name"] for row in result.get("unused_functions", [])}
    assert "worker.render_report" not in unused
    assert f"{package}.worker.render_report" in unused
