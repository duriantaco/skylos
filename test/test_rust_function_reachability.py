"""Closed private cycles must not become roots merely by referring to each other."""

import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze


def project(tmp_path, files):
    for name, source in files.items():
        path = tmp_path / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(source).lstrip())


def scan(tmp_path, grep_verify):
    result = json.loads(
        analyze(str(tmp_path), conf=40, grep_verify=grep_verify, grep_cache=False)
    )
    assert not result.get("analysis_errors")
    return {item["full_name"] for item in result.get("unused_functions", [])}


@pytest.mark.parametrize("grep_verify", [False, True])
def test_private_cycle_and_its_dead_owner_are_unused(tmp_path, grep_verify):
    project(
        tmp_path,
        {
            "main.rs": """
        fn alpha() { beta(); }
        fn beta() { alpha(); }
        fn abandoned() { alpha(); beta(); }
        fn main() {}
    """
        },
    )
    assert scan(tmp_path, grep_verify) == {"alpha", "beta", "abandoned"}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "entry", ["alpha();", "let run = alpha; run();", "external(alpha);"]
)
def test_real_call_or_function_value_keeps_the_whole_cycle(
    tmp_path, grep_verify, entry
):
    project(
        tmp_path,
        {
            "main.rs": f"""
        fn alpha() {{ beta(); }}
        fn beta() {{ alpha(); }}
        fn main() {{ {entry} }}
    """
        },
    )
    assert not scan(tmp_path, grep_verify)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_child_module_can_reach_private_parent_cycle(tmp_path, grep_verify):
    project(
        tmp_path,
        {
            "main.rs": """
            mod child;
            fn alpha() { beta(); }
            fn beta() { alpha(); }
            fn main() { child::start(); }
        """,
            "child.rs": "pub(super) fn start() { super::alpha(); }",
        },
    )
    assert not scan(tmp_path, grep_verify)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "declaration",
    ["pub fn alpha", "#[entry] fn alpha", '#[cfg(feature="other")] fn alpha'],
)
def test_public_attribute_or_cfg_uncertainty_preserves_cycle(
    tmp_path, grep_verify, declaration
):
    project(
        tmp_path,
        {
            "main.rs": f"""
        {declaration}() {{ beta(); }}
        fn beta() {{ alpha(); }}
        fn main() {{}}
    """
        },
    )
    assert not scan(tmp_path, grep_verify)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_external_macro_expansion_does_not_establish_a_closed_program(
    tmp_path, grep_verify
):
    project(
        tmp_path,
        {
            "main.rs": """
        external_macro!();
        fn alpha() { beta(); }
        fn beta() { alpha(); }
        fn main() {}
    """
        },
    )
    assert not scan(tmp_path, grep_verify)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_repeated_internal_calls_do_not_make_dead_cycle_live(tmp_path, grep_verify):
    project(
        tmp_path,
        {
            "main.rs": """
        fn alpha() { beta(); beta(); beta(); }
        fn beta() { alpha(); alpha(); }
        fn main() {}
    """
        },
    )
    assert scan(tmp_path, grep_verify) == {"alpha", "beta"}


@pytest.mark.parametrize("grep_verify", [False, True])
def test_private_self_recursion_is_not_an_entry(tmp_path, grep_verify):
    project(
        tmp_path,
        {
            "main.rs": """
        fn alpha() {
            alpha();
        }
        fn main() {}
    """
        },
    )
    assert scan(tmp_path, grep_verify) == {"alpha"}


def local_definitions(tmp_path):
    from collections import Counter
    from skylos.visitors.languages.rust.core import RustCore

    path = tmp_path / "src" / "main.rs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fn alpha() { beta(); }\nfn beta() { alpha(); }\nfn main() {}\n")
    core = RustCore(str(path), path.read_bytes())
    core.scan()
    counts = Counter(name for name, _ in core.refs)
    definitions = {definition.name: definition for definition in core.defs}
    for definition in definitions.values():
        definition.references = counts[definition.name]
    return definitions, path


@pytest.mark.parametrize(
    "uncertainty", ["partial", "error", "changed_source", "unknown_reference"]
)
def test_uncertain_project_or_reference_counts_cannot_prove_dead_cycle(
    tmp_path, uncertainty
):
    from skylos.visitors.languages.rust.reachability import analyze_rust_reachability

    definitions, path = local_definitions(tmp_path)
    scope, errors = {"complete_repository": True}, []
    if uncertainty == "partial":
        scope["complete_repository"] = False
    elif uncertainty == "error":
        errors.append({"kind": "source_read_error"})
    elif uncertainty == "changed_source":
        path.write_text(path.read_text() + "// source changed after parse\n")
    else:
        definitions["alpha"].references += 1
    report = analyze_rust_reachability(definitions, tmp_path, scope, errors)
    assert not report.unreachable_keys


def test_grep_discards_only_exact_proved_dead_owner_lines(tmp_path):
    from skylos.visitors.languages.rust.reachability import analyze_rust_reachability

    definitions, path = local_definitions(tmp_path)
    report = analyze_rust_reachability(
        definitions, tmp_path, {"complete_repository": True}, []
    )
    assert report.unreachable_keys == {"alpha", "beta"}
    dead = f"{path}:2:fn beta() {{ alpha(); }}"
    config = f"{tmp_path / 'config.toml'}:4:handler='alpha'"
    changed = f"{path}:2:fn beta() {{ alpha(); unknown(alpha); }}"
    unknown_line = f"{path}:99:alpha()"
    raw = {"function_calls": [dead, config, changed, unknown_line], "count": 4}
    assert report.filter_grep_results(definitions["alpha"].to_dict(), raw) == {
        "function_calls": [config, changed, unknown_line],
        "count": 4,
    }
    assert raw["function_calls"] == [dead, config, changed, unknown_line]


@pytest.mark.parametrize("rescued", ["alpha", "beta"])
def test_later_grep_rescue_restores_other_cycle_members(tmp_path, rescued):
    from skylos.analyzer import Skylos

    definitions, _ = local_definitions(tmp_path)
    analyzer = Skylos()
    analyzer.defs = definitions
    analyzer._project_root = tmp_path
    analyzer._analysis_scope = {"complete_repository": True}
    analyzer._propagate_transitive_dead()
    assert definitions["alpha"].references == definitions["beta"].references == 0
    callee = "beta" if rescued == "alpha" else "alpha"
    killed = analyzer._transitive_dead_kills
    analyzer._transitive_dead_kills = {callee: killed[callee], rescued: killed[rescued]}
    definitions[rescued].references = 1  # A retained grep hit rescues this member.
    analyzer._restore_transitive_dead_callees()
    assert definitions["alpha"].references > 0
    assert definitions["beta"].references > 0


@pytest.mark.parametrize("grep_verify", [False, True])
def test_local_macro_arguments_can_generate_external_function_roots(
    tmp_path, grep_verify
):
    project(
        tmp_path,
        {
            "main.rs": """
        macro_rules! register {
            ($target:path) => {
                #[no_mangle]
                pub extern "C" fn entry() { $target(); }
            }
        }
        fn alpha() { beta(); }
        fn beta() { alpha(); }
        fn abandoned() { register!(alpha); }
        fn main() {}
    """
        },
    )
    assert scan(tmp_path, grep_verify) == {"abandoned"}


@pytest.mark.parametrize(
    "attribute",
    [
        '#[cfg_attr(feature="enabled", hook::keep)]',
        '#[cfg_attr(feature="enabled", cfg_attr(unix, hook::keep))]',
        '#[cfg_attr(feature="enabled", derive(hook::Keep))]',
    ],
)
def test_conditional_external_attribute_cannot_prove_a_closed_file(tmp_path, attribute):
    project(
        tmp_path,
        {
            "main.rs": f"""
        {attribute}
        struct Guard;
        fn alpha() {{ beta(); }}
        fn beta() {{ alpha(); }}
        fn main() {{ generated(); }}
    """
        },
    )
    assert not scan(tmp_path, True)


@pytest.mark.parametrize(
    "attribute",
    [
        '#[cfg_attr(feature="enabled", allow(dead_code))]',
        '#[cfg_attr(feature="enabled", cfg_attr(unix, allow(dead_code)))]',
        '#[cfg_attr(feature="enabled", derive(Clone, Copy))]',
    ],
)
def test_conditional_builtin_metadata_keeps_closed_cycle_proof(tmp_path, attribute):
    project(
        tmp_path,
        {
            "main.rs": f"""
        {attribute}
        struct Guard;
        fn alpha() {{ beta(); }}
        fn beta() {{ alpha(); }}
        fn main() {{}}
    """
        },
    )
    assert scan(tmp_path, True) == {"alpha", "beta"}
