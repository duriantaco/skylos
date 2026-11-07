import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file
from skylos.visitors.languages.rust.core import RustCore


def project(tmp_path, source):
    path = tmp_path / "src" / "main.rs"
    path.parent.mkdir(parents=True)
    path.write_text(dedent(source).lstrip())
    return path


def unused(tmp_path, grep_verify=False, conf=40):
    report = json.loads(analyze(str(tmp_path), conf=conf, grep_verify=grep_verify))
    assert not report.get("analysis_errors")
    return {item["full_name"]: item for item in report.get("unused_functions", [])}


@pytest.mark.parametrize("grep_verify", [False, True])
def test_parameter_and_local_value_do_not_rescue_same_named_function(
    tmp_path, grep_verify
):
    project(
        tmp_path,
        """
        fn callback() {}
        fn used_source() {}
        fn invoke(callback: fn()) { callback(); }
        fn main() { let callback = used_source; invoke(callback); }
        """,
    )
    findings = unused(tmp_path, grep_verify)
    assert set(findings) == {"callback"}
    assert findings["callback"]["confidence"] <= 40
    assert not unused(tmp_path, grep_verify, conf=60)


@pytest.mark.parametrize(
    "binding",
    [
        "let callback = external(); callback();",
        "let callback=external();callback();",
        "let mut callback = external(); callback();",
        "let (callback, other) = external(); callback();",
        "let Some(callback) = external() else { return }; callback();",
        "let Holder { callback } = external(); callback();",
        "let Holder { slot: callback } = external(); callback();",
        "for callback in external() { callback(); }",
        "if let Some(callback) = external() { callback(); }",
        "while let Some(callback) = external() { callback(); }",
        "match external() { Some(callback) => callback(), _ => () }",
        "match external() { Some(callback) if callback() => (), _ => () }",
        "let closure = |callback: fn()| callback(); external(closure);",
        "let closure = |(callback, other)| callback(); external(closure);",
        "let callback = external(); let closure = || callback(); external(closure);",
        "{ let callback = external(); { callback(); } }",
    ],
)
def test_proven_pattern_and_closure_bindings_are_local_values(tmp_path, binding):
    project(tmp_path, f"fn callback() {{}}\nfn main() {{ {binding} }}\n")
    assert set(unused(tmp_path)) == {"callback"}


@pytest.mark.parametrize(
    "body",
    [
        "let callback = callback; callback();",
        "let (callback, other) = (callback, ()); callback();",
        "{ let callback = external(); callback(); } callback();",
        "if let Some(callback) = external() { callback(); } else { callback(); }",
        "if let Some(callback) = external() { callback(); } callback();",
        "for callback in external() { callback(); } callback();",
        "match external() { Some(callback) => callback(), _ => callback() }",
        "let closure = |callback: fn()| callback(); callback(); external(closure);",
        "let callback = external(); fn inner() { callback(); } inner();",
        "let Holder { callback } = external(); external(crate::callback);",
        "let closure = || callback(); external(closure);",
        "let result = callback(); external(result);",
        "let result = Holder { callback: callback }; external(result);",
        "match external() { Some(value) if callback() => external(value), _ => () }",
        "{ let target: fn() = callback; external(target); } target();",
    ],
)
def test_binding_scope_and_initializer_reads_preserve_real_function(tmp_path, body):
    project(tmp_path, f"fn callback() {{}}\nfn main() {{ {body} }}\n")
    assert not unused(tmp_path)


def test_function_values_in_dead_initializers_do_not_become_entries(tmp_path):
    project(
        tmp_path,
        """
        fn callback() {}
        fn abandoned() { let callback = callback; external(callback); }
        fn main() {}
        """,
    )
    assert set(unused(tmp_path)) == {"callback", "abandoned"}


def test_initializer_references_retain_their_actual_call_graph_owner(tmp_path):
    path = project(
        tmp_path,
        """
        fn source() {}
        fn callback() {}
        fn main() { let callback = source; callback(); }
        """,
    )
    definitions = {d.name: d for d in scan_rust_file(str(path), {})[0]}
    assert definitions["main"].calls == {"source"}
    assert set(unused(tmp_path)) == {"callback"}


def test_struct_field_label_does_not_reference_same_named_function(tmp_path):
    project(
        tmp_path,
        """
        struct Holder { callback: fn() }
        fn callback() {}
        fn source() {}
        fn main() { let holder = Holder { callback: source }; external(holder); }
        """,
    )
    assert set(unused(tmp_path)) == {"callback"}


def test_macro_tokens_keep_the_existing_conservative_reference_policy(tmp_path):
    project(
        tmp_path,
        """
        fn callback() {}
        fn main() { let callback = external(); unknown_macro!(callback); }
        """,
    )
    assert not unused(tmp_path)


def test_long_blocks_do_not_rescan_every_preceding_binding():
    text_reads = []
    for size in (128, 256):
        statements = "\n".join(
            f"let local_{index} = callback; external(local_{index});"
            for index in range(size)
        )
        source = f"fn callback() {{}} fn main() {{ {statements} }}".encode()
        core = RustCore("main.rs", source)
        original_get_text = core._get_text
        reads = 0

        def counted_text(node):
            nonlocal reads
            reads += 1
            return original_get_text(node)

        core._get_text = counted_text
        core.scan()
        definitions = {definition.name: definition for definition in core.defs}
        assert definitions["main"].calls == {"callback"}
        text_reads.append(reads)
    # Count source work, not elapsed time on a loaded CI runner.
    assert text_reads[1] < 2.5 * text_reads[0]
