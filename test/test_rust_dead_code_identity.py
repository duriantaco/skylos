import json
import os
from pathlib import Path
from tempfile import gettempdir
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file


def _write(path, source):
    temporary_root = Path(gettempdir()).resolve()
    path = path.resolve()
    path.relative_to(temporary_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(dedent(source).lstrip())
    return path


def _definitions(path):
    definitions, *_ = scan_rust_file(str(path), {})
    return {definition.name: definition for definition in definitions}


def _unused(result):
    return {item["full_name"] for item in result.get("unused_functions", [])}


@pytest.mark.parametrize("owners", [("Dormant", "Active"), ("Active", "Dormant")])
@pytest.mark.parametrize("grep_verify", [True, False])
@pytest.mark.parametrize(
    "call", ["active.process();", 'println!("{}", active.process());']
)
def test_concrete_receiver_credits_only_its_owner(tmp_path, owners, grep_verify, call):
    declarations = "\n".join(
        f"struct {owner};\nimpl {owner} {{ fn process(&self) -> u32 {{ 1 }} }}"
        for owner in owners
    )
    path = _write(
        tmp_path / "src" / "main.rs",
        declarations
        + f"\nfn main() {{ let _dormant = Dormant; let active = Active; {call} }}\n",
    )
    definitions = _definitions(path)
    assert "Active.process" in definitions["main"].calls
    assert "Dormant.process" not in definitions["main"].calls

    result = json.loads(analyze(str(tmp_path), grep_verify=grep_verify))
    assert "Active.process" not in _unused(result)
    assert "Dormant.process" in _unused(result)


@pytest.mark.parametrize("grep_verify", [True, False])
def test_module_function_calls_same_named_method_without_losing_helpers(
    tmp_path, grep_verify
):
    _write(tmp_path / "src" / "main.rs", "mod walk;\nfn main() { walk::scan(); }\n")
    path = _write(
        tmp_path / "src" / "walk.rs",
        """
        struct WorkerState;
        impl WorkerState {
            fn new() -> Self { Self }
            fn build_walker(&self) {}
            fn scan(&self) { self.build_walker(); }
            fn unused_helper(&self) {}
        }
        pub fn scan() { WorkerState::new().scan(); }
        """,
    )
    definitions = _definitions(path)
    assert "walk.WorkerState.scan" in definitions["walk.scan"].calls
    assert "walk.WorkerState.build_walker" in definitions["walk.WorkerState.scan"].calls

    result = json.loads(analyze(str(tmp_path), grep_verify=grep_verify))
    unused = _unused(result)
    assert "walk.WorkerState.scan" not in unused
    assert "walk.WorkerState.build_walker" not in unused
    assert "walk.WorkerState.unused_helper" in unused


@pytest.mark.parametrize(
    "body",
    [
        "fn invoke(active: &Active) { active.process(); }",
        "fn invoke() { let active: Active = make(); active.process(); }",
        "fn invoke() { Active::new().process(); }",
        "fn invoke() { let active = Active::new(); active.process(); }",
    ],
)
def test_receiver_types_from_parameters_annotations_and_constructors(tmp_path, body):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        struct Dormant;
        impl Dormant { fn process(&self) {} }
        struct Active;
        impl Active {
            fn new() -> Self { Self }
            fn process(&self) {}
        }
        """
        + body,
    )
    definitions = _definitions(path)
    assert "Active.process" in definitions["invoke"].calls
    assert "Dormant.process" not in definitions["invoke"].calls


def test_self_recursion_compares_full_identity_and_keeps_sibling_methods(tmp_path):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        struct Active;
        impl Active {
            fn process(&self) { self.process(); Self::helper(); }
            fn helper() {}
        }
        fn process(active: Active) { active.process(); }
        fn main() { process(Active); }
        """,
    )
    definitions = _definitions(path)
    assert definitions["process"].calls >= {"Active.process"}
    assert "Active.process" not in definitions["Active.process"].calls
    assert "Active.helper" in definitions["Active.process"].calls


def test_unknown_receiver_does_not_pick_first_same_named_method(tmp_path):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        struct Dormant;
        impl Dormant { fn process(&self) {} }
        struct Active;
        impl Active { fn process(&self) {} }
        fn main() {
            let _dormant = Dormant;
            let _active = Active;
            let receiver = external_factory();
            receiver.process();
        }
        fn stale() {}
        """,
    )
    definitions = _definitions(path)
    assert "Dormant.process" not in definitions["main"].calls
    assert "Active.process" not in definitions["main"].calls
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert "Dormant.process" not in _unused(result)
    assert "Active.process" not in _unused(result)
    assert "stale" in _unused(result)


@pytest.mark.parametrize("pattern", ["receiver", "(receiver, _other)"])
def test_inner_unknown_binding_shadows_outer_known_receiver(tmp_path, pattern):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        struct Active;
        impl Active { fn process(&self) {} }
        fn main() {
            let receiver = Active;
            { let PATTERN = external_factory(); receiver.process(); }
        }
        """.replace("PATTERN", pattern),
    )
    definitions = _definitions(path)
    assert "Active.process" not in definitions["main"].calls


@pytest.mark.parametrize("grep_verify", [True, False])
def test_explicit_external_owner_does_not_rescue_unrelated_local_method(
    tmp_path, grep_verify
):
    _write(
        tmp_path / "src" / "lib.rs",
        """
        use external::Processor;
        struct Active;
        impl Active { fn process(&self) {} }
        pub fn invoke(receiver: external::Other) {
            let _active = Active;
            receiver.process();
        }
        """,
    )
    result = json.loads(analyze(str(tmp_path), grep_verify=grep_verify))
    assert "Active.process" in _unused(result)


def test_factory_return_type_does_not_assume_constructor_owner(tmp_path):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        struct Dormant;
        impl Dormant {
            fn new() -> Active { Active }
            fn process(&self) {}
        }
        struct Active;
        impl Active { fn process(&self) {} }
        fn main() { Dormant::new().process(); }
        """,
    )
    definitions = _definitions(path)
    assert "Active.process" in definitions["main"].calls
    assert "Dormant.process" not in definitions["main"].calls


def test_generic_receiver_is_unresolved_without_a_concrete_type(tmp_path):
    path = _write(
        tmp_path / "src" / "lib.rs",
        """
        trait Processor { fn process(&self); }
        struct Active;
        impl Active { fn process(&self) {} }
        fn invoke<T: Processor>(receiver: T) { receiver.process(); }
        """,
    )
    definitions = _definitions(path)
    assert "Active.process" not in definitions["invoke"].calls
    _, references, *_ = scan_rust_file(str(path), {})
    assert "~.process" in {name for name, _ in references}


def test_external_generic_wrapper_does_not_claim_a_concrete_receiver(tmp_path):
    path = _write(
        tmp_path / "src" / "lib.rs",
        """
        struct Active;
        impl Active { fn process(&self) {} }
        pub fn invoke(receiver: Box<Active>) { receiver.process(); }
        """,
    )
    definitions = _definitions(path)
    assert "Active.process" not in definitions["invoke"].calls
    _, references, *_ = scan_rust_file(str(path), {})
    assert "~.process" in {name for name, _ in references}
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert "Active.process" not in _unused(result)


def test_constructor_called_only_by_dead_helper_remains_dead(tmp_path):
    _write(
        tmp_path / "src" / "tls.rs",
        """
        struct Verifier;
        impl Verifier { fn new() -> Self { Self } }
        fn build_verifier() { Verifier::new(); }
        """,
    )
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert {"tls.Verifier.new", "tls.build_verifier"} <= _unused(result)


@pytest.mark.parametrize(
    "call", ["receiver.process();", 'println!("{}", receiver.process());']
)
def test_simple_local_type_alias_keeps_actual_owner_and_dead_sibling(tmp_path, call):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        type Alias = Active;
        struct Dormant;
        impl Dormant { fn process(&self) -> u32 { 2 } }
        struct Active;
        impl Active { fn process(&self) -> u32 { 1 } }
        fn invoke(receiver: Alias) { CALL }
        fn main() { let _dormant = Dormant; invoke(Active); }
        """.replace("CALL", call),
    )
    definitions = _definitions(path)
    assert "Active.process" in definitions["invoke"].calls
    assert "Dormant.process" not in definitions["invoke"].calls
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert "Active.process" not in _unused(result)
    assert "Dormant.process" in _unused(result)


@pytest.mark.parametrize(
    "call", ["receiver.process();", 'println!("{}", receiver.process());']
)
def test_local_generic_deref_wrapper_keeps_dispatch_unresolved(tmp_path, call):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        use std::ops::Deref;
        struct Active;
        impl Active {
            fn process(&self) -> u32 { 1 }
            fn stale(&self) {}
        }
        struct Wrapper<T>(T);
        impl<T> Deref for Wrapper<T> {
            type Target = T;
            fn deref(&self) -> &Self::Target { &self.0 }
        }
        fn invoke(receiver: Wrapper<Active>) { CALL }
        fn main() { invoke(Wrapper(Active)); }
        """.replace("CALL", call),
    )
    definitions = _definitions(path)
    assert "Active.process" not in definitions["invoke"].calls
    _, refs, *_ = scan_rust_file(str(path), {})
    assert "~.process" in {name for name, _ in refs}
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert "Active.process" not in _unused(result)
    assert "Active.stale" in _unused(result)


def test_ambiguous_import_alias_does_not_guess_a_relative_owner(tmp_path):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        struct Active;
        impl Active { fn process(&self) {} fn stale(&self) {} }
        struct Dormant;
        impl Dormant { fn process(&self) {} }
        mod first {
            use crate::Active as Selected;
            pub fn invoke(receiver: Selected) { receiver.process(); }
        }
        mod second {
            use crate::Dormant as Selected;
            pub fn invoke(receiver: Selected) { receiver.process(); }
        }
        fn main() { first::invoke(Active); second::invoke(Dormant); }
        """,
    )
    _, refs, *_ = scan_rust_file(str(path), {})
    assert "second.Selected.process" not in {name for name, _ in refs}
    assert "~.process" in {name for name, _ in refs}
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert {"Active.process", "Dormant.process"}.isdisjoint(_unused(result))
    assert "Active.stale" in _unused(result)


@pytest.mark.parametrize("owner", ["models::Active", "Selected", "Alias"])
def test_scoped_impl_owner_matches_the_referenced_concrete_type(tmp_path, owner):
    path = _write(
        tmp_path / "src" / "main.rs",
        """
        mod models { pub(crate) struct Active; }
        use models::Active as Selected;
        impl OWNER {
            fn process(&self) {}
            fn stale(&self) {}
        }
        type Alias = models::Active;
        fn invoke(receiver: models::Active) { receiver.process(); }
        fn main() { invoke(models::Active); }
        """.replace("OWNER", owner),
    )
    definitions = _definitions(path)
    assert "models.Active.process" in definitions
    assert "models.Active.process" in definitions["invoke"].calls
    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    assert "models.Active.process" not in _unused(result)
    assert "models.Active.stale" in _unused(result)
