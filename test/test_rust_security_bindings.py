from pathlib import Path

import pytest

from skylos.visitors.languages.rust import scan_rust_file


def scan(tmp_path: Path, source: str):
    path = tmp_path / "lib.rs"
    path.write_text(source, encoding="utf-8")
    return scan_rust_file(str(path), {})[7]


SECURITY_CASES = [
    (
        "sanitizer_substring_identifier",
        """fn main() {
    let file_name_input = std::env::var("REQUEST_PATH").unwrap();
    let _ = std::fs::read_to_string(file_name_input);
}
""",
        [("SKY-D215", 3)],
    ),
    (
        "sanitizer_substring_helper",
        """fn preserve_file_name(path: String) -> String { path }
fn main() {
    let path = std::env::var("REQUEST_PATH").unwrap();
    let _ = std::fs::read_to_string(preserve_file_name(path));
}
""",
        [("SKY-D215", 4)],
    ),
    (
        "resolved_alias_command",
        """use std::process::Command as Process;
fn main() {
    let executable = std::env::var("REQUEST_PROGRAM").unwrap();
    let _ = Process::new(executable).spawn();
}
""",
        [("SKY-D212", 4)],
    ),
    (
        "resolved_fs_alias",
        """use std::fs::read_to_string as load;
fn main() {
    let path = std::env::var("REQUEST_PATH").unwrap();
    let _ = load(path);
}
""",
        [("SKY-D215", 4)],
    ),
    (
        "vector_push_control",
        """fn main() {
    let input = std::env::var("REQUEST_VALUE").unwrap();
    let mut values = Vec::new();
    values.push(input);
}
""",
        [],
    ),
    (
        "custom_read_control",
        """struct Buffer;
impl Buffer { fn read(&self, value: String) -> usize { value.len() } }
fn main() {
    let input = std::env::var("REQUEST_VALUE").unwrap();
    let _ = Buffer.read(input);
}
""",
        [],
    ),
    (
        "custom_command_control",
        """struct Command;
impl Command { fn new(value: String) -> Self { let _ = value; Self } }
fn main() {
    let command = std::env::var("REQUEST_VALUE").unwrap();
    let _ = Command::new(command);
}
""",
        [],
    ),
    (
        "literal_process_control",
        """use std::process::Command;
fn main() {
    let _ = Command::new("git").arg("status").output();
}
""",
        [],
    ),
    (
        "branch_join_taint",
        """fn load(use_fixed: bool) {
    let mut selected = std::env::var("REQUEST_PATH").unwrap();
    if use_fixed { selected = String::from("/srv/data/fixed.txt"); }
    let _ = std::fs::read_to_string(selected);
}
""",
        [("SKY-D215", 4)],
    ),
    (
        "branch_both_safe_control",
        """fn load(use_first: bool) {
    let selected;
    if use_first { selected = "/srv/data/one.txt"; }
    else { selected = "/srv/data/two.txt"; }
    let _ = std::fs::read_to_string(selected);
}
""",
        [],
    ),
    (
        "inner_shadow_does_not_clear_outer",
        """fn main() {
    let path = std::env::var("REQUEST_PATH").unwrap();
    { let path = "/srv/data/fixed.txt"; let _ = path.len(); }
    let _ = std::fs::read_to_string(path);
}
""",
        [("SKY-D215", 4)],
    ),
    (
        "canonicalization_without_root",
        """fn main() {
    let path = std::env::var("REQUEST_PATH").unwrap();
    let resolved = std::fs::canonicalize(path).unwrap();
    let _ = std::fs::read_to_string(resolved);
}
""",
        [("SKY-D215", 4)],
    ),
    (
        "strip_prefix_not_containment",
        """fn main() {
    let path = std::env::var("REQUEST_PATH").unwrap();
    let trimmed = path.strip_prefix("/srv/data").unwrap();
    let _ = std::fs::read_to_string(trimmed);
}
""",
        [("SKY-D215", 4)],
    ),
    (
        "basename_control",
        """use std::path::Path;
fn main() {
    let filename = std::env::var("REQUEST_PATH").unwrap();
    let basename = Path::new(&filename).file_name().unwrap();
    let _ = std::fs::read_to_string(basename);
}
""",
        [],
    ),
    (
        "checked_canonical_root_control",
        """use std::path::Path;
fn main() {
    let input = std::env::var("REQUEST_PATH").unwrap();
    let root = std::fs::canonicalize("/srv/data").unwrap();
    let selected = std::fs::canonicalize(root.join(Path::new(&input))).unwrap();
    if !selected.starts_with(&root) { return; }
    let _ = std::fs::read_to_string(selected);
}
""",
        [],
    ),
]


@pytest.mark.parametrize(
    "case,source,expected", SECURITY_CASES, ids=[c[0] for c in SECURITY_CASES]
)
def test_bound_security_cases(tmp_path, case, source, expected):
    findings = scan(tmp_path, source)
    assert [(f["rule_id"], f["line"]) for f in findings] == expected
    for finding in findings:
        evidence = finding["metadata"]["security_evidence"]
        assert evidence["sources"]
        assert evidence["analysis_complete"] is False


@pytest.mark.parametrize(
    "declaration,call",
    [
        ("use std::fs::read_to_string as load;", "load(input)"),
        (
            "use std::{fs::{self as disk, File as DiskFile}};",
            "disk::read_to_string(input)",
        ),
        ("use std::{fs::{File as DiskFile}};", "DiskFile::open(input)"),
        ("use std::fs;", 'fs::copy("fixed", input)'),
    ],
)
def test_resolved_filesystem_aliases_and_destination(tmp_path, declaration, call):
    findings = scan(tmp_path, f"{declaration}\nfn f(input: String) {{\n    {call};\n}}")
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 3)]


@pytest.mark.parametrize(
    "source",
    [
        """use std::fs::read_to_string as load;
fn f(input: String) { let load = |x: String| x.len(); load(input); }""",
        """use std::process::Command;
fn f(input: String) { struct Command; impl Command { fn new(_: String) -> Self { Self } } Command::new(input); }""",
        """mod std { pub mod fs { pub fn read(_: String) {} } }
fn f(input: String) { std::fs::read(input); }""",
        """fn f(input: String) { let value = "std::env::var(UNTRUSTED)"; std::fs::read(value); }""",
        """use std::fs::read_to_string as load;
fn f(input: String) { let f = |load: fn(String)| { load(input); }; }""",
    ],
)
def test_lookalike_or_shadowed_api_is_not_a_sink(tmp_path, source):
    assert scan(tmp_path, source) == []


def test_alias_source_retains_concrete_provenance(tmp_path):
    findings = scan(
        tmp_path,
        """use std::{env::{var as lookup}, fs::read as load};
fn f() { load(lookup("FILE").unwrap()); }""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 2)]
    assert findings[0]["metadata"]["security_evidence"]["sources"] == ["std::env::var"]


def test_custom_file_name_method_does_not_sanitize(tmp_path):
    findings = scan(
        tmp_path,
        """struct Wrapper(String);
impl Wrapper { fn file_name(self) -> String { self.0 } }
fn f(input: String) {
    let safe = Wrapper(input).file_name();
    std::fs::read(safe);
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 5)]


@pytest.mark.parametrize(
    "middle,expected",
    [
        ('match flag { true => { path = "fixed".into(); }, false => {} }', True),
        (
            'match flag { true => { path = "a".into(); }, false => { path = "b".into(); } }',
            False,
        ),
        (
            'match Some("fixed") { Some(mut path) => { path = "other"; }, None => {} }',
            True,
        ),
        ('let never_called = || { path = "fixed".into(); };', True),
        ('{ let path = "fixed"; let _ = path; }', True),
        ('if flag { path = "fixed".into(); }', True),
        ('if flag { path = "fixed".into(); } else { return; }', False),
        ('while flag { path = "fixed".into(); }', True),
    ],
)
def test_alternative_scopes_do_not_erase_live_taint(tmp_path, middle, expected):
    source = f"""fn f(input: String, flag: bool) {{
    let mut path = input;
    {middle}
    std::fs::read(path);
}}"""
    identities = {(f["rule_id"], f["line"]) for f in scan(tmp_path, source)}
    assert (("SKY-D215", 4) in identities) == expected


def test_for_binding_gets_iterator_input_without_escaping_scope(tmp_path):
    findings = scan(
        tmp_path,
        """fn f() {
    let path = "fixed";
    for path in std::env::args() { std::fs::read(path); }
    std::fs::read(path);
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 3)]


def guarded_source(change, guard="if !selected.starts_with(&root) { return; }"):
    return f"""use std::path::Path;
fn f(input: String, flag: bool) {{
    let root = std::fs::canonicalize("/srv/data").unwrap();
    let mut selected = std::fs::canonicalize(root.join(Path::new(&input))).unwrap();
    {guard}
    {change}
    std::fs::read(selected);
}}"""


@pytest.mark.parametrize(
    "change,expected",
    [
        ("", False),
        ("let _ = selected.exists();", False),
        ("let _ = selected.as_path();", False),
        ("selected = Path::new(&input).to_path_buf();", True),
        ("selected.push(&input);", True),
        ("selected.as_mut_os_string().push(&input);", True),
        ("let view = selected.as_mut_os_string(); view.push(&input);", True),
        ("let view = &mut selected; view.push(&input);", True),
        ("mutate(&mut selected);", True),
        ("selected.unknown_mutator();", True),
        ("selected.clear();", True),
    ],
)
def test_only_unmodified_exact_guarded_path_is_restricted(tmp_path, change, expected):
    identities = {
        (f["rule_id"], f["line"]) for f in scan(tmp_path, guarded_source(change))
    }
    assert (("SKY-D215", 7) in identities) == expected


@pytest.mark.parametrize(
    "guard",
    [
        'if !selected.starts_with(&root) { let _ = "ignored"; }',
        "if flag { if !selected.starts_with(&root) { return; } }",
        "if !Path::new(&input).starts_with(&root) { return; }",
        'let root = Path::new("/srv/data"); if !selected.starts_with(&root) { return; }',
        "let root = std::fs::canonicalize(&input).unwrap(); if !selected.starts_with(&root) { return; }",
    ],
)
def test_incomplete_or_wrong_root_guard_cannot_sanitize(tmp_path, guard):
    identities = {
        (f["rule_id"], f["line"]) for f in scan(tmp_path, guarded_source("", guard))
    }
    assert ("SKY-D215", 7) in identities


@pytest.mark.parametrize(
    "expression,expected",
    [
        ('Command::new("sh").arg("-c").arg(input)', True),
        ('Command::new("sh").arg("-c").arg("echo safe").arg(input)', False),
        ('Command::new("sh").args(["-c", "echo safe", &input])', False),
        ('Command::new("sh").args(["-c", &input, "extra"])', True),
        ('Command::new("git").arg(input)', False),
        (
            'Command::new("sh").arg("-c").arg(Path::new(&input).file_name().unwrap())',
            True,
        ),
        ("Command::new(Path::new(&input).file_name().unwrap())", True),
    ],
)
def test_shell_command_slot_is_distinct_from_positional_arguments(
    tmp_path, expression, expected
):
    findings = scan(
        tmp_path,
        f"""use std::{{process::Command, path::Path}};
fn f(input: String) {{
    {expression}.output();
}}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == (
        [("SKY-D212", 3)] if expected else []
    )


@pytest.mark.parametrize(
    "build",
    [
        'let mut base = PathBuf::from("/srv/data"); base.push(name);',
        'let base = Path::new("/srv/data").join(name);',
    ],
)
def test_proven_basename_keeps_fixed_base_composition_safe(tmp_path, build):
    findings = scan(
        tmp_path,
        f"""use std::path::{{Path, PathBuf}};
fn f(input: String) {{
    let name = Path::new(&input).file_name().unwrap();
    {build}
    std::fs::read(base);
}}""",
    )
    assert findings == []


@pytest.mark.parametrize(
    "format_expr,expected",
    [
        ('format!("{{input}}")', False),
        ('format!("{input}")', True),
        ('format!("{{{input}}}")', True),
        ('format!("{}", input)', True),
    ],
)
def test_format_input_and_escaped_literal_are_distinct(tmp_path, format_expr, expected):
    findings = scan(
        tmp_path,
        f"""fn f(input: String) {{
    std::fs::read({format_expr});
}}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == (
        [("SKY-D215", 2)] if expected else []
    )


def test_later_shell_position_does_not_duplicate_command_finding(tmp_path):
    findings = scan(
        tmp_path,
        """use std::process::Command;
fn f(input: String) {
    let mut process = Command::new("sh");
    process.arg("-c");
    process.arg(input);
    process.arg("extra");
    process.arg("another extra");
    process.output();
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D212", 5)]


def test_later_shell_position_keeps_fixed_command_quiet(tmp_path):
    findings = scan(
        tmp_path,
        """use std::process::Command;
fn f(input: String) {
    let mut process = Command::new("sh");
    process.arg("-c");
    process.arg("echo safe");
    process.arg(input);
    process.output();
}""",
    )
    assert findings == []


def test_recovered_incomplete_match_does_not_abort_scan(tmp_path):
    # Incomplete syntax must not discard another complete finding in the file.
    findings = scan(
        tmp_path,
        """fn f(input: String) {
    std::fs::read(&input);
    match input { Some(path) => }
}""",
    )
    assert any(f["rule_id"] == "SKY-D215" and f["line"] == 2 for f in findings)


@pytest.mark.parametrize(
    "attribute",
    [
        '#[cfg(feature="trusted")]',
        '#[cfg_attr(feature="trusted", cfg(feature="guard"))]',
        '#[/* comment */ cfg(feature="trusted")]',
    ],
)
@pytest.mark.parametrize(
    "statement",
    [
        "if !selected.starts_with(&root) { return; }",
        'selected = Path::new("/srv/data/fixed").to_path_buf();',
        'let selected = Path::new("/srv/data/fixed");',
        '{ selected = Path::new("/srv/data/fixed").to_path_buf(); }',
    ],
)
def test_cfg_statement_cannot_unconditionally_restrict_path(
    tmp_path, attribute, statement
):
    source = guarded_source("", f"{attribute} {statement}")
    assert any(
        f["rule_id"] == "SKY-D215" and f["line"] == 7 for f in scan(tmp_path, source)
    )


def test_cfg_return_does_not_hide_later_source_sink(tmp_path):
    findings = scan(
        tmp_path,
        """fn f(input: String) {
    #[cfg(feature="stop")] return;
    std::fs::read(input);
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 3)]


def test_cfg_can_leave_outer_shadowed_source_binding_live(tmp_path):
    findings = scan(
        tmp_path,
        """fn f(input: String) {
    { #[cfg(feature="fixed")] let input = "fixed";
      std::fs::read(input); }
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 3)]


@pytest.mark.parametrize(
    "source",
    [
        """fn f() { let mut path="fixed";
    #[cfg(feature="other")] path="other";
    std::fs::read(path); }""",
        """fn f(input: String) { let mut path=input;
    #[cfg(feature="other")] path="other".into();
    path="fixed".into(); std::fs::read(path); }""",
        guarded_source('#[cfg(feature="log")] let ignored = "unchanged";'),
    ],
)
def test_cfg_safe_controls_stay_quiet(tmp_path, source):
    assert scan(tmp_path, source) == []


@pytest.mark.parametrize("provider", ["tokio", "async_std"])
@pytest.mark.parametrize("operation", ["open", "create"])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("argument", ["input", '"fixed"'])
def test_async_filesystem_direct_and_alias_sinks(
    tmp_path, provider, operation, alias, argument
):
    declaration = f"use {provider}::fs::File as DiskFile;" if alias else ""
    owner = "DiskFile" if alias else f"{provider}::fs::File"
    source = f"""{declaration}
async fn f(input: String) {{
    {owner}::{operation}({argument}).await;
}}"""
    findings = scan(tmp_path, source)
    assert [(f["rule_id"], f["line"]) for f in findings] == (
        [("SKY-D215", 3)] if argument == "input" else []
    )


@pytest.mark.parametrize("provider", ["tokio", "async_std"])
def test_local_async_provider_name_is_not_standard_filesystem(tmp_path, provider):
    source = f"""mod {provider} {{ pub mod fs {{ pub struct File;
impl File {{ pub async fn open(_: String) {{}} }} }} }}
async fn f(input: String) {{ {provider}::fs::File::open(input).await; }}"""
    assert scan(tmp_path, source) == []


@pytest.mark.parametrize("provider", ["tokio", "async_std"])
def test_local_file_type_shadows_imported_async_file(tmp_path, provider):
    source = f"""use {provider}::fs::File;
async fn f(input: String) {{ struct File;
impl File {{ async fn create(_: String) {{}} }}
File::create(input).await; }}"""
    assert scan(tmp_path, source) == []


@pytest.mark.parametrize(
    "body",
    [
        "|| input.clone()",
        "move || input.clone()",
        "|| { let selected = input.clone(); selected }",
        '|| { if flag { return input.clone(); } "fixed".to_string() }',
        '|| { match flag { true => return input.clone(), false => return "fixed".to_string() } }',
    ],
)
def test_local_closure_return_preserves_captured_source(tmp_path, body):
    findings = scan(
        tmp_path,
        f"""use std::fs::File;
fn f(input: String, flag: bool) {{
    let selected = {body};
    File::open(selected());
}}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 4)]
    assert findings[0]["metadata"]["security_evidence"]["sources"] == [
        "parameter:input"
    ]


def test_local_closure_path_join_return_keeps_source_at_aliased_call(tmp_path):
    findings = scan(
        tmp_path,
        """use std::{fs::File, path::Path};
fn f(dir: &Path) {
    let selected = || dir.join("child");
    let reader_path = selected;
    File::open(reader_path());
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 5)]


@pytest.mark.parametrize(
    "body",
    [
        '|| "fixed"',
        '|| { let _captured = &input; "fixed" }',
        '|| { if flag { return "one"; } "two" }',
        '|| { let inner = || input.clone(); "fixed" }',
        '|| { fn inner(input: String) -> String { return input; } "fixed" }',
    ],
)
def test_local_literal_closure_returns_do_not_inherit_unreturned_inputs(tmp_path, body):
    findings = scan(
        tmp_path,
        f"""use std::fs::File;
fn f(input: String, flag: bool) {{
    let selected = {body};
    File::open(selected());
}}""",
    )
    assert findings == []


def test_local_closure_parameter_shadows_captured_source(tmp_path):
    findings = scan(
        tmp_path,
        """use std::fs::File;
fn f(input: String) {
    let selected = |input: &str| input;
    File::open(selected("fixed"));
}""",
    )
    assert findings == []


def test_unknown_helper_around_closure_result_does_not_sanitize(tmp_path):
    findings = scan(
        tmp_path,
        """use std::fs::File;
fn f(input: String) {
    let selected = || input.clone();
    File::open(sanitize(selected()));
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 4)]


def test_local_closure_summary_does_not_grant_path_safety(tmp_path):
    findings = scan(
        tmp_path,
        """use std::{fs::File, path::Path};
fn f(input: String) {
    let selected = || Path::new(&input).file_name().unwrap();
    File::open(selected());
}""",
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D215", 4)]


def test_rebinding_closure_does_not_keep_old_return_source(tmp_path):
    findings = scan(
        tmp_path,
        """use std::fs::File;
fn f(input: String) {
    let selected = || input.clone();
    let selected = || "fixed";
    File::open(selected());
}""",
    )
    assert findings == []
