"""Rust test-only code and declared encoding alphabets in the secrets scan.

``#[cfg(test)]`` items and ``#[test]``-style functions are treated like files
under ``tests/``: only provider-shaped credentials count there. A string that
is a whole shuffled standard alphabet, handed to an alphabet constructor or
bound to an alphabet name, is an encoding table. Real keys are still found.
"""

from __future__ import annotations

from skylos.rules.secrets import scan_ctx

_VECTOR = "4HcwTg4bQKEbuINCJGMqrij1yipl63Ugu/RazH2y7Qw="
_AWS = "AKIAIOSFODNN7ABCDEFG"
_ALPHABET = "AphruVFwvCetlckdZ2g-foxXBGNbyHnD96qUj3KL_YsE7P1OQiaIR0z4T58mMWJS"


def _findings(source: str, path: str = "src/lib.rs"):
    return [
        (f["line"], f.get("provider"), f.get("public_identifier_evidence"))
        for f in scan_ctx(
            {"relpath": path, "lines": source.splitlines(True), "tree": None}
        )
    ]


def test_cfg_test_module_hides_generic_values_but_not_provider_keys():
    source = f"""const PROD: &str = "{_VECTOR}";
#[cfg(test)]
mod tests {{
    // test vector from the SDK
    const HASH: &str = "{_VECTOR}";
    const KEY: &str = "{_AWS}";
    const DB: &str = "postgres://user:hunter2secret@db/app";
}}
const AFTER: &str = "{_VECTOR}";
"""
    lines = _findings(source)
    assert (1, "generic", None) in lines
    assert (9, "generic", None) in lines
    assert any(
        line == 6 and provider == "aws_access_key_id" for line, provider, _ in lines
    )
    assert not any(line in {5, 7} for line, _, _ in lines)


def test_test_functions_and_test_only_cfg_variants():
    source = f"""#[tokio::test]
async fn login() {{
    let token = "{_VECTOR}";
}}
#[cfg(all(test, feature = "net"))]
fn helper() -> &'static str {{ "{_VECTOR}" }}
#[cfg(any(test, feature = "net"))]
fn shipped() -> &'static str {{ "{_VECTOR}" }}
#[cfg(not(test))]
fn release() -> &'static str {{ "{_VECTOR}" }}
"""
    lines = {line for line, provider, _ in _findings(source) if provider == "generic"}
    assert lines == {8, 10}


def test_inner_cfg_test_attribute_covers_the_file_and_parse_errors_do_not():
    assert _findings(f'#![cfg(test)]\nconst A: &str = "{_VECTOR}";\n') == []
    broken = f'#[cfg(test)]\nmod tests {{\n    const A: &str = "{_VECTOR}";\n'
    assert [line for line, _, _ in _findings(broken)] == [3]


def test_cfg_test_is_rust_only():
    source = f'#[cfg(test)]\nconst A = "{_VECTOR}"\n'
    assert _findings(source, path="src/lib.py") != []


def test_declared_shuffled_alphabet_is_not_a_secret():
    assert _findings(f'let alphabet = Alphabet::new("{_ALPHABET}").unwrap();\n') == []
    assert _findings(f'const ALPHABET: &str = "{_ALPHABET}";\n') == []
    assert _findings(f'CHARSET = "{_ALPHABET}"\n', path="app/ids.py") == []


def test_undeclared_or_incomplete_alphabets_stay_findings():
    [(_, _, evidence)] = _findings(f'let key = "{_ALPHABET}";\n')
    assert evidence == "each character appears once: an encoding alphabet"
    repeated = _ALPHABET[:-1] + "A"
    assert len(_findings(f'let alphabet = Alphabet::new("{repeated}");\n')) == 1
    glued = f'let alphabet = Alphabet::new("{_ALPHABET}.{_VECTOR}");\n'
    assert _findings(glued) != []


def test_cfg_test_on_a_field_statement_or_match_arm_is_test_code():
    source = f"""static SPEC: Spec = Spec {{
    name: "{_VECTOR}",
    #[cfg(test)]
    tests: &[Case {{ input: "postgres://app:s3cr3t-pw@db.internal/app" }}],
}};
fn f(y: u8) {{
    #[cfg(test)]
    let fixture = "{_VECTOR}";
    let shipped = "{_VECTOR}";
    match y {{ #[cfg(test)] 1 => use_it("{_VECTOR}"), _ => () }}
}}
"""
    lines = {line for line, _, _ in _findings(source)}
    # The plain field (2) and the plain statement (9) are still findings.
    assert {2, 9} <= lines
    assert not lines & {4, 8, 10}


def test_custom_test_attributes_mark_test_functions_but_others_do_not():
    source = f"""#[idm_test]
async fn a() {{ let t = "{_VECTOR}"; }}
#[rstest]
fn b() {{ let t = "{_VECTOR}"; }}
#[tracing::instrument]
fn c() {{ let t = "{_VECTOR}"; }}
"""
    lines = {line for line, provider, _ in _findings(source) if provider == "generic"}
    assert lines == {6}


def _module_tree(tmp_path, declaration):
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(f"{declaration}\npub fn api() {{}}\n", encoding="utf-8")
    child = src / "fixtures.rs"
    child.write_text(f'const VECTOR: &str = "{_VECTOR}";\n', encoding="utf-8")
    return child


def _module_findings(path):
    return scan_ctx(
        {
            "relpath": "src/fixtures.rs",
            "lines": path.read_text(encoding="utf-8").splitlines(True),
            "tree": None,
            "abs_path": str(path),
        }
    )


def test_file_declared_cfg_test_module_is_test_code(tmp_path):
    child = _module_tree(tmp_path, "#[cfg(test)]\nmod fixtures;")
    assert _module_findings(child) == []


def test_file_declared_without_cfg_test_keeps_its_findings(tmp_path):
    for index, declaration in enumerate(
        (
            "mod fixtures;",
            "#[cfg(not(test))]\nmod fixtures;",
            "#[cfg(test)]\nmod other;",
        )
    ):
        root = tmp_path / f"case{index}"
        root.mkdir()
        child = _module_tree(root, declaration)
        assert len(_module_findings(child)) == 1, declaration


def test_keyboard_run_provider_token_in_test_code_is_a_fixture():
    fake = "sk_test_" + "1234567890" + "abcdefghijklmnop"
    in_cfg_test = f"""#[cfg(test)]
mod tests {{
    #[rstest]
    #[case::stripe("curl foo.com/bar?key={fake}")]
    fn redacts(#[case] input: &str) {{}}
}}
"""
    assert _findings(in_cfg_test) == []
    assert _findings(f'let key = "{fake}";\n', path="tests/redact.rs") == []


def test_keyboard_run_provider_token_outside_tests_is_still_found():
    fake = "sk_test_" + "1234567890" + "abcdefghijklmnop"
    assert _findings(f'let key = "{fake}";\n') != []


def test_provider_shaped_key_with_a_random_payload_is_still_found():
    real_shape = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    assert any(
        provider not in (None, "generic")
        for _, provider, _ in _findings(f'let key = "{real_shape}";\n')
    )
    # A short ordered run inside a random payload does not excuse it.
    mixed = "sk_live_" + "abcdefgh" + "Q7vLx2RkWz9TmPc4"
    assert _findings(f'let key = "{mixed}";\n') != []


def test_rust_test_module_file_names_are_test_code():
    source = f'const FIXTURE: &str = "{_VECTOR}";\nconst KEY: &str = "{_AWS}";\n'
    for path in (
        "src/tests.rs",
        "src/test.rs",
        "src/parser_tests.rs",
        "src/net_test.rs",
    ):
        providers = {provider for _, provider, _ in _findings(source, path=path)}
        assert providers == {"aws_access_key_id"}, path
    for path in ("src/latest.rs", "src/contests.rs", "src/attest.rs"):
        assert any(
            provider == "generic" for _, provider, _ in _findings(source, path=path)
        ), path


def test_ietf_params_urn_is_a_public_identifier():
    urn = "urn:ietf:params:oauth:token-type:access_token"
    assert (
        _findings(f'pub const OAUTH2_TOKEN_TYPE_ACCESS_TOKEN: &str = "{urn}";\n') == []
    )
    assert _findings(f'pub const ACCESS_TOKEN: &str = "{_VECTOR}";\n') != []
