"""Comments and strings cannot turn a production module into a test harness."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file


@pytest.mark.parametrize(
    "prefix, expected",
    [
        ("", True),
        ("// #[cfg(test)] mod handlers;\n", True),
        ("/* #[cfg(test)] mod handlers; */\n", True),
        ('const DOC: &str = "#[cfg(test)] mod handlers;";\n', True),
        ("#[cfg(test)]\n", False),
    ],
)
def test_only_a_real_test_module_attribute_disables_parameter_hypotheses(
    tmp_path, prefix, expected
):
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="review"\nversion="0.1.0"\nedition="2021"\n'
    )
    (src / "main.rs").write_text(
        prefix
        + "mod handlers;\nfn main() { let path = std::env::args().nth(1).unwrap(); let _ = handlers::read_file(&path); }\n"
    )
    target = src / "handlers.rs"
    target.write_text(
        "use std::fs;\npub fn read_file(path: &str) -> Vec<u8> {\n    fs::read(path).unwrap()\n}\n"
    )
    direct = scan_rust_file(str(target), {})[7]
    result = json.loads(analyze(str(tmp_path), enable_danger=True))
    assert not result.get("analysis_errors")
    for findings in (direct, result.get("danger", [])):
        assert (
            any(f["rule_id"] == "SKY-D215" and f["line"] == 3 for f in findings)
            is expected
        )


@pytest.mark.parametrize(
    "main, library, expected",
    [
        ("#[cfg(test)] mod handlers;", "mod handlers;", True),
        ("#[cfg(test)] mod handlers;", "#[cfg(test)] mod handlers;", False),
        ('#[cfg(test)] #[path="other.rs"] mod handlers;', "", True),
        ("#[cfg(test)] mod handlers;", '#[path="handlers.rs"] mod renamed;', True),
    ],
)
def test_a_test_declaration_cannot_hide_a_competing_or_ambiguous_owner(
    tmp_path, main, library, expected
):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text(main + "\nfn main() {}\n")
    (src / "lib.rs").write_text(library + "\n")
    target = src / "handlers.rs"
    target.write_text(
        "pub fn read_file(path: &str) -> Vec<u8> { std::fs::read(path).unwrap() }\n"
    )
    findings = scan_rust_file(str(target), {})[7]
    assert any(f["rule_id"] == "SKY-D215" for f in findings) is expected
