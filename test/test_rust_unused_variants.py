import json

import pytest

from skylos import analyze

SOURCE = """enum Mode {
    Ready,
    Stale,
    Waiting,
}
fn main() { std::hint::black_box(Mode::Ready); }
"""


def project(root, source=SOURCE, filename="main.rs"):
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / filename).write_text(source)
    (root / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\nedition="2021"'
    )


def scan(root, **kwargs):
    report = json.loads(analyze(str(root), grep_cache=False, **kwargs))
    assert not report["analysis_errors"]
    return report


def variants(report):
    return {
        row["name"]: row
        for row in report["unused_variables"]
        if row.get("rule_id") == "SKY-U009"
    }


def test_private_binary_enum_reports_only_unmentioned_variants(tmp_path):
    project(tmp_path)
    by_name = variants(scan(tmp_path, conf=40))
    assert set(by_name) == {"Mode::Stale", "Mode::Waiting"}
    assert by_name["Mode::Stale"]["confidence"] == 40
    assert by_name["Mode::Stale"]["line"] == 3
    assert by_name["Mode::Waiting"]["type"] == "enum_variant"
    default = scan(tmp_path)
    assert not variants(default)
    assert (
        default["analysis_summary"]["dead_code_experimental"]["rust"]["show_with"]
        == "--confidence 40"
    )


@pytest.mark.parametrize(
    "read",
    [
        "use crate::Mode::*; fn touch() { let _ = Stale; }",
        "use crate::Mode::Stale as Alias; fn touch() { let _ = Alias; }",
        "type Alias = crate::Mode; fn touch() { let _ = Alias::Stale; }",
        "fn touch(m: crate::Mode) { match m { crate::Mode::Stale => (), _ => () } }",
        "enum Other { Stale }",
    ],
)
def test_imports_aliases_patterns_and_shared_names_keep_the_variant(tmp_path, read):
    project(tmp_path, "mod other;\n" + SOURCE)
    (tmp_path / "src/other.rs").write_text(read)
    assert set(variants(scan(tmp_path, conf=40))) == {"Mode::Waiting"}


@pytest.mark.parametrize(
    "source",
    [
        "#[derive(Debug)]\n" + SOURCE,
        "#[derive(serde::Deserialize)]\n" + SOURCE,
        "#[repr(C)]\n" + SOURCE,
        SOURCE + '\nextern "C" { fn foreign(); }',
        SOURCE + '\nextern "C" fn receive() {}',
        SOURCE + "\nunsafe fn boot() {}",
        SOURCE + "\nunsafe trait Wire {} unsafe impl Wire for Mode {}",
        SOURCE + "\nfn raw() { unsafe { core::mem::zeroed::<Mode>(); } }",
        SOURCE + '\nfn extra() { println!("mode"); }',
        SOURCE + "\nmod missing;",
        "#[allow(dead_code)]\n" + SOURCE,
        SOURCE.replace("    Stale,", "    #[allow(dead_code)] Stale,"),
        SOURCE.replace("enum Mode", "pub(crate) enum Mode"),
        SOURCE.replace("enum Mode", "pub enum Mode"),
        SOURCE.replace("std::hint::black_box(Mode::Ready);", ""),
    ],
)
def test_unobserved_or_external_surfaces_produce_no_variant_findings(tmp_path, source):
    project(tmp_path, source)
    assert not variants(scan(tmp_path, conf=40))


def test_library_partial_scan_and_project_ignore(tmp_path):
    project(tmp_path, filename="lib.rs")
    assert not variants(scan(tmp_path, conf=40))
    (tmp_path / "src/lib.rs").rename(tmp_path / "src/main.rs")
    assert not variants(scan(tmp_path / "src/main.rs", conf=40))
    assert not variants(scan(tmp_path, conf=40, exclude_folders=["optional"]))
    (tmp_path / "pyproject.toml").write_text('[tool.skylos]\nignore=["SKY-U009"]')
    assert not variants(scan(tmp_path, conf=40))
