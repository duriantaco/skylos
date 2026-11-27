from __future__ import annotations

import pytest

from skylos.cicd.review import _flatten_findings, _review_only_lines
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_gate_exempt_review
from skylos.visitors.languages.rust import scan_rust_file


def _scan(tmp_path, code):
    path = tmp_path / "lib.rs"
    path.write_text(code, encoding="utf-8")
    return [
        row
        for row in scan_rust_file(str(path), {})[7]
        if row["rule_id"] in {"SKY-D415", "SKY-D416"}
    ]


def test_readonly_advisory_tracks_std_values_and_references(tmp_path):
    rows = _scan(
        tmp_path,
        """
use std::fs::{self, File, Permissions as Rights};
use std::path::Path;
fn update(mut owned: Rights, borrowed: &mut Rights, file: &File, path: &Path) -> std::io::Result<()> {
    owned.set_readonly(false);
    borrowed.set_readonly(false);
    fs::Permissions::set_readonly(borrowed, false);
    let mut p = fs::metadata("a")?.permissions();
    p.set_readonly(false);
    let mut copy = file.metadata()?.permissions().clone();
    copy.set_readonly((false));
    let mut from_path = path.metadata()?.permissions();
    from_path.set_readonly(false);
    let mut from_file = File::open("b")?.metadata()?.permissions();
    from_file.set_readonly(false);
    Ok(())
}
""",
    )
    assert [r["line"] for r in rows] == [5, 6, 7, 9, 11, 13, 15]
    assert {r["rule_id"] for r in rows} == {"SKY-D415"}
    assert all(is_gate_exempt_review(r) for r in rows)
    assert all(r["metadata"]["security_evidence"]["argument"] == "false" for r in rows)


def test_receivers_and_values_require_evidence(tmp_path):
    rows = _scan(
        tmp_path,
        """
use std::fs::Permissions as Rights;
struct Permissions;
impl Permissions { fn set_readonly(&mut self, _: bool) {} }
fn custom(mut other: Permissions, val: bool, mut typed: Rights, read_only: &Rights) {
    other.set_readonly(false);
    typed.set_readonly(val);
    typed.set_readonly(true);
    let typed = other;
    typed.set_readonly(false);
    read_only.set_readonly(false);
}
fn generic<Rights>(mut value: Rights) { value.set_readonly(false); }
mod fake {
    mod std { pub mod fs { pub struct Permissions; } }
    fn example(mut p: std::fs::Permissions) { p.set_readonly(false); }
}
""",
    )
    assert rows == []


def test_detectors_under_platform_conditions(tmp_path):
    rows = _scan(
        tmp_path,
        """
#[cfg(windows)]
fn one(mut p: std::fs::Permissions) { p.set_readonly(false); }
#[cfg(not(unix))]
mod two { fn two(mut p: std::fs::Permissions) { p.set_readonly(false); } }
#[cfg(all(feature="extra", target_os="windows"))]
fn three(mut p: std::fs::Permissions) { p.set_readonly(false); }
#[cfg(any(windows, target_family="windows"))]
fn four(mut p: std::fs::Permissions) { p.set_readonly(false); }
#[cfg(any(unix, feature="extra"))]
fn five(mut p: std::fs::Permissions) { p.set_readonly(false); }
fn branches(mut p: std::fs::Permissions) {
    if cfg!(windows) { p.set_readonly(false); }
    if cfg!(unix) {} else { p.set_readonly(false); }
    if cfg!(windows) {} else { p.set_readonly(false); }
}
""",
    )
    assert [r["line"] for r in rows] == [11, 15]


def test_non_octal_requires_resolved_extension_trait_and_literal(tmp_path):
    rows = _scan(
        tmp_path,
        """
use std::fs::{Permissions, OpenOptions as Options, DirBuilder};
use std::os::unix::fs::{PermissionsExt as Bits, OpenOptionsExt, DirBuilderExt};
fn modes(mut p: Permissions, b: &mut DirBuilder, custom: u32) {
    let _p = Permissions::from_mode(644u32);
    let _q = <Permissions as Bits>::from_mode(640);
    p.set_mode(400);
    Bits::set_mode(&mut p, 444);
    Options::new().write(true).create(true).mode(666);
    b.recursive(true).mode(0x1ed);
    p.set_mode(0o777);
    p.set_mode(0b111_000_000);
    p.set_mode(4);
    p.set_mode(0o640 | custom);
    p.set_mode(custom);
}
""",
    )
    assert [r["line"] for r in rows] == [5, 6, 7, 8, 9, 10]
    assert {r["rule_id"] for r in rows} == {"SKY-D416"}
    assert all(is_gate_exempt_review(r) for r in rows)


def test_similar_modes_and_custom_trait_impl_are_excluded(tmp_path):
    rows = _scan(
        tmp_path,
        """
use std::fs::{Permissions, OpenOptions};
trait Custom { fn set_mode(&mut self, value: u32); }
fn custom(p: &mut Permissions) {
    p.set_mode(644);
    OpenOptions::new().mode(666);
}
mod other {
    use std::os::unix::fs::PermissionsExt;
    use std::fs::Permissions as Rights;
    struct Permissions;
    impl Permissions { fn from_mode(_: u32) -> Self { Permissions } }
    fn test() {
        Permissions::from_mode(644);
        let _: Permissions = PermissionsExt::from_mode(444);
        <Rights as super::Custom>::from_mode(600);
    }
}
""",
    )
    assert rows == []


@pytest.mark.parametrize(
    "rule_id, other", [("SKY-D415", "SKY-D210"), ("SKY-D416", "SKY-D215")]
)
def test_permissions_are_visible_but_exempt_only_with_matching_evidence(
    tmp_path, rule_id, other
):
    rows = _scan(
        tmp_path,
        """
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
fn update(mut p: Permissions) { p.set_readonly(false); p.set_mode(666); }
""",
    )
    row = next(r for r in rows if r["rule_id"] == rule_id)
    gate = {"gate": {"max_security_issues": 0}}
    assert check_gate({"danger": [row]}, gate, strict=True)[0]
    for invalid in (
        {**row, "metadata": {}},
        {**row, "rule_id": other},
        {**row, "review_item": {"kind": "unix_permissions", "blocking": True}},
    ):
        assert not is_gate_exempt_review(invalid)
        assert not check_gate({"danger": [invalid]}, gate, strict=True)[0]
    other_rule = "SKY-D416" if rule_id == "SKY-D415" else "SKY-D415"
    assert not is_gate_exempt_review({**row, "rule_id": other_rule})
    broken = {
        **row["metadata"]["security_evidence"],
        "api": "custom::Permissions::set_mode",
    }
    assert not is_gate_exempt_review({**row, "metadata": {"security_evidence": broken}})
    [review] = _flatten_findings({"danger": [row]})
    lines = _review_only_lines({(rule_id, review["_review_only_kind"]): [review]})
    assert any("intended Unix file permissions" in line for line in lines)


def _cargo_project(root):
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text('[package]\nname = "demo"\nversion = "0.1.0"\n')
    (root / "src/lib.rs").write_text("#[cfg(windows)] mod fs;\n")
    module = root / "src/fs.rs"
    module.write_text(
        "use std::os::unix::fs::PermissionsExt;\n"
        "fn update(p: &mut std::fs::Permissions) {\n"
        "    p.set_readonly(false);\n"
        "    p.set_mode(644);\n"
        "}\n"
    )
    return module


def test_external_windows_only_module_and_file_scope(tmp_path):
    import json

    from skylos import analyze

    module = _cargo_project(tmp_path)

    def checks(path, **kwargs):
        report = json.loads(
            analyze(str(path), enable_danger=True, grep_cache=False, **kwargs)
        )
        assert not report["analysis_errors"]
        return [
            r["rule_id"]
            for r in report.get("danger", [])
            if r["rule_id"] in ("SKY-D415", "SKY-D416")
        ]

    assert checks(tmp_path) == []
    assert checks(module) == ["SKY-D415", "SKY-D416"]
    (tmp_path / "src/main.rs").write_text("mod fs; fn main() {}")
    assert checks(tmp_path) == ["SKY-D415", "SKY-D416"]


@pytest.mark.parametrize(
    "other_source",
    [
        '#[path = "../../first/src/fs.rs"] mod portable;',
        'include!("../../first/src/fs.rs");',
        "unknown_expansion!();",
    ],
)
def test_other_cargo_target_prevents_ambiguous_suppression(tmp_path, other_source):
    import json

    from skylos import analyze

    _cargo_project(tmp_path / "first")
    (tmp_path / "second/src").mkdir(parents=True)
    (tmp_path / "second/Cargo.toml").write_text(
        '[package]\nname="other"\nversion="0.1.0"\n'
    )
    (tmp_path / "second/src/lib.rs").write_text(other_source)
    report = json.loads(analyze(str(tmp_path), enable_danger=True, grep_cache=False))
    assert not report["analysis_errors"]
    assert [r["rule_id"] for r in report["danger"]] == ["SKY-D415", "SKY-D416"]


def test_external_module_proof_uses_only_admitted_project_sources(
    tmp_path, monkeypatch
):
    from skylos.visitors.languages.rust.danger import drop_non_unix_permission_reviews
    from skylos.visitors.languages.rust.project_model import build_project

    module = _cargo_project(tmp_path)
    omitted = tmp_path / "private/source.rs"
    omitted.parent.mkdir()
    omitted.write_text('include!("../src/fs.rs");')
    rows = scan_rust_file(str(module), {})[7]
    project = build_project(tmp_path, [tmp_path / "src/lib.rs", module])
    scope = {"kind": "repository_root", "scan_path": str(tmp_path)}

    def forbid_read(*args, **kwargs):
        pytest.fail("The project stage reopened a source")

    monkeypatch.setattr(project, "_read", forbid_read)
    monkeypatch.setattr(type(module), "read_bytes", forbid_read)
    monkeypatch.setattr(type(module), "read_text", forbid_read)
    monkeypatch.setattr(type(module), "iterdir", forbid_read)
    assert drop_non_unix_permission_reviews(rows, project, scope, []) == []
    limited = {
        **scope,
        "kind": "repository_root_with_exclusions",
        "excluded_folders": ["private"],
    }
    assert drop_non_unix_permission_reviews(rows, project, limited, []) == rows


@pytest.mark.parametrize(
    ("prefix", "known_markdown"),
    [
        ("#[cfg(doctest)] #[macro_use] extern crate doc_comment;", True),
        ('const LOOKALIKE: &str = "extern crate doc_comment;";', False),
        (
            "#[cfg(doctest)] #[macro_use] extern crate doc_comment; macro_rules! doctest { ($x:literal) => {} }",
            False,
        ),
    ],
)
def test_only_identified_documentation_macro_allows_module_proof(
    tmp_path, prefix, known_markdown
):
    from skylos.visitors.languages.rust.danger import drop_non_unix_permission_reviews
    from skylos.visitors.languages.rust.project_model import build_project

    module = _cargo_project(tmp_path)
    owner = tmp_path / "src/lib.rs"
    owner.write_text(
        prefix
        + '\n#[cfg(doctest)] doctest!("../README.md");\n#[cfg(windows)] mod fs;\n'
    )
    rows = scan_rust_file(str(module), {})[7]
    project = build_project(tmp_path, [owner, module])
    scope = {"kind": "repository_root", "scan_path": str(tmp_path)}
    assert (
        bool(drop_non_unix_permission_reviews(rows, project, scope, []))
        is not known_markdown
    )
