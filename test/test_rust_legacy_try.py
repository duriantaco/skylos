import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file
from skylos.visitors.languages.rust.core import RustCore


def crate(tmp_path, source, settings="", extra=""):
    path = tmp_path / "src" / "lib.rs"
    path.parent.mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "legacy"\nversion = "0.1.0"\n' + settings + extra
    )
    path.write_text(source)
    return path


@pytest.mark.parametrize("settings", ["", 'edition = "2015"\n'])
def test_legacy_try_preserves_calls_and_source_positions(tmp_path, settings):
    path = crate(
        tmp_path,
        """use std::os::unix::fs::OpenOptionsExt;
fn make() -> std::io::Result<()> {
    let _é = "try!(a())";
    try!(std::fs::OpenOptions::new().mode(644).open("data"));
    Ok(())
}
pub fn start() -> std::io::Result<()> { try!(make()); Ok(()) }
""",
        settings,
    )
    result = scan_rust_file(str(path), {}, _include_analysis_metadata=True)
    assert result[25] is None
    source = path.read_bytes()
    assert RustCore(str(path), source).root_node.text == source
    assert ("make", str(path)) in result[1]
    (finding,) = [item for item in result[7] if item["rule_id"] == "SKY-D416"]
    assert finding["line"] == 4
    assert finding["col"] == 9
    report = json.loads(analyze(str(tmp_path), conf=40))
    assert not report.get("analysis_errors")
    assert all(item["name"] != "make" for item in report.get("unused_functions", []))


@pytest.mark.parametrize(
    "settings, extra",
    [
        ('edition = "2021"\n', ""),
        ("", '[lib]\nedition = "2018"\n'),
        ("edition.workspace = true\n", ""),
    ],
)
def test_legacy_try_needs_a_proven_2015_target(tmp_path, settings, extra):
    path = crate(tmp_path, "fn f(){ try!(read()); }", settings, extra)
    assert RustCore(str(path), path.read_bytes()).root_node.has_error


def test_legacy_try_checks_workspace_default_in_root_package(tmp_path):
    path = crate(
        tmp_path,
        "fn f(){ try!(read()); }",
        "edition.workspace = true\n",
        '[workspace.package]\nedition = "2015"\n',
    )
    assert not RustCore(str(path), path.read_bytes()).root_node.has_error


def test_legacy_try_keeps_unrelated_errors_and_real_source_lines(tmp_path):
    path = crate(tmp_path, "fn f(){\n try!(read());\n let value = ;\n}\n")
    result = scan_rust_file(str(path), {}, _include_analysis_metadata=True)
    assert result[25]["kind"] == "syntax_error"
    assert result[25]["line"] == 3


@pytest.mark.parametrize(
    "source",
    [
        "fn f(){try!(read() +);}",
        "fn f(){try!; (read());}",
        "macro_rules! try { ($e:expr) => { () } }\nfn f(){ try!(read()); }",
    ],
)
def test_legacy_try_abstains_on_malformed_or_shadowed_calls(tmp_path, source):
    path = crate(tmp_path, source)
    assert RustCore(str(path), path.read_bytes()).root_node.has_error


@pytest.mark.parametrize("edition, has_error", [("2015", False), ("2024", True)])
def test_workspace_member_only_inherits_inside_scan(tmp_path, edition, has_error):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["member"]\n[workspace.package]\n'
        f'edition = "{edition}"\n'
    )
    member = tmp_path / "member"
    member.mkdir()
    path = crate(member, "fn f(){try!(read());}", "edition.workspace = true\n")
    assert (
        RustCore(
            str(path), path.read_bytes(), project_root=tmp_path
        ).root_node.has_error
        == has_error
    )
    assert RustCore(
        str(path), path.read_bytes(), project_root=member
    ).root_node.has_error
    assert bool(json.loads(analyze(str(tmp_path))).get("analysis_errors")) == has_error


def test_legacy_try_requires_an_in_scope_regular_manifest(tmp_path):
    path = crate(tmp_path, "fn f(){try!(read());}")
    original = tmp_path / "original.toml"
    (tmp_path / "Cargo.toml").rename(original)
    (tmp_path / "Cargo.toml").symlink_to(original)
    assert RustCore(
        str(path), path.read_bytes(), project_root=tmp_path
    ).root_node.has_error
    (tmp_path / "Cargo.toml").unlink()
    original.rename(tmp_path / "Cargo.toml")
    linked = tmp_path / "other"
    linked.symlink_to(path.parent, target_is_directory=True)
    assert RustCore(
        str(linked / "lib.rs"), path.read_bytes(), project_root=tmp_path
    ).root_node.has_error


@pytest.mark.parametrize("shadow", [False, True])
def test_textual_macro_scope_from_parent_module(tmp_path, shadow):
    lib = crate(tmp_path, "mod outer;")
    (lib.parent / "outer.rs").write_text(
        ("macro_rules! try { ($e:expr) => { () } }\n" if shadow else "")
        + "mod reader;\n"
    )
    folder = lib.parent / "outer"
    folder.mkdir()
    child = folder / "reader.rs"
    child.write_text("fn f(){try!(read());}")
    assert (
        RustCore(
            str(child), child.read_bytes(), project_root=tmp_path
        ).root_node.has_error
        == shadow
    )


def test_nearby_manifest_cannot_hide_outer_symlink(tmp_path):
    real = tmp_path / "real"
    member = real / "member"
    member.mkdir(parents=True)
    path = crate(member, "fn f(){try!(read());}")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    linked = alias / "member/src/lib.rs"
    assert RustCore(
        str(linked), path.read_bytes(), project_root=tmp_path
    ).root_node.has_error
    assert RustCore(
        str(path), path.read_bytes(), project_root=real / "member/src/child"
    ).root_node.has_error


def test_custom_crate_root_is_ambiguous_for_legacy_children(tmp_path):
    lib = crate(tmp_path, "mod reader;", extra='[lib]\npath = "src/custom.rs"\n')
    (lib.parent / "custom.rs").write_text(
        "macro_rules! try { ($e:expr) => { () } }\nmod reader;\n"
    )
    child = lib.parent / "reader.rs"
    child.write_text("fn f(){try!(read());}")
    assert RustCore(
        str(child), child.read_bytes(), project_root=tmp_path
    ).root_node.has_error
