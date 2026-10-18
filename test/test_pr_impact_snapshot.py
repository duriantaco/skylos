"""The impact baseline holds what the head scan can compare against.

Entries the base snapshot cannot hold (large non-source files, symlinks that
leave the repository, submodules the checkout did not initialize) are left out
instead of failing the comparison, and only where leaving them out cannot
invent a newly unused finding.
"""

import os

import pytest

from skylos.core.pr_impact import ImpactUnavailable, _in_omitted, _LinkTable, _resolve_link
from test.test_pr_impact import baseline, git, scan

CALLER = "def legacy():\n    return 7\n\ndef already_dead():\n    return 8\n\nlegacy()\n"
REMOVED = "def legacy():\n    return 7\n\ndef already_dead():\n    return 8\n\nprint('done')\n"
BIG = 3 * 1024 * 1024

needs_symlinks = pytest.mark.skipif(
    not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symlinks"
)


def commit_all(root, message):
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)


def impact(monkeypatch, capsys, root):
    return scan(monkeypatch, capsys, root, "--diff", "HEAD", "--diff-mode", "impact", "--strict")


def test_large_binary_is_left_out_and_the_removed_caller_still_counts(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, CALLER)
    (tmp_path / "asset.png").write_bytes(b"\x89PNG" + b"\0" * BIG)
    commit_all(tmp_path, "asset")
    source.write_text(REMOVED)

    code, report = impact(monkeypatch, capsys, tmp_path)

    receipt = report["analysis_summary"]["pr_impact"]
    assert code == 1
    assert receipt["status"] == "complete"
    assert receipt["omitted"] == {"oversize_non_source": 1}
    assert [item["name"] for item in report["unused_functions"]] == ["legacy"]
    assert report["unused_functions"][0]["change_status"] == "introduced"


@needs_symlinks
def test_symlink_inside_the_repository_is_recreated(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, CALLER)
    (tmp_path / "AGENTS.md").write_text("Call legacy() from the entry point.\n")
    os.symlink("AGENTS.md", tmp_path / "CLAUDE.md")
    commit_all(tmp_path, "agent docs")
    source.write_text(REMOVED)

    code, report = impact(monkeypatch, capsys, tmp_path)

    receipt = report["analysis_summary"]["pr_impact"]
    assert receipt["status"] == "complete"
    assert "omitted" not in receipt
    assert [item["name"] for item in report["unused_functions"]] == ["legacy"]


@needs_symlinks
def test_symlink_leaving_the_repository_is_left_out(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repository"
    root.mkdir()
    source = baseline(root, CALLER)
    os.symlink("../../outside", root / "docs")
    commit_all(root, "outside link")
    source.write_text(REMOVED)

    code, report = impact(monkeypatch, capsys, root)

    receipt = report["analysis_summary"]["pr_impact"]
    assert receipt["status"] == "complete"
    assert receipt["omitted"] == {"symlink_outside_repository": 1}
    assert [item["name"] for item in report["unused_functions"]] == ["legacy"]


def test_large_source_file_is_never_left_out_silently(tmp_path, monkeypatch, capsys):
    # Analyzed source is never omitted from the baseline. A source file the
    # analyzer cannot read (over its 2,000,000-byte limit) already makes the
    # head scan incomplete, so nothing is claimed as introduced.
    baseline(tmp_path, "from big import big_helper\n\nbig_helper()\n")
    big = tmp_path / "big.py"
    big.write_text('DATA = "' + "a" * BIG + '"\n\n\ndef big_helper():\n    return DATA\n\n\nprint(len(DATA))\n')
    commit_all(tmp_path, "big module")
    (tmp_path / "app.py").write_text("print('done')\n")

    code, report = impact(monkeypatch, capsys, tmp_path)

    receipt = report["analysis_summary"]["pr_impact"]
    assert code == 2
    assert receipt["status"] == "incomplete"
    assert receipt["reason"] == "head_analysis_incomplete"
    assert all("change_status" not in item for item in report["unused_functions"])


def _add_gitlink(root, path):
    sha = git(root, "rev-parse", "HEAD")
    git(root, "update-index", "--add", "--cacheinfo", f"160000,{sha},{path}")
    git(root, "commit", "-q", "-m", "submodule")


def test_submodule_not_checked_out_is_left_out(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, CALLER)
    _add_gitlink(tmp_path, "vendor/lib")
    source.write_text(REMOVED)

    code, report = impact(monkeypatch, capsys, tmp_path)

    receipt = report["analysis_summary"]["pr_impact"]
    assert receipt["status"] == "complete"
    assert receipt["omitted"] == {"submodule_not_checked_out": 1}
    assert [item["name"] for item in report["unused_functions"]] == ["legacy"]


def test_checked_out_submodule_still_blocks(tmp_path, monkeypatch, capsys):
    source = baseline(tmp_path, CALLER)
    _add_gitlink(tmp_path, "vendor/lib")
    (tmp_path / "vendor" / "lib").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vendor" / "lib" / "helpers.py").write_text("def vendored():\n    return 1\n")
    source.write_text(REMOVED)

    code, report = impact(monkeypatch, capsys, tmp_path)

    receipt = report["analysis_summary"]["pr_impact"]
    assert code == 2
    assert receipt["status"] == "incomplete"
    assert receipt["reason"] == "base_submodule_unavailable"
    assert all("change_status" not in item for item in report["unused_functions"])


@needs_symlinks
def test_symlinked_source_is_compared_through_its_real_file(tmp_path, monkeypatch, capsys):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "real.py").write_text("def f():\n    return 1\n")
    os.symlink("real.py", tmp_path / "pkg" / "alias.py")
    baseline(tmp_path, "from pkg.real import f\n\nf()\n")
    commit_all(tmp_path, "package")
    (tmp_path / "app.py").write_text("print('done')\n")

    code, report = impact(monkeypatch, capsys, tmp_path)

    receipt = report["analysis_summary"]["pr_impact"]
    assert receipt["status"] == "complete"
    names = [(item["name"], os.path.basename(item["file"])) for item in report["unused_functions"]]
    assert names == [("f", "real.py")]


@pytest.mark.parametrize(
    ("name", "target", "resolved"),
    [
        ("CLAUDE.md", "AGENTS.md", "AGENTS.md"),
        (".claude/skills/deslop", "../../skills/deslop", "skills/deslop"),
        ("pkg/alias.py", "real.py", "pkg/real.py"),
        ("docs", "../outside", None),
        ("a/b", "../../..", None),
        ("link", "/etc/passwd", None),
        ("link", ".", None),
        ("a/link", "..", None),
        ("link", ".git/config", None),
        ("link", ".GIT/config", None),
        ("link", "", None),
        ("link", "dir\\file", None),
        ("link", "x\0y", None),
    ],
)
def test_resolve_single_link(name, target, resolved):
    files = ["AGENTS.md", "skills/deslop/SKILL.md", "pkg/real.py"]
    assert _resolve_link(name, {name: target}, files)[0] == resolved


CHAIN = {
    "a/b/s": "../../c",
    "p": "a/b/s/../../../x",  # lexically "x"; s/.. is the parent of c
    "q": "a/b/s/f.py",
    "end": "a/b/s",
    "via_end": "end/f.py",
    "to_root": "a/b/s/..",
    "l1": "l2",
    "l2": "l1",
    "self": "self",
    "t": ".git",
    "u": "t/config",
    # On a case-insensitive disk d/e/S is the link d/e/s: the kernel goes to
    # k/../../x, outside; on a case-sensitive one d/e/S is a plain folder.
    "d/e/s": "../../k",
    "case": "d/e/S/../../x",
}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a/b/s", ("c", "")),
        ("p", (None, "symlink_outside_repository")),
        ("q", ("c/f.py", "")),
        ("end", ("c", "")),
        ("via_end", ("c/f.py", "")),
        ("to_root", (None, "symlink_outside_repository")),
        ("l1", (None, "symlink_loop")),
        ("self", (None, "symlink_loop")),
        ("u", (None, "symlink_outside_repository")),
        ("d/e/s", ("k", "")),
        ("case", (None, "symlink_ambiguous_name")),
    ],
)
def test_resolve_link_follows_links_before_dot_dot(name, expected):
    assert _resolve_link(name, CHAIN, ["c/f.py", "k/keep.py"]) == expected


@pytest.mark.parametrize(
    ("links", "files", "expected"),
    [
        # A folder K and a link k are one entry on a case-insensitive disk:
        # k cannot be created, and k/../.. climbs from K, outside.
        ({"k": "sub/deep", "p": "k/../../x"}, ["K/f.py", "sub/deep/g.py", "x/y.py"],
         (None, "symlink_ambiguous_name")),
        # No Unicode table is trusted to match the disk's case folding.
        ({"d/e/\u2c2f": "../../k", "p": "d/e/\u2c5f/../../x"}, ["k/f.py", "x/y.py"],
         (None, "symlink_ambiguous_name")),
        # Nothing in the tree: the disk must never choose what it reaches.
        ({"p": "missing/../x/y.py"}, ["x/y.py"], (None, "symlink_dangling")),
        ({"p": "x/y.py"}, ["x/y.py"], ("x/y.py", "")),
    ],
    ids=["link_vs_folder_case", "non_ascii_component", "through_missing", "plain"],
)
def test_resolution_never_lets_the_disk_choose(links, files, expected):
    assert _resolve_link("p", links, files) == expected


def test_link_chain_longer_than_the_kernel_follows_is_a_loop():
    chain = {f"c{i}": f"c{i + 1}" for i in range(45)}
    chain["c45"] = "real"
    assert _resolve_link("c0", chain, ["real"]) == (None, "symlink_loop")
    assert _resolve_link("c40", chain, ["real"]) == ("real", "")


def test_link_resolution_work_is_bounded():
    noop = "/".join(["."] * 2040)
    table = {f"r{i}": f"{noop}/c0" for i in range(20_000)}
    table.update({f"c{i}": f"{noop}/c{i + 1}" for i in range(40)})
    table["c40"] = "real"
    resolver = _LinkTable(table, ["real"])
    assert {resolver.resolve(name)[1] for name in table} == {"", "symlink_loop"}

    deep = "/".join(["d"] * 1000)
    walk = f"{deep}/" + "/".join([".."] * 1000) + f"/{deep}/x.py"
    resolver = _LinkTable({f"r{i}": walk for i in range(200)}, [f"{deep}/x.py"])
    with pytest.raises(ImpactUnavailable, match="base_symlinks_too_complex"):
        for name in resolver.targets:
            resolver.resolve(name)

    deeper = "/".join(["d"] * 2100)
    assert _resolve_link("r", {"r": deeper}, [f"{deeper}/x.py"]) == (None, "symlink_too_long")


@needs_symlinks
def test_symlink_chain_climbing_out_is_left_out(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repository"
    root.mkdir()
    source = baseline(root, CALLER)
    (root / "c").mkdir()
    (root / "c" / "notes.txt").write_text("notes\n")
    (root / "a" / "b").mkdir(parents=True)
    os.symlink("../../c", root / "a" / "b" / "s")
    os.symlink("a/b/s/../../../outside", root / "p")
    os.symlink("l2", root / "l1")
    os.symlink("l1", root / "l2")
    commit_all(root, "links")
    source.write_text(REMOVED)

    code, report = impact(monkeypatch, capsys, root)

    receipt = report["analysis_summary"]["pr_impact"]
    assert receipt["status"] == "complete"
    assert receipt["omitted"] == {"symlink_outside_repository": 1, "symlink_loop": 2}
    assert [item["name"] for item in report["unused_functions"]] == ["legacy"]


def test_in_omitted_matches_the_path_and_what_is_below_it():
    omitted = {"vendor/lib": "submodule_not_checked_out", "asset.png": "oversize_non_source"}
    assert _in_omitted("vendor/lib", omitted)
    assert _in_omitted("vendor/lib/x.py", omitted)
    assert _in_omitted("asset.png", omitted)
    assert not _in_omitted("vendor/library.py", omitted)
    assert not _in_omitted("app.py", omitted)
