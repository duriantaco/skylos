"""The README PyPI renders has no relative links or images.

pypi.org resolves a relative target against https://pypi.org/project/skylos/,
so every one is a 404 there. tools/release/pypi_readme.py rewrites them to
GitHub URLs pinned to the release tag before the publish build.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from tools.release import pypi_readme
from tools.release.pypi_readme import absolutize, is_relative, main, rewrite

REPO = Path(__file__).resolve().parents[1]
TARGET = re.compile(r'\]\(([^)\s]+)|\b(?:src|href)="([^"]+)"')


def _relative_targets(text: str) -> list[str]:
    targets = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in TARGET.finditer(line):
            target = match.group(1) or match.group(2)
            if is_relative(target):
                targets.append(target)
    return targets


def test_links_point_at_the_release_tag():
    assert (
        absolutize("./docs/done-gate.md#not-yet", "v4.48.0")
        == "https://github.com/duriantaco/skylos/blob/v4.48.0/docs/done-gate.md#not-yet"
    )
    assert absolutize("LICENSE", "v4.48.0").endswith("/blob/v4.48.0/LICENSE")


def test_images_use_raw_content_urls():
    assert (
        absolutize("assets/DOG_1.png", "v4.48.0")
        == "https://raw.githubusercontent.com/duriantaco/skylos/v4.48.0/assets/DOG_1.png"
    )


def test_absolute_links_and_anchors_are_left_alone():
    for target in (
        "https://skylos.dev",
        "#language-support",
        "mailto:founder@skylos.dev",
        "//example.com/x.png",
    ):
        assert absolutize(target, "v1.0.0") == target


def test_fenced_code_is_left_alone():
    text = "[a](./a.md)\n```md\n[b](./b.md)\n```\n"
    assert rewrite(text, "v1.0.0") == (
        "[a](https://github.com/duriantaco/skylos/blob/v1.0.0/a.md)\n"
        "```md\n[b](./b.md)\n```\n"
    )


def test_repository_readme_has_no_relative_targets_after_rewrite():
    text = (REPO / "README.md").read_text(encoding="utf-8")
    assert _relative_targets(text), "README has no relative links; drop this step"
    rewritten = rewrite(text, "v0.0.0")
    assert _relative_targets(rewritten) == []
    # The MCP Registry ownership marker must survive the rewrite.
    assert "<!-- mcp-name: io.github.duriantaco/skylos -->" in rewritten


def test_main_rewrites_in_place(tmp_path):
    readme = tmp_path / "README.md"
    assert write_text_no_symlink(readme, '<img src="assets/logo.png">\n')
    assert main(["--ref", "v9.9.9", str(readme)]) == 0
    assert readme.read_text(encoding="utf-8") == (
        '<img src="https://raw.githubusercontent.com/duriantaco/skylos/v9.9.9/assets/logo.png">\n'
    )


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "[guide][ref]\n[ref]: ./docs/guide.md 'Guide'\n",
            "[guide][ref]\n[ref]: {blob}/docs/guide.md 'Guide'\n",
        ),
        (
            "[guide](<docs/space name.md> 'Title')",
            "[guide](<{blob}/docs/space%20name.md> 'Title')",
        ),
        ("[guide](docs/a(b(c)).md)", "[guide]({blob}/docs/a%28b%28c%29%29.md)"),
        (r"[guide](docs/a\(b\).md)", "[guide]({blob}/docs/a%28b%29.md)"),
        ("[guide](./docs/../LICENSE)", "[guide]({blob}/LICENSE)"),
        (
            "[guide](docs/guide.md?raw=1#intro)",
            "[guide]({blob}/docs/guide.md?raw=1#intro)",
        ),
        (
            "<IMG SRC = 'assets/logo.png' alt='dog'>",
            "<IMG SRC = '{raw}/assets/logo.png' alt='dog'>",
        ),
        ("<a href='LICENSE'>license</a>", "<a href='{blob}/LICENSE'>license</a>"),
        ("<img src='assets/logo'>", "<img src='{raw}/assets/logo'>"),
        ("![logo](assets/logo)", "![logo]({raw}/assets/logo)"),
        (
            "<img data-src='assets/lazy.png' title='href=\"LICENSE\"'>",
            "<img data-src='assets/lazy.png' title='href=\"LICENSE\"'>",
        ),
        ("[missing](docs/unclosed.md", "[missing](docs/unclosed.md"),
        ("[empty]()", "[empty]()"),
        ("[anchor](#language-support)", "[anchor](#language-support)"),
    ],
)
def test_additional_readme_link_forms(text, expected):
    assert rewrite(text, "v1.0.0") == expected.format(
        blob="https://github.com/duriantaco/skylos/blob/v1.0.0",
        raw="https://raw.githubusercontent.com/duriantaco/skylos/v1.0.0",
    )


@pytest.mark.parametrize(
    "example",
    [
        "~~~md\n[x](docs/example.md)\n~~~\n",
        "````md\n```\n[x](docs/example.md)\n```\n````\n",
        "```md\n[x](docs/example.md)\n~~~\n",
        "`[x](docs/example.md)`",
        "``literal ` [x](docs/example.md)``",
        "`[x]\n(docs/example.md)`",
        '`<img src="assets/logo.png">`',
    ],
)
def test_code_examples_are_preserved(example):
    text = example + "\n[real](LICENSE)\n"
    # An unclosed fence deliberately consumes the rest of the document.
    if example.startswith("```md"):
        assert rewrite(text, "v1.0.0") == text
    else:
        assert rewrite(text, "v1.0.0") == example + (
            "\n[real](https://github.com/duriantaco/skylos/blob/v1.0.0/LICENSE)\n"
        )


def test_rewrite_is_idempotent_and_preserves_line_endings():
    text = "[guide](./docs/guide.md)\r\n`[example](relative.md)`\r\n"
    rewritten = rewrite(text, "v1.0.0+release")
    assert "/v1.0.0%2Brelease/" in rewritten
    assert rewritten.count("\r\n") == text.count("\r\n")
    assert rewrite(rewritten, "v1.0.0+release") == rewritten


def test_link_outside_repository_fails_before_overwriting(tmp_path):
    readme = tmp_path / "README.md"
    original = "[outside](../other-repo/README.md)\n"
    assert write_text_no_symlink(readme, original)
    with pytest.raises(ValueError, match="outside the repository"):
        main(["--ref", "v1.0.0", str(readme)])
    assert readme.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("link_kind", ["leaf_symlink", "parent_symlink", "hardlink"])
def test_main_refuses_linked_readme_without_overwriting_target(tmp_path, link_kind):
    external = tmp_path / "external"
    external.mkdir()
    victim = external / "README.md"
    original = "[guide](docs/guide.md)\n"
    assert write_text_no_symlink(victim, original)
    readme = tmp_path / "README.md"
    try:
        if link_kind == "leaf_symlink":
            readme.symlink_to(victim)
        elif link_kind == "parent_symlink":
            linked_parent = tmp_path / "linked"
            linked_parent.symlink_to(external, target_is_directory=True)
            readme = linked_parent / "README.md"
        else:
            os.link(victim, readme)
    except (OSError, NotImplementedError):
        pytest.skip(f"{link_kind} unavailable")

    with pytest.raises(OSError, match="Could not safely rewrite README"):
        main(["--ref", "v1.2.3", str(readme)])

    assert victim.read_text(encoding="utf-8") == original
    if link_kind == "hardlink":
        assert readme.stat().st_ino == victim.stat().st_ino
    else:
        assert (readme if link_kind == "leaf_symlink" else readme.parent).is_symlink()


def test_main_does_not_report_success_when_guarded_write_fails(
    tmp_path, monkeypatch, capsys
):
    readme = tmp_path / "README.md"
    original = "[guide](docs/guide.md)\n"
    assert write_text_no_symlink(readme, original)
    monkeypatch.setattr(pypi_readme, "write_text_no_symlink", lambda *a, **kw: False)

    with pytest.raises(OSError, match="Could not safely rewrite README"):
        main(["--ref", "v1.2.3", str(readme)])

    assert readme.read_text(encoding="utf-8") == original
    assert capsys.readouterr().out == ""


def test_main_rejects_leaf_symlink_swapped_in_after_read(tmp_path, monkeypatch):
    readme = tmp_path / "README.md"
    victim = tmp_path / "victim.md"
    assert write_text_no_symlink(readme, "[guide](docs/guide.md)\n")
    assert write_text_no_symlink(victim, "KEEP\n")
    try:
        probe = tmp_path / "link-probe"
        probe.symlink_to(victim)
        probe.unlink()
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    def swap_then_write(path, text, **kwargs):
        assert Path(path) == readme
        readme.unlink()
        readme.symlink_to(victim)
        return write_text_no_symlink(path, text, **kwargs)

    monkeypatch.setattr(pypi_readme, "write_text_no_symlink", swap_then_write)

    with pytest.raises(OSError, match="Could not safely rewrite README"):
        main(["--ref", "v1.2.3", str(readme)])

    assert victim.read_text(encoding="utf-8") == "KEEP\n"
    assert readme.is_symlink()


def test_script_runs_without_installed_skylos_or_site_packages(tmp_path):
    readme = tmp_path / "README.md"
    assert write_text_no_symlink(readme, "[guide](docs/guide.md)\n")

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(REPO / "tools/release/pypi_readme.py"),
            "--ref",
            "v1.2.3",
            str(readme),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "pointed 1 line(s)" in result.stdout
    assert readme.read_text(encoding="utf-8") == (
        "[guide](https://github.com/duriantaco/skylos/blob/v1.2.3/docs/guide.md)\n"
    )
