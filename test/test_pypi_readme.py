"""The README PyPI renders has no relative links or images.

pypi.org resolves a relative target against https://pypi.org/project/skylos/,
so every one is a 404 there. tools/release/pypi_readme.py rewrites them to
GitHub URLs pinned to the release tag before the publish build.
"""

import re
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
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
