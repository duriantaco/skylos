"""Files a static-site generator loads by convention, and Python used only from
Jupyter notebooks. Each case keeps a genuinely dead file or symbol next to the
convention and requires it to stay reported, and each convention needs its
generator's own evidence."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _scan(root: Path, **options) -> dict:
    return json.loads(analyze(str(root), conf=60, grep_cache=False, **options))


def _reported(result: dict, root: Path) -> set[tuple[str, str, str]]:
    found = set()
    for key in (
        "unused_functions",
        "unused_variables",
        "unused_classes",
        "unused_files",
        "unused_exports",
    ):
        for item in result.get(key) or []:
            rel = Path(item["file"]).resolve().relative_to(root.resolve()).as_posix()
            found.add((key, rel, item.get("simple_name") or item.get("name") or ""))
    return found


def _files(reported: set[tuple[str, str, str]]) -> set[str]:
    return {rel for key, rel, _name in reported if key == "unused_files"}


def _astro_site(root: Path, package: str) -> None:
    _write(root / "package.json", package)
    _write(
        root / "src/content.config.ts",
        "export const collections = { docs: {} };\n",
    )
    _write(
        root / "src/pages/robots.txt.ts",
        'export const GET = () => new Response("User-agent: *");\n',
    )
    _write(root / "src/lib/orphan.ts", "export function stale() { return 1; }\n")


def test_astro_convention_files_are_entry_points(tmp_path):
    _astro_site(tmp_path, '{"name": "site", "dependencies": {"astro": "^5.0.0"}}')
    reported = _reported(_scan(tmp_path), tmp_path)
    assert "src/content.config.ts" not in _files(reported)
    assert "src/pages/robots.txt.ts" not in _files(reported)
    assert not {name for _key, _rel, name in reported} & {"collections", "GET"}
    assert "src/lib/orphan.ts" in _files(reported)


def test_astro_conventions_need_astro(tmp_path):
    _astro_site(tmp_path, '{"name": "site", "dependencies": {"react": "^19.0.0"}}')
    files = _files(_reported(_scan(tmp_path), tmp_path))
    assert "src/content.config.ts" in files


def test_classic_docusaurus_site_files_are_entry_points(tmp_path):
    _write(
        tmp_path / "website/package.json",
        '{"name": "site", "devDependencies": {"docusaurus": "^1.14.7"}}',
    )
    _write(tmp_path / "website/siteConfig.js", "module.exports = { title: 'Docs' };\n")
    _write(
        tmp_path / "website/core/Footer.js",
        "class Footer {}\nmodule.exports = Footer;\n",
    )
    _write(
        tmp_path / "website/lib/unused.js", "module.exports = function stale() {};\n"
    )
    _write(tmp_path / "other/package.json", '{"name": "other"}')
    _write(
        tmp_path / "other/core/Footer.js", "class Footer {}\nmodule.exports = Footer;\n"
    )
    files = _files(_reported(_scan(tmp_path), tmp_path))
    assert "website/siteConfig.js" not in files
    assert "website/core/Footer.js" not in files
    assert "website/lib/unused.js" in files
    assert "other/core/Footer.js" in files


def test_jekyll_includes_count_only_when_a_page_includes_them(tmp_path):
    _write(tmp_path / "site/_config.yml", "title: Docs\n")
    _write(
        tmp_path / "site/index.md",
        "---\nlayout: default\n---\n<script>\n{% include chart.js %}\n</script>\n",
    )
    _write(
        tmp_path / "site/_includes/chart.js",
        "function drawChart() { return 1; }\ndrawChart();\n",
    )
    _write(
        tmp_path / "site/_includes/orphan.js",
        "function unused() { return 2; }\nunused();\n",
    )
    _write(
        tmp_path / "plain/_includes/chart.js",
        "function drawChart() { return 1; }\ndrawChart();\n",
    )
    files = _files(_reported(_scan(tmp_path), tmp_path))
    assert "site/_includes/chart.js" not in files
    assert "site/_includes/orphan.js" in files
    assert "plain/_includes/chart.js" in files


def _notebook(cells: list[dict]) -> str:
    return json.dumps(
        {"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    )


def test_classes_used_only_from_a_notebook_are_kept(tmp_path):
    _write(tmp_path / "pkg/__init__.py", "")
    _write(
        tmp_path / "pkg/models.py",
        "class LassoModel:\n    pass\n\n\n"
        "class PrintedOnly:\n    pass\n\n\n"
        "class DescribedOnly:\n    pass\n",
    )
    _write(
        tmp_path / "notebooks/research.ipynb",
        _notebook(
            [
                {
                    "cell_type": "markdown",
                    "metadata": {},
                    "source": ["We could also try DescribedOnly here."],
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": 1,
                    "source": [
                        "%matplotlib inline\n",
                        "from pkg.models import LassoModel\n",
                        "model = LassoModel()\n",
                    ],
                    "outputs": [
                        {
                            "output_type": "stream",
                            "name": "stdout",
                            "text": ["PrintedOnly was skipped\n"],
                        }
                    ],
                },
            ]
        ),
    )
    names = {
        name
        for key, _rel, name in _reported(_scan(tmp_path, grep_verify=True), tmp_path)
        if key == "unused_classes"
    }
    assert "LassoModel" not in names
    assert {"PrintedOnly", "DescribedOnly"} <= names
