"""Only rendered, selected API declarations can establish external liveness."""

import json

import pytest

from skylos.analyzer import analyze


def _body(name, *, documented=True):
    lines = [f"def {name}(path):"]
    if documented:
        lines.append('    """Public surface when an API page selects it."""')
    lines.extend(
        [
            '    with open(path, encoding="utf-8") as handle:',
            "        rows = handle.read().splitlines()",
            "    return [row.strip() for row in rows if row]",
        ]
    )
    return "\n".join(lines) + "\n\n"


def _scan(tmp_path, doc, suffix="md"):
    (tmp_path / "lib").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="lib"\nversion="1"\n')
    (tmp_path / "lib/__init__.py").write_text("")
    (tmp_path / "lib/api.py").write_text(
        _body("surface_api") + _body("neighbor_api", documented=False)
    )
    (tmp_path / f"docs/api.{suffix}").write_text(doc.lstrip("\n"))
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert not result.get("analysis_errors")
    return {row["simple_name"] for row in result.get("unused_functions", [])}


@pytest.mark.parametrize(
    "doc,suffix",
    [
        ("```rst\n:func:`lib.api.surface_api`\n```\n", "md"),
        ("~~~python\n{func}`lib.api.surface_api`\n~~~\n", "md"),
        ("````markdown\n```{autofunction} lib.api.surface_api\n```\n````\n", "md"),
        ("```{autofunction} lib.api.surface_api\n", "md"),
        ("    {func}`lib.api.surface_api`\n", "md"),
        ("``{func}`lib.api.surface_api` ``\n", "md"),
        ("\\{func}`lib.api.surface_api`\n", "md"),
        ("<!-- {func}`lib.api.surface_api` -->\n", "md"),
        ("<!-- ignored --> {func}`lib.api.surface_api`\n", "md"),
        ("<!--\n```{autofunction} lib.api.surface_api\n```\n-->\n", "md"),
        (".. code-block:: rst\n\n   .. autofunction:: lib.api.surface_api\n", "rst"),
        ("Example::\n\n   :func:`lib.api.surface_api`\n", "rst"),
        ("..\n   :func:`lib.api.surface_api`\n", "rst"),
        ("``:func:`lib.api.surface_api` ``\n", "rst"),
        ("\\:func:`lib.api.surface_api`\n", "rst"),
        (".. autofunction:: lib.api.surface_api\n", "md"),
        (":func:`lib.api.surface_api`\n", "md"),
        ("::: lib.api\n", "rst"),
        (
            ".. automodule:: lib.api\n\n   Example::\n\n      :members:\n      :undoc-members:\n",
            "rst",
        ),
    ],
)
def test_literal_comments_and_foreign_markup_do_not_declare_api(tmp_path, doc, suffix):
    assert _scan(tmp_path, doc, suffix) == {"surface_api", "neighbor_api"}


@pytest.mark.parametrize(
    "doc,suffix",
    [
        (":func:`lib.api.surface_api`\n", "rst"),
        ("`lib.api.surface_api`:func:\n", "rst"),
        (".. autofunction:: lib.api.surface_api\n", "rst"),
        ("{func}`lib.api.surface_api`\n", "md"),
        ("{py:func}`API title <lib.api.surface_api>`\n", "md"),
        ("```{autofunction} lib.api.surface_api\n```\n", "md"),
        (":::{autofunction} lib.api.surface_api\n:::\n", "md"),
        ("```{eval-rst}\n.. autofunction:: lib.api.surface_api\n```\n", "md"),
        ("```rst\n<!--\n```\n{func}`lib.api.surface_api`\n", "md"),
        ("Text <!-- ignored --> {func}`lib.api.surface_api`\n", "md"),
        (".. currentmodule:: lib.api\n\n.. autosummary::\n\n   surface_api\n", "rst"),
    ],
)
def test_real_docs_targets_remain_live_without_rescuing_neighbors(
    tmp_path, doc, suffix
):
    assert _scan(tmp_path, doc, suffix) == {"neighbor_api"}


@pytest.mark.parametrize(
    "options,expected",
    [
        ("", {"neighbor_api"}),
        ('filters: ["!surface_api"]', {"surface_api", "neighbor_api"}),
        ('filters:\n  - "!surface_api"', {"surface_api", "neighbor_api"}),
        ('filters: ["surface"]', {"neighbor_api"}),
        ('filters: ["nothing"]', {"surface_api", "neighbor_api"}),
        ('filters: ["!.*", "^surface_api$"]', {"neighbor_api"}),
        ("filters: []", {"neighbor_api"}),
        ('members: [neighbor_api]\nfilters: ["!neighbor_api"]', {"surface_api"}),
        ("members:\n  - neighbor_api", {"surface_api"}),
        ("members: []", {"surface_api", "neighbor_api"}),
        ("members: false", {"surface_api", "neighbor_api"}),
        ("show_if_no_docstring: true", set()),
        ("show_if_no_docstring: yes", set()),
        ('members: "unknown selection"', {"surface_api", "neighbor_api"}),
        ("filters: {unexpected: shape}", {"surface_api", "neighbor_api"}),
        ('filters: ["["]', {"surface_api", "neighbor_api"}),
        ("filters: !env SOME_FILTER", {"surface_api", "neighbor_api"}),
        ('show_if_no_docstring: "true"', {"surface_api", "neighbor_api"}),
        ('filters: ["!surface_api"]\nfilters: []', {"surface_api", "neighbor_api"}),
        (
            "members: &members [surface_api]\nfilters: *members",
            {"surface_api", "neighbor_api"},
        ),
        ('filters: ["(a+)+$"]', {"surface_api", "neighbor_api"}),
    ],
)
def test_mkdocstrings_selection_is_explicit_and_conservative(
    tmp_path, options, expected
):
    lines = "\n".join("      " + line for line in options.splitlines())
    doc = "::: lib.api\n    options:\n" + lines + "\n"
    assert _scan(tmp_path, doc) == expected


@pytest.mark.parametrize("value", ["[]", "false", '"unknown"'])
def test_invalid_options_container_does_not_claim_a_rendered_module(tmp_path, value):
    assert _scan(tmp_path, "::: lib.api\n    options: " + value + "\n") == {
        "surface_api",
        "neighbor_api",
    }


def test_deeply_nested_documentation_does_not_crash_analysis(tmp_path):
    nested = "\n".join("    " * level + ".. note::" for level in range(80))
    assert _scan(tmp_path, nested + "\n", "rst") == {"surface_api", "neighbor_api"}


@pytest.mark.parametrize("extra", ["", '      filters: ["!surface_api"]\n'])
def test_explicit_all_members_selects_undocumented_members(tmp_path, extra):
    assert (
        _scan(tmp_path, "::: lib.api\n    options:\n      members: true\n" + extra)
        == set()
    )


@pytest.mark.parametrize(
    "doc",
    [
        "<pre>\n{func}`lib.api.surface_api`\n</pre>\n",
        "<script>\n{func}`lib.api.surface_api`\n</script>\n",
        "> ```text\n> {func}`lib.api.surface_api`\n> ```\n",
        '[link](https://example.org "{func}`lib.api.surface_api`")\n',
        '[link](https://example.org "{func}`lib.api.surface_api`") \\{func}`lib.api.surface_api`\n',
    ],
)
def test_markdown_literal_containers_and_link_attributes_do_not_declare_api(
    tmp_path, doc
):
    assert _scan(tmp_path, doc) == {"surface_api", "neighbor_api"}


@pytest.mark.parametrize(
    "doc",
    [
        "> See {func}`lib.api.surface_api`.\n",
        "See *{func}`lib.api.surface_api`*.\n",
    ],
)
def test_rendered_markdown_container_roles_remain_supported(tmp_path, doc):
    assert _scan(tmp_path, doc) == {"neighbor_api"}
