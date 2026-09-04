from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.deadcode.browser_refs import (
    collect_browser_script_entry_files,
    collect_django_static_script_export_files,
)


def _write_static_fixture(tmp_path: Path, template: str) -> Path:
    script = tmp_path / "static" / "widget.js"
    script.parent.mkdir(parents=True)
    script.write_text(
        'export function greet() { return "ok"; }\n',
        encoding="utf-8",
    )
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "page.html").write_text(template, encoding="utf-8")
    return script


def test_django_static_script_preserves_only_its_exported_surface(tmp_path):
    widget = _write_static_fixture(
        tmp_path,
        """{% load static %}
<script src="{% static 'widget.js' %}"></script>
""",
    )
    widget.write_text(
        """export function greet() {
  return "ok";
}

function orphanedHelper() {
  return "unused";
}
""",
        encoding="utf-8",
    )
    unrelated = tmp_path / "unrelated.js"
    unrelated.write_text(
        'export function greet() { return "not loaded"; }\n',
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {
        (Path(item["file"]).name, item["name"])
        for item in result.get("unused_functions", [])
    }

    assert ("widget.js", "greet") not in unused
    assert ("widget.js", "orphanedHelper") in unused
    assert ("unrelated.js", "greet") in unused


@pytest.mark.parametrize(
    "script_tag",
    [
        "<script src=\"{% static 'widget.js' %}\"></script>",
        "<script src='{% static \"widget.js\" %}'></script>",
        "<script defer src=\"{% static 'widget.js?v=1#main' %}\"></script>",
    ],
)
def test_literal_django_static_script_paths_are_resolved(tmp_path, script_tag):
    script = _write_static_fixture(tmp_path, script_tag)

    entries = collect_browser_script_entry_files(tmp_path, [script])

    assert entries == {script.resolve()}


@pytest.mark.parametrize(
    "template",
    [
        '<script src="{% static asset_name %}"></script>',
        "<script src=\"{% static '../widget.js' %}\"></script>",
        "<script src=\"{% static 'missing.js' %}\"></script>",
        "<script data-src=\"{% static 'widget.js' %}\"></script>",
        "<!-- <script src=\"{% static 'widget.js' %}\"></script> -->",
        "{# <script src=\"{% static 'widget.js' %}\"></script> #}",
        (
            "{% comment %}"
            "<script src=\"{% static 'widget.js' %}\"></script>"
            "{% endcomment %}"
        ),
    ],
)
def test_dynamic_unsafe_missing_or_commented_static_paths_do_not_rescue(
    tmp_path, template
):
    script = _write_static_fixture(tmp_path, template)

    entries = collect_browser_script_entry_files(tmp_path, [script])

    assert entries == set()


def test_ambiguous_django_static_path_is_not_guessed(tmp_path):
    first = tmp_path / "first_app" / "static" / "widget.js"
    second = tmp_path / "second_app" / "static" / "widget.js"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("export function first() {}\n", encoding="utf-8")
    second.write_text("export function second() {}\n", encoding="utf-8")
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "page.html").write_text(
        "<script src=\"{% static 'widget.js' %}\"></script>",
        encoding="utf-8",
    )

    entries = collect_browser_script_entry_files(tmp_path, [first, second])

    assert entries == set()


def test_namespaced_django_static_path_selects_exact_asset(tmp_path):
    first = tmp_path / "first_app" / "static" / "first_app" / "widget.js"
    second = tmp_path / "second_app" / "static" / "second_app" / "widget.js"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("export function first() {}\n", encoding="utf-8")
    second.write_text("export function second() {}\n", encoding="utf-8")
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "page.html").write_text(
        "<script src=\"{% static 'first_app/widget.js' %}\"></script>",
        encoding="utf-8",
    )

    entries = collect_browser_script_entry_files(tmp_path, [first, second])

    assert entries == {first.resolve()}


def test_loaded_script_outside_static_directory_is_not_reported_as_dead(tmp_path):
    script = tmp_path / "assets" / "widget.js"
    script.parent.mkdir()
    script.write_text("export function greet() {}\n", encoding="utf-8")
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "page.html").write_text(
        '<script type="module" src="../assets/widget.js"></script>',
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    dead_files = {item["file"] for item in result.get("unused_files", [])}
    unused_functions = {
        (item["file"], item["name"])
        for item in result.get("unused_functions", [])
    }

    assert str(script) not in dead_files
    assert (str(script), "greet") in unused_functions


def test_django_static_module_does_not_consume_its_exports(tmp_path):
    script = _write_static_fixture(
        tmp_path,
        """{% load static %}
<script type="module" src="{% static 'widget.js' %}"></script>
""",
    )

    browser_entries = collect_browser_script_entry_files(tmp_path, [script])
    export_entries = collect_django_static_script_export_files(tmp_path, [script])
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_functions = {
        (item["file"], item["name"])
        for item in result.get("unused_functions", [])
    }

    assert browser_entries == {script.resolve()}
    assert export_entries == set()
    assert (str(script), "greet") in unused_functions
