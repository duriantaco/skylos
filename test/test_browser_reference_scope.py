"""Browser references retain their admitted-script and consumer boundaries."""

import pytest

from skylos.deadcode.browser_refs import collect_browser_event_handler_refs
from test.fixture_paths import write_fixture


SCRIPT = "function browserOnly() { return 1; }\nfunction untouched() { return 2; }\n"
CONSUMER = 'from nicegui import ui\nui.run_javascript("browserOnly()")\n'


def _refs(root, source_files):
    # Sorting retains duplicate occurrences while avoiding set iteration order.
    return sorted(collect_browser_event_handler_refs(root, source_files))


def test_python_consumer_without_any_javascript_has_no_target(tmp_path):
    app = write_fixture(tmp_path, "app.py", CONSUMER)

    assert _refs(tmp_path, [app]) == []


def test_html_event_and_inline_dispatch_survive_without_admitted_scripts(tmp_path):
    app = write_fixture(tmp_path, "app.py", "value = 1\n")
    page = write_fixture(
        tmp_path,
        "index.html",
        '<button onclick="pageClick()">go</button>\n'
        '<script>window["inlineDispatch"]()</script>\n',
    )

    assert _refs(tmp_path, [app]) == [
        ("inlineDispatch", str(page)),
        ("pageClick", str(page)),
    ]


def test_rendered_mdx_component_survives_without_admitted_scripts(tmp_path):
    component = write_fixture(
        tmp_path,
        "Card.tsx",
        "export function Card() { return null; }\n"
        "export function Unrendered() { return null; }\n",
    )
    page = write_fixture(
        tmp_path,
        "page.mdx",
        'import { Card, Unrendered } from "./Card";\n\n'
        "<Card />\n\n```mdx\n<Unrendered />\n```\n",
    )

    assert _refs(tmp_path, [page]) == [("Card", str(component))]


def test_script_on_disk_outside_admitted_sources_does_not_gain_references(tmp_path):
    app = write_fixture(tmp_path, "app.py", CONSUMER)
    write_fixture(tmp_path, "web/app.js", SCRIPT)
    write_fixture(tmp_path, "index.html", '<script src="web/app.js"></script>\n')

    assert _refs(tmp_path, [app]) == []


def test_python_consumer_references_only_the_loaded_classic_target(tmp_path):
    app = write_fixture(tmp_path, "app.py", CONSUMER)
    script = write_fixture(tmp_path, "web/app.js", SCRIPT)
    write_fixture(tmp_path, "index.html", '<script src="web/app.js"></script>\n')

    assert _refs(tmp_path, [app, script]) == [("browserOnly", str(script))]


def test_imported_python_consumer_value_keeps_the_loaded_classic_target(tmp_path):
    value = write_fixture(tmp_path, "config.py", 'code = "browserOnly()"\n')
    app = write_fixture(
        tmp_path,
        "app.py",
        "from config import code\nfrom nicegui import ui\nui.run_javascript(code)\n",
    )
    script = write_fixture(tmp_path, "web/app.js", SCRIPT)
    write_fixture(tmp_path, "index.html", '<script src="web/app.js"></script>\n')

    assert _refs(tmp_path, [app, value, script]) == [("browserOnly", str(script))]


@pytest.mark.parametrize("kind", ["unloaded", "module-tag", "module-syntax"])
def test_python_consumer_does_not_reference_unloaded_or_module_code(tmp_path, kind):
    app = write_fixture(tmp_path, "app.py", CONSUMER)
    source = "export " + SCRIPT if kind == "module-syntax" else SCRIPT
    script = write_fixture(tmp_path, "web/app.js", source)
    if kind != "unloaded":
        module_attribute = ' type="module"' if kind == "module-tag" else ""
        write_fixture(
            tmp_path,
            "index.html",
            f'<script{module_attribute} src="web/app.js"></script>\n',
        )

    assert _refs(tmp_path, [app, script]) == []
