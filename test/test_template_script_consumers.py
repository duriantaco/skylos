"""Inline template JavaScript needs a runtime consumer and a resolved owner."""

import json
from pathlib import Path

import pytest

from skylos.deadcode import browser_refs


def _project(
    tmp_path, markup, source="function greet() {}\nfunction unusedHelper() {}\n"
):
    root = tmp_path.resolve()
    script = root / "static" / "widget.js"
    script.parent.mkdir()
    script.write_text(source)
    template = root / "templates" / "page.html"
    template.parent.mkdir()
    template.write_text(markup)
    return root, script


def _refs(root, script):
    return browser_refs.collect_browser_event_handler_refs(root, [script])


_LOAD = "<script src=\"{% static 'widget.js' %}\"></script>"


@pytest.mark.parametrize(
    "code",
    [
        "greet();",
        "window.greet();",
        'document.addEventListener("DOMContentLoaded", greet);',
        'window.addEventListener("load", greet);',
        'document.querySelector("button").addEventListener("click", greet);',
        'document.addEventListener("DOMContentLoaded", () => greet());',
        "function start() { greet(); } start();",
        'function start() { greet(); } document.addEventListener("DOMContentLoaded", start);',
        "function unrelated(greet) { greet(); } greet();",
        "greet(); greet = () => {};",
        "(() => greet())();",
        "{ const start = () => greet(); start(); }",
    ],
    ids=[
        "direct",
        "window",
        "document-listener",
        "window-listener",
        "element-listener",
        "listener-arrow",
        "called-local-function",
        "registered-local-function",
        "unrelated-shadow",
        "call-before-replacement",
        "called-arrow-iife",
        "called-block-local-function",
    ],
)
def test_inline_classic_runtime_consumers_use_only_loaded_global(tmp_path, code):
    root, script = _project(tmp_path, _LOAD + f"<script>{code}</script>")

    refs = _refs(root, script)

    assert ("greet", str(script)) in refs
    assert ("unusedHelper", str(script)) not in refs


@pytest.mark.parametrize(
    "markup",
    [
        _LOAD + '<script>"greet()"; // greet()\n/* greet() */</script>',
        _LOAD + "<script>function abandoned() { greet(); }</script>",
        _LOAD + "<script>class Unused { run() { greet(); } }</script>",
        _LOAD + "<script>const greet = () => {}; greet();</script>",
        _LOAD + "<script>greet = () => {}; greet();</script>",
        _LOAD + "<script>window.greet = () => {}; window.greet();</script>",
        _LOAD
        + '<script>document.addEventListener("load", (greet) => greet());</script>',
        _LOAD
        + '<script>const document = fake; document.addEventListener("load", greet);</script>',
        _LOAD + '<script>fake.addEventListener("load", greet);</script>',
        _LOAD + '<script type="application/json">greet()</script>',
        _LOAD + '<script src="missing.js">greet()</script>',
        _LOAD + "<template><script>greet()</script></template>",
        _LOAD + "<!-- <script>greet()</script> -->",
        _LOAD + "{% comment %}<script>greet()</script>{% endcomment %}",
        _LOAD + "<p>greet()</p>",
        "<script>greet()</script>",
        "<script>greet()</script>" + _LOAD,
        "<script defer src=\"{% static 'widget.js' %}\"></script><script>greet()</script>",
        _LOAD + '<script type="module">function greet() {} greet();</script>',
        _LOAD
        + '<script>function start() { greet(); } document.addEventListener("load", (start) => start());</script>',
        _LOAD + "<script>function start() { greet(); } start = fake; start();</script>",
        _LOAD + "<script>start(); const start = () => greet();</script>",
        _LOAD + "<script>export {}; greet();</script>",
        _LOAD + '<script>import "missing.js"; greet();</script>',
        _LOAD + '<script>window["greet"] = fake; greet();</script>',
        _LOAD
        + '<script>document.addEventListener = fake; document.addEventListener("load", greet);</script>',
        _LOAD
        + '<script>document.querySelector = fake; document.querySelector("button").addEventListener("click", greet);</script>',
        _LOAD + "<script>greet = fake;</script><script>greet();</script>",
        _LOAD + "<script>(() => { greet = fake; })(); greet();</script>",
        _LOAD + "<script>function start() { return; greet(); } start();</script>",
        _LOAD + "<script>function* start() { greet(); } start();</script>",
        _LOAD
        + '<script>function wipe() { greet = fake; } document.addEventListener("load", wipe); wipe(); greet();</script>',
        _LOAD + "<script>{ const start = () => greet(); } start();</script>",
        _LOAD + "<script>try { throw fake; } catch (greet) { greet(); }</script>",
    ],
    ids=[
        "comments-data",
        "uncalled-function",
        "uncalled-class-method",
        "local-binding",
        "bare-replacement",
        "window-replacement",
        "callback-parameter",
        "fake-document",
        "fake-event-api",
        "inert-type",
        "src-ignores-body",
        "inert-template",
        "html-comment",
        "django-comment",
        "prose",
        "unloaded",
        "called-before-load",
        "deferred-before-inline",
        "local-module-binding",
        "callback-shadows-local-function",
        "replaced-local-function",
        "function-variable-before-initialization",
        "invalid-classic-export",
        "invalid-classic-import",
        "window-bracket-replacement",
        "replaced-document-listener",
        "replaced-document-selector",
        "previous-inline-replacement",
        "iife-replacement",
        "uncalled-after-return",
        "uniterated-generator",
        "registered-then-called-replacement",
        "block-local-callable-does-not-escape",
        "catch-parameter-shadow",
    ],
)
def test_inline_lookalikes_do_not_consume_classic_global(tmp_path, markup):
    root, script = _project(tmp_path, markup)

    assert ("greet", str(script)) not in _refs(root, script)


def test_inline_call_is_not_assigned_to_another_pages_script(tmp_path):
    root, script = _project(tmp_path, _LOAD)
    (root / "templates" / "other.html").write_text("<script>greet()</script>")

    assert ("greet", str(script)) not in _refs(root, script)


@pytest.mark.parametrize(
    "code",
    [
        "import { greet } from \"{% static 'widget.js' %}\"; greet();",
        "import { greet as welcome } from \"{% static 'widget.js' %}\"; welcome();",
        'import { greet } from "/static/widget.js"; document.addEventListener("load", greet);',
        "import * as widget from \"{% static 'widget.js' %}\"; widget.greet();",
    ],
    ids=["django-static", "named-alias", "literal-url-listener", "namespace-import"],
)
def test_inline_module_consumer_references_exact_imported_export(tmp_path, code):
    root, script = _project(
        tmp_path,
        f'<script type="module">{code}</script>',
        "export function greet() {}\nexport function unusedHelper() {}\n",
    )

    refs = _refs(root, script)

    assert ("greet", str(script)) in refs
    assert ("unusedHelper", str(script)) not in refs
    assert browser_refs.collect_browser_script_entry_files(root, [script]) == {script}


@pytest.mark.parametrize(
    "code",
    [
        "import { greet } from \"{% static 'widget.js' %}\";",
        "import { greet } from \"{% static 'widget.js' %}\"; function unused() { greet(); }",
        'import { greet } from "{% static \'widget.js\' %}"; document.addEventListener("load", (greet) => greet());',
        "import { greet } from \"{% static 'missing.js' %}\"; greet();",
        'const label = "greet()";',
        "import * as widget from \"{% static 'widget.js' %}\"; widget.greet = fake; widget.greet();",
    ],
    ids=[
        "uncalled-import",
        "uncalled-local-function",
        "shadowed-import",
        "unresolved-import",
        "string-label",
        "namespace-member-replacement",
    ],
)
def test_inline_module_without_proven_consumer_keeps_export_unused(tmp_path, code):
    root, script = _project(
        tmp_path,
        f'<script type="module">{code}</script>',
        "export function greet() {}\n",
    )

    assert ("greet", str(script)) not in _refs(root, script)


@pytest.mark.parametrize(
    "body",
    ["try {} catch (error) { greet(); }", "switch (0) { case 1: greet(); break; }"],
)
def test_unmodeled_module_control_preserves_import_file_load_without_consuming_export(
    tmp_path, body
):
    code = "import { greet } from \"{% static 'widget.js' %}\"; " + body
    root, script = _project(
        tmp_path,
        f'<script type="module">{code}</script>',
        "export function greet() {}\n",
    )

    assert ("greet", str(script)) not in _refs(root, script)
    assert browser_refs.collect_browser_script_entry_files(root, [script]) == {script}


@pytest.mark.parametrize("module", [False, True], ids=["classic", "module"])
def test_analyzer_preserves_actual_inline_consumer_and_dead_helper(tmp_path, module):
    from skylos.analyzer import analyze

    source = "function greet() {}\nfunction unusedHelper() {}\n"
    markup = _LOAD + "<script>greet();</script>"
    if module:
        source = "export function greet() {}\nexport function unusedHelper() {}\n"
        markup = '<script type="module">import { greet } from "{% static \'widget.js\' %}"; greet();</script>'
    root, script = _project(tmp_path, markup, source)

    result = json.loads(analyze(str(root), conf=0, grep_verify=False))

    assert result.get("analysis_errors") == []
    unused = {item["name"] for item in result.get("unused_functions", [])}
    assert "greet" not in unused
    assert "unusedHelper" in unused
    assert script not in {Path(item["file"]) for item in result.get("unused_files", [])}


@pytest.mark.parametrize(
    ("code", "source", "used"),
    [
        ("if (false) { greet(); }", None, False),
        ("while (false) { greet(); }", None, False),
        ("for (; false;) { greet(); }", None, False),
        (
            "greet();",
            "function greet() {}\ngreet = function replacement() {};\nfunction unusedHelper() {}\n",
            False,
        ),
        ("if (flag) { greet = fake; } else { greet(); }", None, True),
        ("if (flag) { greet = fake; } greet();", None, True),
        ("false && greet();", None, False),
        ("true || greet();", None, False),
        ("true && greet();", None, True),
        ("false || greet();", None, True),
        ("switch (0) { case 1: greet(); break; }", None, False),
        ("try {} catch (error) { greet(); }", None, False),
        ("while (true) { break; greet(); }", None, False),
        ("for (let i = 0; i < 1; i++) { continue; greet(); }", None, False),
        ("if (0) { greet(); }", None, False),
        ("function start() { return greet(); } start();", None, True),
        ("throw Error(); greet();", None, False),
        ("function start() { { return; } greet(); } start();", None, False),
        ("function start() { throw Error(); } start(); greet();", None, False),
    ],
    ids=[
        "dead-if",
        "zero-while",
        "zero-for",
        "external-owner-replaced",
        "else-consumer",
        "fallthrough-consumer",
        "dead-and",
        "dead-or",
        "live-and",
        "live-or",
        "unsupported-switch",
        "unsupported-try",
        "unsupported-break",
        "unsupported-continue",
        "false-scalar",
        "direct-return-consumer",
        "explicit-throw",
        "nested-return",
        "called-throw",
    ],
)
def test_analyzer_inline_branches_and_replacements_keep_actual_usage(
    tmp_path, code, source, used
):
    from skylos.analyzer import analyze

    if source is None:
        source = "function greet() {}\nfunction unusedHelper() {}\n"
    root, _ = _project(tmp_path, _LOAD + f"<script>{code}</script>", source)

    result = json.loads(analyze(str(root), conf=0, grep_verify=False))

    assert result.get("analysis_errors") == []
    unused = {item["name"] for item in result.get("unused_functions", [])}
    assert ("greet" not in unused) == used
    assert "unusedHelper" in unused


@pytest.mark.parametrize("collector", ["refs", "entries"])
def test_shared_external_summary_is_parsed_once_per_collector_and_refreshed_after_edit(
    tmp_path, monkeypatch, collector
):
    from skylos.visitors.languages.typescript import file_references

    source = "function greet() {}\nfunction unusedHelper() {}\n"
    replaced = source + "greet = fake;\n"
    root, script = _project(tmp_path, _LOAD + "<script>greet();</script>", source)
    parser = file_references._TS_PARSER
    assert parser is not None
    external_parses = []
    external_classifications = []
    classify = browser_refs._is_classic_script

    class CountingParser:
        def parse(self, text, *args, **kwargs):
            if text in {source.encode(), replaced.encode()}:
                external_parses.append(text)
            return parser.parse(text, *args, **kwargs)

    monkeypatch.setattr(file_references, "_TS_PARSER", CountingParser())

    def counting_classification(text):
        if text in {source, replaced}:
            external_classifications.append(text)
        return classify(text)

    monkeypatch.setattr(browser_refs, "_is_classic_script", counting_classification)

    def collect(expected_use):
        external_parses.clear()
        external_classifications.clear()
        if collector == "refs":
            refs = browser_refs.collect_browser_event_handler_refs(root, [script])
            assert (("greet", str(script)) in refs) == expected_use
            assert ("unusedHelper", str(script)) not in refs
        else:
            assert browser_refs.collect_browser_script_entry_files(root, [script]) == {
                script
            }
        return len(external_parses), len(external_classifications)

    one_template = collect(True)
    for index in range(19):
        (root / "templates" / f"other{index}.html").write_text(
            _LOAD + "<script>greet();</script>"
        )
    twenty_templates = collect(True)
    script.write_text(replaced)
    edited_source = collect(False)

    assert [one_template, twenty_templates, edited_source] == [(1, 1), (1, 1), (1, 1)]
    assert external_parses == [replaced.encode()]
