"""HTML sinks (SKY-D226) stay quiet when every interpolated value is a number
or passes through a recognised escaper in a position the escaper covers."""

import pytest

from test.test_typescript_expanded import _scan_ts


def _xss_count(tmp_path, code):
    _, _, _, danger = _scan_ts(tmp_path, code)
    return sum(1 for f in danger if f["rule_id"] == "SKY-D226")


@pytest.mark.parametrize(
    "code",
    [
        "export function f(p) { $('#a').html(`${Math.round(p.percent)}%`); }",
        "export function f(n) { el.innerHTML = `<b>${n * 100}</b>`; }",
        "export function f(a, b) { el.innerHTML = '<i>' + (a - b).toFixed(1) + '</i>'; }",
        (
            "const id = `id${Math.random().toString(16).slice(2)}`;\n"
            "el.insertAdjacentHTML('beforeend', `<div id=\"p-${id}\"></div>`);"
        ),
        (
            "function enc(t) { return encodeURIComponent(t); }\n"
            "export function f(code) { pre.insertAdjacentHTML('beforeend', "
            '`<a href="/play/?config=${enc(code)}">Go</a>`); }'
        ),
        (
            "import escapeHtml from 'escape-html';\n"
            "export function f(name) { el.innerHTML = `<li>${escapeHtml(name)}</li>`; }"
        ),
        (
            "import _ from 'lodash';\n"
            "export function f(name) { el.innerHTML = '<li title=\"' + _.escape(name) + '\">x</li>'; }"
        ),
        (
            "import { escape } from 'html-escaper';\n"
            "export function f(name) { el.innerHTML = `<p class='n'>${escape(name)}</p>`; }"
        ),
    ],
    ids=[
        "jquery-number-template",
        "arithmetic",
        "to-fixed",
        "random-id",
        "uri-component-wrapper-in-href",
        "escape-html-text",
        "lodash-escape-attribute",
        "html-escaper-text",
    ],
)
def test_numbers_and_escaped_values_are_quiet(tmp_path, code):
    assert _xss_count(tmp_path, code) == 0


@pytest.mark.parametrize(
    "code",
    [
        "export function f(name) { el.innerHTML = `<li>${name}</li>`; }",
        (
            "import escapeHtml from 'escape-html';\n"
            "export function f(name) { el.innerHTML = `<a onclick=\"go('${escapeHtml(name)}')\">x</a>`; }"
        ),
        (
            "import escapeHtml from 'escape-html';\n"
            "export function f(name) { el.innerHTML = `<a title=${escapeHtml(name)}>x</a>`; }"
        ),
        (
            "import escapeHtml from 'escape-html';\n"
            "export function f(name) { el.innerHTML = `<${escapeHtml(name)}>`; }"
        ),
        (
            "import escapeHtml from 'escape-html';\n"
            'export function f(u) { el.innerHTML = `<a href="${escapeHtml(u)}">x</a>`; }'
        ),
        'export function f(u) { el.innerHTML = `<a href="${encodeURI(u)}">x</a>`; }',
        "export function f(u) { el.innerHTML = `<a title='${encodeURIComponent(u)}'>x</a>`; }",
        (
            "const encodeURIComponent = (x) => x;\n"
            "export function f(u) { el.innerHTML = `<b>${encodeURIComponent(u)}</b>`; }"
        ),
        (
            "function escapeHtml(x) { return x; }\n"
            "export function f(u) { el.innerHTML = `<b>${escapeHtml(u)}</b>`; }"
        ),
        "export function f(n, s) { el.innerHTML = `<b>${n + s}</b>`; }",
    ],
    ids=[
        "raw-value",
        "escaped-in-event-handler",
        "escaped-unquoted-attribute",
        "escaped-tag-name",
        "escaped-url-scheme",
        "encode-uri-url-scheme",
        "uri-in-single-quotes",
        "shadowed-global-encoder",
        "escaper-by-name-only",
        "number-plus-unknown",
    ],
)
def test_unescaped_or_misplaced_values_are_reported(tmp_path, code):
    assert _xss_count(tmp_path, code) == 1
