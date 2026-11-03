"""innerHTML is quiet only when every value it can receive is written in the
file and inert, or comes through a sanitizer proven by its import."""

import pytest

from test.test_typescript_expanded import _scan_ts, _scan_ts_file

QUERY = "new URLSearchParams(location.search).get('html')"


def _xss_count(tmp_path, code):
    _, _, _, danger = _scan_ts(tmp_path, code)
    return sum(1 for f in danger if f["rule_id"] == "SKY-D226")


@pytest.mark.parametrize(
    "code",
    [
        "el.innerHTML = '<b>' + 'Status' + '</b>';",
        "const html = '<b>Status</b>';\nel.innerHTML = html;",
        "const fixed = '<b>Status</b>';\nconst html = fixed;\nel.innerHTML = html;",
        "el.innerHTML = Math.random() > 0.5 ? '<b>A</b>' : '<b>B</b>';",
        "const a = 'Status';\nel.innerHTML = `<b>${a}</b>`;",
        'el.innerHTML = `<div>x</div><script type="application/json" id="d">{}</script>`;',
        f"import DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize({QUERY});",
        f"import purify from 'dompurify';\nel.innerHTML = purify.sanitize({QUERY});",
        f"import sanitizeHtml from 'sanitize-html';\nel.innerHTML = sanitizeHtml({QUERY});",
        f"const DOMPurify = require('dompurify')(window);\nel.innerHTML = DOMPurify.sanitize({QUERY});",
        "el.innerHTML = '<div data-note=\"onload=example\">Hello</div>';",
        "el.innerHTML = 'Documentation: onload=example and javascript: are words.';",
        "el.innerHTML = '<!-- onload=example --><b>Ready</b>';",
    ],
    ids=[
        "literal_concat",
        "const_alias",
        "alias_chain",
        "ternary_of_literals",
        "template_of_const",
        "json_data_block",
        "dompurify_import",
        "dompurify_renamed",
        "sanitize_html_import",
        "dompurify_require",
        "quoted_attribute_text",
        "plain_text_tokens",
        "proper_comment",
    ],
)
def test_inert_or_proven_sanitized_values_are_quiet(tmp_path, code):
    assert _xss_count(tmp_path, code) == 0


@pytest.mark.parametrize(
    "code",
    [
        f"const html = {QUERY};\nel.innerHTML = html;",
        f"let html = '<b>Status</b>';\nhtml = {QUERY};\nel.innerHTML = html;",
        "let html = '<b>x</b>';\nel.innerHTML = html;",
        "export function display(render) { el.innerHTML = render(); }",
        "const html = '<b>x</b>';\nexport function f(html) { el.innerHTML = html; }",
        "el.innerHTML = '<scr' + 'ipt>alert(1)</script>';",
        "el.innerHTML = '<script type=\"application/json\">{}</script><img src=x onerror=alert(1)>';",
        # A sanitizer's name is not proof: these return the input unchanged.
        f"function sanitizeHtml(x) {{ return x; }}\nel.innerHTML = sanitizeHtml({QUERY});",
        f"const DOMPurify = {{ sanitize: x => x }};\nel.innerHTML = DOMPurify.sanitize({QUERY});",
        f"import {{ sanitizeHtml }} from './utils';\nel.innerHTML = sanitizeHtml({QUERY});",
        r"el.innerHTML = '\x3cimg src=x onerror\x3dalert(1)>';",
        "document.write('<script data-type=\"application/json\">alert(1)</script>');",
        f"import purify from 'dompurify'; Object.assign(purify, {{sanitize:x=>x}}); el.innerHTML=purify.sanitize({QUERY});",
        f"import purify from 'dompurify'; const alias=purify; alias.sanitize=x=>x; el.innerHTML=purify.sanitize({QUERY});",
        f"import sanitize from 'sanitize-html'; el.innerHTML=sanitize({QUERY}, {{allowedTags:false,allowedAttributes:false}});",
        f"globalThis.html={QUERY}; function unrelated(){{const html='<b>Safe</b>';}} el.innerHTML=html;",
        f"el.innerHTML=DOMPurify.sanitize({QUERY});",
    ],
    ids=[
        "query_value",
        "rebound_let",
        "let_is_not_proven",
        "unknown_renderer",
        "shadowed_const",
        "concat_forms_script",
        "data_block_then_handler",
        "spoofed_sanitizer_name",
        "shadowed_dompurify",
        "project_wrapper",
        "cooked_escape",
        "script_type_decoy",
        "sanitizer_assign",
        "sanitizer_alias_mutation",
        "unsafe_options",
        "unrelated_local_const",
        "unresolved_sanitizer_global",
    ],
)
def test_unknown_or_unproven_values_are_reported(tmp_path, code):
    assert _xss_count(tmp_path, code) == 1


def _xss_lines(tmp_path, filename, code):
    _, _, _, danger = _scan_ts_file(tmp_path, filename, code)
    return sorted(f["line"] for f in danger if f["rule_id"] == "SKY-D226")


REACT = """import DOMPurify from 'dompurify';
import LocalPurify from './dompurify';
export function A({ html }) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />; }
export function B({ html }) { const clean = DOMPurify.sanitize(html); return <div dangerouslySetInnerHTML={{ __html: clean }} />; }
export function C() { return <span dangerouslySetInnerHTML={{ __html: '&copy; 2026 Acme' }} />; }
export function D({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }
export function E({ html }) { return <div dangerouslySetInnerHTML={{ __html: LocalPurify.sanitize(html) }} />; }
export function F({ html }) { const clean = DOMPurify.sanitize(html); console.log(clean); return <div dangerouslySetInnerHTML={{ __html: html }} />; }
export function G(props) { return <div dangerouslySetInnerHTML={props.markup} />; }
"""


def test_dangerously_set_inner_html_honours_only_proven_sanitizers(tmp_path):
    assert _xss_lines(tmp_path, "c.tsx", REACT) == [6, 7, 8, 9]


DOM = f"""import DOMPurify from 'dompurify';
import $ from 'jquery';
const msg = {QUERY};
el.insertAdjacentHTML('beforeend', msg);
el.insertAdjacentHTML('beforeend', DOMPurify.sanitize(msg));
el.insertAdjacentHTML('afterbegin', '<li class="sep"></li>');
document.writeln(msg);
log.innerHTML += `<li>${{msg}}</li>`;
log.innerHTML += '<li>ready</li>';
$('#title').html(msg);
$('#title').html('<b>Welcome</b>');
const current = $('#title').html();
$('#title').text(msg);
$('#list').append(`<li>${{msg}}</li>`);
$('#list').append($('<li>').text(msg));
el.append(msg);
range.createContextualFragment(msg);
"""


def test_more_html_sinks_report_unproven_values_only(tmp_path):
    assert _xss_lines(tmp_path, "dom.js", DOM) == [4, 7, 8, 10, 14, 17]
