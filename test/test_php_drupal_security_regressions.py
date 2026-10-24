from __future__ import annotations

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.visitors.languages.php import scan_php_file
from skylos.visitors.languages.php.core import PhpCore


def _scan(tmp_path, code):
    path = tmp_path / "example.php"
    path.write_text("<?php\n" + code, encoding="utf-8")
    core = PhpCore(str(path), path.read_bytes())
    assert core.root_node is not None and not core.root_node.has_error
    return path, scan_php_file(str(path), {})[7]


@pytest.mark.parametrize("escaper", ["Html::escape", "Xss::filter", "Xss::filterAdmin"])
@pytest.mark.parametrize("assigned", [False, True])
def test_html_escaping_does_not_validate_filesystem_paths(tmp_path, escaper, assigned):
    expression = f"{escaper}($_GET['path'])"
    if assigned:
        code = f"$path = {expression};\nfile_get_contents($path);"
    else:
        code = f"file_get_contents({expression});"
    _, findings = _scan(tmp_path, code)
    assert [finding["rule_id"] for finding in findings] == ["SKY-D215"]


@pytest.mark.parametrize("escaper", ["Html::escape", "Xss::filter", "Xss::filterAdmin"])
@pytest.mark.parametrize("sink", ["sql", "template", "unserialize"])
def test_html_escaping_does_not_sanitize_other_sink_languages(tmp_path, escaper, sink):
    sinks = {
        "sql": ("$db->query('SELECT * FROM users WHERE uid = ' . $value);", "SKY-D211"),
        "template": (
            "$build = ['#type' => 'inline_template', '#template' => $value];",
            "SKY-D349",
        ),
        "unserialize": ("unserialize($value);", "SKY-D204"),
    }
    expression, rule = sinks[sink]
    _, findings = _scan(tmp_path, f"$value = {escaper}($_GET['value']);\n{expression}")
    assert [finding["rule_id"] for finding in findings] == [rule]


@pytest.mark.parametrize(
    ("sink", "rule"),
    [
        ("$db->query('SELECT * FROM users WHERE uid = ' . $value);", "SKY-D211"),
        ("Markup::create($value);", "SKY-D226"),
        ("['#type' => 'inline_template', '#template' => $value];", "SKY-D349"),
    ],
)
def test_basename_only_sanitizes_paths(tmp_path, sink, rule):
    _, findings = _scan(tmp_path, "$value = basename($_GET['value']);\n" + sink)
    assert [finding["rule_id"] for finding in findings] == [rule]


@pytest.mark.parametrize(
    ("imports", "escaper"),
    [
        ("", "Html::escape"),
        ("", "Xss::filter"),
        ("", "Xss::filterAdmin"),
        ("use Drupal\\Component\\Utility\\Html as H;", "H::escape"),
        ("use Drupal\\Component\\Utility\\{Html as H, Xss};", "H::escape"),
        (
            "namespace Demo; use Drupal\\Component\\Utility\\Xss as Cleaner;",
            "Cleaner::filter",
        ),
        ("", "\\Drupal\\Component\\Utility\\Html::escape"),
    ],
)
def test_actual_html_sanitizers_keep_markup_safe_across_assignments(
    tmp_path, imports, escaper
):
    _, findings = _scan(
        tmp_path,
        f"{imports}\n$value = {escaper}($_GET['html']);\n"
        "\\Drupal\\Core\\Render\\Markup::create($value);",
    )
    assert findings == []


@pytest.mark.parametrize(
    ("declaration", "escaper"),
    [
        (
            "class Html { public static function escape($x) { return $x; } }",
            "Html::escape",
        ),
        (
            "namespace App; class Html { public static function escape($x) { return $x; } }",
            "Html::escape",
        ),
        ("use App\\Html as H;", "H::escape"),
        ("", "\\App\\Html::escape"),
        ("use App\\Html;", "Html::escape"),
    ],
)
def test_html_sanitizer_lookalikes_do_not_hide_markup(tmp_path, declaration, escaper):
    _, findings = _scan(
        tmp_path,
        f"{declaration}\n\\Drupal\\Core\\Render\\Markup::create({escaper}($_GET['html']));",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


def test_real_markup_import_alias_is_a_sink(tmp_path):
    _, findings = _scan(
        tmp_path,
        "namespace Demo;\nuse Drupal\\Core\\Render\\Markup as SafeMarkup;\n"
        "SafeMarkup::create($_GET['html']);",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


def test_unrelated_markup_class_is_not_a_drupal_sink(tmp_path):
    _, findings = _scan(
        tmp_path,
        "namespace Demo; class Markup { public static function create($x) { return $x; } }\n"
        "Markup::create($_GET['value']);",
    )
    assert findings == []


@pytest.mark.parametrize("name", ["intval", "floatval", "basename"])
@pytest.mark.parametrize("binding", ["local", "import", "alias"])
def test_sanitizer_function_names_need_the_actual_builtin(tmp_path, name, binding):
    definitions = {
        "local": f"namespace Demo; function {name}($x) {{ return $x; }}",
        "import": f"namespace Demo; use function Other\\{name};",
        "alias": f"namespace Demo; use function Other\\unchanged as {name};",
    }
    _, findings = _scan(
        tmp_path,
        f"{definitions[binding]}\nfile_get_contents({name}($_GET['path']));\n"
        f"\\Drupal\\Core\\Render\\Markup::create({name}($_GET['html']));",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D215", "SKY-D226"]


@pytest.mark.parametrize("function", ["\\intval", "\\floatval", "number"])
def test_actual_numeric_builtin_qualified_names_and_aliases_are_safe(
    tmp_path, function
):
    _, findings = _scan(
        tmp_path,
        "namespace Demo; use function intval as number;\n"
        f"\\Drupal\\Core\\Render\\Markup::create({function}($_GET['html']));",
    )
    assert findings == []


@pytest.mark.parametrize(
    "markup",
    [
        "'<script>' . $value . '</script>'",
        "'<a href=\"' . $value . '\">link</a>'",
        "'<div onclick=\"' . $value . '\">text</div>'",
        '"<script>$value</script>"',
    ],
)
def test_html_escaping_cannot_prove_javascript_or_navigation_safety(tmp_path, markup):
    _, findings = _scan(
        tmp_path,
        f"$value = Html::escape($_GET['value']);\n$markup = {markup};\nMarkup::create($markup);",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


def test_xss_filter_does_not_escape_a_quoted_attribute(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$value = Xss::filter($_GET['value']);\n"
        "Markup::create('<div title=\"' . $value . '\">text</div>');",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


@pytest.mark.parametrize(
    "tags",
    ["['p', 'em', 'strong']", "['a', 'em']", "[]", "array('p', 'strong')", "NULL"],
)
def test_literal_xss_tag_subsets_preserve_safe_html_body_output(tmp_path, tags):
    _, findings = _scan(
        tmp_path,
        "use Drupal\\Component\\Utility\\Xss;\n"
        f"$value = Xss::filter($_GET['html'], {tags});\nMarkup::create($value);",
    )
    assert findings == []


@pytest.mark.parametrize(
    "tags", ["['script']", "['p', 'script']", "$_GET['tags']", "$unknown_tags"]
)
def test_unsafe_or_unproven_xss_tag_lists_remain_tainted(tmp_path, tags):
    _, findings = _scan(
        tmp_path,
        f"Markup::create(Xss::filter($_GET['html'], {tags}));",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


@pytest.mark.parametrize(
    "sink,expected_rule",
    [
        ("file_get_contents($value);", "SKY-D215"),
        ("$db->query('SELECT * FROM users WHERE uid = ' . $value);", "SKY-D211"),
        ("return ['#type' => 'inline_template', '#template' => $value];", "SKY-D349"),
        ("Markup::create('<div title=\"' . $value . '\">text</div>');", "SKY-D226"),
    ],
)
def test_xss_literal_tags_never_prove_safety_in_other_contexts(
    tmp_path, sink, expected_rule
):
    _, findings = _scan(
        tmp_path, "$value = Xss::filter($_GET['value'], ['p', 'em']);\n" + sink
    )
    assert [finding["rule_id"] for finding in findings] == [expected_rule]


def test_custom_xss_allowed_tags_do_not_supply_a_safety_proof(tmp_path):
    _, findings = _scan(
        tmp_path, "Markup::create(Xss::filter($_GET['html'], ['script']));"
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


@pytest.mark.parametrize("quote", [r"\"", r"\x22", r"\042"])
def test_php_literal_escaped_quotes_form_a_safe_html_attribute(tmp_path, quote):
    _, findings = _scan(
        tmp_path,
        'Markup::create("<p title='
        + quote
        + "\" . Html::escape($_GET['html']) . \""
        + quote
        + '>ok</p>");',
    )
    assert findings == []


@pytest.mark.parametrize("opening", [r"\x3c", r"\074", r"\u{3c}"])
def test_php_literal_escapes_cannot_hide_script_context(tmp_path, opening):
    _, findings = _scan(
        tmp_path,
        'Markup::create("'
        + opening
        + 'script>" . Html::escape($_GET[\'html\']) . "</script>");',
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


def test_php_single_quoted_literals_keep_double_quote_escape_text(tmp_path):
    _, findings = _scan(
        tmp_path,
        r"""Markup::create('<p title=\"' . Html::escape($_GET['html']) . '\">ok</p>');""",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


def test_php_single_quoted_literals_do_not_decode_hexadecimal_escapes(tmp_path):
    _, findings = _scan(
        tmp_path,
        r"""Markup::create('\x3cscript>' . Html::escape($_GET['html']) . '\x3c/script>');""",
    )
    assert findings == []


@pytest.mark.parametrize(
    "declaration,expression",
    [
        (
            "if (!class_exists('Html')) { class Html { static function escape($x) { return $x; } } }",
            "Html::escape",
        ),
        (
            "namespace Demo; if (!function_exists('Demo\\\\intval')) { function intval($x) { return $x; } }",
            "intval",
        ),
    ],
)
def test_conditional_declarations_are_not_sanitizer_proofs(
    tmp_path, declaration, expression
):
    _, findings = _scan(
        tmp_path,
        declaration
        + "\n\\Drupal\\Core\\Render\\Markup::create("
        + expression
        + "($_GET['html']));",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


@pytest.mark.parametrize(
    "expression", ["$request->query->get('html')", "$form_state->getValue('html')"]
)
def test_request_method_interpolation_still_reaches_markup(tmp_path, expression):
    _, findings = _scan(tmp_path, 'Markup::create("<p>{' + expression + '}</p>");')
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


def test_namespace_relative_markup_class_is_a_sink(tmp_path):
    _, findings = _scan(
        tmp_path,
        "namespace Drupal; namespace\\Core\\Render\\Markup::create($_GET['html']);",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D226"]


@pytest.mark.parametrize(
    "expression",
    [
        "intval($_GET['value'])",
        "floatval($_GET['value'])",
        "(int) $_GET['value']",
        "(float) $_GET['value']",
    ],
)
def test_numeric_conversion_remains_safe_for_all_sinks(tmp_path, expression):
    _, findings = _scan(
        tmp_path,
        f"$value = {expression};\n"
        "file_get_contents('/srv/data/' . $value);\n"
        "$db->query('SELECT * FROM users WHERE uid = ' . $value);\n"
        "Markup::create($value);\n"
        "$build = ['#type' => 'inline_template', '#template' => $value];",
    )
    assert findings == []


@pytest.mark.parametrize(
    "code",
    [
        "header('Content-Type: application/json'); echo json_encode(['#template' => $_GET['value']]);",
        "$data = ['#type' => 'html_tag', '#template' => $_GET['value']];",
        "$data = ['#type' => 'inline_template', '#context' => ['#template' => $_GET['value']]];",
    ],
)
def test_template_key_without_inline_render_context_is_data(tmp_path, code):
    _, findings = _scan(tmp_path, code)
    assert findings == []


def test_template_type_can_follow_template_source(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template'], '#type' => 'inline_template'];",
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D349"]


@pytest.mark.parametrize("last_type", ["inline_template", "html_tag"])
def test_last_template_type_key_determines_render_context(tmp_path, last_type):
    if last_type == "inline_template":
        first_type = "html_tag"
        expected_rules = ["SKY-D349"]
    else:
        first_type = "inline_template"
        expected_rules = []
    _, findings = _scan(
        tmp_path,
        f"['#type' => '{first_type}', '#type' => '{last_type}', '#template' => $_GET['template']];",
    )
    assert [finding["rule_id"] for finding in findings] == expected_rules


def test_template_context_is_data_and_fixed_template_is_safe(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$build = ['#type' => 'inline_template', '#template' => '{{ value }}', "
        "'#context' => ['value' => $_GET['value']]];",
    )
    assert findings == []


@pytest.mark.parametrize(
    ("code", "rule"),
    [
        ("file_get_contents(Html::escape($_GET['path']));", "SKY-D215"),
        (
            "$value = Html::escape($_GET['id']); $db->query('SELECT * FROM users WHERE uid = ' . $value);",
            "SKY-D211",
        ),
        ("Markup::create(basename($_GET['html']));", "SKY-D226"),
        (
            "['#type' => 'inline_template', '#template' => Html::escape($_GET['template'])];",
            "SKY-D349",
        ),
        (
            "header('Content-Type: application/json'); echo json_encode(['#template' => $_GET['value']]);",
            None,
        ),
        ("Markup::create(Html::escape($_GET['html']));", None),
    ],
)
def test_security_results_survive_listing_and_gate(tmp_path, code, rule):
    path, raw = _scan(tmp_path, code)
    result = json.loads(
        analyze(str(path), enable_danger=True, grep_verify=False, grep_cache=False)
    )
    assert result.get("analysis_errors", []) == []
    findings = result.get("danger", [])
    expected_rules = []
    if rule:
        expected_rules = [rule]
    assert [finding["rule_id"] for finding in raw] == expected_rules
    assert [finding["rule_id"] for finding in findings] == expected_rules
    if rule:
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["listing"]["listed"] is True
    passed, _ = check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})
    assert passed is (rule is None)


def test_split_inline_template_keeps_the_original_source_location(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $request->query->get('template')];\n"
        "$build['#type'] = 'inline_template';\nreturn $build;",
    )
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D349", 2)
    ]


@pytest.mark.parametrize(
    "tail",
    [
        "return new JsonResponse($build);",
        "$build = []; $build['#type'] = 'inline_template'; return $build;",
        "$build = ['#template' => 'fixed']; $build['#type'] = 'inline_template'; return $build;",
        "$build['#template'] = '{{ value }}'; $build['#type'] = 'inline_template'; return $build;",
        "unset($build); $build['#type'] = 'inline_template'; return $build;",
        "unset($build['#template']); $build['#type'] = 'inline_template'; return $build;",
        "$other = []; $other['#type'] = 'inline_template'; return $build;",
        "$build['#type'] = 'html_tag'; return $build;",
        "$callback = function () use ($build) { $build['#type'] = 'inline_template'; }; return new JsonResponse($build);",
    ],
)
def test_split_template_provenance_requires_the_same_current_builder(tmp_path, tail):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $request->query->get('template')];\n" + tail,
    )
    assert findings == []


def test_template_builders_do_not_cross_named_callables(tmp_path):
    _, findings = _scan(
        tmp_path,
        "function data($request) {\n"
        " $build = ['#template' => $request->query->get('template')];\n"
        " return new JsonResponse($build);\n}\n"
        "function page() { $build['#type'] = 'inline_template'; return $build; }",
    )
    assert findings == []


@pytest.mark.parametrize(
    "expression,rule",
    [
        ("Markup::create($_GET['html'])", "SKY-D226"),
        ("file_get_contents($_GET['path'])", "SKY-D215"),
    ],
)
def test_arrow_function_body_still_checks_its_outermost_sink(
    tmp_path, expression, rule
):
    _, findings = _scan(tmp_path, "$callback = fn() => " + expression + ";")
    assert [finding["rule_id"] for finding in findings] == [rule]


def test_closure_local_builder_does_not_replace_the_outer_builder(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $request->query->get('template')];\n"
        "$callback = function () { $build = []; };\n"
        "$build['#type'] = 'inline_template';\nreturn $build;",
    )
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D349", 2)
    ]


@pytest.mark.parametrize(
    "tail,expected_rules",
    [
        (
            "$copy = $build; $copy['#type'] = 'inline_template'; return $copy;",
            ["SKY-D349"],
        ),
        (
            "$copy = $build; $build['#template'] = 'fixed'; $copy['#type'] = 'inline_template'; return $copy;",
            ["SKY-D349"],
        ),
        (
            "$copy = $build; $copy['#template'] = 'fixed'; $build['#type'] = 'inline_template'; return $build;",
            ["SKY-D349"],
        ),
        (
            "$copy = $build; $copy['#template'] = 'fixed'; $copy['#type'] = 'inline_template'; return $copy;",
            [],
        ),
    ],
)
def test_template_array_value_copies_retain_independent_snapshots(
    tmp_path, tail, expected_rules
):
    _, findings = _scan(
        tmp_path, "$build = ['#template' => $_GET['template']];\n" + tail
    )
    assert [finding["rule_id"] for finding in findings] == expected_rules
    if findings:
        assert findings[0]["line"] == 2


def test_template_builder_keeps_the_value_stored_before_scalar_reassignment(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$input = $_GET['template'];\n$build = ['#template' => $input];\n"
        "$input = 'fixed';\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D349", 3)
    ]


def test_last_template_literal_value_can_overwrite_untrusted_source(tmp_path):
    _, findings = _scan(
        tmp_path,
        "return ['#type' => 'inline_template', '#template' => $_GET['template'], "
        "'#template' => 'fixed'];",
    )
    assert findings == []


@pytest.mark.parametrize(
    "reset",
    [
        "$build['#template'] = 'fixed';",
        "unset($build['#template']);",
        "$build = ['#template' => 'fixed'];",
        "unset($build);",
    ],
)
@pytest.mark.parametrize("conditional", [False, True])
def test_template_resets_preserve_other_reachable_branches(
    tmp_path, reset, conditional
):
    if conditional:
        reset = "if (isset($_GET['clear'])) { " + reset + " }"
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        + reset
        + "\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    expected_rules = []
    if conditional:
        expected_rules = ["SKY-D349"]
    assert [finding["rule_id"] for finding in findings] == expected_rules
    if findings:
        assert findings[0]["line"] == 2


@pytest.mark.parametrize(
    "branches",
    [
        "if ($clear) { $build['#template'] = 'fixed'; } else { unset($build['#template']); }",
        "if ($first) { $build = []; } elseif ($second) { unset($build); } else { $build['#template'] = 'fixed'; }",
    ],
)
def test_template_is_safe_when_every_branch_removes_the_tainted_source(
    tmp_path, branches
):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        + branches
        + "\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    assert findings == []


def test_branch_join_does_not_combine_disjoint_template_and_type_values(tmp_path):
    _, findings = _scan(
        tmp_path,
        "if ($choice) { $build = ['#template' => $_GET['template']]; }\n"
        "else { $build = ['#type' => 'inline_template']; }\nreturn $build;",
    )
    assert findings == []


@pytest.mark.parametrize(
    "loop",
    [
        "while ($again) { $build['#template'] = 'fixed'; }",
        "foreach ($items as $item) { unset($build['#template']); }",
        "for ($i = 0; $i < $count; $i++) { $build = []; }",
    ],
)
def test_zero_iteration_loop_cannot_discard_the_original_template(tmp_path, loop):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        + loop
        + "\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D349", 2)
    ]


def test_do_loop_applies_its_unconditional_first_template_reset(tmp_path):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        "do { $build['#template'] = 'fixed'; } while ($again);\n"
        "$build['#type'] = 'inline_template';\nreturn $build;",
    )
    assert findings == []


@pytest.mark.parametrize(
    "body,unsafe",
    [
        ("break; unset($build['#template']);", True),
        ("if ($stop) { break; } unset($build['#template']);", True),
        ("unset($build['#template']); break;", False),
    ],
)
def test_do_loop_respects_early_break_before_template_cleanup(tmp_path, body, unsafe):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\ndo { "
        + body
        + " } while (false);\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    expected_rules = []
    if unsafe:
        expected_rules = ["SKY-D349"]
    assert [finding["rule_id"] for finding in findings] == expected_rules


@pytest.mark.parametrize(
    "control,unsafe",
    [
        ("switch ($mode) { case 'clear': unset($build['#template']); break; }", True),
        (
            "switch ($mode) { case 'keep': break; default: unset($build['#template']); }",
            True,
        ),
        (
            "switch ($mode) { case 'clear': unset($build['#template']); break; default: $build = []; }",
            False,
        ),
        (
            "switch ($mode) { case 'first': $label = 'fallthrough'; default: unset($build['#template']); }",
            False,
        ),
        (
            "switch ($mode) { case 'clear': unset($build['#template']); case 'keep': break; default: $build = []; }",
            True,
        ),
        (
            "switch ($mode) { case 'maybe': if ($stop) { break; } unset($build['#template']); break; default: $build = []; }",
            True,
        ),
        (
            "switch ($mode) { case 'clear': if ($choice) { unset($build); break; } else { $build = []; break; } default: $build = []; }",
            False,
        ),
        (
            "try { risky(); unset($build['#template']); } catch (\\Exception $e) {}",
            True,
        ),
        (
            "try { throw new \\Exception(); unset($build['#template']); } catch (\\Exception $e) {}",
            True,
        ),
        ("try { $build = risky(); } catch (\\Exception $e) {}", True),
        (
            "try { $build = ['#template' => 'fixed', 'data' => risky()]; } catch (\\Exception $e) {}",
            True,
        ),
        (
            "try { unset($build['#template']); risky(); } catch (\\Exception $e) {}",
            False,
        ),
        (
            "try { unset($build['#template']); throw new \\Exception(); } catch (\\Exception $e) {}",
            False,
        ),
        (
            "try { risky(); unset($build['#template']); } catch (\\Exception $e) { unset($build['#template']); }",
            False,
        ),
        (
            "try { risky(); } catch (\\Exception $e) {} finally { unset($build['#template']); }",
            False,
        ),
        ("try { risky(); } finally { unset($build['#template']); }", False),
        (
            "try { if ($clear) { unset($build['#template']); } risky(); unset($build['#template']); } catch (\\Exception $e) {}",
            True,
        ),
        (
            "for ($i = 0; $i < $count; $i++): $label = 'body'; unset($build['#template']); endfor;",
            True,
        ),
        (
            "while ($again): $label = 'body'; unset($build['#template']); endwhile;",
            True,
        ),
        (
            "foreach ($items as $item): $label = 'body'; unset($build['#template']); endforeach;",
            True,
        ),
        ("if ($clear): unset($build['#template']); else: $build = []; endif;", False),
        ("if ($clear): unset($build['#template']); endif;", True),
    ],
)
def test_structured_control_keeps_only_reachable_template_alternatives(
    tmp_path, control, unsafe
):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        + control
        + "\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    expected = []
    if unsafe:
        expected = [("SKY-D349", 2)]
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == expected


@pytest.mark.parametrize(
    "reset",
    [
        "",
        "if ($clear) { $build['#template'] = 'fixed'; }",
        "while ($again) { unset($build['#template']); }",
        "switch ($mode) { case 'clear': unset($build['#template']); break; }",
        "try { risky(); unset($build['#template']); } catch (\\Exception $e) {}",
        "for ($i = 0; $i < $count; $i++): $label = 'body'; unset($build['#template']); endfor;",
    ],
)
def test_split_inline_template_in_a_route_is_listed_and_blocks_the_gate(
    tmp_path, reset
):
    root = tmp_path / "demo"
    path = root / "src" / "Controller" / "Page.php"
    path.parent.mkdir(parents=True)
    (root / "demo.info.yml").write_text("name: Demo\ntype: module\n", encoding="utf-8")
    (root / "demo.routing.yml").write_text(
        "demo.page:\n  path: /demo\n  defaults:\n"
        "    _controller: '\\Drupal\\demo\\Controller\\Page::view'\n"
        "  requirements:\n    _access: 'TRUE'\n",
        encoding="utf-8",
    )
    path.write_text(
        "<?php\nnamespace Drupal\\demo\\Controller;\nclass Page {\n"
        " public function view($request) {\n"
        "  $build = ['#template' => $request->query->get('template')];\n"
        + reset
        + "\n"
        + "  $build['#type'] = 'inline_template';\n  return $build;\n }\n}\n",
        encoding="utf-8",
    )
    core = PhpCore(str(path), path.read_bytes())
    assert core.root_node is not None and not core.root_node.has_error
    raw = scan_php_file(str(path), {})[7]
    result = json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, grep_cache=False)
    )
    assert result.get("analysis_errors", []) == []
    assert result.get("unused_classes", []) == []
    assert [(finding["rule_id"], finding["line"]) for finding in raw] == [
        ("SKY-D349", 5)
    ]
    findings = result.get("danger", [])
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D349", 5)
    ]
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["listing"]["listed"] is True
    passed, _ = check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})
    assert passed is False


@pytest.mark.parametrize(
    "control,unsafe",
    [
        (
            "try { try { throw new \\Exception(); unset($build['#template']); } catch (\\TypeError $e) { unset($build['#template']); } } catch (\\Exception $e) {}",
            True,
        ),
        (
            "try { try { risky(); unset($build['#template']); } catch (\\Throwable $e) { unset($build['#template']); } } catch (\\Exception $e) {}",
            False,
        ),
    ],
)
def test_uncaught_exception_paths_reach_outer_handlers(tmp_path, control, unsafe):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        + control
        + "\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    expected_rules = []
    if unsafe:
        expected_rules = ["SKY-D349"]
    assert [finding["rule_id"] for finding in findings] == expected_rules


@pytest.mark.parametrize(
    "control,unsafe",
    [
        (
            "switch ($mode) { case 'keep': $x = 1; case ($build = []): break; default: $build = []; }",
            True,
        ),
        ("switch ($mode) { case ($build = []): break; default: $build = []; }", False),
        ("switch ($mode) { default: break; case ($build = []): break; }", False),
    ],
)
def test_switch_dispatch_effects_do_not_run_on_fallthrough(tmp_path, control, unsafe):
    _, findings = _scan(
        tmp_path,
        "$build = ['#template' => $_GET['template']];\n"
        + control
        + "\n$build['#type'] = 'inline_template';\nreturn $build;",
    )
    expected_rules = []
    if unsafe:
        expected_rules = ["SKY-D349"]
    assert [finding["rule_id"] for finding in findings] == expected_rules


@pytest.mark.parametrize(
    "prefix",
    [
        "try { throw new \\Exception(); } finally {}",
        "switch ($mode) { default: throw new \\Exception(); }",
    ],
)
def test_terminal_program_flow_does_not_skip_named_callable_analysis(tmp_path, prefix):
    _, findings = _scan(
        tmp_path,
        prefix + "\nfunction vulnerable() {\n"
        " file_get_contents($_GET['path']);\n unserialize($_GET['data']);\n"
        " Markup::create($_GET['html']);\n}\n",
    )
    assert [finding["rule_id"] for finding in findings] == [
        "SKY-D215",
        "SKY-D204",
        "SKY-D226",
    ]
