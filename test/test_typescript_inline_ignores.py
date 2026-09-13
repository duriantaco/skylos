import json

import pytest

from skylos.analyzer import analyze


_TS_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


def _scan(
    tmp_path,
    source: str,
    suffix: str = ".js",
    *,
    enable_secrets: bool = False,
) -> dict:
    source_file = tmp_path / f"same_report{suffix}"
    source_file.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        source,
        encoding="utf-8",
    )
    return json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_danger=True,
            enable_secrets=enable_secrets,
            grep_verify=False,
            trace_file=False,
        )
    )


def _rule_findings(result: dict, section: str, rule_id: str) -> list[dict]:
    return [
        finding
        for finding in result.get(section, [])
        if finding.get("rule_id") == rule_id
    ]


@pytest.mark.parametrize("suffix", _TS_JS_SUFFIXES)
def test_rule_specific_inline_ignore_suppresses_issue_839_for_every_ts_js_suffix(
    tmp_path, suffix
):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        "  // skylos: ignore[SKY-D253] public digest\n"
        "}\n",
        suffix,
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    suppressed = _rule_findings(result, "suppressed", "SKY-D253")
    assert len(suppressed) == 1
    assert suppressed[0]["reason"] == "inline ignore comment"


def test_rule_specific_inline_ignore_does_not_hide_other_rule_on_same_line(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return eval(record.report_sha256 === digest);"
        "  // skylos: ignore[SKY-D253] public digest\n"
        "}\n",
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    assert len(_rule_findings(result, "suppressed", "SKY-D253")) == 1
    assert len(_rule_findings(result, "danger", "SKY-D201")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D201") == []


def test_inline_ignore_accepts_multiple_comma_separated_rule_ids(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return eval(record.report_sha256 === digest);"
        " // skylos: ignore[sky-d253, SKY-D201]\n"
        "}\n",
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    assert _rule_findings(result, "danger", "SKY-D201") == []
    assert len(_rule_findings(result, "suppressed", "SKY-D253")) == 1
    assert len(_rule_findings(result, "suppressed", "SKY-D201")) == 1


def test_blanket_typescript_inline_ignore_suppresses_all_findings_on_line(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return eval(record.report_sha256 === digest); // skylos: ignore\n"
        "}\n",
        ".ts",
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    assert _rule_findings(result, "danger", "SKY-D201") == []
    assert len(_rule_findings(result, "suppressed", "SKY-D253")) == 1
    assert len(_rule_findings(result, "suppressed", "SKY-D201")) == 1


def test_wrong_rule_id_does_not_suppress_typescript_finding(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        "  // skylos: ignore[SKY-D252] unrelated rule\n"
        "}\n",
        ".ts",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize(
    "literal",
    (
        '"// skylos: ignore[SKY-D253]"',
        "`// skylos: ignore[SKY-D253]`",
    ),
)
def test_directive_text_inside_js_literal_cannot_suppress_finding(tmp_path, literal):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        f"  if (record.report_sha256 === digest) {{ console.log({literal}); }}\n"
        "}\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


def test_error_recovery_cannot_turn_unclosed_template_text_into_directive(tmp_path):
    result = _scan(
        tmp_path,
        "const docs = `// skylos: ignore-start\n"
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize(
    "comment",
    (
        '// Example: "# skylos: ignore[SKY-D253]"',
        "// Docs use `# skylos: ignore[SKY-D253]`",
        "// explanation # skylos: ignore[SKY-D253]",
        '/* Example: "skylos: ignore[SKY-D253]" */',
    ),
)
def test_documented_directive_text_inside_comment_cannot_suppress_finding(
    tmp_path, comment
):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        f"  return record.report_sha256 === digest; {comment}\n"
        "}\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


def test_documented_ignore_start_text_cannot_suppress_later_findings(tmp_path):
    result = _scan(
        tmp_path,
        '// Never copy "# skylos: ignore-start" without an end marker\n'
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


def test_multiline_block_comment_cannot_define_ignore_directive(tmp_path):
    result = _scan(
        tmp_path,
        "/*\n"
        ' * Example starts: "\n'
        " * skylos: ignore-start\n"
        ' * "\n'
        " */\n"
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize(
    "explanation",
    (
        'Example: "skylos: ignore[SKY-D253]"',
        'Never use "skylos: ignore" here',
    ),
)
def test_explanation_cannot_broaden_leading_rule_specific_ignore(tmp_path, explanation):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        f" // skylos: ignore[SKY-D252] {explanation}\n"
        "}\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


def test_explanation_cannot_start_ignore_block(tmp_path):
    result = _scan(
        tmp_path,
        '// skylos: ignore[SKY-D252] Do not write "skylos: ignore-start"\n'
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize(
    "malformed",
    (
        "ignore-started",
        "ignore-endless",
        "ignore-me",
        "ignore.other",
        "ignore/start",
        "ignore[SKY-D253]x",
        "ignore[SKY-D253",
    ),
)
def test_malformed_directive_cannot_suppress_finding(tmp_path, malformed):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        f" // skylos: {malformed}\n"
        "}\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize(
    "directive",
    (
        "ſkylos: ignore[SKY-D253]",
        "skyloſ: ignore[SKY-D253]",
        "skylos: ignore[ſKY-D253]",
    ),
)
def test_non_ascii_case_folding_cannot_create_directive(tmp_path, directive):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        f" // {directive}\n"
        "}\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


def test_non_ascii_rule_id_cannot_suppress_secret(tmp_path):
    result = _scan(
        tmp_path,
        'const token = "ghp_1234567890abcdef1234567890abcdef1234";'
        " // skylos: ignore[SKY-ſ101]\n",
        enable_secrets=True,
    )

    assert _rule_findings(result, "secrets", "SKY-S101")
    assert _rule_findings(result, "suppressed", "SKY-S101") == []


@pytest.mark.parametrize(
    "lookalike",
    (
        'const docs = "skylos: ignore[SKY-S101]";',
        "const docs = `skylos: ignore[SKY-S101]`;",
        "// docs: skylos: ignore[SKY-S101]",
    ),
)
def test_secret_ignore_text_outside_directive_comment_cannot_suppress(
    tmp_path, lookalike
):
    result = _scan(
        tmp_path,
        'const token = "ghp_1234567890abcdef1234567890abcdef1234"; ' + lookalike + "\n",
        enable_secrets=True,
    )

    assert _rule_findings(result, "secrets", "SKY-S101")
    assert _rule_findings(result, "suppressed", "SKY-S101") == []


def test_valid_rule_specific_comment_moves_secret_to_suppressed_output(tmp_path):
    result = _scan(
        tmp_path,
        'const token = "ghp_1234567890abcdef1234567890abcdef1234";'
        " // skylos: ignore[SKY-S101]\n",
        enable_secrets=True,
    )

    assert _rule_findings(result, "secrets", "SKY-S101") == []
    assert _rule_findings(result, "suppressed", "SKY-S101")


def test_rule_list_cannot_inject_ignore_block(tmp_path):
    result = _scan(
        tmp_path,
        "// skylos: ignore[SKY-D252 # skylos: ignore-start]\n"
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize("separator", ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"))
def test_non_line_separator_inside_comment_cannot_shift_directive(tmp_path, separator):
    result = _scan(
        tmp_path,
        f"/* example{separator}skylos: ignore[SKY-D253] */\n"
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize("separator", ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"))
def test_non_line_separator_cannot_shift_secret_onto_later_ignore(tmp_path, separator):
    result = _scan(
        tmp_path,
        f"/* explanatory{separator}text */\n"
        'const token = "ghp_1234567890abcdef1234567890abcdef1234";\n'
        "// skylos: ignore[SKY-S101]\n",
        enable_secrets=True,
    )

    secrets = _rule_findings(result, "secrets", "SKY-S101")
    assert secrets
    assert {finding["line"] for finding in secrets} == {2}
    assert _rule_findings(result, "suppressed", "SKY-S101") == []


@pytest.mark.parametrize("separator", ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"))
def test_non_line_separator_cannot_shift_archive_finding_onto_later_ignore(
    tmp_path, separator
):
    result = _scan(
        tmp_path,
        'const fs = require("fs");\n'
        'const path = require("path");\n'
        'const unzipper = require("unzipper");\n'
        "\n"
        'fs.createReadStream("archive.zip")\n'
        "  .pipe(unzipper.Parse())\n"
        '  .on("entry", entry => {\n'
        f"    /* explanatory{separator}text */\n"
        "    const fileName = entry.path;\n"
        '    entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));\n'
        "  }); // skylos: ignore[SKY-D215]\n",
    )

    findings = _rule_findings(result, "danger", "SKY-D215")
    assert len(findings) == 1
    assert _rule_findings(result, "suppressed", "SKY-D215") == []


@pytest.mark.parametrize("line_ending", ("\n", "\r\n", "\r", "\u2028", "\u2029"))
def test_secret_line_numbers_follow_ecmascript_line_terminators(tmp_path, line_ending):
    result = _scan(
        tmp_path,
        "/* explanatory text */"
        + line_ending
        + 'const token = "ghp_1234567890abcdef1234567890abcdef1234";\n',
        enable_secrets=True,
    )

    secrets = _rule_findings(result, "secrets", "SKY-S101")
    assert secrets
    assert {finding["line"] for finding in secrets} == {2}


@pytest.mark.parametrize("separator", ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"))
def test_secret_line_numbers_do_not_split_on_non_terminator_controls(
    tmp_path, separator
):
    result = _scan(
        tmp_path,
        "/* explanatory text */"
        + separator
        + 'const token = "ghp_1234567890abcdef1234567890abcdef1234";\n',
        enable_secrets=True,
    )

    secrets = _rule_findings(result, "secrets", "SKY-S101")
    assert secrets
    assert {finding["line"] for finding in secrets} == {1}


def test_separate_rule_comments_on_same_line_are_combined(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        " /* skylos: ignore[SKY-D252] */"
        " /* skylos: ignore[SKY-D253] */\n"
        "}\n",
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    assert len(_rule_findings(result, "suppressed", "SKY-D253")) == 1


def test_typescript_ignore_block_is_bounded(tmp_path):
    result = _scan(
        tmp_path,
        "export function compare(record, firstDigest, secondDigest) {\n"
        "  // skylos: ignore-start\n"
        "  const first = record.first_sha256 === firstDigest;\n"
        "  // skylos: ignore-end\n"
        "  const second = record.second_sha256 === secondDigest;\n"
        "  return first || second;\n"
        "}\n",
        ".ts",
    )

    active = _rule_findings(result, "danger", "SKY-D253")
    suppressed = _rule_findings(result, "suppressed", "SKY-D253")
    assert [finding["line"] for finding in active] == [5]
    assert [finding["line"] for finding in suppressed] == [3]


def test_typescript_block_comment_can_hold_inline_ignore(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\n"
        "  return record.report_sha256 === digest;"
        "  /* skylos: ignore[SKY-D253] public digest */\n"
        "}\n",
        ".tsx",
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    assert len(_rule_findings(result, "suppressed", "SKY-D253")) == 1


def test_closed_same_line_ignore_block_does_not_bleed(tmp_path):
    result = _scan(
        tmp_path,
        "/* skylos: ignore-start skylos: ignore-end */\n"
        "if (record.report_sha256 === digest) { proceed(); }\n",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


@pytest.mark.parametrize("line_ending", ("\r", "\u2028", "\u2029"))
def test_unsupported_js_line_endings_fail_open_for_inline_ignores(
    tmp_path, line_ending
):
    result = _scan(
        tmp_path,
        "// skylos: ignore-start"
        + line_ending
        + "if (record.report_sha256 === digest) { proceed(); }"
        + line_ending
        + "// skylos: ignore-end",
    )

    assert len(_rule_findings(result, "danger", "SKY-D253")) == 1
    assert _rule_findings(result, "suppressed", "SKY-D253") == []


def test_crlf_typescript_inline_ignore_is_supported(tmp_path):
    result = _scan(
        tmp_path,
        "export function sameReport(record, digest) {\r\n"
        "  return record.report_sha256 === digest;"
        " // skylos: ignore[SKY-D253]\r\n"
        "}\r\n",
        ".ts",
    )

    assert _rule_findings(result, "danger", "SKY-D253") == []
    assert len(_rule_findings(result, "suppressed", "SKY-D253")) == 1


def test_blanket_js_inline_ignore_applies_to_dead_code(tmp_path):
    result = _scan(
        tmp_path,
        "function unusedHelper() { return 1; } // skylos: ignore\n",
    )

    unused = [
        finding
        for finding in result.get("unused_functions", [])
        if finding.get("simple_name") == "unusedHelper"
    ]
    suppressed = [
        finding
        for finding in result.get("suppressed", [])
        if finding.get("name") == "unusedHelper"
    ]
    assert unused == []
    assert len(suppressed) == 1
    assert suppressed[0]["reason"] == "inline ignore comment"


def test_js_rule_specific_inline_ignore_reaches_later_ai_checks(tmp_path):
    (tmp_path / "security.js").write_text(
        "export function authenticate(request) { return request; }\n",
        encoding="utf-8",
    )
    (tmp_path / "views.js").write_text(
        'import * as security from "./security.js";\n'
        "export function handler(request) {\n"
        "  return security.require_auth(request);"
        " // skylos: ignore[SKY-L012] missing local export\n"
        "}\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_ai_defects=True,
            grep_verify=False,
            trace_file=False,
        )
    )

    assert _rule_findings(result, "ai_defects", "SKY-L012") == []
    suppressed = _rule_findings(result, "suppressed", "SKY-L012")
    assert len(suppressed) == 1
    assert suppressed[0]["reason"] == "inline ignore comment"
