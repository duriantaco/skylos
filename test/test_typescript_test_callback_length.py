"""Regression coverage for function-length findings in JS/TS test sources."""

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


_ASSERTIONS = "".join(f"  assert.equal({index}, {index});\n" for index in range(52))


def _scan_quality(tmp_path, filename, source, *, config=None):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source, encoding="utf-8"
    )
    return scan_typescript_file(str(path), config=config)[6]


def _length_findings(findings):
    return [finding for finding in findings if finding["rule_id"] == "SKY-C304"]


@pytest.mark.parametrize(
    ("filename", "call"),
    [
        ("test/example.test.ts", "test"),
        ("test/e2e/example.test.ts", "suite"),
        ("__tests__/example.spec.js", "it"),
        ("tests/example.ts", "describe"),
        ("tests/example.js", "test.only"),
        ("tests/example.ts", "describe.skip"),
        ("test/e2e/playwright.spec.ts", "test.describe"),
        ("tests/table.test.ts", "test.each([[1], [2]])"),
    ],
)
def test_long_anonymous_test_and_suite_callbacks_do_not_report_length(
    tmp_path, filename, call
):
    source = f"{call}('scenario', () => {{\n{_ASSERTIONS}}});\n"

    assert _length_findings(_scan_quality(tmp_path, filename, source)) == []


def test_node_test_callback_without_name_does_not_report_length(tmp_path):
    source = (
        "import { test } from 'node:test';\n"
        f"test(() => {{\n{_ASSERTIONS}}});\n"
    )

    assert _length_findings(_scan_quality(tmp_path, "test/unnamed.test.ts", source)) == []


def test_node_test_options_before_callback_do_not_report_length(tmp_path):
    source = (
        "import { test } from 'node:test';\n"
        f"test('scenario', {{ skip: true }}, () => {{\n{_ASSERTIONS}}});\n"
    )

    assert _length_findings(_scan_quality(tmp_path, "test/options.test.ts", source)) == []


@pytest.mark.parametrize("call", ["test", "test.each([[1], [2]])"])
def test_jest_timeout_after_callback_does_not_report_length(tmp_path, call):
    source = f"{call}('scenario', () => {{\n{_ASSERTIONS}}}, 1000);\n"

    assert _length_findings(_scan_quality(tmp_path, "tests/timeout.test.js", source)) == []


@pytest.mark.parametrize("filename", ["test/subtest.test.ts", "test/subtest.test.js"])
def test_node_subtest_callback_does_not_report_length(tmp_path, filename):
    source = (
        "import { test } from 'node:test';\n"
        "test('outer', async (t) => {\n"
        "  await t.test('inner', () => {\n"
        f"{_ASSERTIONS}"
        "  });\n"
        "});\n"
    )

    assert _length_findings(_scan_quality(tmp_path, filename, source)) == []


def test_nested_test_and_suite_callbacks_do_not_report_length(tmp_path):
    source = (
        "describe('suite', () => {\n"
        "  it('case', () => {\n"
        f"{_ASSERTIONS}"
        "  });\n"
        "});\n"
    )

    assert _length_findings(_scan_quality(tmp_path, "test/nested.test.ts", source)) == []


def test_named_long_helper_in_test_suite_still_reports_length(tmp_path):
    source = (
        "describe('suite', () => {\n"
        "  function prepareFixture() {\n"
        f"{_ASSERTIONS}"
        "  }\n"
        "  prepareFixture();\n"
        "});\n"
    )

    findings = _length_findings(_scan_quality(tmp_path, "test/helpers.test.ts", source))

    assert [finding["name"] for finding in findings] == ["prepareFixture"]


def test_unrelated_long_callback_in_test_file_still_reports_length(tmp_path):
    source = f"runScenario('scenario', () => {{\n{_ASSERTIONS}}});\n"

    findings = _length_findings(_scan_quality(tmp_path, "test/callbacks.test.ts", source))

    assert len(findings) == 1
    assert findings[0]["name"] == "anonymous"


def test_unrelated_test_method_still_reports_length(tmp_path):
    source = f"obj.test('scenario', () => {{\n{_ASSERTIONS}}});\n"

    findings = _length_findings(_scan_quality(tmp_path, "test/other-method.test.ts", source))

    assert len(findings) == 1
    assert findings[0]["name"] == "anonymous"


def test_nested_unrelated_callback_still_reports_length(tmp_path):
    source = (
        "test('scenario', () => {\n"
        "  runScenario(() => {\n"
        f"{_ASSERTIONS}"
        "  });\n"
        "});\n"
    )

    findings = _length_findings(_scan_quality(tmp_path, "test/callbacks.test.js", source))

    assert len(findings) == 1
    assert findings[0]["name"] == "anonymous"
    assert findings[0]["line"] == 2


def test_test_callback_outside_test_source_still_reports_length(tmp_path):
    source = f"test('scenario', () => {{\n{_ASSERTIONS}}});\n"

    findings = _length_findings(_scan_quality(tmp_path, "src/runner.ts", source))

    assert len(findings) == 1
    assert findings[0]["name"] == "anonymous"


def test_other_quality_findings_still_report_for_test_callback(tmp_path):
    source = (
        "test('scenario', () => {\n"
        "  if (ready) { assert.equal(1, 1); }\n"
        f"{_ASSERTIONS}"
        "});\n"
    )
    findings = _scan_quality(
        tmp_path,
        "test/quality.test.ts",
        source,
        config={"languages": {"typescript": {"complexity": 1}}},
    )

    assert _length_findings(findings) == []
    assert any(
        finding["rule_id"] == "SKY-Q301" and finding["name"] == "anonymous"
        for finding in findings
    )
