"""RegExp scope regressions using inert, in-memory TypeScript sources."""

import pytest
from tree_sitter import Parser

from skylos.visitors.languages.typescript import danger as danger_module


def _scan_exec_findings(source: str, expected_exec_lines: list[int]) -> list[tuple]:
    source_bytes = source.encode("utf-8")
    lang = danger_module.TS_LANG
    assert lang is not None
    root = Parser(lang).parse(source_bytes).root_node
    assert not root.has_error

    captures = danger_module._run_batch(
        root, lang, "danger_complex", danger_module._COMPLEX_PATTERN
    )
    assert (
        sorted(node.start_point[0] + 1 for node in captures.get("exec_prop", []))
        == expected_exec_lines
    )

    findings = danger_module.scan_danger(
        root, "src/labels.ts", lang=lang, source=source_bytes
    )
    assert not [
        finding
        for finding in findings
        if finding["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    ]
    return [
        (finding["rule_id"], finding["file"], finding["line"])
        for finding in findings
        if finding["rule_id"] == "SKY-D212"
    ]


def test_code_block_regex_exec_is_not_command_execution():
    source = (
        "const codeBlockRegex = /```([\\s\\S]*?)```/g;\n"
        'const content = "```label```";\n'
        "let match;\n"
        "while ((match = codeBlockRegex.exec(content)) !== null) {\n"
        "  const block = match[1];\n"
        "}\n"
    )

    assert _scan_exec_findings(source, [4]) == []


@pytest.mark.parametrize(
    "inner_scope",
    [
        pytest.param(
            "function describe(codeBlockRegex) {\n  return codeBlockRegex.length;\n}\n",
            id="function-parameter",
        ),
        pytest.param(
            "function describe<T>(codeBlockRegex: T): T {\n"
            "  return codeBlockRegex;\n"
            "}\n",
            id="typed-generic-parameter",
        ),
        pytest.param(
            "const describe = (codeBlockRegex: string) => codeBlockRegex.length;\n",
            id="typed-arrow-parameter",
        ),
        pytest.param(
            "function describe() {\n"
            '  const codeBlockRegex = "label";\n'
            "  return codeBlockRegex.length;\n"
            "}\n",
            id="function-const-local",
        ),
        pytest.param(
            "function describe() {\n"
            '  var codeBlockRegex = "label";\n'
            "  return codeBlockRegex.length;\n"
            "}\n",
            id="function-var-local",
        ),
        pytest.param(
            "{\n"
            '  let codeBlockRegex = "label";\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="block-let-local",
        ),
        pytest.param(
            "try {\n"
            '  throw "label";\n'
            "} catch (codeBlockRegex) {\n"
            "  const label = codeBlockRegex;\n"
            "}\n",
            id="catch-binding",
        ),
        pytest.param(
            "function describe({ codeBlockRegex }: { codeBlockRegex: string }) {\n"
            "  return codeBlockRegex.length;\n"
            "}\n",
            id="typed-destructured-parameter",
        ),
        pytest.param(
            'for (const codeBlockRegex of ["label"]) {\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="for-of-lexical-binding",
        ),
        pytest.param(
            "for (let codeBlockRegex = 0; codeBlockRegex < 1; codeBlockRegex++) {\n"
            "  const index = codeBlockRegex;\n"
            "}\n",
            id="for-initializer-lexical-binding",
        ),
        pytest.param(
            "{\n"
            '  const { codeBlockRegex } = { codeBlockRegex: "label" };\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="object-destructured-local",
        ),
        pytest.param(
            "{\n"
            '  const { label: codeBlockRegex } = { label: "label" };\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="renamed-destructured-local",
        ),
        pytest.param(
            "{\n"
            '  const { codeBlockRegex = "label" } = {};\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="object-destructuring-literal-default",
        ),
        pytest.param(
            "{\n"
            '  const [codeBlockRegex = "label"] = [];\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="array-destructuring-literal-default",
        ),
        pytest.param(
            "const describe = function codeBlockRegex() {\n"
            "  return codeBlockRegex.name;\n"
            "};\n",
            id="named-function-expression",
        ),
        pytest.param(
            "const Label = class codeBlockRegex {\n"
            "  describe() { return codeBlockRegex.name; }\n"
            "};\n",
            id="named-class-expression",
        ),
        pytest.param(
            "const labels = {\n"
            "  describe(codeBlockRegex: string) { return codeBlockRegex.length; }\n"
            "};\n",
            id="object-method-parameter",
        ),
        pytest.param(
            "class Label {\n"
            "  describe(codeBlockRegex: string) { return codeBlockRegex.length; }\n"
            "}\n",
            id="class-method-parameter",
        ),
    ],
)
def test_inner_shadow_does_not_invalidate_outer_regexp(inner_scope):
    source = (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        + inner_scope
        + 'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, len(source.splitlines())]) == []


def test_sibling_function_binding_does_not_affect_local_regexp():
    source = (
        "function matchLabel() {\n"
        "  const codeBlockRegex = /label/g;\n"
        '  return codeBlockRegex.exec("label");\n'
        "}\n"
        "function describe(codeBlockRegex: string) {\n"
        "  return codeBlockRegex.length;\n"
        "}\n"
    )

    assert _scan_exec_findings(source, [3]) == []


def test_nested_regexp_bindings_keep_their_own_calls():
    source = (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        "function matchOtherLabel() {\n"
        "  const codeBlockRegex = /other/g;\n"
        '  return codeBlockRegex.exec("other");\n'
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 5, 7]) == []


def test_closure_preserves_outer_literal_regexp():
    source = (
        "const codeBlockRegex = /label/g;\n"
        "function matchLabel(text: string) {\n"
        "  return codeBlockRegex.exec(text);\n"
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3, 5]) == []


def test_nested_var_is_body_scoped_without_shadowing_parameter_default():
    source = (
        "const codeBlockRegex = /label/g;\n"
        'function describe(match = codeBlockRegex.exec("label")) {\n'
        "  if (true) {\n"
        '    var codeBlockRegex = "label";\n'
        "  }\n"
        "  const label = codeBlockRegex;\n"
        "  return match;\n"
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 9]) == []


@pytest.mark.parametrize(
    "declaration",
    ["const labels = {", "class Label {"],
    ids=["object-method", "class-method"],
)
def test_computed_method_name_uses_outer_regexp_before_parameter_scope(declaration):
    source = (
        "const codeBlockRegex = /label/g;\n"
        f"{declaration}\n"
        '  [codeBlockRegex.exec("label")![0]](codeBlockRegex: string) {\n'
        "    return codeBlockRegex.length;\n"
        "  }\n"
        "};\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3, 7]) == []


@pytest.mark.parametrize(
    "import_statement",
    [
        pytest.param(
            'import { codeBlockRegex as label } from "./labels";',
            id="aliased-remote-spelling",
        ),
        pytest.param(
            'import type { codeBlockRegex } from "./labels";',
            id="type-only-import",
        ),
        pytest.param(
            'import { type codeBlockRegex } from "./labels";',
            id="type-only-specifier",
        ),
    ],
)
def test_static_import_names_do_not_contaminate_runtime_regexp(import_statement):
    source = (
        f"{import_statement}\n"
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3]) == []


@pytest.mark.parametrize(
    "function_body",
    [
        pytest.param("  return arguments.length;\n", id="ordinary-function"),
        pytest.param(
            "  const count = () => arguments.length;\n  return count;\n",
            id="arrow-inherits-function-arguments",
        ),
    ],
)
def test_implicit_arguments_is_independent_of_outer_regexp(function_body):
    source = (
        "const arguments = /label/g;\n"
        'arguments.exec("label");\n'
        "function describe() {\n"
        f"{function_body}"
        "}\n"
        'arguments.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, len(source.splitlines())]) == []


def test_arrow_retains_outer_regexp_named_arguments():
    source = (
        "const arguments = /label/g;\n"
        "const matchLabel = (text: string) => arguments.exec(text);\n"
        'arguments.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 3]) == []


# An opaque ``X.exec`` is a command sink only when the file loads a command
# module; these two keep the RegExp proof scoped when one is loaded.
_LOADS_CHILD_PROCESS = 'import { spawn } from "node:child_process";\n'


def test_opaque_same_named_parameter_does_not_inherit_outer_regexp_proof():
    source = _LOADS_CHILD_PROCESS + (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        "function describe(codeBlockRegex: { exec(text: string): string }) {\n"
        '  return codeBlockRegex.exec("label");\n'
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3, 5, 7]) == [("SKY-D212", "src/labels.ts", 5)]


def test_unknown_exec_receiver_is_not_exempted_by_nearby_regexp():
    source = _LOADS_CHILD_PROCESS + (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        "declare const receiver: { exec(text: string): string };\n"
        'receiver.exec("label");\n'
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3, 5, 6]) == [("SKY-D212", "src/labels.ts", 5)]


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "export function find(regex: RegExp, lineText: string) {\n"
            "  return regex.exec(lineText);\n"
            "}\n",
            id="regexp-parameter",
        ),
        pytest.param(
            "export function wrap(lineText: string) {\n"
            "  let regex = /(\\*+)/g;\n"
            "  if (lineText.length > 3) { regex = /(_+)/g; }\n"
            "  return regex.exec(lineText);\n"
            "}\n",
            id="reassigned-regexp",
        ),
        pytest.param(
            "declare const receiver: { exec(text: string): string };\n"
            'receiver.exec("label");\n',
            id="opaque-receiver",
        ),
    ],
)
def test_exec_without_a_command_module_is_not_command_injection(source):
    findings = danger_module.scan_danger(
        Parser(danger_module.TS_LANG).parse(source.encode()).root_node,
        "src/labels.ts",
        lang=danger_module.TS_LANG,
        source=source.encode(),
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D212"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        pytest.param(
            'import cp from "child_process";\ncp.exec(cmd);\n', 2, id="default-import"
        ),
        pytest.param(
            'import * as cp from "node:child_process";\ncp.exec(cmd);\n',
            2,
            id="namespace-import",
        ),
        pytest.param(
            'const childProcess = require("child_process");\nchildProcess.exec(cmd);\n',
            2,
            id="require",
        ),
        pytest.param(
            'import shell from "shelljs";\nshell.exec(cmd);\n', 2, id="shelljs"
        ),
        pytest.param(
            'const cp = await import("node:child_process");\ncp.exec(cmd);\n',
            2,
            id="dynamic-import",
        ),
        pytest.param(
            'import { spawn } from "child_process";\nrunner.exec(cmd);\n',
            2,
            id="opaque-receiver-with-module-loaded",
        ),
        pytest.param(
            'import db from "child_process";\ndb.exec(cmd);\n',
            2,
            id="database-named-alias",
        ),
    ],
)
def test_command_module_exec_stays_command_injection(source, line):
    findings = danger_module.scan_danger(
        Parser(danger_module.TS_LANG).parse(source.encode()).root_node,
        "src/run.ts",
        lang=danger_module.TS_LANG,
        source=source.encode(),
    )
    assert [f["line"] for f in findings if f["rule_id"] == "SKY-D212"] == [line]


# Remote and container exec (coordinator round 2): ssh2, node-ssh and
# dockerode run commands on another host or in a container.
@pytest.mark.parametrize(
    ("source", "line", "message_start"),
    [
        pytest.param(
            'const { Client } = require("ssh2");\n'
            "const conn = new Client();\n"
            "conn.exec(cmd, cb);\n",
            3,
            "SSH exec()",
            id="ssh2-conn",
        ),
        pytest.param(
            'import { NodeSSH } from "node-ssh";\n'
            "const ssh = new NodeSSH();\n"
            "ssh.exec(cmd, []);\n",
            3,
            "SSH exec()",
            id="node-ssh",
        ),
        pytest.param(
            'import Docker from "dockerode";\n'
            "const container = new Docker().getContainer(id);\n"
            'container.exec({ Cmd: ["sh", "-c", cmd] });\n',
            3,
            "dockerode exec()",
            id="dockerode",
        ),
        pytest.param(
            'import cp from "child_process";\ncp.exec(cmd);\n',
            2,
            "child_process.exec()",
            id="child-process-message-unchanged",
        ),
    ],
)
def test_remote_and_container_exec_is_command_injection(source, line, message_start):
    findings = danger_module.scan_danger(
        Parser(danger_module.TS_LANG).parse(source.encode()).root_node,
        "src/run.ts",
        lang=danger_module.TS_LANG,
        source=source.encode(),
    )
    d212 = [f for f in findings if f["rule_id"] == "SKY-D212"]
    assert [f["line"] for f in d212] == [line]
    assert d212[0]["message"].startswith(message_start)


def test_regexp_proof_still_wins_in_a_file_that_loads_ssh2():
    source = (
        'const { Client } = require("ssh2");\n'
        "const re = /a/g;\n"
        "re.exec(text);\n"
        "const conn = new Client();\n"
        "conn.exec(cmd, cb);\n"
    )
    findings = danger_module.scan_danger(
        Parser(danger_module.TS_LANG).parse(source.encode()).root_node,
        "src/run.ts",
        lang=danger_module.TS_LANG,
        source=source.encode(),
    )
    assert [f["line"] for f in findings if f["rule_id"] == "SKY-D212"] == [5]


def test_database_conn_exec_stays_exempt_when_a_database_driver_is_loaded():
    source = (
        'import { Client } from "ssh2";\n'
        'import sqlite3 from "better-sqlite3";\n'
        "conn.exec(sql);\n"
    )
    findings = danger_module.scan_danger(
        Parser(danger_module.TS_LANG).parse(source.encode()).root_node,
        "src/db.ts",
        lang=danger_module.TS_LANG,
        source=source.encode(),
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D212"]
