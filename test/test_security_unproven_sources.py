"""Security findings are listed only when attacker input is shown to reach the
sink. Sinks whose source stays unknown (callers not visible, an operator URL,
a maintainer-only workflow value, a literal command) remain in the report as
review signals that are not listed and do not fail gates."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import _gate_findings
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.listing import (
    UNPROVEN_SOURCE_REASON,
    demotion_reason,
    is_gate_exempt_review,
    is_listed,
    is_unproven_source_review,
)
from skylos.rules.config.cicd.github_actions import scan_github_actions
from skylos.rules.danger.danger_fs import path_provenance
from test.fixture_paths import write_fixture
from test.test_typescript_expanded import _scan_ts_file


def _analyze(tmp_path, files):
    write_fixture(
        tmp_path, "pyproject.toml", '[project]\nname = "proj"\n', overwrite=True
    )
    for name, code in files.items():
        write_fixture(tmp_path, name, code, overwrite=True)
    return json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
            all_advice=False,
        )
    )


def _rows(result, rule, symbol=None):
    return [
        row
        for row in result.get("danger", [])
        if row["rule_id"] == rule and (symbol is None or row.get("symbol") == symbol)
    ]


# ---------------------------------------------------------------- Python paths

HELPER = (
    "from pathlib import Path\n\n"
    "def f0(name):\n    return (Path('/srv') / name).read_text()\n\n"
    + "".join(
        f"def f{index}(f{index - 1}):\n    return f{index - 1}\n\n"
        for index in range(1, 20)
    )
)


def test_incomplete_caller_provenance_is_an_unlisted_nonblocking_review(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 24)

    result = _analyze(tmp_path, {"app.py": HELPER})

    rows = _rows(result, "SKY-D215", "f0")
    assert rows, "the finding stays in the report"
    for row in rows:
        assert row["metadata"]["path_provenance"]["status"] == "incomplete"
        assert row["review_item"] == {"kind": "unproven_source", "blocking": False}
        assert row["message"].startswith("Review (not listed, not blocking)")
        assert is_unproven_source_review(row)
        assert not is_listed(row, "danger")
        assert row["listing"]["reason"] == UNPROVEN_SOURCE_REASON
    gated = _gate_findings(result)["danger"]
    assert not any(row["rule_id"] == "SKY-D215" for row in gated)


FLASK_ROUTE = """import os
from flask import Flask, request

app = Flask(__name__)


@app.route('/save', methods=['POST'])
def save():
    name = request.form['name']
    with open(os.path.join('/srv/data', name), 'w') as handle:
        handle.write('x')
    return 'ok'
"""


def test_request_data_reaching_a_path_stays_listed_and_blocking(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 24)

    result = _analyze(tmp_path, {"app.py": FLASK_ROUTE})

    rows = _rows(result, "SKY-D215")
    assert rows
    assert all(is_listed(row, "danger") for row in rows)
    assert not any(row.get("review_item") for row in rows)
    gated = _gate_findings(result)["danger"]
    assert any(row["rule_id"] == "SKY-D215" for row in gated)


def test_a_forged_review_item_does_not_hide_a_proven_path_finding():
    row = {
        "rule_id": "SKY-D215",
        "review_item": {"kind": "unproven_source", "blocking": False},
        "metadata": {
            "path_source": "resolved_caller",
            "path_provenance": {"status": "untrusted", "untrusted": [["route"]]},
        },
    }
    assert not is_unproven_source_review(row)
    assert demotion_reason(row) is None
    assert not is_gate_exempt_review(row)
    other_rule = {**row, "rule_id": "SKY-D212", "metadata": {}}
    assert not is_unproven_source_review(other_rule)


# ------------------------------------------- Flask request through the module

FLASK_MODULE = """import os
import flask

bp = flask.Blueprint("json", __name__)


@bp.route("/add", methods=["POST"])
def add():
    package = flask.request.form.get("package")
    with open(os.path.join("/srv/data", package + ".dlc"), "wb") as handle:
        handle.write(b"x")
    return "ok"
"""

URLLIB_MODULE = """import os
import urllib.request


def refresh():
    data = urllib.request.urlopen("https://example.com/feed").read()
    with open(os.path.join("/srv/data", "feed.json"), "wb") as handle:
        handle.write(data)
"""

LOCAL_REQUEST_ATTRIBUTE = """import os


class Job:
    def __init__(self, request):
        self.request = request


def run(job: Job):
    name = job.request.label
    with open(os.path.join("/srv/data", "fixed.txt"), "w") as handle:
        handle.write(name)
"""


def test_flask_request_read_through_the_module_is_a_request_source(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(tmp_path, {"app.py": FLASK_MODULE})

    rows = _rows(result, "SKY-D215")
    assert [row["line"] for row in rows] == [10]
    source = rows[0]["metadata"]["security_evidence"]["source"]
    assert "flask.request.form" in source
    assert is_listed(rows[0], "danger")


@pytest.mark.parametrize("source", [URLLIB_MODULE, LOCAL_REQUEST_ATTRIBUTE])
def test_other_request_attributes_are_not_request_sources(
    tmp_path, monkeypatch, source
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(tmp_path, {"app.py": source})

    assert not _rows(result, "SKY-D215")


# ------------------------------------------------------------- TypeScript SSRF

SERVICE = """import { getAxios } from './request';
export class FilesService {
  async importOne(importURL: string) {
    const axios = await getAxios();
    return await axios.get<Readable>(encodeURL(importURL), { responseType: 'stream' });
  }
  async notify(webhookURL: string) {
    return await fetch<Response>(webhookURL, { method: 'POST' });
  }
}
"""

ROUTE = """import express from 'express';
import axios from 'axios';
const app = express();
app.get('/proxy', async (req, res) => {
  const response = await axios.get<string>(req.query.url as string);
  res.send(response.data);
});
"""


def _ssrf(tmp_path, name, code):
    _, _, _, danger = _scan_ts_file(tmp_path, name, code)
    return [row for row in danger if row["rule_id"] == "SKY-D216"]


def test_awaited_generic_requests_without_request_data_are_review_signals(tmp_path):
    rows = _ssrf(tmp_path, "files.ts", SERVICE)

    # ``await axios.get<T>(...)`` parses with the await as the callee; it is
    # still an axios request.
    assert sorted(row["line"] for row in rows) == [5, 8]
    for row in rows:
        assert row["review_item"] == {"kind": "unproven_source", "blocking": False}
        assert is_unproven_source_review(row)
        assert demotion_reason(row) == UNPROVEN_SOURCE_REASON
        assert is_gate_exempt_review(row)


def test_request_data_choosing_the_url_stays_a_listed_finding(tmp_path):
    rows = _ssrf(tmp_path, "route.ts", ROUTE)

    assert [row["line"] for row in rows] == [5]
    assert rows[0].get("security_evidence")
    assert "review_item" not in rows[0]
    assert not is_unproven_source_review(rows[0])
    assert demotion_reason(rows[0]) is None


# --------------------------------------------------------- TypeScript commands

DATABASE_EXEC = """const { R } = require("redbean-node");
const childProcess = require("child_process");
async function activate(id) {
  await R.exec("UPDATE monitor SET active = 1 WHERE id = ?", [id]);
}
module.exports = { activate };
"""

COMMANDS = """const childProcess = require("child_process");
function install() {
  childProcess.exec("apt update && apt --yes install chromium");
}
function ping(host) {
  childProcess.exec("ping -c 1 " + host);
}
module.exports = { install, ping };
"""


def _commands(tmp_path, name, code):
    _, _, _, danger = _scan_ts_file(tmp_path, name, code)
    return {row["line"]: row for row in danger if row["rule_id"] == "SKY-D212"}


def test_database_client_exec_is_not_a_command(tmp_path):
    assert _commands(tmp_path, "server.js", DATABASE_EXEC) == {}


def test_literal_commands_are_low_risk_and_built_commands_are_findings(tmp_path):
    rows = _commands(tmp_path, "setup.js", COMMANDS)

    assert sorted(rows) == [3, 6]
    assert rows[3]["low_risk_context"]["reason"] == "constant-argument"
    assert demotion_reason(rows[3]) == "low-risk-context"
    assert "low_risk_context" not in rows[6]
    assert demotion_reason(rows[6]) is None


# ------------------------------------------------ GitHub Actions (SKY-D294)


def _workflow(tmp_path, text):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(
        workflows / "ci.yml", textwrap.dedent(text).lstrip(), encoding="utf-8"
    )
    return {
        row["line"]: row
        for row in scan_github_actions(tmp_path)
        if row["rule_id"] == "SKY-D294"
    }


def test_outsider_text_is_an_injection_and_maintainer_values_are_low_risk(tmp_path):
    rows = _workflow(
        tmp_path,
        """
        name: t
        on:
          issues:
          workflow_dispatch:
            inputs:
              version:
                type: string
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}"
              - run: echo "${{ inputs.version }}"
              - run: echo "${{ github.event.sender.login }} ${{ github.event.issue.user.login }}"
              - run: echo "${{ github.event.issue.number }} ${{ github.event.issue.node_id }}"
        """,
    )

    # Issue titles come from any account; GitHub lists them as untrusted.
    assert demotion_reason(rows[13]) is None
    # A workflow_dispatch input is set only by accounts with write access.
    assert rows[14]["low_risk_context"]["reason"] == "no-outsider-input"
    assert demotion_reason(rows[14]) == "low-risk-context"
    # Logins, numbers and node ids cannot carry shell syntax.
    assert 15 not in rows and 16 not in rows


def test_pull_request_head_is_untrusted_and_base_is_the_target_repository(tmp_path):
    rows = _workflow(
        tmp_path,
        """
        name: t
        on: pull_request_target
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.head.ref }}"
              - run: echo "${{ github.event.pull_request.base.ref }}"
              - run: echo "${{ github.event.pull_request.head.repo.full_name }}"
        """,
    )

    assert sorted(rows) == [8, 10]
    assert all(demotion_reason(row) is None for row in rows.values())


# ------------------------------------------------- unreachable Python sinks

LOADER = """import importlib.abc


class Loader(importlib.abc.Loader):
    def __init__(self, path):
        self.path = path

    def exec_module(self, module):
        return importlib.abc.Loader.load_module(module, fullname=module.__name__)
        with open(self.path) as handle:
            code = handle.read()
        exec(code, module.__dict__)

    def run(self, module):
        with open(self.path) as handle:
            code = handle.read()
        exec(code, module.__dict__)
"""


def test_a_sink_after_an_unconditional_return_is_not_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(tmp_path, {"loader.py": LOADER})

    exec_lines = sorted(row["line"] for row in _rows(result, "SKY-D202"))
    # Line 12 can never run; the same call in run() still can.
    assert exec_lines == [17]


def test_a_module_level_raise_does_not_hide_the_module(tmp_path, monkeypatch):
    # A file that raises at import time to stay unimported is still code.
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = (
        'raise RuntimeError("do not import")\n\n\ndef run(code):\n    exec(code, {})\n'
    )
    result = _analyze(tmp_path, {"loader.py": source})

    assert [row["line"] for row in _rows(result, "SKY-D202")] == [5]


REDIRECTS = """import flask

app = flask.Flask(__name__)


@app.route("/go")
def go():
    return flask.redirect(flask.request.args.get("next"))


@app.route("/back")
def back():
    return flask.redirect(flask.request.endpoint)
"""


def test_module_request_data_is_a_redirect_source_but_routing_fields_are_not(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(tmp_path, {"app.py": REDIRECTS})

    # The matched endpoint name comes from the application's routing table.
    assert [row["line"] for row in _rows(result, "SKY-D230")] == [8]


# ------------------------------------------------------- shell script arguments


def test_shell_script_arguments_are_an_unlisted_review_and_stdin_stays_listed():
    from skylos.visitors.languages.shell.danger import scan_danger

    serve = scan_danger(
        "serve.sh",
        '#!/bin/bash\nDIR="$1"\neval "find $DIR -type f"\ncat "$DIR/config"\n',
    )
    for row in serve:
        if row["rule_id"] in {"SKY-D212", "SKY-D215"}:
            assert row["metadata"] == {"shell_source": "script_arguments"}
            assert is_unproven_source_review(row)
            assert is_gate_exempt_review(row)
    assert {row["rule_id"] for row in serve} >= {"SKY-D212", "SKY-D215"}

    piped = scan_danger(
        "fetch.sh", '#!/bin/bash\nread -r TARGET\neval "curl $TARGET"\n'
    )
    commands = [row for row in piped if row["rule_id"] == "SKY-D212"]
    assert commands
    assert not any(is_unproven_source_review(row) for row in commands)
    assert all(demotion_reason(row) is None for row in commands)
