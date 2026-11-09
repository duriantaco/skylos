import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate


def _scan(tmp_path, files):
    for name, source in files.items():
        (tmp_path / name).write_text(source)
    return json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )


def test_unknown_redirect_remains_a_diagnostic(tmp_path):
    result = _scan(
        tmp_path,
        {
            "redirects.py": "from flask import redirect\ndef finish(target):\n    return redirect(target)\n"
        },
    )
    assert not [r for r in result.get("danger", []) if r["rule_id"] == "SKY-D230"]
    rows = [r for r in result.get("suppressed", []) if r["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["redirect_provenance"]["status"] == "unknown"
    assert rows[0]["metadata"]["redirect_provenance"]["safety_proven"] is False
    assert check_gate(result, {"gate": {"max_high": 0}})[0]


def test_redirect_from_a_route_through_a_helper_keeps_the_attack_trace(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": "from flask import Flask, request\nfrom redirects import finish\napp = Flask(__name__)\n@app.get('/go')\ndef route():\n    return finish(request.args['next'])\n",
            "redirects.py": "from flask import redirect\ndef finish(target):\n    return redirect(target)\n",
        },
    )
    rows = [r for r in result.get("danger", []) if r["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["redirect_provenance"]["status"] == "untrusted"
    assert rows[0]["metadata"]["security_evidence"]["source"]
    assert not check_gate(result, {"gate": {"max_high": 0}})[0]


def test_scheme_audit_does_not_replace_actual_ssrf_source_evidence(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": "from flask import Flask, request\nfrom urllib.request import urlopen\napp = Flask(__name__)\n@app.get('/fetch')\ndef route():\n    return urlopen(request.args['url'])\n"
        },
    )
    assert any(r["rule_id"] == "SKY-D216" for r in result.get("danger", []))
    assert not any(r["rule_id"] == "SKY-D218" for r in result.get("danger", []))
    rows = [r for r in result.get("suppressed", []) if r["rule_id"] == "SKY-D218"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["url_scheme_provenance"]["status"] == "unknown"


def test_operator_redirect_input_is_unknown_not_a_remote_source(tmp_path):
    result = _scan(
        tmp_path,
        {
            "cli.py": "from flask import redirect\nimport os\ndef finish(target):\n    return redirect(target)\nfinish(os.getenv('NEXT_URL'))\n"
        },
    )
    assert not any(r["rule_id"] == "SKY-D230" for r in result.get("danger", []))
    rows = [r for r in result.get("suppressed", []) if r["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["redirect_provenance"]["status"] == "unknown"


@pytest.mark.parametrize(
    "body",
    [
        "self.redirect(self.get_argument('next', '/'))",
        "target = self.get_argument('next', '/')\n        self.redirect(target.strip())",
    ],
)
def test_native_tornado_request_source_survives_project_policy(tmp_path, body):
    result = _scan(
        tmp_path,
        {
            "app.py": "import tornado\nclass Login(tornado.web.RequestHandler):\n"
            "    def get(self):\n        " + body + "\n"
        },
    )
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["source_status"] == "untrusted"
    assert (
        rows[0]["metadata"]["redirect_source_proof"]["kind"]
        == "native_framework_request"
    )
    assert not check_gate(result, {"gate": {"max_high": 0}})[0]


def test_unrelated_tornado_read_does_not_promote_a_generic_target(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": "import tornado\nclass Login(tornado.web.RequestHandler):\n"
            "    def finish(self, target):\n"
            "        unused = self.get_argument('next', '/')\n"
            "        self.redirect(target)\n"
        },
    )
    assert not [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D230"]
    rows = [row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["redirect_provenance"]["status"] == "unknown"
    assert rows[0]["metadata"]["redirect_provenance"]["safety_proven"] is False


def test_native_location_assignment_source_survives_project_policy(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": "from flask import request\ndef finish(response):\n"
            "    response.headers['Location'] = request.args['next']\n"
        },
    )
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["source_status"] == "untrusted"
    assert rows[0]["metadata"]["security_evidence"]["source"]


def test_native_redirect_sink_does_not_promote_cli_input(tmp_path):
    result = _scan(
        tmp_path,
        {
            "cli.py": "import click\nfrom starlette.responses import RedirectResponse\n"
            "@click.command()\n@click.argument('target')\ndef finish(target):\n"
            "    return RedirectResponse(target)\n"
        },
    )
    assert not [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D230"]
    rows = [row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D230"]
    assert len(rows) == 1
    assert rows[0]["metadata"]["redirect_provenance"]["status"] == "unknown"
