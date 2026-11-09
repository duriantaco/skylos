import json

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
