import ast
from skylos.rules.danger.danger_cors.cors_flow import scan


def _scan_code(code, filename="app.py"):
    tree = ast.parse(code)
    findings = []
    scan(tree, filename, findings)
    return findings


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_flask_cors_no_origins():
    code = (
        "from flask_cors import CORS\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "CORS(app)\n"
    )
    findings = _scan_code(code)
    assert "SKY-D231" in _rule_ids(findings)


def test_django_cors_allow_all():
    code = "CORS_ALLOW_ALL_ORIGINS = True\n"
    findings = _scan_code(code)
    assert "SKY-D231" in _rule_ids(findings)


def test_cors_with_origins_safe():
    code = (
        "from flask_cors import CORS\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "CORS(app, origins=['https://example.com'])\n"
    )
    findings = _scan_code(code)
    assert "SKY-D231" not in _rule_ids(findings)


def test_django_cors_allow_all_false_safe():
    code = "CORS_ALLOW_ALL_ORIGINS = False\n"
    findings = _scan_code(code)
    assert "SKY-D231" not in _rule_ids(findings)
