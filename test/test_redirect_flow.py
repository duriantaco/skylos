import ast
from skylos.rules.danger.danger_redirect.redirect_flow import scan


def _scan_code(code, filename="app.py"):
    tree = ast.parse(code)
    findings = []
    scan(tree, filename, findings)
    return findings


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_flask_redirect_tainted():
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    url = request.args.get('url')\n"
        "    return redirect(url)\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_django_redirect_tainted():
    code = (
        "from django.http import HttpResponseRedirect\n"
        "def f(request):\n"
        "    url = request.GET.get('next')\n"
        "    return HttpResponseRedirect(url)\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_constant_safe():
    code = "from flask import redirect\ndef f():\n    return redirect('/home')\n"
    findings = _scan_code(code)
    assert "SKY-D230" not in _rule_ids(findings)


def test_redirect_hardcoded_path_safe():
    code = (
        "from flask import redirect\n"
        "def f():\n"
        "    return redirect('https://example.com/dashboard')\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" not in _rule_ids(findings)
