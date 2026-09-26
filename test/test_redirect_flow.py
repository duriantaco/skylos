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


# --- D230 enhancement: request.args.get() with default ---


def test_redirect_request_args_get_with_default():
    """redirect(request.args.get('next', '/')) should still be flagged."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    return redirect(request.args.get('next', '/'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)
    assert "default value" in findings[0]["message"].lower()


def test_redirect_request_args_get_no_default():
    """redirect(request.args.get('url')) should be flagged."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    return redirect(request.args.get('url'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_request_GET_get():
    """Django: redirect(request.GET.get('next')) should be flagged."""
    code = (
        "from django.shortcuts import redirect\n"
        "def f(request):\n"
        "    return redirect(request.GET.get('next'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_request_params_get():
    """redirect(request.params.get('url')) should be flagged."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    return redirect(request.params.get('url'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_request_query_get():
    """redirect(request.query.get('next')) should be flagged."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    return redirect(request.query.get('next'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_with_urlparse_guard_safe():
    """If urlparse().netloc check exists, don't flag."""
    code = (
        "from flask import redirect, request\n"
        "from urllib.parse import urlparse\n"
        "def f():\n"
        "    url = request.args.get('next', '/')\n"
        "    if urlparse(url).netloc:\n"
        "        return redirect('/')\n"
        "    return redirect(request.args.get('next', '/'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" not in _rule_ids(findings)


def test_redirect_with_startswith_guard_safe():
    """If .startswith('/') check exists, don't flag."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    url = request.args.get('next', '/')\n"
        "    if not url.startswith('/'):\n"
        "        url = '/'\n"
        "    return redirect(request.args.get('next', '/'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" not in _rule_ids(findings)


def test_redirect_tainted_variable_still_flagged():
    """Original taint-based detection should still work."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    url = request.args['next']\n"
        "    return redirect(url)\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_url_for_with_user_value_is_internal():
    # agent-pr-bench mb-07: url_for builds an application-internal path; the
    # user value only fills a path parameter.
    code = (
        "from flask import redirect, url_for, request\n"
        "def follow(username):\n"
        "    return redirect(url_for('main.user', username=username))\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    target = url_for('main.search') + '?q=' + q\n"
        "    return redirect(target)\n"
        "def detail(request, pk):\n"
        "    return redirect(reverse('detail', args=[pk]))\n"
    )
    assert "SKY-D230" not in _rule_ids(_scan_code(code))


def test_redirect_user_url_next_to_url_for_still_flags():
    code = (
        "from flask import redirect, url_for, request\n"
        "def login(next_url):\n"
        "    if not next_url:\n"
        "        return redirect(url_for('main.index'))\n"
        "    return redirect(next_url)\n"
    )
    assert "SKY-D230" in _rule_ids(_scan_code(code))
