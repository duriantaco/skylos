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


def test_redirect_with_urlparse_guard_is_not_proven_safe():
    """A netloc check does not prove browser-safe redirect semantics."""
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
    assert "SKY-D230" in _rule_ids(findings)


def test_redirect_with_startswith_guard_is_not_proven_safe():
    """A slash prefix accepts protocol-relative URLs and cannot validate a new read."""
    code = (
        "from flask import redirect, request\n"
        "def f():\n"
        "    url = request.args.get('next', '/')\n"
        "    if not url.startswith('/'):\n"
        "        url = '/'\n"
        "    return redirect(request.args.get('next', '/'))\n"
    )
    findings = _scan_code(code)
    assert "SKY-D230" in _rule_ids(findings)


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


def _d230_lines(code):
    return sorted(f["line"] for f in _scan_code(code) if f["rule_id"] == "SKY-D230")


def test_django_host_and_scheme_check_guards_only_its_passing_branch():
    code = (
        "from django.shortcuts import redirect\n"
        "from django.utils.http import url_has_allowed_host_and_scheme\n"
        "def passing(request):\n"
        "    nxt = request.GET.get('next')\n"
        "    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
        "def reset(request):\n"
        "    nxt = request.GET.get('next')\n"
        "    if not url_has_allowed_host_and_scheme(url=nxt, allowed_hosts=None):\n"
        "        nxt = '/'\n"
        "    return redirect(nxt)\n"
        "def failing(request):\n"
        "    nxt = request.GET.get('next')\n"
        "    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts=None):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
        "def ignored(request):\n"
        "    nxt = request.GET.get('next')\n"
        "    url_has_allowed_host_and_scheme(nxt, allowed_hosts=None)\n"
        "    return redirect(nxt)\n"
        "def other_value(request):\n"
        "    nxt = request.GET.get('next')\n"
        "    if url_has_allowed_host_and_scheme(request.GET.get('x'), allowed_hosts=None):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
    )
    assert _d230_lines(code) == [16, 21, 25]


def test_local_function_named_like_the_django_check_is_not_a_guard():
    code = (
        "from django.shortcuts import redirect\n"
        "def url_has_allowed_host_and_scheme(url, allowed_hosts=None):\n"
        "    return True\n"
        "def view(request):\n"
        "    nxt = request.GET.get('next')\n"
        "    if url_has_allowed_host_and_scheme(nxt, allowed_hosts=None):\n"
        "        return redirect(nxt)\n"
        "    return redirect('/')\n"
    )
    assert _d230_lines(code) == [7]


def test_asgi_aiohttp_redirects_and_location_headers_are_sinks():
    code = (
        "from aiohttp import web\n"
        "from starlette.responses import RedirectResponse, Response\n"
        "@app.get('/a')\n"
        "async def a(next):\n"
        "    return RedirectResponse(next)\n"
        "async def b(request):\n"
        "    return RedirectResponse(url=request.query_params['next'])\n"
        "async def c(request):\n"
        "    raise web.HTTPFound(location=request.query.get('to'))\n"
        "def d(request):\n"
        "    response = Response(status_code=302)\n"
        "    response.headers['Location'] = request.query_params['next']\n"
        "    return response\n"
        "def e(request):\n"
        "    return Response(status_code=302, headers={'Location': request.query_params['n']})\n"
        "async def f():\n"
        "    return RedirectResponse(url='/home')\n"
        "def g(request):\n"
        "    data = {}\n"
        "    data['location'] = request.GET['city']\n"
        "    return data\n"
    )
    assert _d230_lines(code) == [5, 7, 9, 12, 15]


def test_root_query_or_fragment_prefix_keeps_the_origin():
    code = (
        "from starlette.responses import RedirectResponse\n"
        "@app.get('/a')\n"
        "async def a(target):\n"
        "    return RedirectResponse(f'/?v=app&next={target}')\n"
        "@app.get('/b')\n"
        "async def b(target):\n"
        "    return RedirectResponse('/#' + target)\n"
        "@app.get('/c')\n"
        "async def c(target):\n"
        "    return RedirectResponse('/' + target)\n"
    )
    assert _d230_lines(code) == [10]


def test_absolute_url_of_the_current_request_stays_on_the_site():
    code = (
        "from starlette.datastructures import URL\n"
        "from starlette.requests import Request\n"
        "from starlette.responses import RedirectResponse, Response\n"
        "async def b(request: Request):\n"
        "    return RedirectResponse(request.url.replace(scheme='https'))\n"
        "async def c(scope):\n"
        "    url = URL(scope=scope)\n"
        "    return RedirectResponse(url.replace(path=url.path + '/'))\n"
        "async def d(request: Request):\n"
        "    return RedirectResponse(request.url.path)\n"
        "async def e(request: Request):\n"
        "    return RedirectResponse(request.url.replace(netloc=request.query_params['h']))\n"
        "async def f(request):\n"
        "    return RedirectResponse(request.url)\n"
        "class Location(Response):\n"
        "    def __init__(self, url):\n"
        "        self.headers['location'] = url\n"
    )
    assert _d230_lines(code) == [10, 12, 14]


_NEW_SINK_ROUTES = (
    "from fastapi import FastAPI, Request\n"
    "from starlette.responses import RedirectResponse\n"
    "from app.helpers import get_next_url\n"
    "app = FastAPI()\n"
    "def local_next(request):\n"
    "    return request.query_params.get('next', '/')\n"
    "@app.get('/a')\n"
    "async def a(request: Request):\n"
    "    next_url = get_next_url(request)\n"
    "    for q in request.query_params:\n"
    "        next_url += f'&{q}={request.query_params[q]}'\n"
    "    return RedirectResponse(url=next_url)\n"
    "@app.get('/b')\n"
    "async def b(request: Request):\n"
    "    return RedirectResponse(url=get_next_url(request.query_params['next']))\n"
    "@app.get('/c')\n"
    "async def c(request: Request):\n"
    "    return RedirectResponse(url=local_next(request))\n"
    "@app.get('/d')\n"
    "async def d(request: Request):\n"
    "    return RedirectResponse(url='https://' + request.query_params['host'])\n"
    "@app.get('/e')\n"
    "async def e(request: Request):\n"
    "    target = get_next_url(request) + request.query_params['x']\n"
    "    return RedirectResponse(target)\n"
    "@app.get('/f')\n"
    "async def f(request: Request):\n"
    "    target = request.query_params.get('next', '').strip()\n"
    "    return RedirectResponse(url=target)\n"
    "def helper(url):\n"
    "    return RedirectResponse(url)\n"
)


def test_new_redirect_sinks_need_request_data_reaching_the_target():
    assert _d230_lines(_NEW_SINK_ROUTES) == [18, 21, 29]


def test_legacy_redirect_sinks_keep_their_parameter_taint():
    code = (
        "from flask import redirect, request\n"
        "from app.helpers import get_next_url\n"
        "def a(url):\n"
        "    return redirect(url)\n"
        "def b():\n"
        "    return redirect(get_next_url(request.args['next']))\n"
        "def c():\n"
        "    return redirect(request.url)\n"
    )
    assert _d230_lines(code) == [4, 6, 8]
