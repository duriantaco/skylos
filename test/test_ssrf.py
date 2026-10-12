import pytest
from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def _ssrf_findings(findings):
    return [f for f in findings if f["rule_id"] == "SKY-D216"]


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def test_requests_tainted_url_flags(tmp_path):
    code = "import requests\ndef f():\n    u = input()\n    requests.get(u)\n"
    out = _scan_one(tmp_path, "ssrf_req.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_tainted_url_includes_security_evidence(tmp_path):
    code = "import requests\n@app.get('/x')\ndef fetch_url(url):\n    return requests.get(url)\n"
    out = _scan_one(tmp_path, "ssrf_evidence.py", code)
    finding = _ssrf_findings(out)[0]

    evidence = finding["metadata"]["security_evidence"]
    assert evidence["evidence_kind"] == "source_to_sink"
    assert evidence["entrypoint"] == "fetch_url"
    assert evidence["source"] == "tainted variable `url`"
    assert evidence["sink"] == "requests.get"
    assert "URL host or scheme allowlist" in evidence["guards_missing"]
    assert "test_hint" in evidence
    assert "fix_shape" in evidence


def test_httpx_tainted_url_flags(tmp_path):
    code = "import httpx\n@app.get('/x')\ndef f(url):\n    httpx.post('http://' + url)\n"
    out = _scan_one(tmp_path, "ssrf_httpx.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_neutral_assignment_alias_flags(tmp_path):
    code = (
        "import requests\n"
        "api = requests\n"
        "@app.get('/x')\n"
        "def f(url):\n"
        "    api.get(url)\n"
    )
    out = _scan_one(tmp_path, "ssrf_requests_alias.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_unrelated_get_receiver_is_not_http(tmp_path):
    code = (
        "def f(url):\n"
        "    cache = {}\n"
        "    cache.get(url)\n"
    )
    out = _scan_one(tmp_path, "ssrf_unrelated_get.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_urllib_urlopen_tainted_url_flags(tmp_path):
    code = "import urllib.request as u\n@app.get('/x')\ndef f(x):\n    u.urlopen(f'http://{x}')\n"
    out = _scan_one(tmp_path, "ssrf_urlopen.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_urllib_urlopen_security_evidence_names_sink(tmp_path):
    code = "import urllib.request as u\n@app.get('/x')\ndef f(x):\n    u.urlopen(f'http://{x}')\n"
    out = _scan_one(tmp_path, "ssrf_urlopen_evidence.py", code)
    evidence = _ssrf_findings(out)[0]["metadata"]["security_evidence"]

    assert evidence["sink"] == "u.urlopen"
    assert evidence["source"] == "interpolated URL expression"
    assert any("HTTP sink `u.urlopen`" == step for step in evidence["path"])


def test_urllib_request_constructor_is_not_inbound_request_data(tmp_path):
    code = (
        "import json\n"
        "import urllib.request\n"
        "from typing import Any\n"
        "def post_json(base_url: str, path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:\n"
        "    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')\n"
        "    request = urllib.request.Request(\n"
        "        base_url + path, data=body, method='POST',\n"
        "        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},\n"
        "    )\n"
        "    with urllib.request.urlopen(request, timeout=timeout) as response:\n"
        "        data = response.read().decode('utf-8')\n"
        "    value = json.loads(data or '{}')\n"
        "    return value if isinstance(value, dict) else {}\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_request_helper.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_constructor_keeps_real_request_source(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def post_json():\n"
        "    outbound = urllib.request.Request(request.args['url'], method='POST')\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_request_input.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"] == "request data `request.args`"


def test_urllib_request_tainted_host_still_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "@app.get('/x')\n"
        "def fetch(host):\n"
        "    outbound = urllib.request.Request('https://' + host)\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_request_host.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"].startswith("route parameter `host`")


def test_urllib_name_shadowed_by_route_parameter_still_flags(tmp_path):
    code = (
        "import requests\n"
        "@app.get('/x')\n"
        "def fetch(urllib):\n"
        "    return requests.get(urllib.request.url)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_shadow.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"].startswith("route parameter `urllib`")


def test_urllib_request_alias_is_not_inbound_request_data(tmp_path):
    code = (
        "from urllib import request\n"
        "def post_json(base_url, path):\n"
        "    outbound = request.Request(base_url + path)\n"
        "    return request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_alias_helper.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_fixed_url_ignores_tainted_post_body(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def send():\n"
        "    outbound = urllib.request.Request(\n"
        "        'https://api.example.com/upload', data=request.form['body'])\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_request_body.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_fixed_host_ignores_tainted_path(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request(\n"
        "        'https://api.example.com/items/' + request.args['id'])\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_request_path.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_direct_constructor_tainted_host_flags(tmp_path):
    code = (
        "import urllib.request as u\n"
        "@app.get('/x')\n"
        "def fetch(host):\n"
        "    return u.urlopen(u.Request('https://' + host))\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_direct.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"].startswith("route parameter `host`")


def test_urllib_request_imported_constructor_and_urlopen_flag(tmp_path):
    code = (
        "from urllib.request import Request as R, urlopen as open_url\n"
        "@app.get('/x')\n"
        "def fetch(host):\n"
        "    outbound = R(url='https://' + host)\n"
        "    return open_url(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_imports.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"].startswith("route parameter `host`")


def test_urllib_request_full_url_mutation_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    outbound.full_url = request.args['url']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_mutation.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"] == "request data `request.args`"


def test_urllib_request_fixed_url_mutation_ignores_tainted_body(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request(\n"
        "        'https://api.example.com/', data=request.form['body'])\n"
        "    outbound.full_url = 'https://api.example.com/items/' + request.args['id']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_fixed_mutation_body.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_alias_full_url_mutation_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    alias = outbound\n"
        "    alias.full_url = request.args['url']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_alias_mutation.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"] == "request data `request.args`"


def test_urllib_request_alias_mutation_survives_original_rebinding(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    alias = outbound\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    alias.host = request.args['host']\n"
        "    return urllib.request.urlopen(alias)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_alias_rebinding.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_alias_keeps_mutation_before_rebinding(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    outbound.host = request.args['host']\n"
        "    alias = outbound\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    return urllib.request.urlopen(alias)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_alias_copy_mutation.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_host_augassign_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    outbound.host += request.args['suffix']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_host_augassign.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_full_url_augassign_can_change_authority(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com')\n"
        "    outbound.full_url += request.args['suffix']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_url_augassign.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_full_url_augassign_after_path_is_safe(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    outbound.full_url += request.args['path']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_safe_augassign.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_safe_augassign_ignores_tainted_body(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request(\n"
        "        'https://api.example.com/', data=request.form['body'])\n"
        "    outbound.full_url += request.args['path']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_safe_augassign_body.py", code)
    assert _ssrf_findings(out) == []


def test_urllib_request_alias_augassign_after_rebinding_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com')\n"
        "    alias = outbound\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    alias.full_url += request.args['suffix']\n"
        "    return urllib.request.urlopen(alias)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_alias_augassign.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_setattr_full_url_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    setattr(outbound, 'full_url', request.args['url'])\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_setattr.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_set_proxy_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('https://api.example.com/')\n"
        "    outbound.set_proxy(request.args['proxy'], 'https')\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_proxy.py", code)
    assert _ssrf_findings(out)


def test_urllib_request_proxy_selector_mutation_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    outbound = urllib.request.Request('http://api.example.com/')\n"
        "    outbound.set_proxy('proxy.example.com:8080', 'http')\n"
        "    outbound.selector = request.args['url']\n"
        "    return urllib.request.urlopen(outbound)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_proxy_selector.py", code)
    assert _ssrf_findings(out)


def test_urllib_urlopen_keyword_url_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def fetch():\n"
        "    return urllib.request.urlopen(url=request.args['url'])\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_keyword.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["metadata"]["untrusted_source"] == "request data `request.args`"


def test_rebound_request_constructor_keeps_tainted_body_visible(tmp_path):
    code = (
        "import urllib.request\n"
        "from urllib.request import Request as R\n"
        "from flask import request\n"
        "def R(url, data=None):\n"
        "    return urllib.request.Request(data)\n"
        "def fetch():\n"
        "    return urllib.request.urlopen(R('https://api.example.com/', data=request.args['url']))\n"
    )
    out = _scan_one(tmp_path, "ssrf_rebound_constructor.py", code)
    assert _ssrf_findings(out)


def test_rebound_imported_urlopen_is_not_an_http_sink(tmp_path):
    code = (
        "from urllib.request import urlopen as open_url\n"
        "from flask import request\n"
        "def open_url(url):\n"
        "    return url\n"
        "def read():\n"
        "    return open_url(request.args['url'])\n"
    )
    out = _scan_one(tmp_path, "ssrf_rebound_urlopen.py", code)
    assert _ssrf_findings(out) == []


def test_global_urllib_rebinding_does_not_hide_request_source(tmp_path):
    code = (
        "import urllib.request\n"
        "import requests\n"
        "from types import SimpleNamespace\n"
        "from flask import request as inbound\n"
        "def change():\n"
        "    global urllib\n"
        "    urllib = SimpleNamespace(request=inbound)\n"
        "change()\n"
        "def fetch():\n"
        "    return requests.get(f\"https://{urllib.request.args['url']}\")\n"
    )
    out = _scan_one(tmp_path, "ssrf_global_urllib_rebind.py", code)
    assert _ssrf_findings(out)


def test_route_to_urllib_request_helper_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "def post_json(base_url, path):\n"
        "    outbound = urllib.request.Request(base_url + path)\n"
        "    return urllib.request.urlopen(outbound)\n"
        "@app.get('/proxy')\n"
        "def proxy(target):\n"
        "    return post_json(target, '/v1')\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_helper_route.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["symbol"] == "post_json"
    assert finding["metadata"]["untrusted_source"].startswith("route parameter `target`")


def test_literal_caller_to_urllib_request_helper_is_not_ssrf(tmp_path):
    code = (
        "import urllib.request\n"
        "def post_json(base_url, path):\n"
        "    outbound = urllib.request.Request(base_url + path)\n"
        "    return urllib.request.urlopen(outbound)\n"
        "def job():\n"
        "    return post_json('https://api.example.com/', '/v1')\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_helper_literal.py", code)
    assert _ssrf_findings(out) == []


def test_dynamic_caller_to_generic_urllib_helper_still_flags(tmp_path):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "def post_json(base_url, path):\n"
        "    outbound = urllib.request.Request(base_url + request.args['path'])\n"
        "    return urllib.request.urlopen(outbound)\n"
        "def job():\n"
        "    return post_json('https://api.example.com/', '/v1')\n"
        "@app.get('/items')\n"
        "def items(target):\n"
        "    return globals()['post_json'](target, '/v1')\n"
    )
    out = _scan_one(tmp_path, "ssrf_urllib_helper_dynamic.py", code)
    finding = _ssrf_findings(out)[0]
    assert finding["symbol"] == "post_json"
    assert finding["metadata"]["untrusted_source"] == "request data `request.args`"


def test_requests_constant_url_ok(tmp_path):
    code = (
        "import requests\n"
        "def f():\n"
        "    requests.get('https://example.com', timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_ok.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_requests_fixed_host_interpolated_path_ok(tmp_path):
    code = (
        "import requests\n"
        "def f(user_id):\n"
        "    requests.get(f'https://api.example.com/users/{user_id}', timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_fixed_host.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_requests_uppercase_fstring_base_variable_flags(tmp_path):
    code = (
        "import requests\n"
        "@app.get('/x')\n"
        "def f(BASE_URL):\n"
        "    requests.get(f'{BASE_URL}/health', timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_uppercase_base.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_fixed_host_urljoin_path_ok(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "def f(user_id):\n"
        "    url = urljoin('https://cdn.example.com/', f'avatars/{user_id}.png')\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_fixed_host.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_requests_urljoin_direct_tainted_filename_can_override_host(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "@app.get('/x')\n"
        "def f(user_id):\n"
        "    return requests.get(urljoin('https://cdn.example.com/', f'{user_id}.png'), timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_direct_filename.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_urljoin_bare_tainted_target_flags(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "@app.get('/x')\n"
        "def f(path):\n"
        "    url = urljoin('https://cdn.example.com/', path)\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_bare_target.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_urljoin_slash_prefixed_tainted_target_flags(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "@app.get('/x')\n"
        "def f(path):\n"
        "    url = urljoin('https://cdn.example.com/', '/' + path)\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_slash_target.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_urljoin_scheme_prefixed_tainted_target_flags(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "@app.get('/x')\n"
        "def f(path):\n"
        "    url = urljoin('https://cdn.example.com/', 'https:' + path)\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_scheme_target.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_urljoin_partial_scheme_tainted_target_flags(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "@app.get('/x')\n"
        "def f(path):\n"
        "    url = urljoin('https://cdn.example.com/', 'http' + path)\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_partial_scheme_target.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_urljoin_absolute_tainted_target_flags(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
        "@app.get('/x')\n"
        "def f(host):\n"
        "    url = urljoin('https://cdn.example.com/', 'https://' + host)\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_host_override.py", code)
    assert "SKY-D216" in _rule_ids(out)


# --- 3.8b: SSRF requires an untrusted source and a host the literal does not pin


def test_flask_request_arg_url_flags(tmp_path):
    code = (
        "import requests\n"
        "from flask import request\n"
        "@bp.route('/link_preview')\n"
        "def link_preview():\n"
        "    url = request.args.get('url', '')\n"
        "    resp = requests.get(url)\n"
        "    return resp.text\n"
    )
    finding = _ssrf_findings(_scan_one(tmp_path, "ssrf_flask.py", code))[0]
    assert "request" in finding["metadata"]["untrusted_source"]


def test_mcp_tool_argument_url_flags(tmp_path):
    code = (
        "import requests\n"
        "@mcp.tool()\n"
        "def import_asset(zip_file_url: str):\n"
        "    if not zip_file_url.startswith(('http://', 'https://')):\n"
        "        raise ValueError('bad scheme')\n"
        "    return requests.get(zip_file_url, timeout=30)\n"
    )
    out = _scan_one(tmp_path, "ssrf_mcp_tool.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_helper_parameter_without_untrusted_source_ok(tmp_path):
    # Operator/caller configuration; the call site decides whether it is SSRF.
    code = (
        "import httpx\n"
        "async def post_reward(event_url: str, reward: float) -> None:\n"
        "    async with httpx.AsyncClient(timeout=10.0) as client:\n"
        "        await client.post(event_url, json={'value': reward})\n"
    )
    out = _scan_one(tmp_path, "ssrf_helper.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_constant_host_format_query_ok(tmp_path):
    code = (
        "import requests\n"
        "@bp.route('/translate')\n"
        "def translate(text, source_language, dest_language):\n"
        "    session = requests.Session()\n"
        "    r = session.post(\n"
        "        'https://api.cognitive.microsofttranslator.com'\n"
        "        '/translate?api-version=3.0&from={}&to={}'.format(\n"
        "            source_language, dest_language), json=[{'Text': text}])\n"
        "    return r.json()\n"
    )
    out = _scan_one(tmp_path, "ssrf_const_format.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_constant_host_through_local_variable_ok(tmp_path):
    code = (
        "import requests\n"
        "from flask import request\n"
        "@bp.route('/u')\n"
        "def user():\n"
        "    url = 'https://api.example.com/users/%s' % request.args['id']\n"
        "    return requests.get(url, timeout=3).text\n"
    )
    out = _scan_one(tmp_path, "ssrf_const_var.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_test_client_call_in_test_ok(tmp_path):
    code = (
        "from fastapi.testclient import TestClient\n"
        "def test_read_items(client: TestClient, db) -> None:\n"
        "    item = create_random_item(db)\n"
        "    response = client.get(f'{settings.API_V1_STR}/items/{item.id}')\n"
        "    assert response.status_code == 200\n"
    )
    out = _scan_one(tmp_path, "test_items.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_environment_configured_url_ok(tmp_path):
    code = (
        "import os, requests\n"
        "def ping():\n"
        "    base = os.environ.get('SERVICE_URL')\n"
        "    return requests.get(f'{base}/health', timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_env.py", code)
    assert "SKY-D216" not in _rule_ids(out)


def test_cli_configured_url_through_helper_is_not_ssrf(tmp_path):
    code = (
        "import argparse, urllib.request\n"
        "def post_json(base_url):\n"
        "    request = urllib.request.Request(base_url + '/ingest')\n"
        "    return urllib.request.urlopen(request, timeout=3)\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    parser.add_argument('--backend')\n"
        "    args = parser.parse_args()\n"
        "    return post_json(args.backend)\n"
    )
    out = _scan_one(tmp_path, "ssrf_cli_backend.py", code)
    assert _ssrf_findings(out) == []


def test_direct_argv_url_is_operator_input(tmp_path):
    code = (
        "import sys, requests\n"
        "def main():\n"
        "    return requests.get(f'{sys.argv[1]}', timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_direct_argv.py", code)
    assert _ssrf_findings(out) == []


def test_request_parser_arguments_are_not_cli_configuration(tmp_path):
    code = (
        "import requests\n"
        "from flask_restful import reqparse\n"
        "@app.get('/proxy')\n"
        "def proxy():\n"
        "    parser = reqparse.RequestParser()\n"
        "    parser.add_argument('url')\n"
        "    args = parser.parse_args()\n"
        "    return requests.get(args['url'], timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_request_parser.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [8]


def test_request_source_after_four_operator_sources_still_flags(tmp_path):
    code = (
        "import argparse, os, requests, sys\n"
        "@app.get('/proxy')\n"
        "def proxy(host):\n"
        "    a = os.getenv('A')\n"
        "    b = os.environ['B']\n"
        "    c = sys.argv[1]\n"
        "    parser = argparse.ArgumentParser()\n"
        "    d = parser.parse_args().url\n"
        "    return requests.get(f'{a}{b}{c}{d}{host}', timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_many_sources.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [9]


def test_dispatch_source_survives_unrelated_cli_call(tmp_path):
    code = (
        "import argparse, requests\n"
        "def fetch(url):\n"
        "    return requests.get(url, timeout=3)\n"
        "def other(url):\n"
        "    return url\n"
        "handlers = {'fetch': fetch, 'other': other}\n"
        "def dispatch(command):\n"
        "    return handlers[command['name']](command['url'])\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    parser.add_argument('--url')\n"
        "    args = parser.parse_args()\n"
        "    return fetch(args.url)\n"
    )
    out = _scan_one(tmp_path, "ssrf_dispatch_and_cli.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [3]


def test_route_param_controls_host_flags(tmp_path):
    code = (
        "import requests\n"
        "@app.get('/status')\n"
        "def status(host: str):\n"
        "    return requests.get(f'https://{host}/status', timeout=3).text\n"
    )
    out = _scan_one(tmp_path, "ssrf_route_host.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_command_dispatch_table_argument_url_flags(tmp_path):
    # agent-pr-bench real-15: an MCP add-on dispatches socket commands through
    # a handler table; the URL argument comes from the client.
    code = (
        "import requests\n"
        "class Server:\n"
        "    def execute(self, command):\n"
        "        handlers = {\n"
        "            'get_scene': self.get_scene,\n"
        "            'import_asset': self.import_asset,\n"
        "        }\n"
        "        return handlers[command['type']](**command['params'])\n"
        "    def get_scene(self):\n"
        "        return {}\n"
        "    def import_asset(self, *args, **kwargs):\n"
        "        return self.import_asset_impl(*args, **kwargs)\n"
        "    def import_asset_impl(self, name, zip_file_url):\n"
        "        return requests.get(zip_file_url, stream=True)\n"
    )
    out = _scan_one(tmp_path, "ssrf_dispatch.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [14]


def test_mock_patch_decorator_is_not_a_route(tmp_path):
    # mozilla/pontoon: a ``@patch`` test parameter was labelled a PATCH route
    # parameter, so every Django test-client call became CRITICAL SSRF.
    code = (
        "from unittest.mock import patch\n"
        "from unittest import mock\n"
        "@patch('app.views.render')\n"
        "def test_locale_view(render_mock, locale, client):\n"
        "    client.get(f'/{locale.code}/')\n"
        "@mock.patch('app.views.render')\n"
        "def test_team_view(render_mock, team, admin_client):\n"
        "    admin_client.get(f'/{team.slug}/')\n"
    )
    out = _scan_one(tmp_path, "test_views.py", code)
    assert _ssrf_findings(out) == []


def test_patch_route_decorator_still_flags(tmp_path):
    code = (
        "import requests\n"
        "from litestar import patch\n"
        "@patch('/proxy')\n"
        "def proxy(url: str):\n"
        "    return requests.get(url)\n"
        "@router.patch('/fetch')\n"
        "def fetch(url: str):\n"
        "    return requests.get(url)\n"
    )
    out = _scan_one(tmp_path, "routes.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [5, 8]


def test_unbound_patch_decorator_still_counts_as_route(tmp_path):
    code = (
        "import requests\n"
        "@patch('/proxy')\n"
        "def proxy(url):\n"
        "    return requests.get(url)\n"
    )
    out = _scan_one(tmp_path, "routes.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_in_process_test_clients_are_not_ssrf(tmp_path):
    code = (
        "from django.test import Client, RequestFactory, TestCase\n"
        "from rest_framework.test import APIClient, APITestCase\n"
        "from fastapi.testclient import TestClient\n"
        "def test_django_client():\n"
        "    client = Client()\n"
        "    client.get(input())\n"
        "def test_api_client():\n"
        "    api_client = APIClient()\n"
        "    api_client.post(input(), {})\n"
        "def test_request_factory():\n"
        "    request_factory = RequestFactory()\n"
        "    request_factory.get(input())\n"
        "def test_fastapi(app):\n"
        "    with TestClient(app) as client:\n"
        "        client.get(input())\n"
        "def test_flask(app):\n"
        "    app.test_client().get(input())\n"
        "def test_pytest_django_fixture(client, admin_client):\n"
        "    client.get(input())\n"
        "    admin_client.get(input())\n"
        "class ViewTests(TestCase):\n"
        "    def test_view(self):\n"
        "        self.client.get(input())\n"
        "class ApiTests(APITestCase):\n"
        "    def test_api(self):\n"
        "        self.client.get(input())\n"
        "class SetUpTests(APITestCase):\n"
        "    def setUp(self):\n"
        "        self.http_client = APIClient()\n"
        "    def test_api(self):\n"
        "        self.http_client.get(input())\n"
    )
    out = _scan_one(tmp_path, "test_clients.py", code)
    assert _ssrf_findings(out) == []


def test_real_http_clients_named_like_test_clients_still_flag(tmp_path):
    code = (
        "import httpx, requests\n"
        "from django.test import Client, TestCase\n"
        "def test_session():\n"
        "    client = requests.Session()\n"
        "    client.get(input())\n"
        "def test_rebound_client():\n"
        "    client = Client()\n"
        "    client = httpx.Client()\n"
        "    client.get(input())\n"
        "def fetch(client):\n"
        "    client.get(input())\n"
        "class Api:\n"
        "    def __init__(self):\n"
        "        self.client = httpx.Client()\n"
        "    def run(self):\n"
        "        self.client.get(input())\n"
        "class Swapped(TestCase):\n"
        "    client_class = httpx.Client\n"
        "    def test_x(self):\n"
        "        self.client.get(input())\n"
        "class Assigned(TestCase):\n"
        "    def setUp(self):\n"
        "        self.client = requests.Session()\n"
        "    def test_x(self):\n"
        "        self.client.get(input())\n"
        "class Plain:\n"
        "    def test_x(self):\n"
        "        self.client.get(input())\n"
    )
    out = _scan_one(tmp_path, "test_real_clients.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [5, 9, 11, 16, 20, 25, 28]


_CONFIGURED_BASE = (
    "import os\n"
    "import requests\n"
    "from urllib.parse import urlencode\n"
    "from app.settings import SITE_URL\n"
    "API_BASE = os.environ['API_BASE']\n"
)


def test_module_setting_host_and_helper_built_url_are_not_ssrf(tmp_path):
    # mozilla/pontoon search/views.py: the URL comes from a helper that returns
    # f"{SITE_URL}/api/...?{urlencode(...)}"; request data only fills the query.
    code = _CONFIGURED_BASE + (
        "def create_api_url(search, page=None):\n"
        '    return f\'{SITE_URL}/api/v2/search/?{urlencode({"q": search, "p": page})}\'\n'
        "def search_results(request):\n"
        "    search = request.GET.get('search')\n"
        "    if request.GET.get('page'):\n"
        "        api_url = create_api_url(search, page=1)\n"
        "        requests.get(api_url)\n"
        "    else:\n"
        "        api_url = create_api_url(search)\n"
        "        requests.get(api_url)\n"
        "def user(request):\n"
        "    return requests.get(f\"{API_BASE}/users/{request.GET['id']}\")\n"
        "def concat(request):\n"
        "    return requests.get(API_BASE + '/users/' + request.GET['id'])\n"
    )
    out = _scan_one(tmp_path, "views.py", code)
    assert _ssrf_findings(out) == []


def test_request_controlled_base_or_host_still_flags(tmp_path):
    code = _CONFIGURED_BASE + (
        "def base_from_request(request):\n"
        "    base = request.GET['base']\n"
        "    return requests.get(f'{base}/health')\n"
        "def no_path_delimiter(request):\n"
        "    return requests.get(f\"{SITE_URL}{request.GET['p']}\")\n"
        "def make_url(request, raw):\n"
        "    if request.GET.get('fixed'):\n"
        "        return f'{SITE_URL}/a'\n"
        "    return raw\n"
        "def mixed_helper(request):\n"
        "    return requests.get(make_url(request, request.GET['u']))\n"
        "def mixed_branches(request):\n"
        "    if request.GET.get('a'):\n"
        "        url = f'{SITE_URL}/a'\n"
        "    else:\n"
        "        url = request.GET['u']\n"
        "    return requests.get(url)\n"
        "@app.get('/proxy')\n"
        "def proxy(url, fixed):\n"
        "    if fixed:\n"
        "        url = f'{SITE_URL}/a'\n"
        "    return requests.get(url)\n"
    )
    out = _scan_one(tmp_path, "views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [8, 10, 16, 22, 27]


def test_setting_rebound_through_global_still_flags(tmp_path):
    code = _CONFIGURED_BASE + (
        "def configure(request):\n"
        "    global SITE_URL\n"
        "    SITE_URL = request.GET['u']\n"
        "def fetch(request):\n"
        "    return requests.get(f\"{SITE_URL}/x/{request.GET['q']}\")\n"
    )
    out = _scan_one(tmp_path, "views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [10]


def test_client_parameter_outside_test_code_or_on_a_route_still_flags(tmp_path):
    # A FastAPI route named test_* gets ``client`` from dependency injection.
    code = (
        "import httpx\n"
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "def get_http_client():\n"
        "    return httpx.AsyncClient()\n"
        "@router.post('/integrations/webhook/test')\n"
        "async def test_webhook(url: str, client: httpx.AsyncClient = Depends(get_http_client)):\n"
        "    return await client.post(url, json={'ping': True})\n"
        "def test_helper(client):\n"
        "    return client.get(input())\n"
    )
    out = _scan_one(tmp_path, "integrations.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [8, 10]

    # Named test_* but no test framework: app code, so line 10 still flags.
    app_named_like_test = _scan_one(tmp_path, "test_integrations.py", code)
    assert [f["line"] for f in _ssrf_findings(app_named_like_test)] == [8, 10]

    route_in_test_module = _scan_one(
        tmp_path, "test_integrations.py", "import pytest\n" + code
    )
    assert [f["line"] for f in _ssrf_findings(route_in_test_module)] == [9]


def test_computed_module_value_is_not_a_configured_host(tmp_path):
    code = (
        "import requests\n"
        "REMOTE = requests.get('https://config.example.com').json()['base']\n"
        "def fetch(request):\n"
        "    return requests.get(f\"{REMOTE}/x/{request.GET['q']}\")\n"
    )
    out = _scan_one(tmp_path, "views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [4]


def test_quote_with_custom_safe_characters_is_not_a_url_sanitizer(tmp_path):
    code = (
        "import requests\n"
        "import urllib.parse\n"
        "from urllib.parse import quote\n"
        "from flask import request\n"
        "@app.route('/fetch')\n"
        "def fetch():\n"
        "    target = request.args['url']\n"
        "    requests.get(quote(target, safe=':/?&='))\n"
        "    requests.get(urllib.parse.quote(target, ':/'))\n"
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == [8, 9]


def _sink_lines(code):
    return [n for n, line in enumerate(code.splitlines(), 1) if line.endswith("# sink")]


_FLASK_APP = (
    "import functools, os, sys\n"
    "import requests\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
)
_FIXED_HELPER = _FLASK_APP + (
    "API = 'https://api.example.com'\ndef build(path):\n    return f'{API}/{path}'\n"
)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            "def fetch(build, path):\n"
            "    return requests.get(build(path))  # sink\n"
            "@app.route('/f')\n"
            "def f():\n"
            "    return fetch(lambda p: request.args['base'] + p, '/x')\n",
            id="parameter",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    build = lambda p: request.args['base'] + p\n"
            "    return requests.get(build('/x'))  # sink\n",
            id="local-lambda",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    for build in handlers:\n"
            "        requests.get(build(request.args['p']))  # sink\n",
            id="for-target",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    with ctx() as build:\n"
            "        return requests.get(build(request.args['p']))  # sink\n",
            id="with-as",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception as build:\n"
            "        return requests.get(build(request.args['p']))  # sink\n",
            id="except-as",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    from other import make as build\n"
            "    return requests.get(build(request.args['p']))  # sink\n",
            id="local-import",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    def build(p):\n"
            "        return request.args['base'] + p\n"
            "    return requests.get(build(request.args['p']))  # sink\n",
            id="nested-def",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    build = make(request.args['base'])\n"
            "    def inner():\n"
            "        return requests.get(build(request.args['p']))  # sink\n"
            "    return inner()\n",
            id="enclosing-function",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    if (build := make(request.args['base'])):\n"
            "        return requests.get(build(request.args['p']))  # sink\n",
            id="walrus",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    return [requests.get(build(request.args['p'])) for build in hs]  # sink\n",
            id="comprehension-target",
        ),
        pytest.param(
            "@app.route('/f')\n"
            "def f():\n"
            "    go = lambda build: requests.get(build(request.args['p']))  # sink\n"
            "    return go(make(request.args['b']))\n",
            id="lambda-parameter",
        ),
        pytest.param(
            "@app.route('/cfg')\n"
            "def cfg():\n"
            "    globals()['build'] = make(request.args['base'])\n"
            "@app.route('/f')\n"
            "def f():\n"
            "    return requests.get(build(request.args['p']))  # sink\n",
            id="globals-write",
        ),
    ],
)
def test_shadowed_fixed_host_helper_still_flags(tmp_path, body):
    code = _FIXED_HELPER + body
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_decorated_helper_does_not_prove_a_fixed_host(tmp_path):
    code = _FIXED_HELPER.replace("def build", "@wrap\ndef build") + (
        "@app.route('/f')\n"
        "def f():\n"
        "    return requests.get(build(request.args['p']))  # sink\n"
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


@pytest.mark.parametrize(
    "setting, url",
    [
        pytest.param(
            "'https:'",
            "f\"{BASE}//{request.args['host']}/api\"",
            id="scheme-then-double-slash",
        ),
        pytest.param(
            "'https:'",
            "BASE + '//' + request.args['host']",
            id="scheme-concat-double-slash",
        ),
        pytest.param(
            "'https:'", "f\"{BASE}/{request.args['host']}\"", id="scheme-then-slash"
        ),
        pytest.param(
            "'https://'", "f\"{BASE}/{request.args['host']}\"", id="empty-host"
        ),
        pytest.param("''", "f\"{BASE}/{request.args['host']}\"", id="empty-string"),
        pytest.param(
            "'https://api.example.com@'",
            "f\"{BASE}/{request.args['host']}\"",
            id="userinfo-only",
        ),
        pytest.param(
            "'https://api.example.com'",
            "f\"{BASE}//{request.args['p']}\"",
            id="host-then-double-slash",
        ),
        pytest.param(
            "os.getenv('SCHEME', 'https:')",
            "f\"{BASE}/{request.args['host']}\"",
            id="env-default-without-host",
        ),
        pytest.param(
            "os.getenv('UPSTREAM', '')",
            "f\"{BASE}/{request.args['host']}\"",
            id="env-default-empty",
        ),
        pytest.param(
            "'https://' + os.environ['HOST']",
            "f\"{BASE}/{request.args['host']}\"",
            id="concat-starts-without-host",
        ),
        pytest.param(
            "SCHEME",
            "f\"{BASE}/{request.args['host']}\"",
            id="alias-of-hostless-setting",
        ),
        pytest.param(
            "getenv('https://api.example.com')",
            "f\"{BASE}/{request.args['host']}\"",
            id="local-getenv",
        ),
        pytest.param(
            "environ.get('API_BASE')",
            "f\"{BASE}/{request.args['host']}\"",
            id="local-environ",
        ),
        pytest.param(
            "os.getenv(input())",
            "f\"{BASE}/{request.args['host']}\"",
            id="env-name-from-input",
        ),
    ],
)
def test_module_setting_without_a_host_still_flags(tmp_path, setting, url):
    code = _FLASK_APP + (
        "SCHEME = 'https:'\n"
        "def getenv(key):\n"
        "    return request.args['h']\n"
        "class environ:\n"
        "    get = staticmethod(getenv)\n"
        f"BASE = {setting}\n"
        "@app.route('/f')\n"
        "def f():\n"
        f"    return requests.get({url})  # sink\n"
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_helper_returning_hostless_setting_still_flags(tmp_path):
    code = _FLASK_APP + (
        "SCHEME = 'https:'\n"
        "def build(host):\n"
        "    return f'{SCHEME}//{host}/api'\n"
        "@app.route('/f')\n"
        "def f():\n"
        "    return requests.get(build(request.args['h']))  # sink\n"
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


_BASE_SINK = (
    "@app.route('/f')\n"
    "def f():\n"
    "    return requests.get(f\"{BASE}/{request.args['p']}\")  # sink\n"
)


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param(
            "    globals()['BASE'] = request.args['b']\n", id="globals-subscript"
        ),
        pytest.param("    globals().update(request.get_json())\n", id="globals-update"),
        pytest.param(
            "    g = globals()\n    g[request.args['k']] = request.args['v']\n",
            id="globals-alias",
        ),
        pytest.param(
            "    setattr(sys.modules[__name__], 'BASE', request.args['b'])\n",
            id="setattr-sys-modules",
        ),
        pytest.param(
            "    this = sys.modules[__name__]\n"
            "    setattr(this, request.args['k'], request.args['v'])\n",
            id="setattr-module-alias",
        ),
        pytest.param(
            "    sys.modules[__name__].BASE = request.args['b']\n",
            id="module-attribute",
        ),
        pytest.param(
            "    import app as me\n    me.BASE = request.args['b']\n",
            id="self-import-attribute",
        ),
        pytest.param(
            "    sys.modules[__name__].__dict__['BASE'] = request.args['b']\n",
            id="module-dict",
        ),
        pytest.param(
            "    vars(sys.modules[__name__])['BASE'] = request.args['b']\n",
            id="vars-module",
        ),
        pytest.param(
            "    exec('global BASE; BASE = ' + repr(request.args['b']))\n",
            id="exec",
        ),
        pytest.param(
            "    global BASE\n    BASE = request.args['b']\n",
            id="global-statement",
        ),
        pytest.param(
            "    import builtins\n    builtins.globals()['BASE'] = request.args['b']\n",
            id="builtins-globals",
        ),
        pytest.param(
            "    sys._getframe().f_globals['BASE'] = request.args['b']\n",
            id="frame-globals",
        ),
        pytest.param(
            "    cfg.__globals__['BASE'] = request.args['b']\n",
            id="function-globals",
        ),
        pytest.param(
            "    g = globals\n    g()['BASE'] = request.args['b']\n",
            id="globals-function-alias",
        ),
        pytest.param(
            "    def configure(mod, value):\n"
            "        mod.BASE = value\n"
            "    configure(sys.modules[__name__], request.args['b'])\n",
            id="module-passed-to-helper",
        ),
        pytest.param(
            "    import importlib\n"
            "    os.environ['BASE'] = request.args['b']\n"
            "    importlib.reload(sys.modules[__name__])\n",
            id="reload",
        ),
        pytest.param(
            "    sys.modules[__name__].__setattr__('BASE', request.args['b'])\n",
            id="module-dunder-setattr",
        ),
        pytest.param(
            "    sys.modules.__getitem__(__name__).BASE = request.args['b']\n",
            id="modules-dunder-getitem",
        ),
        pytest.param(
            "    setter = sys.modules[__name__].__setattr__\n"
            "    setter('BASE', request.args['b'])\n",
            id="bound-dunder-alias",
        ),
        pytest.param(
            "    getattr(sys.modules[__name__], '__dict__')['BASE'] = request.args['b']\n",
            id="getattr-dict",
        ),
        pytest.param(
            "    getattr(cfg, '__globals__')['BASE'] = request.args['b']\n",
            id="getattr-function-globals",
        ),
        pytest.param(
            "    import builtins\n"
            "    getattr(builtins, 'globals')()['BASE'] = request.args['b']\n",
            id="getattr-builtins-globals",
        ),
        pytest.param(
            "    from importlib import import_module as im\n"
            "    im(__name__).BASE = request.args['b']\n",
            id="import-module-alias",
        ),
        pytest.param(
            "    import inspect\n    inspect.getmodule(cfg).BASE = request.args['b']\n",
            id="inspect-getmodule",
        ),
        pytest.param(
            "    import __main__\n    __main__.BASE = request.args['b']\n",
            id="main-module",
        ),
    ],
)
def test_dynamically_rebound_module_setting_still_flags(tmp_path, rebind):
    code = (
        _FLASK_APP
        + "BASE = 'https://api.example.com'\n"
        + "@app.route('/cfg')\n"
        + "def cfg():\n"
        + rebind
        + _BASE_SINK
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


@pytest.mark.parametrize(
    "module_code",
    [
        pytest.param("vars()['BASE'] = input()\n", id="module-vars"),
        pytest.param("from settings import *\n", id="star-import"),
        pytest.param("BASE = input()\n", id="second-assignment"),
    ],
)
def test_module_level_rebinding_of_setting_still_flags(tmp_path, module_code):
    code = _FLASK_APP + "BASE = 'https://api.example.com'\n" + module_code + _BASE_SINK
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


@pytest.mark.parametrize(
    "binding",
    [
        pytest.param("from flask import session as BASE\n", id="flask-session"),
        pytest.param("from flask import request as BASE\n", id="flask-request"),
        pytest.param("from flask import g as BASE\n", id="flask-g"),
        pytest.param("from flask import session\nBASE = session\n", id="alias"),
        pytest.param(
            "from werkzeug.local import LocalProxy\n"
            "BASE = LocalProxy(lambda: request.headers['X-Upstream'])\n",
            id="local-proxy",
        ),
        pytest.param("from aiohttp import web as BASE\n", id="aiohttp-web"),
        pytest.param(
            "from contextvars import copy_context as BASE\n", id="contextvars"
        ),
    ],
)
def test_request_scoped_import_is_not_a_setting(tmp_path, binding):
    code = _FLASK_APP + binding + _BASE_SINK
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_setting_shadowed_in_enclosing_function_still_flags(tmp_path):
    code = _FLASK_APP + (
        "BASE = 'https://api.example.com'\n"
        "@app.route('/f')\n"
        "def f():\n"
        "    BASE = request.args['b']\n"
        "    def inner():\n"
        "        return requests.get(f\"{BASE}/{request.args['p']}\")  # sink\n"
        "    return inner()\n"
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_fixed_host_settings_and_helpers_stay_quiet(tmp_path):
    code = _FIXED_HELPER + (
        "BASE = 'https://api.example.com'\n"
        "V1 = 'https://api.example.com/v1'\n"
        "ENV_BASE = os.environ['API_BASE']\n"
        "ENV_DEFAULT = os.getenv('API_BASE', 'https://api.example.com')\n"
        "ENV_NONE = os.environ.get('API_BASE', None)\n"
        "from os import getenv as env_get, environ as env_map\n"
        "IMPORTED_GETENV = env_get('API_BASE')\n"
        "IMPORTED_ENVIRON = env_map['API_BASE']\n"
        "ALIAS = BASE\n"
        "from flaskapp.settings import SITE\n"
        "SEEN = 'DEBUG' in globals() and globals().get('DEBUG')\n"
        "HAS = hasattr(sys.modules[__name__], 'X') and 'json' in sys.modules\n"
        "@functools.lru_cache(maxsize=None)\n"
        "def cached(path):\n"
        "    return f'{BASE}/{path}'\n"
        "@app.route('/f')\n"
        "def f():\n"
        "    p = request.args['p']\n"
        "    requests.get(f'{BASE}/{p}')\n"
        "    requests.get(V1 + '?q=' + p)\n"
        "    requests.get(f'{ENV_BASE}/{p}')\n"
        "    requests.get(f'{ENV_DEFAULT}#{p}')\n"
        "    requests.get(f'{ENV_NONE}/{p}')\n"
        "    requests.get(f'{IMPORTED_GETENV}/{p}')\n"
        "    requests.get(f'{IMPORTED_ENVIRON}/{p}')\n"
        "    requests.get(f'{ALIAS}/{p}')\n"
        "    requests.get(f'{SITE}/{p}')\n"
        "    requests.get(build(p))\n"
        "    requests.get(cached(p))\n"
        "    url = build(p)\n"
        "    requests.get(url)\n"
        "    requests.get('https://api.example.com/' + p)\n"
        "    requests.get('https://api.example.com' + p)  # sink\n"
    )
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


_CLIENT_APP = (
    "import httpx\n"
    "from django.test import Client\n"
    "from rest_framework.test import APIClient\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "client = httpx.Client()\n"
)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            "@app.route('/proxy')\n"
            "def proxy():\n"
            "    def _helper():\n"
            "        client = Client()\n"
            "        return client\n"
            "    return client.get(request.args['url']).text  # sink\n",
            id="nested-function",
        ),
        pytest.param(
            "@app.route('/proxy')\n"
            "def proxy():\n"
            "    make = lambda: [client for client in [Client()]]\n"
            "    return client.get(request.args['url']).text  # sink\n",
            id="comprehension-in-lambda",
        ),
        pytest.param(
            "@app.route('/proxy')\n"
            "def proxy():\n"
            "    class _Case:\n"
            "        client = Client()\n"
            "    return client.get(request.args['url']).text  # sink\n",
            id="nested-class",
        ),
        pytest.param(
            "def setup():\n"
            "    global client\n"
            "    client = Client()\n"
            "@app.route('/proxy')\n"
            "def proxy():\n"
            "    return client.get(request.args['url']).text  # sink\n",
            id="global-in-other-function",
        ),
        pytest.param(
            "@app.route('/proxy')\n"
            "def proxy():\n"
            "    client = httpx.Client()\n"
            "    def inner():\n"
            "        def deeper():\n"
            "            client = Client()\n"
            "        return client.get(request.args['url']).text  # sink\n"
            "    return inner()\n",
            id="enclosing-function-binding",
        ),
        pytest.param(
            "class Proxy:\n"
            "    class Fixture:\n"
            "        def setUp(self):\n"
            "            self.client = APIClient()\n"
            "    @app.route('/proxy')\n"
            "    def get(self):\n"
            "        return self.client.get(request.args['url']).text  # sink\n",
            id="self-attribute-of-nested-class",
        ),
    ],
)
def test_client_bound_in_another_scope_is_not_a_test_client(tmp_path, body):
    code = _CLIENT_APP + body
    out = _scan_one(tmp_path, "app.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_test_client_resolved_through_enclosing_scopes_stays_quiet(tmp_path):
    code = (
        "from django.test import Client\n"
        "client = Client()\n"
        "def test_module_client():\n"
        "    client.get(input())\n"
        "def test_enclosing_client():\n"
        "    local = Client()\n"
        "    def check():\n"
        "        local.get(input())\n"
        "    check()\n"
    )
    out = _scan_one(tmp_path, "test_views.py", code)
    assert _ssrf_findings(out) == []


def _ssrf_scan_seconds(code):
    import ast
    import time

    from skylos.rules.danger.danger_net import ssrf_flow

    tree = ast.parse(code)
    best = float("inf")
    for _ in range(3):
        findings = []
        start = time.perf_counter()
        ssrf_flow.scan(tree, "test_items.py", findings)
        best = min(best, time.perf_counter() - start)
    return best


def _django_test_case(n):
    return "from django.test import TestCase\nclass ItemTests(TestCase):\n" + "".join(
        f"    def test_item_{i}(self):\n"
        f"        self.client.get(f'/items/{i}/')\n"
        f"        self.client.post('/items/', {{'n': {i}}})\n"
        for i in range(n)
    )


def _module_functions(n):
    return "import requests\n" + "".join(
        f"def f{i}(url):\n    return requests.get(url + '/a').text\n" for i in range(n)
    )


def _many_sinks_in_one_function(n):
    return (
        "import requests\nBASE = 'https://api.example.com'\ndef f(x):\n"
        "    url = f'{BASE}/{x}'\n" + "    requests.get(url)\n" * n
    )


@pytest.mark.parametrize(
    "make", [_django_test_case, _module_functions, _many_sinks_in_one_function]
)
def test_ssrf_scan_time_grows_linearly(make):
    # Per-call re-walks of the module or class made a 300-test Django
    # TestCase take ~56s; a linear scan takes well under a second.
    small = _ssrf_scan_seconds(make(100))
    large = _ssrf_scan_seconds(make(300))
    assert large < 3.0
    assert large / max(small, 0.05) < 6


_DJANGO_CASE = "import requests\nfrom django.test import Client, TestCase\n"


_PROBE = "    def test_x(self):\n        return self.client.get(input())  # sink\n"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            "class T(TestCase):\n"
            "    def setUp(self):\n"
            "        setattr(self, 'client', requests.Session())\n" + _PROBE,
            id="setattr-self",
        ),
        pytest.param(
            "class T(TestCase):\n"
            "    def setUp(self):\n"
            "        self.__dict__['client'] = requests.Session()\n" + _PROBE,
            id="instance-dict",
        ),
        pytest.param(
            "class T(TestCase):\n"
            "    def setUp(self):\n"
            "        vars(self).update(client=requests.Session())\n" + _PROBE,
            id="vars-self",
        ),
        pytest.param(
            "class T(TestCase):\n" + _PROBE + "T.client_class = requests.Session\n",
            id="client-class-outside",
        ),
        pytest.param(
            "class Real:\n"
            "    client_class = requests.Session\n"
            "class T(Real, TestCase):\n" + _PROBE,
            id="mixin-client-class",
        ),
        pytest.param(
            "from helpers import ApiMixin\nclass T(ApiMixin, TestCase):\n" + _PROBE,
            id="imported-mixin",
        ),
        pytest.param(
            "class T(TestCase):\n"
            "    client = requests.Session()\n"
            "    def _pre_setup(self):\n"
            "        pass\n" + _PROBE,
            id="pre-setup-override",
        ),
        pytest.param(
            "class T(TestCase):\n" + _PROBE + "T().client = requests.Session()\n",
            id="external-store",
        ),
        pytest.param(
            "class T(TestCase):\n"
            "    def setUp(self):\n"
            "        self.client = Client()\n"
            "        class Patch:\n"
            "            def apply(inner):\n"
            "                self.client = requests.Session()\n"
            "        Patch().apply()\n" + _PROBE,
            id="nested-closure-self",
        ),
        pytest.param(
            "class T(TestCase):\n" + _PROBE + "class T(TestCase):\n"
            "    def setUp(self):\n"
            "        self.client = requests.Session()\n",
            id="redefined-class",
        ),
    ],
)
def test_django_test_case_client_that_may_be_replaced_still_flags(tmp_path, body):
    code = _DJANGO_CASE + body
    out = _scan_one(tmp_path, "test_views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_django_test_case_client_replaced_by_subclass_still_flags(tmp_path):
    # ``Base.test_x`` also runs on ``Real`` instances, whose client is real.
    code = _DJANGO_CASE + (
        "class Base(TestCase):\n"
        "    def setUp(self):\n"
        "        self.client = Client()\n"
        "    def test_x(self):\n"
        "        return self.client.get(input())  # sink\n"
        "class Real(Base):\n"
        "    def setUp(self):\n"
        "        self.client = requests.Session()\n"
    )
    out = _scan_one(tmp_path, "test_views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_self_client_outside_django_test_cases_still_flags(tmp_path):
    code = (
        "from django.test import Client\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "class Svc:\n"
        "    def __init__(self):\n"
        "        self.client = Client()\n"
        "    def go(self):\n"
        "        return self.client.get(request.args['u']).text  # sink\n"
    )
    out = _scan_one(tmp_path, "views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param("from requests import *\n", id="star-import"),
        pytest.param(
            "sys.modules[__name__].Client = requests.Session\n", id="module-attr"
        ),
        pytest.param(
            "setattr(sys.modules[__name__], 'Client', requests.Session)\n",
            id="setattr-module",
        ),
        pytest.param("globals()['Client'] = requests.Session\n", id="globals-write"),
    ],
)
def test_rebound_test_client_class_still_flags(tmp_path, rebind):
    code = (
        "import sys, requests\n"
        "from django.test import Client\n"
        + rebind
        + "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/p')\n"
        "def p():\n"
        "    client = Client()\n"
        "    return client.get(request.args['u']).text  # sink\n"
    )
    out = _scan_one(tmp_path, "views.py", code)
    assert [f["line"] for f in _ssrf_findings(out)] == _sink_lines(code)


def test_django_test_case_subclass_and_local_mixin_stay_quiet(tmp_path):
    code = (
        "from django.test import TestCase\n"
        "class LoginMixin:\n"
        "    def login(self):\n"
        "        return None\n"
        "class Base(LoginMixin, TestCase):\n"
        "    pass\n"
        "class Probe(Base):\n"
        "    def test_x(self):\n"
        "        return self.client.get(input())\n"
    )
    out = _scan_one(tmp_path, "test_views.py", code)
    assert _ssrf_findings(out) == []
