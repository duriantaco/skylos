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
