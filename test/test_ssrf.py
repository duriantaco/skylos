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
