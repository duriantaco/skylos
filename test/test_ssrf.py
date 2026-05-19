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
    code = "import requests\ndef fetch_url(url):\n    return requests.get(url)\n"
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
    code = "import httpx\ndef f(url):\n    httpx.post('http://' + url)\n"
    out = _scan_one(tmp_path, "ssrf_httpx.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_requests_neutral_assignment_alias_flags(tmp_path):
    code = (
        "import requests\n"
        "api = requests\n"
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
    code = "import urllib.request as u\ndef f(x):\n    u.urlopen(f'http://{x}')\n"
    out = _scan_one(tmp_path, "ssrf_urlopen.py", code)
    assert "SKY-D216" in _rule_ids(out)


def test_urllib_urlopen_security_evidence_names_sink(tmp_path):
    code = "import urllib.request as u\ndef f(x):\n    u.urlopen(f'http://{x}')\n"
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


def test_requests_urljoin_bare_tainted_target_flags(tmp_path):
    code = (
        "from urllib.parse import urljoin\n"
        "import requests\n"
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
        "def f(host):\n"
        "    url = urljoin('https://cdn.example.com/', 'https://' + host)\n"
        "    requests.get(url, timeout=3)\n"
    )
    out = _scan_one(tmp_path, "ssrf_urljoin_host_override.py", code)
    assert "SKY-D216" in _rule_ids(out)
