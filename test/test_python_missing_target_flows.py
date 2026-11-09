import pytest

from skylos.rules.danger.danger import scan_ctx


def scan(tmp_path, source, rule):
    path = tmp_path / "app.py"
    path.write_text(source)
    return [row for row in scan_ctx(tmp_path, [path]) if row["rule_id"] == rule]


@pytest.mark.parametrize(
    "url",
    [
        "f'http://{host}?token={token}'",
        "'http://' + host + '/path'",
        "f'http://api.example.com/{path}'",
    ],
)
def test_explicit_http_scheme_with_dynamic_url(tmp_path, url):
    findings = scan(
        tmp_path,
        "import requests\ndef load(host,token,path):\n    url = "
        + url
        + "\n    return requests.get(url)\n",
        "SKY-D356",
    )
    assert [row["line"] for row in findings] == [4]


@pytest.mark.parametrize(
    "url",
    [
        "f'https://{host}/{path}'",
        "f'http://localhost/{path}'",
        "f'http://127.0.0.1/{path}'",
        "f'{scheme}://api.example.com/{path}'",
    ],
)
def test_dynamic_url_does_not_invent_http_or_remote_host(tmp_path, url):
    assert not scan(
        tmp_path,
        "import requests\ndef load(host,path,scheme):\n    return requests.get("
        + url
        + ")\n",
        "SKY-D356",
    )


def test_loop_public_bind_and_optional_auth_mapping(tmp_path):
    findings = scan(
        tmp_path,
        "import gradio as gr\nwith gr.Blocks() as demo:\n    pass\ndef launch(users):\n    auth = {}\n    if users:\n        auth = {'auth': users}\n    addresses = []\n    if ipv6():\n        addresses.append('[::]')\n    addresses.append('0.0.0.0')\n    addresses.append('127.0.0.1')\n    for addr in addresses:\n        demo.launch(server_name=addr, **auth)\n",
        "SKY-D358",
    )
    assert [row["line"] for row in findings] == [14]
    assert (
        findings[0]["security_evidence"]["evidence_kind"]
        == "python_public_launch_branch"
    )


@pytest.mark.parametrize(
    "statement",
    ["auth = {'auth': users}", "auth = options", "auth = {}\n    configure(auth)"],
)
def test_public_loop_unknown_or_present_auth_is_not_missing_auth_proof(
    tmp_path, statement
):
    source = (
        "import gradio as gr\nwith gr.Blocks() as demo:\n    pass\ndef launch(users,options):\n    "
        + statement
        + "\n    for addr in ['0.0.0.0', '127.0.0.1']:\n        demo.launch(server_name=addr, **auth)\n"
    )
    assert not scan(tmp_path, source, "SKY-D358")


def test_loopback_bind_with_optional_auth_stays_quiet(tmp_path):
    source = "import gradio as gr\ndef launch(users):\n    auth = {}\n    if users:\n        auth = {'auth': users}\n    for addr in ['localhost','127.0.0.1']:\n        gr.Blocks().launch(server_name=addr, **auth)\n"
    assert not scan(tmp_path, source, "SKY-D358")


def test_correlated_bind_and_auth_branches_do_not_invent_public_noauth(tmp_path):
    source = "import gradio as gr\ndef launch(public,users):\n    if public:\n        addresses=['0.0.0.0']\n        auth={'auth':users}\n    else:\n        addresses=['127.0.0.1']\n        auth={}\n    for addr in addresses:\n        gr.Blocks().launch(server_name=addr, **auth)\n"
    assert not scan(tmp_path, source, "SKY-D358")
