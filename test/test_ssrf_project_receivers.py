"""SKY-D216: a ``.get``/``.post`` on the project's own class or module is not
an outbound HTTP request, however HTTP-like the receiver's name."""

from pathlib import Path

from skylos.rules.danger.danger import scan_ctx


def _write(root: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, code in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        paths.append(path)
    return paths


def _ssrf_lines(tmp_path: Path, files: dict[str, str], target: str) -> list[int]:
    findings = scan_ctx(tmp_path, _write(tmp_path, files))
    return sorted(
        f["line"]
        for f in findings
        if f["rule_id"] == "SKY-D216" and Path(f["file"]).name == target
    )


_CLIENT_CLASS = """\
class Client:
    cache = {}

    @classmethod
    def get(cls, user_id):
        return cls.cache.get(user_id)
"""


def test_same_file_project_class_classmethod_get_is_not_ssrf(tmp_path):
    code = (
        "from flask import request\n\n" + _CLIENT_CLASS + "\n@app.route('/c')\n"
        "def view():\n"
        "    user_id = request.args['id']\n"
        "    return Client.get(user_id)\n"
    )
    assert _ssrf_lines(tmp_path, {"client.py": code}, "client.py") == []


def test_imported_project_class_is_not_ssrf_but_project_module_still_is(tmp_path):
    # A project module may wrap an HTTP client behind ``post``; keep it.
    files = {
        "pkg/__init__.py": "",
        "pkg/client.py": _CLIENT_CLASS,
        "pkg/session.py": "import requests\n\ndef post(url):\n    return requests.post(url)\n",
        "pkg/web/__init__.py": "",
        "pkg/web/api.py": (
            "from flask import request\n"
            "from ..client import Client\n"
            "from pkg.client import Client as HttpClient\n"
            "from .. import client\n"
            "from pkg import session\n\n"
            "@app.route('/a')\n"
            "def view():\n"
            "    user_id = request.args['id']\n"
            "    Client.get(user_id)\n"
            "    HttpClient.get(user_id)\n"
            "    client.Client.get(user_id)\n"
            "    session.post(user_id)\n"
            "    return 'ok'\n"
        ),
    }
    assert _ssrf_lines(tmp_path, files, "api.py") == [13]


def test_requests_get_with_request_url_still_flags(tmp_path):
    code = (
        "import requests\n"
        "from flask import request\n\n" + _CLIENT_CLASS + "\n@app.route('/f')\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    Client.get(url)\n"
        "    return requests.get(url).text\n"
    )
    assert _ssrf_lines(tmp_path, {"fetch.py": code}, "fetch.py") == [15]


def test_project_http_client_instance_still_flags(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/http.py": "import requests\n\nsession = requests.Session()\n",
        "pkg/views.py": (
            "from flask import request\n"
            "from .http import session\n\n"
            "@app.route('/p')\n"
            "def proxy():\n"
            "    return session.get(request.args['url']).text\n"
        ),
    }
    assert _ssrf_lines(tmp_path, files, "views.py") == [6]


def test_unresolved_and_http_library_receivers_still_flag(tmp_path):
    code = (
        "import httpx\n"
        "from flask import request\n"
        "from vendor_sdk import Client\n\n"
        "@app.route('/u')\n"
        "def fetch():\n"
        "    url = request.args['url']\n"
        "    Client.get(url)\n"
        "    return httpx.Client().get(url).text\n"
    )
    assert _ssrf_lines(tmp_path, {"unresolved.py": code}, "unresolved.py") == [8, 9]
