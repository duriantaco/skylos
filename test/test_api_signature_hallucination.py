from __future__ import annotations

from skylos.rules.danger.danger_hallucination.api_signature_hallucination import (
    RULE_ID_API_SIGNATURE,
    scan_python_api_signature_hallucinations,
)


def _write_sample_package(site_root):
    package_dir = site_root / "sampleapi"
    package_dir.mkdir(parents=True)
    package_file = package_dir / "__init__.py"
    package_file.write_text(
        "\n".join(
            [
                "def make_user(name: str, *, active: bool = True) -> dict:",
                "    return {'name': name, 'active': active}",
                "",
                "class Client:",
                "    def connect(self, timeout: int = 5) -> str:",
                "        return str(timeout)",
                "",
                "    @classmethod",
                "    def from_env(cls):",
                "        return cls()",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_py(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scan(repo, py_file):
    return scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
    )


def test_scan_flags_missing_members_and_bad_keywords(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi as api",
                "",
                "def handler():",
                "    api.missing()",
                "    api.make_user(name='ada', active=True, imaginary=True)",
                "    client = api.Client()",
                "    client.missing()",
                "    client.connect(timeout=1, wait=True)",
                "",
            ]
        ),
    )

    findings = _scan(repo, py_file)
    messages = []
    for finding in findings:
        messages.append(finding["message"])

    assert len(findings) == 4
    assert all(finding["rule_id"] == RULE_ID_API_SIGNATURE for finding in findings)
    assert any("sampleapi.missing" in message for message in messages)
    assert any("argument 'imaginary'" in message for message in messages)
    assert any("sampleapi.Client.missing" in message for message in messages)
    assert any("argument 'wait'" in message for message in messages)


def test_scan_allows_known_members_and_keywords(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi as api",
                "",
                "def handler():",
                "    api.make_user(name='ada', active=False)",
                "    client = api.Client()",
                "    client.connect(timeout=1)",
                "",
            ]
        ),
    )

    findings = _scan(repo, py_file)

    assert findings == []


def test_scan_handles_from_import_aliases(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "from sampleapi import Client, make_user as build",
                "",
                "def handler():",
                "    build(unknown=True)",
                "    client = Client()",
                "    client.connect(wait=True)",
                "",
            ]
        ),
    )

    findings = _scan(repo, py_file)
    messages = []
    for finding in findings:
        messages.append(finding["message"])

    assert len(findings) == 2
    assert any("argument 'unknown'" in message for message in messages)
    assert any("argument 'wait'" in message for message in messages)


def test_scan_flags_module_level_client_resource_method(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi as api",
                "",
                "client = api.Client()",
                "",
                "def handler():",
                "    client.resource.missing()",
                "",
            ]
        ),
    )

    def surface_loader(_project_root, module_name):
        assert module_name == "sampleapi"
        return {
            "members": {
                "Client": {
                    "kind": "class",
                    "methods": {},
                    "properties": {
                        "resource": {
                            "kind": "property",
                            "methods": {
                                "create": {
                                    "kind": "method",
                                    "parameters": [],
                                },
                            },
                        },
                    },
                },
            },
        }

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
        surface_loader=surface_loader,
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_ID_API_SIGNATURE
    assert findings[0]["symbol"] == "sampleapi.Client.resource.missing"


def test_scan_default_allowlist_flags_openai_resource_method(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "summarizer.py",
        "\n".join(
            [
                "from openai import OpenAI",
                "",
                "client = OpenAI(api_key='test-key')",
                "",
                "def summarize(ticket):",
                "    return client.responses.parse_json(input=ticket)",
                "",
            ]
        ),
    )

    def surface_loader(_project_root, module_name):
        assert module_name == "openai"
        return {
            "members": {
                "OpenAI": {
                    "kind": "class",
                    "methods": {},
                    "properties": {
                        "responses": {
                            "kind": "property",
                            "methods": {
                                "parse": {
                                    "kind": "method",
                                    "parameters": [],
                                },
                            },
                        },
                    },
                },
            },
        }

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        surface_loader=surface_loader,
    )

    assert len(findings) == 1
    assert findings[0]["symbol"] == "openai.OpenAI.responses.parse_json"


def test_scan_skips_local_modules_named_like_allowlisted_package(
    tmp_path,
    monkeypatch,
):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_py(repo / "sampleapi.py", "def local():\n    return None\n")
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi",
                "sampleapi.missing()",
                "",
            ]
        ),
    )

    findings = _scan(repo, py_file)

    assert findings == []
