from __future__ import annotations

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cache_api_symbol_surface,
)
from skylos.core.python_api_surface import python_environment_key
from skylos.rules.ai_defect.api_signature_hallucination import (
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


def test_scan_allows_dynamic_getattr_and_kwargs_expansion(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi",
                "",
                "def handler(payload):",
                "    builder = getattr(sampleapi, 'make_user')",
                "    builder(name='ada', **payload)",
                "    sampleapi.make_user(**payload)",
                "",
            ]
        ),
    )

    def surface_loader(_project_root, module_name):
        assert module_name == "sampleapi"
        return {
            "members": {
                "make_user": {
                    "kind": "function",
                    "parameters": [
                        {"name": "name", "kind": "POSITIONAL_OR_KEYWORD"},
                    ],
                }
            }
        }

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
        surface_loader=surface_loader,
    )

    assert findings == []


def test_scan_allows_var_keyword_surface_parameters(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi",
                "",
                "def handler():",
                "    sampleapi.make_user(name='ada', imaginary=True)",
                "",
            ]
        ),
    )

    def surface_loader(_project_root, module_name):
        assert module_name == "sampleapi"
        return {
            "members": {
                "make_user": {
                    "kind": "function",
                    "parameters": [
                        {"name": "name", "kind": "POSITIONAL_OR_KEYWORD"},
                        {"name": "kwargs", "kind": "VAR_KEYWORD"},
                    ],
                }
            }
        }

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
        surface_loader=surface_loader,
    )

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


def test_scan_uses_shared_python_api_truth_cache(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    assert cache_api_symbol_surface(
        repo,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "sampleapi",
            "environment_key": python_environment_key(),
            "members": {
                "make_user": {
                    "kind": "function",
                    "parameters": [
                        {"name": "name", "kind": "POSITIONAL_OR_KEYWORD"},
                    ],
                }
            },
        },
    )
    py_file = _write_py(
        repo / "app.py",
        "\n".join(
            [
                "import sampleapi",
                "sampleapi.missing()",
                "sampleapi.make_user(name='ada', imaginary=True)",
                "",
            ]
        ),
    )

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
    )
    messages = [finding["message"] for finding in findings]

    assert len(findings) == 2
    assert any("sampleapi.missing" in message for message in messages)
    assert any("argument 'imaginary'" in message for message in messages)


def test_scan_ignores_stale_shared_truth_and_falls_back_to_current_surface(
    tmp_path,
    monkeypatch,
):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    assert cache_api_symbol_surface(
        repo,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "sampleapi",
            "environment_key": "stale",
            "members": {
                "make_user": {
                    "kind": "function",
                    "parameters": [
                        {"name": "name", "kind": "POSITIONAL_OR_KEYWORD"},
                        {"name": "imaginary", "kind": "KEYWORD_ONLY"},
                    ],
                }
            },
        },
    )
    py_file = _write_py(
        repo / "app.py",
        "import sampleapi\nsampleapi.make_user(name='ada', imaginary=True)\n",
    )

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
    )

    assert len(findings) == 1
    assert "argument 'imaginary'" in findings[0]["message"]


def test_scan_rejects_malformed_shared_truth_and_falls_back_to_current_surface(
    tmp_path,
    monkeypatch,
):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    assert not cache_api_symbol_surface(
        repo,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "sampleapi",
            "environment_key": python_environment_key(),
            "members": {"make_user": ["bad"]},
        },
    )
    py_file = _write_py(
        repo / "app.py",
        "import sampleapi\nsampleapi.make_user(name='ada', imaginary=True)\n",
    )

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi",),
    )

    assert len(findings) == 1
    assert "argument 'imaginary'" in findings[0]["message"]


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


def test_scan_skips_missing_members_when_surface_truncated(tmp_path):
    py_file = _write_py(
        tmp_path / "app.py",
        "\n".join(
            [
                "import bigmod",
                "bigmod.beyond_cap()",
                "client = bigmod.Client()",
                "client.beyond_cap()",
                "",
            ]
        ),
    )

    def loader(_root, _module_name):
        return {
            "members": {
                "known": {"kind": "function", "parameters": []},
                "Client": {
                    "kind": "class",
                    "parameters": [],
                    "methods": {},
                    "methods_truncated": True,
                    "properties": {},
                },
            },
            "members_truncated": True,
        }

    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [py_file],
        allowed_modules=("bigmod",),
        surface_loader=loader,
    )

    assert findings == []


def test_load_config_sanitizes_api_signature_modules(tmp_path):
    from skylos.config import load_config

    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos]\napi_signature_modules = ["httpx", 42]\n',
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config["api_signature_modules"] == ["httpx"]


def test_analyzer_passes_configured_allowlist_to_scan(tmp_path, monkeypatch):
    from skylos import analyzer as analyzer_module
    from skylos.rules.ai_defect import api_signature_hallucination as api_sig
    from skylos.rules.ai_defect import dependency_hallucination as dep_mod
    from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest_mod

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n\n'
        '[tool.skylos]\napi_signature_modules = ["httpx"]\n',
        encoding="utf-8",
    )
    _write_py(tmp_path / "app.py", "import httpx\n")

    seen = {}

    def fake_scan(project_root, py_files, *, allowed_modules=None, **kwargs):
        seen["allowed_modules"] = allowed_modules
        return []

    monkeypatch.setattr(
        api_sig, "scan_python_api_signature_hallucinations", fake_scan
    )
    # The D224 scan is gated behind enable_dependency_hallucinations, so keep
    # it on but stub the registry-touching scans to stay offline.
    monkeypatch.setattr(
        dep_mod, "scan_python_dependency_hallucinations", lambda *a, **k: []
    )
    monkeypatch.setattr(
        manifest_mod, "scan_manifest_dependency_hallucinations", lambda *a, **k: []
    )

    analyzer_module.analyze(
        str(tmp_path),
        enable_ai_defects=True,
        grep_verify=False,
    )

    assert seen["allowed_modules"] == ("httpx",)
