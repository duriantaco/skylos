from __future__ import annotations

import threading

from skylos.core import python_api_surface
from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cache_api_symbol_surface,
    cached_api_symbol_surface,
)
from skylos.core.python_api_surface import (
    cached_python_api_surface,
    load_python_api_surface_cache,
    python_environment_key,
    save_python_api_surface_cache,
)
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


def test_scan_batches_api_surface_cache_io(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    other_package = site_root / "otherapi"
    other_package.mkdir(parents=True)
    (other_package / "__init__.py").write_text(
        "def known():\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site_root))
    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "import sampleapi\nimport otherapi\nsampleapi.missing()\notherapi.missing()\n",
    )
    load_counts = {"python": 0, "shared": 0}
    save_counts = {"python": 0, "shared": 0}
    original_python_load = python_api_surface.load_python_api_surface_cache
    original_shared_load = python_api_surface.load_api_symbol_truth_cache
    original_python_save = python_api_surface._save_python_api_surface_cache_unlocked
    original_shared_save = python_api_surface._save_api_symbol_truth_cache_unlocked

    def load_python(*args, **kwargs):
        load_counts["python"] += 1
        return original_python_load(*args, **kwargs)

    def load_shared(*args, **kwargs):
        load_counts["shared"] += 1
        return original_shared_load(*args, **kwargs)

    def save_python(*args, **kwargs):
        save_counts["python"] += 1
        return original_python_save(*args, **kwargs)

    def save_shared(*args, **kwargs):
        save_counts["shared"] += 1
        return original_shared_save(*args, **kwargs)

    monkeypatch.setattr(
        python_api_surface,
        "load_python_api_surface_cache",
        load_python,
    )
    monkeypatch.setattr(
        python_api_surface,
        "load_api_symbol_truth_cache",
        load_shared,
    )
    monkeypatch.setattr(
        python_api_surface,
        "_save_python_api_surface_cache_unlocked",
        save_python,
    )
    monkeypatch.setattr(
        python_api_surface,
        "_save_api_symbol_truth_cache_unlocked",
        save_shared,
    )

    cold_findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi", "otherapi"),
    )
    warm_findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("sampleapi", "otherapi"),
    )

    assert [finding["symbol"] for finding in cold_findings] == [
        "sampleapi.missing",
        "otherapi.missing",
    ]
    assert warm_findings == cold_findings
    assert load_counts == {"python": 2, "shared": 3}
    assert save_counts == {"python": 1, "shared": 1}


def test_scan_preserves_surfaces_cached_during_batch(tmp_path, monkeypatch):
    from skylos.rules.ai_defect import api_signature_hallucination as api_sig

    repo = tmp_path / "repo"
    repo.mkdir()
    py_file = _write_py(
        repo / "app.py",
        "import pkg_a\nimport pkg_b\npkg_a.missing()\npkg_b.known()\n",
    )
    pkg_b_members = {"known": {"kind": "function", "parameters": []}}

    def build_surface(module_name):
        if module_name == "pkg_a":
            return {
                "module": "pkg_a",
                "members": {},
                "members_truncated": False,
            }
        return None

    original_add_missing = api_sig._ApiSignatureChecker._add_missing_finding

    def add_missing_and_cache_pkg_b(checker, node, target):
        original_add_missing(checker, node, target)
        if target.module_name != "pkg_a":
            return

        python_payload = load_python_api_surface_cache(repo)
        python_payload["modules"] = {
            "pkg_b": {
                "module": "pkg_b",
                "members": pkg_b_members,
                "members_truncated": False,
            }
        }
        assert save_python_api_surface_cache(repo, python_payload)
        assert cache_api_symbol_surface(
            repo,
            {
                "kind": SURFACE_KIND_PYTHON_MODULE,
                "name": "pkg_b",
                "environment_key": python_environment_key(),
                "members": pkg_b_members,
            },
        )

    monkeypatch.setattr(python_api_surface, "build_python_api_surface", build_surface)
    monkeypatch.setattr(
        api_sig._ApiSignatureChecker,
        "_add_missing_finding",
        add_missing_and_cache_pkg_b,
    )

    findings = scan_python_api_signature_hallucinations(
        repo,
        [py_file],
        allowed_modules=("pkg_a", "pkg_b"),
    )

    assert [finding["symbol"] for finding in findings] == ["pkg_a.missing"]
    assert cached_python_api_surface(repo, "pkg_a") is not None
    assert cached_python_api_surface(repo, "pkg_b") is not None
    assert (
        cached_api_symbol_surface(
            repo,
            SURFACE_KIND_PYTHON_MODULE,
            "pkg_a",
            environment_key=python_environment_key(),
        )
        is not None
    )
    assert (
        cached_api_symbol_surface(
            repo,
            SURFACE_KIND_PYTHON_MODULE,
            "pkg_b",
            environment_key=python_environment_key(),
        )
        is not None
    )


def test_concurrent_cache_sessions_preserve_different_modules(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()

    def build_surface(module_name):
        return {
            "module": module_name,
            "origin": f"/{module_name}.py",
            "members": {},
            "members_truncated": False,
        }

    monkeypatch.setattr(python_api_surface, "build_python_api_surface", build_surface)
    first_session = python_api_surface.PythonApiSurfaceCacheSession(repo)
    second_session = python_api_surface.PythonApiSurfaceCacheSession(repo)
    assert first_session.load_surface(repo, "pkg_a") is not None
    assert second_session.load_surface(repo, "pkg_b") is not None

    original_save = python_api_surface._save_python_api_surface_cache_unlocked
    first_save_entered = threading.Event()
    second_save_entered = threading.Event()
    save_count_lock = threading.Lock()
    save_count = 0

    def delayed_save(*args, **kwargs):
        nonlocal save_count
        with save_count_lock:
            save_count += 1
            call_number = save_count
        if call_number == 1:
            first_save_entered.set()
            second_save_entered.wait(timeout=0.25)
        else:
            second_save_entered.set()
        return original_save(*args, **kwargs)

    monkeypatch.setattr(
        python_api_surface,
        "_save_python_api_surface_cache_unlocked",
        delayed_save,
    )
    errors = []

    def flush(session):
        try:
            session.flush()
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first_thread = threading.Thread(target=flush, args=(first_session,))
    second_thread = threading.Thread(target=flush, args=(second_session,))
    first_thread.start()
    assert first_save_entered.wait(timeout=1.0)
    second_thread.start()
    first_thread.join(timeout=2.0)
    second_thread.join(timeout=2.0)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert errors == []
    assert second_save_entered.is_set()
    assert set(load_python_api_surface_cache(repo)["modules"]) == {"pkg_a", "pkg_b"}
    shared_surfaces = python_api_surface.load_api_symbol_truth_cache(repo)["surfaces"]
    assert set(shared_surfaces) == {
        "python_module:pkg_a",
        "python_module:pkg_b",
    }


def test_stale_cache_session_does_not_replace_newer_module(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    origins = iter(("older.py", "newer.py"))

    def build_surface(module_name):
        return {
            "module": module_name,
            "origin": next(origins),
            "members": {},
            "members_truncated": False,
        }

    monkeypatch.setattr(python_api_surface, "build_python_api_surface", build_surface)
    stale_session = python_api_surface.PythonApiSurfaceCacheSession(repo)
    newer_session = python_api_surface.PythonApiSurfaceCacheSession(repo)
    assert stale_session.load_surface(repo, "pkg_a")["origin"] == "older.py"
    assert newer_session.load_surface(repo, "pkg_a")["origin"] == "newer.py"

    newer_session.flush()
    stale_session.flush()

    assert cached_python_api_surface(repo, "pkg_a")["origin"] == "newer.py"
    shared = cached_api_symbol_surface(
        repo,
        SURFACE_KIND_PYTHON_MODULE,
        "pkg_a",
        environment_key=python_environment_key(),
    )
    assert shared["origin"] == "newer.py"


def test_scan_skips_parsing_files_without_allowed_roots(tmp_path, monkeypatch):
    from skylos.rules.ai_defect import api_signature_hallucination as api_sig

    unrelated_file = _write_py(tmp_path / "unrelated.py", "print('hello')\n")
    relevant_file = _write_py(
        tmp_path / "relevant.py",
        "import sampleapi\nsampleapi.missing()\n",
    )
    parsed_sources = []
    original_parse = api_sig.ast.parse

    def parse(source, *args, **kwargs):
        parsed_sources.append(source)
        return original_parse(source, *args, **kwargs)

    def loader(_root, module_name):
        assert module_name == "sampleapi"
        return {"members": {}, "members_truncated": False}

    monkeypatch.setattr(api_sig.ast, "parse", parse)

    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [unrelated_file, relevant_file],
        allowed_modules=("sampleapi",),
        surface_loader=loader,
    )

    assert parsed_sources == ["import sampleapi\nsampleapi.missing()\n"]
    assert [finding["symbol"] for finding in findings] == ["sampleapi.missing"]


def test_scan_skips_prefilter_for_large_allowlists(tmp_path, monkeypatch):
    from skylos.rules.ai_defect import api_signature_hallucination as api_sig

    unrelated_file = _write_py(tmp_path / "unrelated.py", "print('hello')\n")
    relevant_file = _write_py(
        tmp_path / "relevant.py",
        "import sampleapi\nsampleapi.missing()\n",
    )
    parsed_sources = []
    original_parse = api_sig.ast.parse

    def parse(source, *args, **kwargs):
        parsed_sources.append(source)
        return original_parse(source, *args, **kwargs)

    def loader(_root, module_name):
        assert module_name == "sampleapi"
        return {"members": {}, "members_truncated": False}

    monkeypatch.setattr(api_sig.ast, "parse", parse)
    allowed_modules = ("sampleapi", *(f"package_{index}" for index in range(64)))

    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [unrelated_file, relevant_file],
        allowed_modules=allowed_modules,
        surface_loader=loader,
    )

    assert parsed_sources == [
        "print('hello')\n",
        "import sampleapi\nsampleapi.missing()\n",
    ]
    assert [finding["symbol"] for finding in findings] == ["sampleapi.missing"]


def test_scan_prefilter_handles_normalized_import_identifiers(tmp_path):
    py_file = _write_py(
        tmp_path / "app.py",
        "import 𝕡andas as pd\npd.missing()\n",
    )

    def loader(_root, module_name):
        assert module_name == "pandas"
        return {"members": {}, "members_truncated": False}

    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [py_file],
        allowed_modules=("pandas",),
        surface_loader=loader,
    )

    assert [finding["symbol"] for finding in findings] == ["pandas.missing"]


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
