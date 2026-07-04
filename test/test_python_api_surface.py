from __future__ import annotations

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cached_api_symbol_surface,
)
from skylos.core.python_api_surface import (
    build_python_api_surface,
    cache_python_api_surface,
    cached_python_api_surface,
    load_python_api_surface_cache,
    python_environment_key,
    save_python_api_surface_cache,
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
                "VALUE = 42",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_cache_python_api_surface_records_functions_and_methods(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    project_root = tmp_path / "repo"
    project_root.mkdir()

    surface = cache_python_api_surface(project_root, "sampleapi")
    cached = cached_python_api_surface(project_root, "sampleapi")

    assert surface is not None
    assert cached is not None
    assert cached["module"] == "sampleapi"
    assert cached["origin"].endswith("__init__.py")

    members = cached["members"]
    assert "make_user" in members
    assert members["make_user"]["kind"] == "function"
    assert "name: str" in members["make_user"]["signature"]
    assert "active: bool = True" in members["make_user"]["signature"]
    assert _parameter_names(members["make_user"]) == ["name", "active"]

    assert "Client" in members
    client = members["Client"]
    assert client["kind"] == "class"
    assert "connect" in client["methods"]
    assert "timeout: int = 5" in client["methods"]["connect"]["signature"]
    assert _parameter_names(client["methods"]["connect"]) == ["self", "timeout"]
    assert "VALUE" not in members
    shared = cached_api_symbol_surface(
        project_root,
        SURFACE_KIND_PYTHON_MODULE,
        "sampleapi",
        environment_key=python_environment_key(),
    )
    assert shared is not None
    assert shared["members"]["make_user"]["kind"] == "function"
    assert _parameter_names(shared["members"]["make_user"]) == ["name", "active"]
    assert _parameter_names(shared["members"]["Client"]["methods"]["connect"]) == [
        "self",
        "timeout",
    ]
    assert (
        cached_api_symbol_surface(
            project_root,
            SURFACE_KIND_PYTHON_MODULE,
            "sampleapi",
            environment_key="stale",
        )
        is None
    )


def test_python_api_surface_cache_invalidates_environment_key(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _write_sample_package(site_root)
    monkeypatch.syspath_prepend(str(site_root))
    project_root = tmp_path / "repo"
    project_root.mkdir()

    surface = cache_python_api_surface(project_root, "sampleapi")
    payload = load_python_api_surface_cache(project_root)

    assert surface is not None
    assert "sampleapi" in payload["modules"]

    payload["environment"]["key"] = "stale"
    saved = save_python_api_surface_cache(project_root, payload)
    reloaded = load_python_api_surface_cache(project_root)

    assert saved is True
    assert reloaded["modules"] == {}


def test_build_python_api_surface_rejects_unsafe_module_name():
    imported = []

    def importer(name):
        imported.append(name)
        raise AssertionError("unsafe module name should not import")

    surface = build_python_api_surface("sampleapi;rm", importer=importer)

    assert surface is None
    assert imported == []


def _parameter_names(entry):
    names = []
    for parameter in entry["parameters"]:
        names.append(parameter["name"])
    return names
