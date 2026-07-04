from __future__ import annotations

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_CLI,
    SURFACE_KIND_CONFIG,
    SURFACE_KIND_PYTHON_MODULE,
    SURFACE_KIND_ROUTE,
    SURFACE_KIND_SCHEMA,
    api_symbol_surface_key,
    cache_api_symbol_surface,
    cached_api_symbol_surface,
    load_api_symbol_truth_cache,
    normalize_api_symbol_surface,
)


def test_api_symbol_truth_cache_holds_multiple_surface_kinds(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "sampleapi",
            "source": "test",
            "environment_key": "env-a",
            "members": {
                "make_user": {
                    "kind": "function",
                    "parameters": [{"name": "active", "kind": "KEYWORD_ONLY"}],
                }
            },
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos",
            "flags": ["--format", "--diff"],
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CONFIG,
            "name": "skylos.toml",
            "config_keys": ["rules", "exclude"],
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_ROUTE,
            "name": "api",
            "routes": ["/v1/items"],
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_SCHEMA,
            "name": "User",
            "schema_fields": ["id", "email"],
        },
    )

    payload = load_api_symbol_truth_cache(project_root)

    assert set(payload["surfaces"]) == {
        "python_module:sampleapi",
        "cli:skylos",
        "config:skylos.toml",
        "route:api",
        "schema:User",
    }
    assert cached_api_symbol_surface(
        project_root,
        SURFACE_KIND_PYTHON_MODULE,
        "sampleapi",
    ) is None
    shared = cached_api_symbol_surface(
        project_root,
        SURFACE_KIND_PYTHON_MODULE,
        "sampleapi",
        environment_key="env-a",
    )
    assert shared["members"]["make_user"]["kind"] == "function"
    assert shared["members"]["make_user"]["parameters"] == [
        {"name": "active", "kind": "KEYWORD_ONLY"}
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


def test_api_symbol_truth_cache_rejects_malformed_surfaces(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    assert normalize_api_symbol_surface({"kind": "unknown", "name": "x"}) is None
    assert normalize_api_symbol_surface(
        {"kind": SURFACE_KIND_CLI, "name": "skylos"}
    ) is None
    assert api_symbol_surface_key("unknown", "x") is None
    assert api_symbol_surface_key(SURFACE_KIND_CLI, 123) is None
    assert normalize_api_symbol_surface(
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos",
            "flags": ["--format", 123, None],
        }
    )["flags"] == ["--format"]
    assert (
        normalize_api_symbol_surface(
            {
                "kind": SURFACE_KIND_PYTHON_MODULE,
                "name": "sampleapi",
                "environment_key": "env-a",
                "members": ["make_user"],
            }
        )
        is None
    )
    assert (
        normalize_api_symbol_surface(
            {
                "kind": SURFACE_KIND_PYTHON_MODULE,
                "name": "sampleapi",
                "environment_key": "env-a",
                "members": {"make_user": ["bad"]},
            }
        )
        is None
    )
    assert not cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos\nbad",
            "flags": ["--format"],
        },
    )
    assert load_api_symbol_truth_cache(project_root)["surfaces"] == {}
