from __future__ import annotations

from pathlib import Path

import skylos.analysis.fastapi_controls as fastapi_controls
from skylos.analysis.fastapi_controls import (
    discover_fastapi_controls,
    discover_fastapi_controls_for_scan,
)
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS


def _write(root: Path, source: str, name: str = "app.py") -> Path:
    path = root / name
    path.write_text(source, encoding="utf-8")
    return path


def test_discovers_supported_fastapi_guards_without_executing_source(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import APIRouter, Depends, Security
from typing import Annotated

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(requireTenant)],
)
route_dependencies = [Depends(require_admin), Depends(get_db)]

@router.api_route(
    "/users",
    methods=["GET", "POST"],
    dependencies=route_dependencies,
)
async def list_users(
    current: Annotated[str, Security(get_current_user, scopes=["admin"])],
    db=Depends(get_db),
):
    secret_in_body = "must-never-enter-registry-evidence"
    return secret_in_body
""",
    )

    first = discover_fastapi_controls(tmp_path, tmp_path)
    second = discover_fastapi_controls(tmp_path, tmp_path)

    assert first == second
    assert first["complete"] is True
    controls = first["controls"]
    assert len(controls) == 6
    assert {(item["route"]["method"], item["route"]["path"]) for item in controls} == {
        ("GET", "/admin/users"),
        ("POST", "/admin/users"),
    }
    assert {item["guard_name"] for item in controls} == {
        "requireTenant",
        "require_admin",
        "get_current_user",
    }
    assert {item["control_type"] for item in controls} == {
        "tenant_isolation",
        "authorization",
    }
    assert all(item["confidence"] == "high" for item in controls)
    evidence = " ".join(
        str(value) for item in controls for value in item["evidence"].values()
    )
    assert "must-never-enter-registry-evidence" not in evidence
    assert "Depends(require_admin)" in evidence
    assert "Security(get_current_user)" in evidence


def test_supports_import_aliases_factories_and_dynamic_routes(tmp_path):
    _write(
        tmp_path,
        """
import fastapi as api
import typing_extensions as tx

Router = api.APIRouter
D = api.Depends
S = api.Security
router = Router()
Admin = tx.Annotated[str, S(requireRole("admin"))]

@router.get(route_path)
def read_admin(
    principal: Admin,
    tenant= D(requireWorkspace),
):
    return principal
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)

    assert len(result["controls"]) == 2
    by_guard = {item["guard_name"]: item for item in result["controls"]}
    assert by_guard["requireRole"]["control_type"] == "authorization"
    assert by_guard["requireRole"]["confidence"] == "medium"
    assert by_guard["requireRole"]["route"]["path"] is None
    assert by_guard["requireWorkspace"]["control_type"] == "tenant_isolation"


def test_marks_only_guards_supported_by_contract_enforcement_as_protectable(
    tmp_path,
):
    _write(
        tmp_path,
        """
import fastapi as api
from fastapi import APIRouter, Depends, Security
from typing import Annotated

D = Depends
shared = [Depends(require_shared_admin)]
router = APIRouter(dependencies=[Depends(require_router_admin)])

@router.get("/direct", dependencies=[Depends(require_direct_admin)])
def direct(user=api.Depends(require_direct_user)):
    pass

@router.get("/alias", dependencies=[D(require_alias_admin)])
def alias():
    pass

@router.get("/shared", dependencies=shared)
def shared_route():
    pass

@router.get("/factory")
def factory(user=Depends(require_role("admin"))):
    pass

@router.get("/annotated")
def annotated(user: Annotated[str, Depends(require_annotated_user)]):
    pass

@router.get("/security")
def security(user=Security(require_security_user, scopes=["admin"])):
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)
    by_guard = {
        (item["handler"], item["guard_name"]): item["guard_kind"]
        for item in result["controls"]
    }

    assert by_guard[("direct", "require_direct_admin")] == "fastapi_dependency"
    assert by_guard[("direct", "require_direct_user")] == "fastapi_dependency"
    assert by_guard[("alias", "require_alias_admin")] == (
        "fastapi_dependency_observation"
    )
    assert by_guard[("shared_route", "require_shared_admin")] == (
        "fastapi_dependency_observation"
    )
    assert by_guard[("factory", "require_role")] == ("fastapi_dependency_observation")
    assert by_guard[("annotated", "require_annotated_user")] == (
        "fastapi_dependency_observation"
    )
    assert by_guard[("security", "require_security_user")] == "fastapi_security"
    for handler in {
        "direct",
        "alias",
        "shared_route",
        "factory",
        "annotated",
        "security",
    }:
        assert by_guard[(handler, "require_router_admin")] == (
            "fastapi_dependency_observation"
        )


def test_downgrades_ambiguous_shapes_the_contract_scanner_cannot_enforce(
    tmp_path,
):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends
import auth

app = FastAPI()

@app.get("/direct", dependencies=[Depends(require_direct_admin)])
def direct():
    pass

@app.api_route("/api", methods=["GET"], dependencies=[Depends(require_api_admin)])
def api_route_handler():
    pass

@app.trace("/trace", dependencies=[Depends(require_trace_admin)])
def trace_handler():
    pass

@app.websocket_route("/socket", dependencies=[Depends(require_socket_admin)])
def socket_handler():
    pass

@app.get("/keyword", dependencies=[Depends(dependency=require_keyword_admin)])
def keyword_handler():
    pass

def install():
    @app.get("/nested", dependencies=[Depends(require_nested_admin)])
    def endpoint():
        pass

class Routes:
    @app.get("/class", dependencies=[Depends(require_class_admin)])
    def endpoint(self):
        pass

@app.get("/multi-get", dependencies=[Depends(require_get_admin)])
@app.post("/multi-post", dependencies=[Depends(require_post_admin)])
def multi_handler():
    pass

@app.get("/qualified", dependencies=[Depends(auth.require_admin)])
def qualified_handler():
    pass

@app.get("/duplicate-one", dependencies=[Depends(require_duplicate_one_admin)])
def duplicate_handler():
    pass

@app.get("/duplicate-two", dependencies=[Depends(require_duplicate_two_admin)])
def duplicate_handler():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)
    direct = [
        item
        for item in result["controls"]
        if item["guard_name"] == "require_direct_admin"
    ]
    ambiguous = [
        item
        for item in result["controls"]
        if item["guard_name"] != "require_direct_admin"
    ]

    assert len(direct) == 1
    assert direct[0]["guard_kind"] == "fastapi_dependency"
    assert len(ambiguous) == 11
    assert {item["guard_kind"] for item in ambiguous} == {
        "fastapi_dependency_observation"
    }


def test_downgrades_duplicate_handlers_inside_module_control_flow(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

if FEATURE_FLAG:
    @app.get("/admins", dependencies=[Depends(require_admin)])
    def endpoint():
        pass
else:
    @app.get("/owners", dependencies=[Depends(require_owner)])
    async def endpoint():
        pass

try:
    @app.get("/staff", dependencies=[Depends(require_staff)])
    def recovery_endpoint():
        pass
except RuntimeError:
    @app.get("/managers", dependencies=[Depends(require_manager)])
    def recovery_endpoint():
        pass

def install_routes():
    def safe_handler():
        pass

class RouteFactory:
    def safe_handler(self):
        pass

@app.get("/safe", dependencies=[Depends(require_safe_admin)])
def safe_handler():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)
    by_guard = {item["guard_name"]: item["guard_kind"] for item in result["controls"]}

    assert by_guard == {
        "require_admin": "fastapi_dependency_observation",
        "require_owner": "fastapi_dependency_observation",
        "require_staff": "fastapi_dependency_observation",
        "require_manager": "fastapi_dependency_observation",
        "require_safe_admin": "fastapi_dependency",
    }


def test_downgrades_top_level_route_shadowed_by_nested_or_class_route(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

class Routes:
    @app.get("/class", dependencies=[Depends(require_class_admin)])
    def endpoint(self):
        pass

if FEATURE_FLAG:
    @app.get("/top", dependencies=[Depends(require_top_admin)])
    def endpoint():
        pass

def install():
    @app.get("/nested", dependencies=[Depends(require_nested_owner)])
    def owner_endpoint():
        pass

@app.get("/owner", dependencies=[Depends(require_top_owner)])
def owner_endpoint():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)

    assert {item["guard_kind"] for item in result["controls"]} == {
        "fastapi_dependency_observation"
    }


def test_rejects_rebound_fastapi_route_method(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()
app.get = fake_route

@app.get("/decoy", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)

    assert result["controls"] == []


def test_does_not_truncate_long_guard_into_protectable_identity(tmp_path):
    guard = "require_admin_" + "a" * 300
    _write(
        tmp_path,
        f"""
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/admin", dependencies=[Depends({guard})])
def endpoint():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)

    assert result["controls"] == []


def test_full_monorepo_subpath_is_complete_for_linked_cloud_project(tmp_path):
    project = tmp_path / "services" / "api"
    project.mkdir(parents=True)
    _write(
        project,
        """
from fastapi import FastAPI, Depends
app = FastAPI()
@app.get("/admin", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    result = discover_fastapi_controls_for_scan(
        {
            "project_root": "services/api",
            "analysis_summary": {
                "project_root": "services/api",
                "comparison_scope": {
                    "kind": "subdirectory",
                    "scan_path": str(project),
                    "repository_root": str(tmp_path),
                    "complete_repository": False,
                    "changed_files_only": False,
                    "excluded_folders": [],
                },
            },
        }
    )

    assert result["complete"] is True
    assert result["controls"][0]["file_path"] == "services/api/app.py"

    defaults_only = discover_fastapi_controls_for_scan(
        {
            "project_root": "services/api",
            "analysis_summary": {
                "project_root": "services/api",
                "comparison_scope": {
                    "kind": "subdirectory",
                    "scan_path": str(project),
                    "repository_root": str(tmp_path),
                    "complete_repository": False,
                    "changed_files_only": False,
                    "excluded_folders": sorted(DEFAULT_EXCLUDE_FOLDERS),
                },
            },
        }
    )

    assert defaults_only["complete"] is True


def test_default_exclusions_keep_a_root_registry_snapshot_complete(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends
app = FastAPI()
@app.get("/admins", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    report = discover_fastapi_controls_for_scan(
        {
            "analysis_summary": {
                "comparison_scope": {
                    "kind": "repository_root_with_exclusions",
                    "scan_path": str(tmp_path),
                    "repository_root": str(tmp_path),
                    "complete_repository": False,
                    "changed_files_only": False,
                    "excluded_folders": sorted(DEFAULT_EXCLUDE_FOLDERS),
                }
            }
        }
    )

    assert report["complete"] is True


def test_internally_inconsistent_root_scope_fails_closed(tmp_path):
    _write(tmp_path, "from fastapi import FastAPI\napp = FastAPI()\n")
    base_scope = {
        "scan_path": str(tmp_path),
        "repository_root": str(tmp_path),
        "changed_files_only": False,
    }

    claimed_partial_root = discover_fastapi_controls_for_scan(
        {
            "analysis_summary": {
                "comparison_scope": {
                    **base_scope,
                    "kind": "repository_root",
                    "complete_repository": False,
                    "excluded_folders": [],
                }
            }
        }
    )
    claimed_complete_exclusions = discover_fastapi_controls_for_scan(
        {
            "analysis_summary": {
                "comparison_scope": {
                    **base_scope,
                    "kind": "repository_root_with_exclusions",
                    "complete_repository": True,
                    "excluded_folders": sorted(DEFAULT_EXCLUDE_FOLDERS),
                }
            }
        }
    )

    assert claimed_partial_root["complete"] is False
    assert claimed_complete_exclusions["complete"] is False


def test_subpath_snapshot_stays_incomplete_when_binding_or_scope_differs(tmp_path):
    project = tmp_path / "services" / "api"
    project.mkdir(parents=True)
    _write(project, "from fastapi import FastAPI\napp = FastAPI()\n")

    base = {
        "project_root": "services/api",
        "analysis_summary": {
            "comparison_scope": {
                "kind": "subdirectory",
                "scan_path": str(project),
                "repository_root": str(tmp_path),
                "complete_repository": False,
                "changed_files_only": False,
                "excluded_folders": [],
            },
        },
    }
    mismatch = {
        **base,
        "project_root": "services/web",
    }
    excluded = {
        **base,
        "analysis_summary": {
            "comparison_scope": {
                **base["analysis_summary"]["comparison_scope"],
                "excluded_folders": ["generated"],
            }
        },
    }

    assert discover_fastapi_controls_for_scan(mismatch)["complete"] is False
    assert discover_fastapi_controls_for_scan(excluded)["complete"] is False


def test_rejects_decoys_generic_dependencies_and_uncertain_rebindings(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

if runtime_flag:
    app = fake_application

@app.get("/uncertain", dependencies=[Depends(require_admin)])
def uncertain_route():
    pass

real = FastAPI()
from another_framework import Depends

@real.get("/fake-wrapper", dependencies=[Depends(require_admin)])
def fake_wrapper():
    pass

from fastapi import Depends as RealDepends

@real.get("/services")
def service_route(
    db=RealDepends(get_db),
    cache=RealDepends(get_cache),
):
    pass

@real.get("/protected", dependencies=[RealDepends(require_admin)])
def protected_route():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)

    assert [(item["handler"], item["guard_name"]) for item in result["controls"]] == [
        ("protected_route", "require_admin")
    ]


def test_qualified_wrapper_mutation_blocks_false_fastapi_proof(tmp_path):
    _write(
        tmp_path,
        """
import fastapi

app = fastapi.FastAPI()
fastapi.Depends = custom_depends

@app.get("/decoy", dependencies=[fastapi.Depends(require_admin)])
def decoy():
    pass
""",
    )

    result = discover_fastapi_controls(tmp_path, tmp_path)

    assert result["controls"] == []


def test_module_alias_mutation_blocks_all_spellings_of_same_fastapi_module(tmp_path):
    _write(
        tmp_path,
        """
import fastapi as api

alias = api
app = api.FastAPI()
alias.Depends = custom_depends

@app.get("/decoy", dependencies=[api.Depends(require_admin)])
def decoy():
    pass
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_route_method_mutation_poisoning_follows_all_owner_aliases(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()
first_alias = app
first_alias.get = replacement
later_alias = app

@later_alias.get("/decoy", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_setattr_route_mutation_poisoning_follows_owner_aliases(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()
alias = app
setattr(alias, "get", replacement)

@app.get("/decoy", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_imported_builtin_setattr_alias_blocks_decoy_route(tmp_path):
    _write(
        tmp_path,
        """
from builtins import setattr as mutate
from fastapi import FastAPI, Depends

app = FastAPI()
mutate(app, "get", replacement)

@app.get("/decoy", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_unrelated_owner_attribute_mutation_keeps_real_route(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()
setattr(app, "title", "Service")
app.description = "API"

@app.get("/admin", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    controls = discover_fastapi_controls(tmp_path, tmp_path)["controls"]
    assert [(item["handler"], item["guard_name"]) for item in controls] == [
        ("endpoint", "require_admin")
    ]


def test_star_import_poisoning_rejects_prior_fastapi_bindings(tmp_path):
    _write(
        tmp_path,
        """
import fastapi

from untrusted import *

app = fastapi.FastAPI()

@app.get("/decoy", dependencies=[fastapi.Depends(require_admin)])
def endpoint():
    pass
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_pattern_captures_shadow_fastapi_bindings_per_case(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

match candidate:
    case ("route", app):
        pass
    case _:
        pass

@app.get("/decoy", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_dynamic_router_prefix_keeps_route_path_unknown(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import APIRouter, Depends

dynamic_router = APIRouter(prefix=build_prefix())
plain_router = APIRouter()

@dynamic_router.get("/admins", dependencies=[Depends(require_admin)])
def dynamic_endpoint():
    pass

@plain_router.get("/users", dependencies=[Depends(require_admin)])
def plain_endpoint():
    pass
""",
    )

    controls = {
        item["handler"]: item
        for item in discover_fastapi_controls(tmp_path, tmp_path)["controls"]
    }

    assert controls["dynamic_endpoint"]["route"]["path"] is None
    assert controls["dynamic_endpoint"]["confidence"] == "medium"
    assert controls["plain_endpoint"]["route"]["path"] == "/users"
    assert controls["plain_endpoint"]["confidence"] == "high"


def test_route_paths_with_invisible_formatting_characters_are_not_displayed(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/admin\u202ereversed", dependencies=[Depends(require_admin)])
def endpoint():
    pass
""",
    )

    controls = discover_fastapi_controls(tmp_path, tmp_path)["controls"]

    assert len(controls) == 1
    assert controls[0]["route"]["path"] is None
    assert controls[0]["confidence"] == "medium"


def test_generic_user_repository_dependency_is_not_an_auth_control(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/repository", dependencies=[Depends(get_user_repository)])
def repository_endpoint():
    pass

@app.get("/identity", dependencies=[Depends(get_current_user)])
def identity_endpoint():
    pass

@app.get("/oauth", dependencies=[Depends(oauth2_scheme)])
def oauth_endpoint():
    pass
""",
    )

    controls = discover_fastapi_controls(tmp_path, tmp_path)["controls"]

    assert {item["guard_name"] for item in controls} == {
        "get_current_user",
        "oauth2_scheme",
    }
    assert {item["control_type"] for item in controls} == {"auth"}
    assert all("syntactically declares" in item["description"] for item in controls)


def test_only_fastapi_candidate_files_are_parsed_and_candidate_errors_are_incomplete(
    tmp_path, monkeypatch
):
    _write(tmp_path, "ordinary = 1\n", "ordinary.py")
    candidate = _write(
        tmp_path,
        "from fastapi import FastAPI\napp = FastAPI()\n",
        "candidate.py",
    )
    calls = []
    original = fastapi_controls.load_python_module

    def tracked_loader(path, mode):
        calls.append(path)
        return original(path, mode)

    monkeypatch.setattr(fastapi_controls, "load_python_module", tracked_loader)

    report = discover_fastapi_controls(tmp_path, tmp_path)

    assert report["complete"] is True
    assert calls == [candidate]

    _write(tmp_path, "import fastapi\ndef = broken\n", "broken.py")
    broken = discover_fastapi_controls(tmp_path, tmp_path)

    assert broken["complete"] is False
    assert broken["files_skipped"] == 1


def test_relative_library_named_imports_do_not_prove_fastapi_controls(tmp_path):
    _write(
        tmp_path,
        """
from .fastapi import FastAPI, Depends
from .fastapi.params import Security

app = FastAPI()

@app.get("/admin", dependencies=[Depends(require_admin), Security(require_user)])
def admin():
    return "ok"
""",
    )

    assert discover_fastapi_controls(tmp_path, tmp_path)["controls"] == []


def test_non_library_paths_are_covered_but_not_collected_as_controls(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/production", dependencies=[Depends(require_admin)])
def production_endpoint():
    pass
""",
        "app.py",
    )
    fixtures = tmp_path / "test" / "fixtures"
    fixtures.mkdir(parents=True)
    _write(
        fixtures,
        """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/fixture", dependencies=[Depends(require_fixture_admin)])
def fixture_endpoint():
    pass
""",
        "routes.py",
    )

    report = discover_fastapi_controls(tmp_path, tmp_path)

    assert report["complete"] is True
    assert report["files_scanned"] == 2
    assert [(item["handler"], item["guard_name"]) for item in report["controls"]] == [
        ("production_endpoint", "require_admin")
    ]


def test_scope_and_limits_are_explicit_and_symlinks_are_not_followed(tmp_path):
    _write(
        tmp_path,
        """
from fastapi import FastAPI, Depends
app = FastAPI()
@app.get("/one", dependencies=[Depends(require_admin)])
def one(): pass
@app.get("/two", dependencies=[Depends(require_admin)])
def two(): pass
""",
    )
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    link = tmp_path / "outside.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pass

    bounded = discover_fastapi_controls(tmp_path, tmp_path, max_controls=1)
    assert len(bounded["controls"]) == 1
    assert bounded["truncated"] is True
    assert bounded["complete"] is False

    partial = discover_fastapi_controls_for_scan(
        {
            "analysis_summary": {
                "comparison_scope": {
                    "kind": "changed_files",
                    "scan_path": str(tmp_path),
                    "repository_root": str(tmp_path),
                    "changed_files_only": True,
                }
            }
        }
    )
    assert partial == {
        "controls": [],
        "status": "skipped",
        "reason": "unsupported_partial_scope",
    }

    invalid = discover_fastapi_controls(outside, tmp_path)
    assert invalid["reason"] == "invalid_scope"
