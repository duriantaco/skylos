from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.cicd.review import filter_findings_to_diff
from skylos.rules.catalog import get_rule_catalog
from skylos.rules.config import scan_config_files
from skylos.rules.config.deployment.exposure import scan_deployment_exposure


def _write_app(tmp_path: Path, source: str | None = None) -> Path:
    app = tmp_path / "app" / "main.py"
    app.parent.mkdir(parents=True, exist_ok=True)
    app.write_text(  # skylos: ignore[SKY-D324] all callers pass pytest tmp_path
        source
        or """from fastapi import FastAPI

app = FastAPI()

@app.get("/admin/users")
def list_admin_users():
    return {"ok": True}
""",
        encoding="utf-8",
    )
    return app


def _server_command(
    server: str,
    *,
    flags: tuple[str, ...] = (),
    host: str = "0.0.0.0",
    port: int = 8000,
) -> tuple[list[str], list[str]]:
    if server == "flask":
        return ["flask"], [
            "--app",
            "app.main:app",
            "run",
            *flags,
            "--host",
            host,
            "--port",
            str(port),
        ]
    if server == "gunicorn":
        return ["gunicorn"], [
            "app.main:app",
            *flags,
            "--bind",
            f"{host}:{port}",
        ]
    if server == "python-uvicorn":
        return ["python3", "-m", "uvicorn"], [
            "app.main:app",
            *flags,
            "--host",
            host,
            "--port",
            str(port),
        ]
    if server == "echo-uvicorn":
        return ["echo", "uvicorn"], [
            "app.main:app",
            *flags,
            "--host",
            host,
            "--port",
            str(port),
        ]
    return ["uvicorn"], [
        "app.main:app",
        *flags,
        "--host",
        host,
        "--port",
        str(port),
    ]


def _write_kubernetes(
    tmp_path: Path,
    *,
    host: str = "api.example.com",
    ingress_path: str = "/",
    path_type: str = "Prefix",
    external_scope: bool = True,
    source_file: str | None = "app/main.py",
    required_guards: str | None = "require_admin",
    service_name: str = "api-public",
    target_port: str = "http",
    service_protocol: str = "TCP",
    server: str = "uvicorn",
    server_flags: tuple[str, ...] = (),
    server_host: str = "0.0.0.0",
    server_port: int = 8000,
    ingress_annotations: str = "",
    extra_documents: str = "",
    ingress_api_version: str = "networking.k8s.io/v1",
    service_api_version: str = "v1",
    workload_api_version: str = "apps/v1",
) -> Path:
    manifest = tmp_path / "deploy" / "rendered.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    command, args = _server_command(
        server,
        flags=server_flags,
        host=server_host,
        port=server_port,
    )
    workload_annotations = []
    if source_file is not None:
        workload_annotations.append(f"        skylos.dev/source-file: {source_file}")
    if required_guards is not None:
        workload_annotations.append(
            f"        skylos.dev/required-guards: {required_guards}"
        )
    workload_annotation_block = (
        "      annotations:\n" + "\n".join(workload_annotations) + "\n"
        if workload_annotations
        else ""
    )
    ingress_annotation_lines = ["    skylos.dev/backend-protocol: http"]
    if external_scope:
        ingress_annotation_lines.append("    skylos.dev/network-scope: external")
    if ingress_annotations:
        ingress_annotation_lines.extend(ingress_annotations.rstrip().splitlines())
    ingress_annotation_block = (
        "  annotations:\n" + "\n".join(ingress_annotation_lines) + "\n"
        if ingress_annotation_lines
        else ""
    )
    manifest.write_text(  # skylos: ignore[SKY-D324] all callers pass pytest tmp_path
        f"""apiVersion: {workload_api_version}
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
{workload_annotation_block}    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:sha-123
          command: {json.dumps(command)}
          args: {json.dumps(args)}
          ports:
            - name: http
              containerPort: 8000
---
apiVersion: {service_api_version}
kind: Service
metadata:
  name: {service_name}
  namespace: prod
spec:
  type: ClusterIP
  selector:
    app: api
  ports:
    - name: http
      protocol: {service_protocol}
      port: 80
      targetPort: {target_port}
---
apiVersion: {ingress_api_version}
kind: Ingress
metadata:
  name: api-public
  namespace: prod
{ingress_annotation_block}spec:
  rules:
    - host: {host}
      http:
        paths:
          - path: {ingress_path}
            pathType: {path_type}
            backend:
              service:
                name: api-public
                port:
                  name: http
{extra_documents}""",
        encoding="utf-8",
    )
    return manifest


def _rule_ids(findings: list[dict]) -> set[str]:
    return {str(finding["rule_id"]) for finding in findings}


def _finding(findings: list[dict], rule_id: str) -> dict:
    return next(finding for finding in findings if finding["rule_id"] == rule_id)


def _fake_aws_access_key_id() -> str:
    return "AKIA" + "ABCDEFGHIJKLMNOP"


def _replace_container_args(manifest: Path, args: list[str]) -> None:
    lines = manifest.read_text(  # skylos: ignore[SKY-D325] pytest tmp_path manifest
        encoding="utf-8"
    ).splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("args:"):
            indent = line[: len(line) - len(line.lstrip())]
            lines[index] = f"{indent}args: {json.dumps(args)}"
            manifest.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path manifest
                "\n".join(lines) + "\n", encoding="utf-8"
            )
            return
    raise AssertionError("container args were not found")


def test_proves_bundle_entrypoint_source_route_and_missing_contract_guard(tmp_path):
    app = _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)

    finding = _finding(scan_deployment_exposure(tmp_path), "SKY-DEP001")

    assert {
        "kind": "config",
        "category": "SECURITY",
        "domain": "deployment",
        "provider": "kubernetes",
        "type": "deployment_exposure",
        "severity": "HIGH",
    }.items() <= finding.items()
    assert finding["file"] == str(app)
    assert finding["metadata"]["contract"] == {
        "network_scope": "external",
        "backend_protocol": "http",
        "source_file": "app/main.py",
        "required_guards": ["require_admin"],
    }
    assert finding["metadata"]["route"]["missing_guards"] == ["require_admin"]
    assert finding["metadata"]["evidence_files"] == [str(app), str(manifest)]
    assert finding["metadata"]["proof_state"] == "correlated_static"
    assert finding["evidence_contract"]["proof_state"] == "candidate"
    assert any(
        "does not prove" in limitation and "image" in limitation
        for limitation in finding["evidence_contract"]["limitations"]
    )
    assert "command" not in finding["metadata"]["workload"]


@pytest.mark.parametrize(
    "source",
    [
        """from fastapi import Depends, FastAPI

app = FastAPI()
def require_admin(): return True

@app.get("/admin/users")
def list_admin_users(user=Depends(require_admin)):
    return {"ok": True}
""",
        """from fastapi import Depends, FastAPI

def require_admin(): return True
app = FastAPI(dependencies=[Depends(require_admin)])

@app.get("/admin/users")
def list_admin_users():
    return {"ok": True}
""",
        """from typing import Annotated
from fastapi import Depends, FastAPI

app = FastAPI()
def require_admin(): return True

@app.get("/admin/users")
def list_admin_users(user: Annotated[object, Depends(require_admin)]):
    return {"ok": True}
""",
        """from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route("/admin/users")
@login_required
def list_admin_users():
    return {"ok": True}
""",
    ],
)
def test_exact_required_framework_guard_satisfies_contract(tmp_path, source):
    _write_app(tmp_path, source)
    server = "gunicorn" if "from flask" in source else "uvicorn"
    required = "login_required" if "from flask" in source else "require_admin"
    _write_kubernetes(tmp_path, server=server, required_guards=required)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    "source",
    [
        """from fastapi import Depends, FastAPI

app = FastAPI()
def optional_auth(): return None

@app.get("/admin/users")
def list_admin_users(user=Depends(optional_auth)):
    return {"ok": True}
""",
        """from fastapi import FastAPI

app = FastAPI()

@app.get("/admin/users")
def list_admin_users():
    verify_token()
    return {"ok": True}
""",
    ],
)
def test_unrequired_or_body_only_auth_evidence_does_not_satisfy_contract(
    tmp_path, source
):
    _write_app(tmp_path, source)
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_custom_depends_lookalike_does_not_satisfy_contract(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI

def Depends(value): return value
def require_admin(): return True
app = FastAPI()

@app.get("/admin/users")
def route(user=Depends(require_admin)):
    return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_aliased_fastapi_dependency_satisfies_exact_contract(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import Depends as Inject, FastAPI as API

def require_admin(): return True
app = API()

@app.get("/admin/users")
def route(user=Inject(require_admin)):
    return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    ("required_guard", "should_emit"),
    [("auth.require_admin", False), ("other.require_admin", True)],
)
def test_qualified_guard_contract_requires_exact_identity(
    tmp_path, required_guard, should_emit
):
    _write_app(
        tmp_path,
        """import auth
from fastapi import Depends, FastAPI

app = FastAPI()

@app.get("/admin/users", dependencies=[Depends(auth.require_admin)])
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path, required_guards=required_guard)

    assert (
        "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))
    ) is should_emit


def test_route_decorator_order_preserves_flask_registration_semantics(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@login_required
@app.route("/admin/users")
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path, server="gunicorn", required_guards="login_required")

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_each_stacked_route_uses_only_its_own_dependency_contract(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import Depends, FastAPI

def require_admin(): return True
app = FastAPI()

@app.get("/admin/guarded", dependencies=[Depends(require_admin)])
@app.get("/admin/raw")
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    findings = [
        finding
        for finding in scan_deployment_exposure(tmp_path)
        if finding["rule_id"] == "SKY-DEP001"
    ]
    assert [finding["metadata"]["route"]["path"] for finding in findings] == [
        "/admin/raw"
    ]


@pytest.mark.parametrize(
    ("source_file", "required_guards"),
    [
        (None, "require_admin"),
        ("app/main.py", None),
        ("other/main.py", "require_admin"),
        ("src/app/main.py", "require_admin"),
    ],
)
def test_missing_or_mismatched_source_guard_contract_abstains(
    tmp_path, source_file, required_guards
):
    _write_app(tmp_path)
    _write_kubernetes(
        tmp_path,
        source_file=source_file,
        required_guards=required_guards,
    )

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_non_framework_and_unreachable_nested_routes_abstain(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI

app = FastAPI()

def unused_factory():
    @app.get("/admin/users")
    def nested():
        return {"ok": True}
    return nested
""",
    )
    _write_kubernetes(tmp_path)
    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_invalid_framework_route_api_and_rebound_app_abstain(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
app = Flask(__name__)
@app.api_route("/admin/users", methods=["GET"])
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path, server="gunicorn")
    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))

    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
app = FastAPI()
""",
    )
    _write_kubernetes(tmp_path)
    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))

    _write_app(
        tmp_path,
        """class CustomApp:
    def get(self, path): return lambda function: function
app = CustomApp()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
    )
    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    "source",
    [
        """from fastapi_evil import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
def replacement(): return None
FastAPI = replacement
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
import other as app
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
del app
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.api_route("/admin/users", methods=["GET", None])
def route(): return {"ok": True}
""",
    ],
)
def test_spoofed_or_invalid_python_framework_provenance_abstains(tmp_path, source):
    _write_app(tmp_path, source)
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    "source",
    [
        """from .fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """import fastapi as framework
framework.FastAPI = lambda: object()
app = framework.FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
app.get = lambda path: (lambda function: function)
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(value, value): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users", methods=["POST"])
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
app.router.routes.clear()
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.GET("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
if True:
    app.router.routes.clear()
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
routes = app.router.routes
routes.clear()
""",
        """from fastapi import APIRouter, FastAPI
app = FastAPI()
router = APIRouter()
app.include_router(router)
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
setattr(app, "get", lambda path: (lambda function: function))
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
def clear(target): target.router.routes.clear()
clear(app)
""",
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
apps = [app]
apps[0].router.routes.clear()
""",
    ],
)
def test_untrusted_framework_provenance_and_invalid_route_shapes_abstain(
    tmp_path, source
):
    _write_app(tmp_path, source)
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_rebound_qualified_depends_cannot_spoof_required_guard(tmp_path):
    _write_app(
        tmp_path,
        """import fastapi as framework
framework.Depends = lambda value: value
app = framework.FastAPI()
def require_admin(): return True
@app.get("/admin/users")
def route(user=framework.Depends(require_admin)): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_earlier_dynamic_fastapi_route_shadows_later_literal_route(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/{name}")
def dynamic(name: str): return {"name": name}
@app.get("/admin")
def admin(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_later_dynamic_fastapi_route_does_not_shadow_literal_route(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin")
def admin(): return {"ok": True}
@app.get("/{name}")
def dynamic(name: str): return {"name": name}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_nonmatching_typed_route_does_not_shadow_literal_route(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/{item_id:int}")
def by_id(item_id: int): return {"id": item_id}
@app.get("/admin")
def admin(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_first_flask_handler_wins_for_duplicate_method_and_path(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
app = Flask(__name__)
def require_admin(function): return function
@app.get("/admin")
@require_admin
def first(): return {"ok": True}
@app.get("/admin")
def unreachable_second(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path, server="gunicorn", required_guards="require_admin")

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_starlette_uuid_converter_shadow_accepts_unhyphenated_uuid(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
def require_admin(function): return function
@app.get("/admin/{item_id:uuid}")
@require_admin
def by_id(item_id): return {"id": item_id}
@app.get("/admin/550e8400e29b41d4a716446655440000")
def unreachable_literal(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    ("source", "server"),
    [
        (
            """from flask import Flask
app = Flask(__name__)
@app.route("/admin/users")
def route(): return {"ok": True}
""",
            "uvicorn",
        ),
        (
            """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
            "gunicorn",
        ),
    ],
)
def test_server_and_source_framework_must_match(tmp_path, source, server):
    _write_app(tmp_path, source)
    _write_kubernetes(tmp_path, server=server)

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    ("source", "server"),
    [
        (
            """from fastapi import FastAPI
app = FastAPI()
@app.get(path="/admin/users")
def route(): return {"ok": True}
""",
            "uvicorn",
        ),
        (
            """from flask import Flask
app = Flask(import_name=__name__)
@app.route(rule="/admin/users")
def route(): return {"ok": True}
""",
            "gunicorn",
        ),
    ],
)
def test_valid_framework_keyword_route_shapes_are_correlated(tmp_path, source, server):
    _write_app(tmp_path, source)
    _write_kubernetes(tmp_path, server=server)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_flask_constructor_requires_import_name(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
app = Flask()
@app.route("/admin/users")
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path, server="gunicorn")

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_fastapi_api_route_default_get_is_correlated(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
@app.api_route("/admin/users")
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize("path", ["/admin/login", "/actuator/health", "/manage/readyz"])
def test_sensitive_route_names_cannot_override_explicit_guard_contract(tmp_path, path):
    _write_app(
        tmp_path,
        f"""from fastapi import FastAPI
app = FastAPI()
@app.get("{path}")
def public_endpoint(): return {{"ok": True}}
""",
    )
    _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_external_scope_is_explicit_and_host_name_is_not_isolation(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, external_scope=False)
    assert scan_deployment_exposure(tmp_path) == []

    _write_kubernetes(tmp_path, host="api.internal", external_scope=True)
    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_ingress_or_mesh_auth_does_not_replace_required_app_guard(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(
        tmp_path,
        ingress_annotations=(
            "    nginx.ingress.kubernetes.io/auth-url: "
            "https://auth.example.com/verify\n"
        ),
        extra_documents="""---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: require-user, namespace: prod}
spec:
  selector: {matchLabels: {app: api}}
  action: ALLOW
  rules:
    - from:
        - source: {requestPrincipals: ["*"]}
""",
    )

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    ("ingress_path", "path_type", "service_name", "target_port"),
    [
        ("/public", "Exact", "api-public", "http"),
        ("/", "ImplementationSpecific", "api-public", "http"),
        ("/", "Prefix", "different-service", "http"),
        ("/", "Prefix", "api-public", "missing"),
    ],
)
def test_broken_or_ambiguous_graph_edges_abstain(
    tmp_path, ingress_path, path_type, service_name, target_port
):
    _write_app(tmp_path)
    _write_kubernetes(
        tmp_path,
        ingress_path=ingress_path,
        path_type=path_type,
        service_name=service_name,
        target_port=target_port,
    )

    assert scan_deployment_exposure(tmp_path) == []


def test_ingress_backend_with_both_port_identities_abstains(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        rendered.replace(
            "                port:\n                  name: http",
            "                port:\n                  name: http\n                  number: 80",
        ),
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


def test_exact_ingress_path_preserves_trailing_slash_semantics(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, ingress_path="/admin/users/", path_type="Exact")

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_default_backend_does_not_override_explicit_rule_routing(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, ingress_path="/admin")
    rendered = manifest.read_text(encoding="utf-8")
    ingress_spec = "spec:\n  rules:"
    assert ingress_spec in rendered
    rendered = rendered.replace(
        ingress_spec,
        "spec:\n"
        "  defaultBackend:\n"
        "    service:\n"
        "      name: api-public\n"
        "      port:\n"
        "        name: http\n"
        "  rules:",
        1,
    )
    rendered = rendered.replace(
        "                name: api-public",
        "                name: another-service",
        1,
    )
    manifest.write_text(rendered, encoding="utf-8")

    assert scan_deployment_exposure(tmp_path) == []


def test_default_only_backend_can_form_proof_chain(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    prefix, _ = manifest.read_text(encoding="utf-8").rsplit("spec:\n", 1)
    manifest.write_text(
        prefix + "spec:\n"
        "  defaultBackend:\n"
        "    service:\n"
        "      name: api-public\n"
        "      port:\n"
        "        name: http\n",
        encoding="utf-8",
    )

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    "overrides",
    [
        {"service_protocol": "UDP"},
        {"ingress_api_version": "example.com/v1"},
        {"service_api_version": "example.com/v1"},
        {"workload_api_version": "example.com/v1"},
        {"server": "echo-uvicorn", "server_flags": ("--reload",)},
    ],
)
def test_fake_or_non_http_graph_and_nonexecuted_server_tokens_abstain(
    tmp_path, overrides
):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, **overrides)

    assert scan_deployment_exposure(tmp_path) == []


def test_bundle_boundaries_prevent_cross_environment_edges(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    text = manifest.read_text(encoding="utf-8")
    documents = text.split("---\n")
    manifest.write_text("---\n".join(documents[:2]), encoding="utf-8")
    (manifest.parent / "ingress.yaml").write_text(documents[2], encoding="utf-8")

    assert scan_deployment_exposure(tmp_path) == []


def test_inline_resource_metadata_abstains_instead_of_using_global_line_one(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    rendered = rendered.replace(
        "metadata:\n  name: api\n  namespace: prod",
        "metadata: {name: api, namespace: prod}",
        1,
    )
    rendered = rendered.replace(
        "metadata:\n  name: api-public\n  namespace: prod",
        "metadata: {name: api-public, namespace: prod}",
        2,
    )
    manifest.write_text(
        "# skylos: ignore[SKY-DEP001]\n" + rendered,
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


def test_harmless_template_marker_does_not_blind_rendered_resources(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    manifest.write_text(
        "# harmless {{ marker\n" + manifest.read_text(), encoding="utf-8"
    )

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_dynamic_proof_relevant_value_abstains(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, host='"${PUBLIC_HOST}"')

    assert scan_deployment_exposure(tmp_path) == []


def test_duplicate_yaml_mapping_keys_abstain(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        rendered.replace(
            '          command: ["uvicorn"]',
            '          command: ["echo"]\n          command: ["uvicorn"]',
            1,
        ),
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  namespace: prod", '  namespace: "{{ .Values.namespace }}"'),
        ("        app: api", "        app: 123"),
        ("    matchLabels:\n      app: api", "    matchLabels:\n      app: other"),
        ("spec:\n  selector:", "spec:\n  replicas: 0\n  selector:"),
    ],
)
def test_dynamic_or_unreachable_workload_graph_abstains(tmp_path, old, new):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    assert old in rendered
    manifest.write_text(rendered.replace(old, new), encoding="utf-8")

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize(
    "manifest_kwargs",
    [
        {
            "ingress_annotations": (
                "    nginx.ingress.kubernetes.io/backend-protocol: GRPC\n"
            )
        },
        {
            "ingress_annotations": (
                "    nginx.ingress.kubernetes.io/backend-protocol: HTTPS\n"
            )
        },
        {
            "ingress_annotations": (
                '    nginx.ingress.kubernetes.io/ssl-passthrough: "true"\n'
            )
        },
        {
            "ingress_annotations": (
                "    traefik.ingress.kubernetes.io/service.serversscheme: https\n"
            )
        },
        {"ingress_annotations": "    nginx.org/ssl-services: api-public\n"},
        {"ingress_annotations": "    nginx.org/grpc-services: api-public\n"},
        {"ingress_annotations": '    haproxy.org/server-ssl: "true"\n'},
        {"ingress_annotations": "    konghq.com/protocol: https\n"},
        {"ingress_annotations": '    konghq.com/strip-path: "true"\n'},
        {"ingress_annotations": "    konghq.com/path: /different\n"},
        {"ingress_annotations": "    konghq.com/methods: POST\n"},
    ],
)
def test_non_http_ingress_transport_abstains(tmp_path, manifest_kwargs):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, **manifest_kwargs)

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize("app_protocol", ["grpc", "https", "kubernetes.io/h2c"])
def test_non_http_service_app_protocol_abstains(tmp_path, app_protocol):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        rendered.replace(
            "      protocol: TCP",
            f"      protocol: TCP\n      appProtocol: {app_protocol}",
        ),
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize(
    "annotation",
    [
        "traefik.ingress.kubernetes.io/service.serversscheme: https",
        'haproxy.org/server-ssl: "true"',
        "nginx.org/ssl-services: api-public",
        "konghq.com/protocol: https",
    ],
)
def test_non_http_service_annotation_abstains(tmp_path, annotation):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    service_metadata = "metadata:\n  name: api-public\n  namespace: prod\nspec:"
    assert service_metadata in rendered
    manifest.write_text(
        rendered.replace(
            service_metadata,
            "metadata:\n  name: api-public\n  namespace: prod\n"
            f"  annotations:\n    {annotation}\n"
            "spec:",
            1,
        ),
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "  ports:\n    - name: http\n      protocol: TCP\n      port: 80",
            "  ports:\n    - name: https\n      protocol: TCP\n      port: 80",
        ),
        ("      port: 80", "      port: 443"),
    ],
)
def test_implicit_https_service_port_abstains(tmp_path, old, new):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    assert old in rendered
    rendered = rendered.replace(old, new, 1)
    if "    - name: https" in new:
        rendered = rendered.replace(
            "                  name: http", "                  name: https", 1
        )
    manifest.write_text(rendered, encoding="utf-8")

    assert scan_deployment_exposure(tmp_path) == []


def test_external_ingress_requires_explicit_http_backend_contract(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "    skylos.dev/backend-protocol: http\n", "", 1
        ),
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


def test_unrelated_resource_ignore_cannot_suppress_scoped_ingress_evidence(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    rendered = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        """apiVersion: v1
kind: ConfigMap
metadata:
  # skylos: ignore[SKY-DEP001]
  name: api-public
data:
  note: unrelated
---
"""
        + rendered,
        encoding="utf-8",
    )

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_unrelated_workload_annotations_cannot_spoof_inline_ignores(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
app = Flask(__name__)
@app.route("/admin/users")
def route(): return {"ok": True}
""",
    )
    manifest = _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug",),
        required_guards="login_required",
    )
    rendered = manifest.read_text(encoding="utf-8")
    rendered = rendered.replace(
        "  namespace: prod\nspec:",
        "  namespace: prod\n"
        "  annotations:\n"
        "    skylos.dev/required-guards: login_required # skylos: ignore[SKY-DEP001]\n"
        '    note: "--debug # skylos: ignore[SKY-DEP002]"\n'
        "spec:",
        1,
    )
    manifest.write_text(rendered, encoding="utf-8")

    assert {"SKY-DEP001", "SKY-DEP002"} <= _rule_ids(scan_deployment_exposure(tmp_path))


def test_quoted_ignore_text_adjacent_to_real_contributor_does_not_suppress(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
app = Flask(__name__)
marker = "skylos: ignore[SKY-DEP001]"
@app.route("/admin/users")
def route(): return {"ok": True}
""",
    )
    manifest = _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug",),
        required_guards="login_required",
    )
    rendered = manifest.read_text(encoding="utf-8")
    rendered = rendered.replace(
        "          args:",
        "          env:\n"
        "            - name: NOTE\n"
        '              value: "skylos: ignore[SKY-DEP002]"\n'
        "          args:",
        1,
    )
    manifest.write_text(rendered, encoding="utf-8")

    assert {"SKY-DEP001", "SKY-DEP002"} <= _rule_ids(scan_deployment_exposure(tmp_path))


def test_real_yaml_comment_on_command_flag_suppresses_only_that_rule(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="flask", server_flags=("--debug",))
    lines = manifest.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("args:"):
            lines[index] += " # skylos: ignore[SKY-DEP002]"
            break
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rule_ids = _rule_ids(scan_deployment_exposure(tmp_path))
    assert "SKY-DEP002" not in rule_ids
    assert "SKY-DEP003" in rule_ids


def test_command_flag_locator_requires_an_exact_argv_scalar(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="flask")
    args = [
        "--debug",
        "--env-file",
        "settings --debug",
        "--app",
        "app.main:app",
        "run",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]
    lines = manifest.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("args:"):
            indent = line[: len(line) - len(line.lstrip())]
            replacement = [f"{indent}args:"]
            for value in args:
                suffix = (
                    " # skylos: ignore[SKY-DEP002]"
                    if value == "settings --debug"
                    else ""
                )
                replacement.append(f"{indent}  - {json.dumps(value)}{suffix}")
            lines[index : index + 1] = replacement
            break
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")

    findings = scan_deployment_exposure(tmp_path)
    debug = _finding(findings, "SKY-DEP002")
    assert (
        manifest.read_text(encoding="utf-8").splitlines()[debug["line"] - 1].strip()
        == '- "--debug"'
    )


def test_yaml_block_scalar_ignore_text_is_not_a_comment(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="flask", server_flags=("--debug",))
    rendered = manifest.read_text(encoding="utf-8")
    rendered = rendered.replace(
        "          args:",
        "          env:\n"
        "            - name: NOTE\n"
        "              value: |\n"
        "                # skylos: ignore[SKY-DEP002]\n"
        "          args:",
        1,
    )
    manifest.write_text(rendered, encoding="utf-8")

    assert "SKY-DEP002" in _rule_ids(scan_deployment_exposure(tmp_path))


def test_distinct_ingresses_to_same_route_keep_distinct_contract_failures(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    with manifest.open("a", encoding="utf-8") as handle:
        handle.write(
            """---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-second
  namespace: prod
  annotations:
    skylos.dev/network-scope: external
    skylos.dev/backend-protocol: http
spec:
  rules:
    - host: second.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-public
                port:
                  name: http
"""
        )

    findings = [
        finding
        for finding in scan_deployment_exposure(tmp_path)
        if finding["rule_id"] == "SKY-DEP001"
    ]
    assert {finding["metadata"]["ingress"]["name"] for finding in findings} == {
        "api-public",
        "api-second",
    }


def test_flask_debugger_and_reload_mode_have_distinct_rules(tmp_path):
    _write_app(
        tmp_path,
        """from flask import Flask
app = Flask(__name__)
@app.route("/admin/users")
def route(): return {"ok": True}
""",
    )
    manifest = _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug", "--reload"),
    )

    findings = scan_deployment_exposure(tmp_path)

    debug = _finding(findings, "SKY-DEP002")
    reload = _finding(findings, "SKY-DEP003")
    assert debug["severity"] == "HIGH" and debug["category"] == "SECURITY"
    assert reload["severity"] == "MEDIUM" and reload["category"] == "RELIABILITY"
    assert debug["file"] == str(manifest)
    manifest_lines = manifest.read_text(encoding="utf-8").splitlines()
    assert "--debug" in manifest_lines[debug["line"] - 1]
    assert "--reload" in manifest_lines[reload["line"] - 1]


def test_flask_no_debugger_and_uvicorn_debug_do_not_emit_security_rule(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug", "--no-debugger"),
    )
    assert "SKY-DEP002" not in _rule_ids(scan_deployment_exposure(tmp_path))

    _write_kubernetes(tmp_path, server="uvicorn", server_flags=("--debug",))
    assert "SKY-DEP002" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_negated_reload_and_non_run_flask_command_do_not_emit_mode_rules(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--reload", "--no-reload"),
    )
    assert "SKY-DEP003" not in _rule_ids(scan_deployment_exposure(tmp_path))

    manifest = _write_kubernetes(tmp_path, server="flask")
    _replace_container_args(
        manifest,
        [
            "--app",
            "app.main:app",
            "shell",
            "--debug",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
    )
    assert not (
        {"SKY-DEP002", "SKY-DEP003"} & _rule_ids(scan_deployment_exposure(tmp_path))
    )


def test_flask_boolean_flag_precedence_is_respected(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug", "--no-debug"),
    )
    assert "SKY-DEP002" not in _rule_ids(scan_deployment_exposure(tmp_path))

    _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug", "--no-debugger", "--debugger"),
    )
    assert "SKY-DEP002" in _rule_ids(scan_deployment_exposure(tmp_path))

    _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--no-reload", "--reload"),
    )
    assert "SKY-DEP003" in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    ("flags", "should_emit", "enabling_flag"),
    [
        (("--debugger",), True, "--debugger"),
        (("--no-debug", "--debugger"), True, "--debugger"),
        (("--debug", "--no-debugger"), False, None),
        (("--debugger", "--no-debugger"), False, None),
        (("--no-debugger", "--debugger"), True, "--debugger"),
    ],
)
def test_explicit_flask_debugger_semantics(tmp_path, flags, should_emit, enabling_flag):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="flask", server_flags=flags)

    findings = scan_deployment_exposure(tmp_path)
    assert ("SKY-DEP002" in _rule_ids(findings)) is should_emit
    if enabling_flag is not None:
        finding = _finding(findings, "SKY-DEP002")
        assert enabling_flag in finding["message"]
        assert finding["value"].endswith(f":{enabling_flag}")
        assert (
            enabling_flag
            in manifest.read_text(  # skylos: ignore[SKY-D325] pytest tmp_path manifest
                encoding="utf-8"
            ).splitlines()[finding["line"] - 1]
        )


def test_flask_debug_mode_implies_reload_unless_explicitly_disabled(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, server="flask", server_flags=("--debug",))
    findings = scan_deployment_exposure(tmp_path)
    reload_finding = _finding(findings, "SKY-DEP003")
    assert reload_finding["value"].endswith(":--debug")
    assert "`--debug` enabling reload mode" in reload_finding["message"]

    _write_kubernetes(
        tmp_path,
        server="flask",
        server_flags=("--debug", "--no-reload"),
    )
    assert "SKY-DEP003" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    "args",
    [
        [
            "run",
            "--app",
            "app.main:app",
            "--debug",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
        [
            "--app",
            "app.main:app",
            "run",
            "--unknown-option",
            "--debug",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
    ],
)
def test_invalid_flask_option_placement_or_unknown_option_abstains(tmp_path, args):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="flask")
    _replace_container_args(manifest, args)

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize("eager_flag", ["--help", "--version"])
def test_flask_eager_exit_group_flags_abstain(tmp_path, eager_flag):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="flask")
    _replace_container_args(
        manifest,
        [
            eager_flag,
            "--app",
            "app.main:app",
            "run",
            "--debug",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
    )

    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize("server", ["uvicorn", "gunicorn"])
def test_unsupported_negative_reload_flag_abstains(tmp_path, server):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, server=server, server_flags=("--no-reload",))

    assert scan_deployment_exposure(tmp_path) == []


def test_empty_argv_and_case_changed_executable_abstain(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="uvicorn", server_flags=("--reload",))
    args = [
        "app.main:app",
        "",
        "--reload",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]
    _replace_container_args(manifest, args)
    assert scan_deployment_exposure(tmp_path) == []

    rendered = manifest.read_text(encoding="utf-8").replace(
        'command: ["uvicorn"]', 'command: ["Uvicorn"]'
    )
    manifest.write_text(rendered, encoding="utf-8")
    _replace_container_args(manifest, [item for item in args if item])
    assert scan_deployment_exposure(tmp_path) == []


@pytest.mark.parametrize(
    "new_command",
    [
        '["/tmp/uvicorn"]',
        '["/tmp/python3", "-m", "uvicorn"]',
    ],
)
def test_path_impersonating_known_server_executable_abstains(tmp_path, new_command):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="uvicorn", server_flags=("--reload",))
    rendered = manifest.read_text(encoding="utf-8")
    assert 'command: ["uvicorn"]' in rendered
    manifest.write_text(
        rendered.replace('command: ["uvicorn"]', f"command: {new_command}", 1),
        encoding="utf-8",
    )

    assert scan_deployment_exposure(tmp_path) == []


def test_python_module_target_named_py_maps_as_a_module_not_a_filename(tmp_path):
    root_app = tmp_path / "app.py"
    root_app.write_text(
        """from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def route(): return {"ok": True}
""",
        encoding="utf-8",
    )
    manifest = _write_kubernetes(tmp_path, source_file="app.py")
    _replace_container_args(
        manifest,
        [
            "app.py:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
    )

    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


@pytest.mark.parametrize(
    "args",
    [
        [
            "app.:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--reload",
        ],
        [
            "../app/main.py:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--reload",
        ],
        [
            "--root-path",
            "app.main:app",
            "app.main:app",
            "--reload",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
        [
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--reload",
        ],
        [
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--",
            "--reload",
        ],
    ],
)
def test_ambiguous_or_nonexecuted_uvicorn_argv_abstains(tmp_path, args):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server="uvicorn")
    _replace_container_args(manifest, args)

    assert scan_deployment_exposure(tmp_path) == []


def test_production_server_has_no_mode_findings(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path)

    assert not (
        {"SKY-DEP002", "SKY-DEP003"} & _rule_ids(scan_deployment_exposure(tmp_path))
    )


@pytest.mark.parametrize("host", ["127.0.0.1", "*"])
def test_non_external_server_binding_abstains(tmp_path, host):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, server_flags=("--reload",), server_host=host)
    assert scan_deployment_exposure(tmp_path) == []


def test_mismatched_server_port_abstains(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path, server_flags=("--reload",), server_port=9000)
    assert scan_deployment_exposure(tmp_path) == []


def test_direct_manifest_scan_resolves_project_and_source_contract(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)

    assert "SKY-DEP001" in _rule_ids(scan_deployment_exposure(manifest))


def test_analyzer_source_list_keeps_project_config_contract_without_widening_sources(
    tmp_path,
):
    (tmp_path / ".git").mkdir()
    app = _write_app(tmp_path)
    _write_kubernetes(tmp_path)
    (tmp_path / "app" / "not_staged.py").write_text(
        "def untouched():\n    return True\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            [str(app)],
            enable_danger=True,
            changed_files={str(app)},
        )
    )

    assert "SKY-DEP001" in _rule_ids(result["danger"])
    assert result["analysis_summary"]["total_files"] == 1


def test_diff_anchors_changed_source_or_bundle_and_skips_unrelated_change(tmp_path):
    app = _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    (tmp_path / "other.py").write_text("value = 1\n", encoding="utf-8")

    source_finding = _finding(
        scan_deployment_exposure(tmp_path, changed_files={"app/main.py"}),
        "SKY-DEP001",
    )
    manifest_finding = _finding(
        scan_deployment_exposure(tmp_path, changed_files={"deploy/rendered.yaml"}),
        "SKY-DEP001",
    )

    assert source_finding["file"] == str(app)
    assert manifest_finding["file"] == str(manifest)
    assert scan_deployment_exposure(tmp_path, changed_files={"other.py"}) == []


def test_diff_filter_keeps_cross_layer_finding_for_changed_ingress_span(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    finding = _finding(scan_deployment_exposure(tmp_path), "SKY-DEP001")
    ingress_location = max(
        (
            location
            for location in finding["related_locations"]
            if location["file"] == str(manifest)
        ),
        key=lambda location: location["start_line"],
    )

    assert filter_findings_to_diff(
        [finding],
        [
            {
                "file": "deploy/rendered.yaml",
                "start": ingress_location["end_line"],
                "end": ingress_location["end_line"],
            }
        ],
    ) == [finding]


def test_diff_filter_keeps_cross_layer_finding_for_source_provenance_change(tmp_path):
    _write_app(tmp_path)
    _write_kubernetes(tmp_path)
    finding = _finding(scan_deployment_exposure(tmp_path), "SKY-DEP001")

    assert finding["file"].endswith("app/main.py")
    assert finding["line"] > 1
    assert filter_findings_to_diff(
        [finding],
        [{"file": "app/main.py", "start": 1, "end": 1}],
    ) == [finding]


def test_ignore_and_inline_ignore_are_rule_specific(tmp_path):
    _write_app(
        tmp_path,
        """from fastapi import FastAPI
app = FastAPI()
# skylos: ignore[SKY-DEP001]
@app.get("/admin/users")
def route(): return {"ok": True}
""",
    )
    _write_kubernetes(tmp_path, server_flags=("--reload",))

    findings = scan_deployment_exposure(tmp_path, ignore={"SKY-DEP003"})

    assert findings == []


def test_dynamic_manifest_and_symlinked_source_fail_closed(tmp_path):
    app = _write_app(tmp_path)
    _write_kubernetes(tmp_path, host='"{{ .Values.host }}"')
    assert scan_deployment_exposure(tmp_path) == []

    _write_kubernetes(tmp_path)
    real_app = tmp_path / "real-main.py"
    app.replace(real_app)
    try:
        app.symlink_to(real_app)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert "SKY-DEP001" not in _rule_ids(scan_deployment_exposure(tmp_path))


def test_direct_symlinked_manifest_is_not_followed(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path)
    link = tmp_path / "rendered-link.yaml"
    try:
        link.symlink_to(manifest)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    assert scan_deployment_exposure(link) == []


def test_direct_yaml_remains_secret_scannable_without_python_parse_error(tmp_path):
    manifest = tmp_path / "secret.yaml"
    manifest.write_text(
        f'aws_access_key_id: "{_fake_aws_access_key_id()}"\n',
        encoding="utf-8",
    )

    result = json.loads(analyze(str(manifest), enable_secrets=True))

    assert result["analysis_errors"] == []
    assert result["analysis_summary"]["analysis_error_count"] == 0
    assert any(
        finding.get("provider") == "aws_access_key_id" for finding in result["secrets"]
    )


def test_yaml_only_directory_remains_secret_scannable(tmp_path):
    manifest = tmp_path / "config" / "secret.yaml"
    manifest.parent.mkdir()
    manifest.write_text(
        f'aws_access_key_id: "{_fake_aws_access_key_id()}"\n',
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), enable_secrets=True))

    assert any(
        finding.get("provider") == "aws_access_key_id" for finding in result["secrets"]
    )
    assert result["analysis_summary"]["secrets_count"] == len(result["secrets"])


def test_direct_yaml_symlink_is_not_followed_by_analyzer(tmp_path):
    manifest = tmp_path / "secret.yaml"
    manifest.write_text(
        f'aws_access_key_id: "{_fake_aws_access_key_id()}"\n',
        encoding="utf-8",
    )
    link = tmp_path / "secret-link.yaml"
    try:
        link.symlink_to(manifest)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    result = json.loads(analyze(str(link), enable_secrets=True, enable_danger=True))

    assert result.get("secrets", []) == []
    assert result.get("danger", []) == []
    assert result["analysis_errors"] == []


def test_config_registry_and_analyzer_include_deployment_rules(tmp_path):
    _write_app(tmp_path)
    manifest = _write_kubernetes(tmp_path, server_flags=("--reload",))

    registry_ids = _rule_ids(scan_config_files(tmp_path))
    directory_result = json.loads(analyze(str(tmp_path), enable_danger=True))
    direct_result = json.loads(analyze(str(manifest), enable_danger=True))

    assert {"SKY-DEP001", "SKY-DEP003"} <= registry_ids
    assert "SKY-DEP001" in _rule_ids(directory_result["danger"])
    assert "SKY-DEP003" in _rule_ids(directory_result["reliability"])
    assert "SKY-DEP003" in _rule_ids(direct_result["reliability"])
    assert "SKY-DEP003" not in _rule_ids(direct_result["danger"])
    assert direct_result["analysis_errors"] == []
    assert direct_result["analysis_summary"]["analysis_error_count"] == 0
    assert directory_result["analysis_summary"]["reliability_count"] == len(
        directory_result["reliability"]
    )


def test_rule_catalog_deployment_query_discovers_full_family():
    assert {entry["id"] for entry in get_rule_catalog("deployment")} == {
        "SKY-DEP001",
        "SKY-DEP002",
        "SKY-DEP003",
    }
