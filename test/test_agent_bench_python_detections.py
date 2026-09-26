"""Regression tests for detections added after the agent-code benchmark.

Covers SKY-D349 (SSTI), SKY-D346 (Flask debug via app factory), SKY-D231
(wildcard CORS with credentials) and SKY-L014 (real-looking secret literals
in annotated defaults and env/config fallbacks).
"""

import ast
import textwrap
from pathlib import Path

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx
from skylos.rules.quality.logic_security import HardcodedCredentialRule


def _danger(tmp_path: Path, code: str, name: str = "app_mod.py") -> list[dict]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return scan_ctx(tmp_path, [path])


def _calls(code: str, filename: str = "microblog.py") -> list[dict]:
    linter = LinterVisitor([DangerousCallsRule()], filename)
    linter.visit(ast.parse(textwrap.dedent(code)))
    return linter.findings


def _creds(code: str, filename: str = "config.py") -> list[dict]:
    rule = HardcodedCredentialRule()
    findings = []
    for node in ast.walk(ast.parse(textwrap.dedent(code))):
        found = rule.visit_node(node, {"filename": filename})
        if found:
            findings.extend(found)
    return findings


def _ids(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


# --- SKY-D349 server-side template injection ---------------------------------

SSTI_POSITIVES = {
    "concat": """
        from flask import Blueprint, request, render_template_string
        bp = Blueprint("main", __name__)

        @bp.route("/banner")
        def banner():
            message = request.args.get("message", "Welcome back!")
            return render_template_string(
                '<div class="alert alert-info">' + message + '</div>')
    """,
    "fstring": """
        from flask import Flask, request, render_template_string
        app = Flask(__name__)

        @app.route("/hello")
        def hello():
            return render_template_string(f"<h1>{request.args['name']}</h1>")
    """,
    "format_via_variable": """
        from flask import Flask, request, render_template_string
        app = Flask(__name__)

        @app.route("/hello")
        def hello():
            tmpl = "<h1>{}</h1>".format(request.form["name"])
            return render_template_string(tmpl)
    """,
    "jinja_from_string": """
        import jinja2
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/r")
        def r():
            return jinja2.Environment().from_string(request.data.decode()).render()
    """,
}


@pytest.mark.parametrize("code", SSTI_POSITIVES.values(), ids=SSTI_POSITIVES.keys())
def test_ssti_detected_with_request_evidence(tmp_path, code):
    findings = _ids(_danger(tmp_path, code), "SKY-D349")
    assert len(findings) == 1
    evidence = findings[0]["security_evidence"]
    assert "request" in evidence["source"]
    assert evidence["evidence_kind"] == "python_ssti_taint"


SSTI_NEGATIVES = {
    "context_variable": """
        from flask import Flask, request, render_template_string
        app = Flask(__name__)

        @app.route("/hello")
        def hello():
            return render_template_string("<h1>{{ name }}</h1>", name=request.args["name"])
    """,
    "constant_template": """
        from flask import render_template_string
        HEADER = "<h1>Hi</h1>"

        def page():
            return render_template_string(HEADER + "<p>static</p>")
    """,
    "operator_config_only": """
        import os
        from flask import render_template_string

        def banner():
            return render_template_string(os.environ.get("BANNER_TEMPLATE", "") + "<p/>")
    """,
    "plain_helper_parameter": """
        from flask import render_template_string

        def render_email(body_template):
            return render_template_string("<div>" + body_template + "</div>")
    """,
}


@pytest.mark.parametrize("code", SSTI_NEGATIVES.values(), ids=SSTI_NEGATIVES.keys())
def test_ssti_safe_forms_not_reported(tmp_path, code):
    assert _ids(_danger(tmp_path, code), "SKY-D349") == []


# --- SKY-D346 Flask debug mode ------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        """
        from app import create_app
        app = create_app()
        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000, debug=True)
        """,
        """
        from myservice.web import app
        app.run(debug=True)
        """,
        """
        from flask_socketio import SocketIO
        socketio = SocketIO()
        socketio.run(app, debug=True)
        """,
        """
        from app import create_app
        create_app().run(debug=True)
        """,
    ],
)
def test_flask_debug_run_via_factory_or_import(code):
    assert len(_ids(_calls(code), "SKY-D346")) == 1


@pytest.mark.parametrize(
    "code,filename",
    [
        ("from app import create_app\napp = create_app()\napp.run(debug=False)\n", "run.py"),
        ("import uvicorn\nuvicorn.run(app, debug=True)\n", "run.py"),
        ("pipeline.run(debug=True)\n", "run.py"),
        ("import os\napp.run(debug=os.environ.get('DEBUG') == '1')\n", "run.py"),
        ("from app import create_app\ncreate_app().run(debug=True)\n", "tests/test_app.py"),
    ],
)
def test_flask_debug_negatives(code, filename):
    assert _ids(_calls(code, filename), "SKY-D346") == []


def test_flask_debug_direct_flask_reported_once():
    code = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
    assert len(_ids(_calls(code), "SKY-D346")) == 1


# --- SKY-D231 wildcard CORS with credentials ------------------------------------

CORS_POSITIVES = {
    "flask_cors": """
        from flask import Flask
        from flask_cors import CORS
        app = Flask(__name__)
        CORS(app, supports_credentials=True, origins="*")
    """,
    "flask_cors_resources": """
        from flask_cors import CORS
        CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
    """,
    "fastapi_add_middleware": """
        from fastapi import FastAPI
        from starlette.middleware.cors import CORSMiddleware
        app = FastAPI()
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
        )
    """,
    "starlette_middleware_list": """
        from starlette.middleware import Middleware
        from starlette.middleware.cors import CORSMiddleware
        middleware = [Middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)]
    """,
}


@pytest.mark.parametrize("code", CORS_POSITIVES.values(), ids=CORS_POSITIVES.keys())
def test_cors_wildcard_with_credentials(tmp_path, code):
    findings = [
        f
        for f in _ids(_danger(tmp_path, code), "SKY-D231")
        if "credential" in f["message"]
    ]
    assert len(findings) == 1


def test_fastapi_cors_finding_anchors_origin_line(tmp_path):
    findings = _ids(_danger(tmp_path, CORS_POSITIVES["fastapi_add_middleware"]), "SKY-D231")
    assert findings[0]["line"] == 7


CORS_NEGATIVES = {
    "explicit_origins_with_credentials": """
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[settings.FRONTEND_HOST],
            allow_credentials=True,
        )
    """,
    "wildcard_without_credentials": """
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False)
    """,
    "flask_cors_listed_origins": """
        from flask_cors import CORS
        CORS(app, origins=["https://app.example.org"], supports_credentials=True)
    """,
}


@pytest.mark.parametrize("code", CORS_NEGATIVES.values(), ids=CORS_NEGATIVES.keys())
def test_cors_safe_forms(tmp_path, code):
    assert _ids(_danger(tmp_path, code), "SKY-D231") == []


# --- SKY-L014 secret literals in defaults / fallbacks -----------------------------

SECRET_POSITIVES = {
    "or_fallback_password": (
        "import os\nclass Config:\n"
        "    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'Mb!2024-smtp-Pa55w0rd'\n",
        3,
    ),
    "hex_key_config_fallback": (
        "def t(current_app):\n"
        "    subscription_key = current_app.config.get('MS_TRANSLATOR_KEY') or \\\n"
        "        '4f2b9c1e7d8a4b3f9e6c0a1d2b3c4e5f'\n",
        3,
    ),
    "annotated_settings_default": (
        "class Settings:\n"
        '    SECRET_KEY: str = "7f3d9a1c5e8b2046d1f4a7c9e3b58d20a6c1f9e4b7d3a8c2"\n',
        2,
    ),
    "getenv_default": (
        "import os\nSTRIPE_KEY = os.getenv('STRIPE_KEY', 'rk9Qz2LmX7vB4nT1pW8sK3dF')\n",
        2,
    ),
    "env_name_marks_credential": (
        "import os\nkey = os.environ.get('SIGNING_SECRET', 'a91f03c7e2b84d6f9c05e1a7b3d2f468')\n",
        2,
    ),
}


@pytest.mark.parametrize(
    "code,line", SECRET_POSITIVES.values(), ids=SECRET_POSITIVES.keys()
)
def test_secret_fallback_literals(code, line):
    findings = _ids(_creds(code), "SKY-L014")
    assert [f["line"] for f in findings] == [line]
    assert findings[0]["value"] == "hardcoded_fallback"


SECRET_NEGATIVES = {
    "placeholder_changethis": 'class S:\n    SECRET_KEY: str = "changethis"\n',
    "placeholder_hint": "import os\nAPI_KEY = os.getenv('API_KEY', 'your-api-key-here-123')\n",
    "dev_default": "import os\nSECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-9f8e7d'\n",
    "empty_default": "import os\nPASSWORD = os.getenv('PASSWORD', '')\n",
    "non_credential_name": "import os\nREGION = os.getenv('REGION', '4f2b9c1e7d8a4b3f9e6c0a1d2b3c4e5f')\n",
    "annotated_non_secret": 'class S:\n    PROJECT_NAME: str = "Xk29fLq8Wm3Rt7Vb1Nz5"\n',
    "annotated_no_value": "class S:\n    SECRET_KEY: str\n",
    "annotated_computed": "import secrets\nclass S:\n    SECRET_KEY: str = secrets.token_urlsafe(32)\n",
    "short_word_fallback": "import os\nDB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres')\n",
}


@pytest.mark.parametrize("code", SECRET_NEGATIVES.values(), ids=SECRET_NEGATIVES.keys())
def test_secret_fallback_negatives(code):
    assert _ids(_creds(code), "SKY-L014") == []


def test_secret_fallback_skipped_in_tests():
    code = SECRET_POSITIVES["or_fallback_password"][0]
    assert _creds(code, filename="test_config.py") == []
