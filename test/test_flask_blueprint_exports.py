"""Flask blueprint callbacks can live in a module importing its blueprint."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _scan(root, *, register=True, blueprint_tail="", provider="flask"):
    files = {
        "app/__init__.py": "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    from app.views import bp\n"
        + ("    app.register_blueprint(bp)\n" if register else "")
        + "    return app\n",
        "app/views/__init__.py": f"from {provider} import Blueprint\nbp = Blueprint('main', __name__)\n"
        + blueprint_tail
        + "\nfrom app.views import routes\n",
        "app/views/routes.py": "from app.views import bp\n@bp.before_app_request\ndef prepare(): return helper()\ndef helper(): return 1\ndef retired(): return 2\n",
        "lookalike.py": "class Blueprint: pass\n",
    }
    for path, body in files.items():
        write_fixture(root, path, textwrap.dedent(body).lstrip(), overwrite=True)
    return json.loads(analyze(str(root), grep_verify=False, grep_cache=False))


def _unused(result):
    return {item["full_name"] for item in result.get("unused_functions", [])}


def test_registered_blueprint_export_keeps_imported_app_hook(tmp_path):
    unused = _unused(_scan(tmp_path))
    assert "app.views.routes.prepare" not in unused
    assert "app.views.routes.helper" not in unused
    assert "app.views.routes.retired" in unused


@pytest.mark.parametrize(
    "options",
    [
        {"register": False},
        {"blueprint_tail": "bp = replacement\n"},
        {"provider": "lookalike"},
    ],
)
def test_unregistered_replaced_or_fake_blueprint_does_not_rescue_hook(
    tmp_path, options
):
    unused = _unused(_scan(tmp_path, **options))
    assert "app.views.routes.prepare" in unused
    assert "app.views.routes.helper" in unused
    assert "app.views.routes.retired" in unused
