"""Static callback registration needs an actual provider, not a method name."""

import pytest

from test.web_framework_fixtures import _scan, _unused


@pytest.mark.parametrize(
    "method",
    ["user_loader", "request_loader", "unauthorized_handler", "needs_refresh_handler"],
)
@pytest.mark.parametrize("imported", [False, True])
def test_login_manager_callbacks_preserve_helpers_and_dead_siblings(
    tmp_path, method, imported
):
    provider = "from flask_login import LoginManager\nlogin = LoginManager()\n"
    callback = (
        f"@login.{method}\ndef callback(value=None): return helper()\n"
        "def helper(): return 1\ndef retired(): return 2\n"
    )
    sources = {"app.py": provider + callback}
    if imported:
        sources = {
            "providers.py": provider,
            "app.py": "from providers import login\n" + callback,
        }
    result = _scan(tmp_path, sources)
    unused = _unused(result)
    assert "app.callback" not in unused
    assert "app.helper" not in unused
    assert "app.retired" in unused
    assert any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )


@pytest.mark.parametrize(
    "provider",
    [
        "class LoginManager: pass\nlogin = LoginManager()\n",
        "from flask_login import LoginManager\nLoginManager = replacement\nlogin = LoginManager()\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nlogin = replacement\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nlogin.user_loader = replacement\n",
        "from flask_login import LoginManager\nLoginManager.user_loader = replacement\nlogin = LoginManager()\n",
        "import flask_login\nflask_login.LoginManager = replacement\nlogin = flask_login.LoginManager()\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nsetattr(login, 'user_loader', replacement)\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nlogin.__dict__['user_loader'] = replacement\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nfrom unittest.mock import patch\npatch('providers.login.user_loader', replacement).start()\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nfrom unittest.mock import patch\npatch.object(LoginManager, 'user_loader', replacement).start()\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nglobals().update({'login': replacement})\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\ndef replace():\n    global login\n    login = replacement\nreplace()\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\ndef replace():\n    login.user_loader = replacement\nopaque(replace)\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nopaque(login)\n",
        "from flask_login import LoginManager\nLoginManager.__new__ = replacement\nlogin = LoginManager()\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nlogin.__class__ = replacement\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nLoginManager.user_loader.__code__ = replacement.__code__\n",
        "from flask_login import LoginManager\nlogin = LoginManager()\nopaque(LoginManager)\n",
    ],
)
def test_lookalike_replaced_and_patched_login_providers_do_not_prove_callbacks(
    tmp_path, provider
):
    result = _scan(
        tmp_path,
        {
            "providers.py": provider,
            "app.py": "from providers import login\n@login.user_loader\ndef callback(): return 1\n",
        },
    )
    evidence = result["definitions"]["app.callback"]["dead_code_evidence"]
    assert not any(item["kind"] == "framework_root" for item in evidence)


def test_import_cycle_does_not_invent_a_callback_provider(tmp_path):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from other import login\n",
            "other.py": "from providers import login\n",
            "app.py": "from providers import login\n@login.user_loader\ndef callback(): return 1\n",
        },
    )
    assert "app.callback" in _unused(result)


@pytest.mark.parametrize(
    "escape", ["opaque(login)", "values = {'manager': login}; opaque(values)"]
)
def test_imported_manager_passed_to_opaque_consumer_stays_unknown(tmp_path, escape):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask_login import LoginManager\nlogin = LoginManager()\n",
            "app.py": "from providers import login\n"
            + escape
            + "\n@login.user_loader\ndef callback(): return 1\n",
        },
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )


def test_login_view_configuration_does_not_replace_loader_registration(tmp_path):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask_login import LoginManager\nlogin = LoginManager()\nlogin.login_view = 'auth.login'\n",
            "app.py": "from providers import login\n@login.user_loader\ndef callback(user_id): return user_id\ndef retired(): return 1\n",
        },
    )
    assert "app.callback" not in _unused(result)
    assert "app.retired" in _unused(result)


def test_imported_flask_instance_shell_context_is_a_registered_callback(tmp_path):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask import Flask\napp = Flask(__name__)\n",
            "app.py": "from providers import app\n@app.shell_context_processor\ndef shell_context(): return {'value': helper()}\ndef helper(): return 1\ndef retired(): return 2\n",
        },
    )
    assert "app.shell_context" not in _unused(result)
    assert "app.helper" not in _unused(result)
    assert "app.retired" in _unused(result)


def test_factory_result_without_instance_identity_stays_unproved(tmp_path):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    return app\n",
            "app.py": "from providers import create_app\napp = create_app()\nalias = app\nalias.shell_context_processor = replacement\n@app.shell_context_processor\ndef callback(): return {}\n",
        },
    )
    assert "app.callback" in _unused(result)
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )


@pytest.mark.parametrize("receiver", ["login", "alias"])
def test_global_replacement_of_imported_receiver_does_not_prove_callback(
    tmp_path, receiver
):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask_login import LoginManager\nlogin = LoginManager()\n",
            "app.py": "from providers import login\nalias = login\ndef replace():\n    global "
            + receiver
            + "\n    "
            + receiver
            + " = replacement\nreplace()\n@"
            + receiver
            + ".user_loader\ndef callback(): return 1\n",
        },
    )
    assert "app.callback" in _unused(result)
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )


def test_global_constructor_replacement_keeps_callback_unproved(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": "from flask_login import LoginManager\ndef replace():\n    global LoginManager\n    LoginManager = replacement\nreplace()\nlogin = LoginManager()\n@login.user_loader\ndef callback(): return 1\n"
        },
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )


@pytest.mark.parametrize(
    "factory",
    [
        "from flask import Flask\ndef create_app():\n    return replacement\n",
        "from flask import Flask\ndef create_app(Flask):\n    app = Flask(__name__)\n    return app\n",
        "from flask import Flask\ndef create_app(flag):\n    if flag:\n        return replacement\n    app = Flask(__name__)\n    return app\n",
        "from flask import Flask\n@decorator\ndef create_app():\n    app = Flask(__name__)\n    return app\n",
        "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    return app\ncreate_app = replacement\n",
        "from flask import Flask\nasync def create_app():\n    app = Flask(__name__)\n    return app\n",
        "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    yield 1\n    return app\n",
        "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    yield from []\n    return app\n",
    ],
)
def test_unknown_mixed_and_replaced_factory_results_do_not_prove_shell_hooks(
    tmp_path, factory
):
    result = _scan(
        tmp_path,
        {
            "providers.py": factory,
            "app.py": "from providers import create_app\napp = create_app()\n@app.shell_context_processor\ndef shell_context(): return {}\n",
        },
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.shell_context"]["dead_code_evidence"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "app.shell_context_processor = replacement",
        "setattr(app, 'shell_context_processor', replacement)",
        "alias = app; alias.shell_context_processor = replacement",
        "opaque(app)",
        "alias = app; opaque(alias)",
        "holder.value = app",
        "opaque({'app': app})",
        "patch = lambda: app; opaque(patch)",
    ],
)
def test_mutated_or_escaped_factory_objects_do_not_prove_shell_hooks(tmp_path, change):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    "
            + change
            + "\n    return app\n",
            "app.py": "from providers import create_app\napp = create_app()\n@app.shell_context_processor\ndef shell_context(): return {}\n",
        },
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.shell_context"]["dead_code_evidence"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "app.shell_context_processor = replacement",
        "setattr(app, 'shell_context_processor', replacement)",
        "if flag:\n    app = replacement",
    ],
)
def test_factory_result_replacement_in_consumer_stays_unknown(tmp_path, change):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    return app\n",
            "app.py": "from providers import create_app\napp = create_app()\n"
            + change
            + "\n@app.shell_context_processor\ndef shell_context(): return {}\n",
        },
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.shell_context"]["dead_code_evidence"]
    )


@pytest.mark.parametrize(
    "provider, decorator",
    [
        (
            "from flask_login import LoginManager\nlogin = LoginManager()\n",
            "login.config.user_loader",
        ),
        (
            "from flask import Flask\napp = Flask(__name__)\n",
            "app.config.shell_context_processor",
        ),
        (
            "from flask import Flask\napp = Flask(__name__)\nother = app.config\n",
            "other.shell_context_processor",
        ),
    ],
)
def test_attributes_of_framework_objects_are_not_the_provider_itself(
    tmp_path, provider, decorator
):
    result = _scan(
        tmp_path, {"app.py": provider + f"@{decorator}\ndef callback(): return 1\n"}
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )


def test_factory_returning_an_attribute_is_not_a_flask_instance_proof(tmp_path):
    result = _scan(
        tmp_path,
        {
            "providers.py": "from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    return app.config\n",
            "app.py": "from providers import create_app\napp = create_app()\n@app.shell_context_processor\ndef callback(): return {}\n",
        },
    )
    assert not any(
        item["kind"] == "framework_root"
        for item in result["definitions"]["app.callback"]["dead_code_evidence"]
    )
