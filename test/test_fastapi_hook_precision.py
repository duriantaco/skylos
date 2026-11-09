"""FastAPI callbacks require actual providers, registrations and callback roles."""

import json

import pytest

from skylos.analyzer import Skylos


def _scan(root, sources, *, conf=0, grep=False):
    for filename, source in sources.items():
        path = root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(root), thr=conf, grep_verify=grep))
    assert not result.get("analysis_errors")
    return result, {item.name: item for item in analyzer.defs.values()}


_STARTUP = "def startup():\n    return helper()\n\ndef helper():\n    return 1\n\n"
_HANDLER = "def handle_error(request, exc):\n    return helper()\n\ndef helper():\n    return 1\n\n"


def _unused(result, bucket="unused_functions"):
    return {item["full_name"] for item in result[bucket]}


@pytest.mark.parametrize("conf", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_startup_in_an_uncalled_app_factory_is_unused(tmp_path, conf, grep):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": "from fastapi import FastAPI\n"
            + _STARTUP
            + "def unused_factory():\n    return FastAPI(on_startup=[startup])\n"
        },
        conf=conf,
        grep=grep,
    )
    assert {"app.startup", "app.helper", "app.unused_factory"} <= _unused(result)
    assert "framework_root" not in definitions["app.startup"].heuristic_refs


@pytest.mark.parametrize("conf", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_exception_handler_in_uncalled_setup_is_unused(tmp_path, conf, grep):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": "from fastapi import FastAPI\n"
            + _HANDLER
            + "app = FastAPI()\ndef unused_setup():\n    app.add_exception_handler(Exception, handle_error)\n"
        },
        conf=conf,
        grep=grep,
    )
    assert {"app.handle_error", "app.helper", "app.unused_setup"} <= _unused(result)
    assert "framework_root" not in definitions["app.handle_error"].heuristic_refs


@pytest.mark.parametrize(
    "role", ["on_startup", "on_shutdown", "exception_handlers", "lifespan"]
)
def test_actual_constructor_callbacks_and_required_parameters_are_live(tmp_path, role):
    source = "from fastapi import FastAPI as App\n"
    hook = "def callback():\n    return helper()\n"
    value = "[callback]"
    if role == "exception_handlers":
        hook = "def callback(request, exc):\n    return helper()\n"
        value = "{Exception: callback}"
    elif role == "lifespan":
        source += "from contextlib import asynccontextmanager\n"
        hook = (
            "@asynccontextmanager\nasync def callback(app):\n    helper()\n    yield\n"
        )
        value = "callback"
    source += hook + "\ndef helper(): return 1\napp = App(" + role + "=" + value + ")\n"
    result, definitions = _scan(tmp_path, {"app.py": source})
    assert not {"app.callback", "app.helper"} & _unused(result)
    assert definitions["app.callback"].heuristic_refs.get("framework_root") == 1.0
    assert not {
        name
        for name in _unused(result, "unused_parameters")
        if name.startswith("app.callback.")
    }


@pytest.mark.parametrize("included", [False, True])
def test_router_lifespan_needs_inclusion_and_its_app_argument_is_a_contract(
    tmp_path, included
):
    source = (
        "from fastapi import FastAPI, APIRouter\n"
        "from contextlib import asynccontextmanager\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    helper()\n    yield\n"
        "def helper(): return 1\n"
        "router = APIRouter(lifespan=lifespan)\napp = FastAPI()\n"
    )
    if included:
        source += "app.include_router(router)\n"
    result, definitions = _scan(tmp_path, {"app.py": source})
    rooted = "framework_root" in definitions["app.lifespan"].heuristic_refs
    assert rooted is included
    if included:
        assert "app.lifespan.app" not in _unused(result, "unused_parameters")


@pytest.mark.parametrize(
    "setup, registration",
    [
        (
            "class FastAPI:\n    def __init__(self, **kwargs): pass\n",
            "app = FastAPI(on_startup=[startup])\n",
        ),
        (
            "from fastapi import FastAPI as App\nApp = lambda **kwargs: None\n",
            "app = App(on_startup=[startup])\n",
        ),
        (
            "from fastapi import FastAPI\n",
            "def unused_factory(FastAPI):\n    return FastAPI(on_startup=[startup])\n",
        ),
        (
            "import fastapi\nclass Sink:\n    def add_exception_handler(self, exc, handler): pass\napp = Sink()\n",
            "app.add_exception_handler(Exception, startup)\n",
        ),
    ],
)
def test_fake_shadowed_and_rebound_providers_do_not_prove_callback_execution(
    tmp_path, setup, registration
):
    _, definitions = _scan(tmp_path, {"app.py": setup + _STARTUP + registration})
    assert "framework_root" not in definitions["app.startup"].heuristic_refs


@pytest.mark.parametrize(
    "decorator",
    ["middleware('http')", "exception_handler(Exception)", "on_event('startup')"],
)
def test_identity_lookalike_decorators_are_not_framework_callbacks(tmp_path, decorator):
    method = decorator.split("(", 1)[0]
    source = (
        "class Sink:\n    def "
        + method
        + "(self, option):\n        return lambda fn: fn\n"
        "app = Sink()\n@app."
        + decorator
        + "\ndef callback(*args):\n    return helper()\n"
        "def helper(): return 1\n"
    )
    _, definitions = _scan(tmp_path, {"app.py": source})
    assert "framework_root" not in definitions["app.callback"].heuristic_refs


def test_imperative_exception_handler_consumes_its_request_and_exception_parameters(
    tmp_path,
):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": "from fastapi import FastAPI\n"
            + _HANDLER
            + "app = FastAPI()\napp.add_exception_handler(Exception, handle_error)\n"
        },
    )
    assert definitions["app.handle_error"].heuristic_refs.get("framework_root") == 1.0
    assert not {"app.handle_error.request", "app.handle_error.exc"} & _unused(
        result, "unused_parameters"
    )


@pytest.mark.parametrize("style", ["imperative", "decorator"])
def test_middleware_dispatch_parameters_are_required(tmp_path, style):
    source = "from fastapi import FastAPI\nfrom starlette.middleware.base import BaseHTTPMiddleware\napp = FastAPI()\n"
    if style == "decorator":
        source += "@app.middleware('http')\n"
    source += "async def timing(request, call_next):\n    return helper()\ndef helper(): return 1\n"
    if style == "imperative":
        source += "app.add_middleware(BaseHTTPMiddleware, dispatch=timing)\n"
    result, definitions = _scan(tmp_path, {"app.py": source})
    assert definitions["app.timing"].heuristic_refs.get("framework_root") == 1.0
    assert not {"app.timing.request", "app.timing.call_next"} & _unused(
        result, "unused_parameters"
    )


def test_custom_lifespan_does_not_prove_the_replaced_startup_events_run(tmp_path):
    _, definitions = _scan(
        tmp_path,
        {
            "app.py": "from fastapi import FastAPI\nfrom contextlib import asynccontextmanager\n"
            + _STARTUP
            + "@asynccontextmanager\nasync def lifespan(app):\n    yield\napp = FastAPI(lifespan=lifespan, on_startup=[startup])\n"
        },
    )
    assert definitions["app.lifespan"].heuristic_refs.get("framework_root") == 1.0
    assert "framework_root" not in definitions["app.startup"].heuristic_refs


@pytest.mark.parametrize("role", ["lifespan", "exception_handler", "middleware"])
def test_callback_contract_preserves_only_the_framework_supplied_arguments(
    tmp_path, role
):
    source = "from fastapi import FastAPI\napp = FastAPI()\n"
    if role == "lifespan":
        source += (
            "from contextlib import asynccontextmanager\n"
            "@asynccontextmanager\nasync def callback(app, legacy=None):\n    yield\n"
            "app = FastAPI(lifespan=callback)\n"
        )
        supplied = {"app.callback.app"}
    elif role == "exception_handler":
        source += (
            "def callback(request, exc, legacy=None): return 1\n"
            "app.add_exception_handler(Exception, callback)\n"
        )
        supplied = {"app.callback.request", "app.callback.exc"}
    else:
        source += (
            "from starlette.middleware.base import BaseHTTPMiddleware\n"
            "async def callback(request, call_next, legacy=None): return 1\n"
            "app.add_middleware(BaseHTTPMiddleware, dispatch=callback)\n"
        )
        supplied = {"app.callback.request", "app.callback.call_next"}
    result, _ = _scan(tmp_path, {"app.py": source})
    assert not supplied & _unused(result, "unused_parameters")
    assert "app.callback.legacy" in _unused(result, "unused_parameters")


@pytest.mark.parametrize("role", ["on_startup", "exception_handlers"])
def test_constructor_callback_containers_follow_source_bound_aliases(tmp_path, role):
    source = "from fastapi import FastAPI as App\n" + _HANDLER
    value = "{Exception: handle_error}"
    if role == "on_startup":
        source = "from fastapi import FastAPI as App\n" + _STARTUP
        value = "[startup]"
    source += (
        "callbacks = "
        + value
        + "\nconfigured = callbacks\napp = App("
        + role
        + "=configured)\n"
    )
    _, definitions = _scan(tmp_path, {"app.py": source})
    name = "app.handle_error"
    if role == "on_startup":
        name = "app.startup"
    assert definitions[name].heuristic_refs.get("framework_root") == 1.0


@pytest.mark.parametrize("provider", ["starlette.middleware", "fastapi.middleware"])
def test_constructor_base_http_middleware_dispatch_is_a_callback_contract(
    tmp_path, provider
):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from fastapi import FastAPI\n"
                "from " + provider + " import Middleware\n"
                "from starlette.middleware.base import BaseHTTPMiddleware\n"
                "async def timing(request, call_next): return 1\n"
                "app = FastAPI(middleware=[Middleware(BaseHTTPMiddleware, dispatch=timing)])\n"
            )
        },
    )
    assert definitions["app.timing"].heuristic_refs.get("framework_root") == 1.0
    assert not {"app.timing.request", "app.timing.call_next"} & _unused(
        result, "unused_parameters"
    )


@pytest.mark.parametrize(
    "method", ["add_exception_handler", "exception_handler", "middleware"]
)
def test_replaced_registration_methods_do_not_prove_callbacks_run(tmp_path, method):
    source = "from fastapi import FastAPI\napp = FastAPI()\n"
    if method == "add_exception_handler":
        source += (
            _HANDLER
            + "app.add_exception_handler = lambda *args: None\napp.add_exception_handler(Exception, handle_error)\n"
        )
        name = "app.handle_error"
    else:
        argument = "Exception"
        if method == "middleware":
            argument = "'http'"
        source += (
            "app." + method + " = lambda option: lambda fn: fn\n"
            "@app." + method + "(" + argument + ")\n"
            "def callback(request, extra): return 1\n"
        )
        name = "app.callback"
    _, definitions = _scan(tmp_path, {"app.py": source})
    assert "framework_root" not in definitions[name].heuristic_refs


def test_conditional_handler_has_a_signature_contract_without_a_proven_root(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "import os\nfrom fastapi import FastAPI\n"
                + _HANDLER
                + "app = FastAPI()\n"
                "if os.getenv('USE_HANDLER'):\n"
                "    app.add_exception_handler(Exception, handle_error)\n"
            )
        },
    )
    assert "framework_root" not in definitions["app.handle_error"].heuristic_refs
    assert "app.handle_error" not in _unused(result)
    assert not {"app.handle_error.request", "app.handle_error.exc"} & _unused(
        result, "unused_parameters"
    )


def test_conditional_registration_inside_a_dead_owner_remains_unused(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "import os\nfrom fastapi import FastAPI\n"
                + _HANDLER
                + "app = FastAPI()\ndef unused_setup():\n"
                "    if os.getenv('USE_HANDLER'):\n"
                "        app.add_exception_handler(Exception, handle_error)\n"
            )
        },
    )
    assert {"app.handle_error", "app.helper", "app.unused_setup"} <= _unused(result)
    assert "framework_root" not in definitions["app.handle_error"].heuristic_refs


def test_callable_instance_handler_uses_its_bound_signature(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from fastapi import FastAPI\n"
                "class Handler:\n    def __call__(self, request, exc): return 1\n"
                "handler = Handler()\napp = FastAPI()\n"
                "app.add_exception_handler(Exception, handler)\n"
            )
        },
    )
    assert (
        definitions["app.Handler.__call__"].heuristic_refs.get("framework_root") == 1.0
    )
    assert not {"app.Handler.__call__.request", "app.Handler.__call__.exc"} & _unused(
        result, "unused_parameters"
    )


def test_replacing_callback_decorator_cannot_prove_original_body_execution(tmp_path):
    _, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from fastapi import FastAPI\n"
                "def replace(fn): return lambda: None\n"
                "@replace\ndef startup(): return helper()\n"
                "def helper(): return 1\napp = FastAPI(on_startup=[startup])\n"
            )
        },
    )
    assert "framework_root" not in definitions["app.startup"].heuristic_refs


def test_plain_async_lifespan_is_not_an_entered_context_manager(tmp_path):
    _, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from fastapi import FastAPI\n"
                "async def lifespan(app): return helper()\n"
                "def helper(): return 1\napp = FastAPI(lifespan=lifespan)\n"
            )
        },
    )
    assert "framework_root" not in definitions["app.lifespan"].heuristic_refs


@pytest.mark.parametrize("same_object", [False, True])
def test_conditional_factory_result_preserves_handler_signature_uncertainty(
    tmp_path, same_object
):
    factory = (
        "def make_application(flag):\n    if flag:\n        return FastAPI()\n"
        "    else:\n        return FastAPI()\n"
    )
    if same_object:
        factory = (
            "def make_application(flag):\n    application = FastAPI()\n"
            "    if flag:\n        return application\n"
            "    else:\n        return application\n"
        )
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "import os\nfrom fastapi import FastAPI\n"
                + _HANDLER
                + factory
                + "app = make_application(os.getenv('APP_CHOICE'))\n"
                "app.add_exception_handler(Exception, handle_error)\n"
            )
        },
    )
    assert "app.handle_error" not in _unused(result)
    assert not {"app.handle_error.request", "app.handle_error.exc"} & _unused(
        result, "unused_parameters"
    )
    assert "framework_root" not in definitions["app.handle_error"].heuristic_refs


def test_known_fake_handler_registry_does_not_gain_unknown_framework_use(tmp_path):
    _, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from fastapi import FastAPI\n"
                + _HANDLER
                + "class Registry:\n    def add_exception_handler(self, exc, handler): pass\n"
                "app = Registry()\napp.add_exception_handler(Exception, handle_error)\n"
            )
        },
    )
    assert "framework_root" not in definitions["app.handle_error"].heuristic_refs
    assert "unresolved_callback" not in definitions["app.handle_error"].heuristic_refs


@pytest.mark.parametrize("provider_kind", ["class", "function"])
def test_source_owned_starlette_lookalike_does_not_prove_dispatch_execution(
    tmp_path, provider_kind
):
    provider = (
        "class BaseHTTPMiddleware:\n"
        "    def __init__(self, app, **kwargs): pass\n"
        "    async def __call__(self, scope, receive, send): pass\n"
    )
    if provider_kind == "function":
        provider = (
            "def BaseHTTPMiddleware(app, **kwargs):\n"
            "    async def middleware(scope, receive, send): pass\n"
            "    return middleware\n"
        )
    _, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from fastapi import FastAPI\n"
                "from starlette.middleware.base import BaseHTTPMiddleware\n"
                "def dispatch(request, call_next): return 1\n"
                "app = FastAPI()\n"
                "app.add_middleware(BaseHTTPMiddleware, dispatch=dispatch)\n"
            ),
            "starlette/__init__.py": "",
            "starlette/middleware/__init__.py": "",
            "starlette/middleware/base.py": provider,
        },
    )
    assert "framework_root" not in definitions["app.dispatch"].heuristic_refs
