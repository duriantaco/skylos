"""Framework decorator registry keyed by resolved import origin.

Root inference must not treat a bare decorator *name* as evidence of framework
registration.  A project-local ``@register`` no-op shares its name with plugin
registration APIs, so name matching silently rescues genuinely dead code.  The
registry below is keyed by the dotted origin a decorator resolves to after
import and instance binding, so ``@register`` from a first-party module never
matches ``pluggy``'s hook marker.

Confidence tiers are consumed by the evidence ledger:

``EXACT``
    The origin is a known framework registration decorator.
``FRAMEWORK_PACKAGE``
    The origin resolves into a known framework distribution, but the specific
    attribute is not in the registry.  Importing a decorator from Flask is
    still strong evidence of registration, so this stays above the default
    liveness threshold.
``UNKNOWN_THIRD_PARTY`` / ``UNRESOLVED``
    Below the default threshold.  These become uncertainty evidence rather
    than liveness, so the reporter abstains instead of declaring the symbol
    alive.
"""

from __future__ import annotations

from typing import Final

from skylos.research.dead_code.roots import RootKind

CONFIDENCE_EXACT: Final[float] = 1.0
CONFIDENCE_FRAMEWORK_PACKAGE: Final[float] = 0.75
CONFIDENCE_UNKNOWN_THIRD_PARTY: Final[float] = 0.35
CONFIDENCE_UNRESOLVED: Final[float] = 0.25

_HTTP_METHOD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
        "websocket",
        "api_route",
        "add_api_route",
    }
)

_ROUTER_CLASSES: Final[tuple[str, ...]] = (
    "flask.Flask",
    "flask.Blueprint",
    "fastapi.FastAPI",
    "fastapi.APIRouter",
    "starlette.applications.Starlette",
    "starlette.routing.Router",
    "sanic.Sanic",
    "sanic.Blueprint",
    "quart.Quart",
    "quart.Blueprint",
    "aiohttp.web.RouteTableDef",
    "litestar.Litestar",
    "bottle.Bottle",
)

_CLI_GROUP_CLASSES: Final[tuple[str, ...]] = (
    "click.Group",
    "click.Command",
    "typer.Typer",
    "flask.cli.AppGroup",
)

_CLI_MODULE_DECORATORS: Final[tuple[str, ...]] = (
    "click.command",
    "click.group",
    "typer.run",
)

_TASK_DECORATORS: Final[tuple[str, ...]] = (
    "celery.shared_task",
    "celery.Celery.task",
    "celery.app.base.Celery.task",
    "rq.job",
    "dramatiq.actor",
    "huey.Huey.task",
    "huey.Huey.periodic_task",
    "apscheduler.schedulers.base.BaseScheduler.scheduled_job",
)

_TEST_DECORATORS: Final[tuple[str, ...]] = (
    "pytest.fixture",
    "_pytest.fixtures.fixture",
    "unittest.mock.patch",
)

_VALIDATOR_DECORATORS: Final[tuple[str, ...]] = (
    "pydantic.validator",
    "pydantic.field_validator",
    "pydantic.model_validator",
    "pydantic.root_validator",
    "pydantic.functional_validators.field_validator",
    "pydantic.functional_validators.model_validator",
    "sqlalchemy.orm.validates",
    "marshmallow.validates",
    "marshmallow.validates_schema",
    "marshmallow.decorators.validates",
    "marshmallow.decorators.validates_schema",
)

_SERIALIZER_DECORATORS: Final[tuple[str, ...]] = (
    "pydantic.field_serializer",
    "pydantic.model_serializer",
    "pydantic.computed_field",
    "pydantic.functional_serializers.field_serializer",
    "pydantic.functional_serializers.model_serializer",
    "marshmallow.pre_load",
    "marshmallow.post_load",
    "marshmallow.pre_dump",
    "marshmallow.post_dump",
    "marshmallow.decorators.pre_load",
    "marshmallow.decorators.post_load",
    "marshmallow.decorators.pre_dump",
    "marshmallow.decorators.post_dump",
)

_PLUGIN_DECORATORS: Final[tuple[str, ...]] = (
    "pluggy.HookimplMarker",
    "pluggy.HookspecMarker",
    "django.dispatch.receiver",
    "blinker.Signal.connect",
    "pyramid.events.subscriber",
    "pyramid.view.view_config",
)


def _build_registry() -> dict[str, RootKind]:
    registry: dict[str, RootKind] = {}

    for class_origin in _ROUTER_CLASSES:
        for method in _HTTP_METHOD_NAMES:
            registry[f"{class_origin}.{method}"] = RootKind.FRAMEWORK_ROUTE

    for class_origin in _CLI_GROUP_CLASSES:
        for method in ("command", "group", "callback", "result_callback"):
            registry[f"{class_origin}.{method}"] = RootKind.CLI_COMMAND
    for origin in _CLI_MODULE_DECORATORS:
        registry[origin] = RootKind.CLI_COMMAND
    registry["flask.Flask.cli.command"] = RootKind.CLI_COMMAND

    for origin in _TASK_DECORATORS:
        registry[origin] = RootKind.TASK
    for origin in _TEST_DECORATORS:
        registry[origin] = RootKind.TEST
    for origin in _VALIDATOR_DECORATORS:
        registry[origin] = RootKind.VALIDATOR
    for origin in _SERIALIZER_DECORATORS:
        registry[origin] = RootKind.SERIALIZER
    for origin in _PLUGIN_DECORATORS:
        registry[origin] = RootKind.PLUGIN_HOOK

    return registry


DECORATOR_ORIGIN_REGISTRY: Final[dict[str, RootKind]] = _build_registry()

KNOWN_FRAMEWORK_PACKAGES: Final[frozenset[str]] = frozenset(
    {
        "aiohttp",
        "apscheduler",
        "blinker",
        "bottle",
        "celery",
        "click",
        "django",
        "dramatiq",
        "fastapi",
        "flask",
        "huey",
        "litestar",
        "marshmallow",
        "pluggy",
        "pydantic",
        "pyramid",
        "pytest",
        "quart",
        "rq",
        "sanic",
        "sqlalchemy",
        "starlette",
        "strawberry",
        "tornado",
        "typer",
        "_pytest",
    }
)

FRAMEWORK_INSTANCE_CLASSES: Final[frozenset[str]] = frozenset(
    (
        *_ROUTER_CLASSES,
        *_CLI_GROUP_CLASSES,
        "celery.Celery",
        "pluggy.HookimplMarker",
        "pluggy.HookspecMarker",
        "huey.Huey",
        "typer.Typer",
    )
)

GROUP_PRODUCING_DECORATORS: Final[dict[str, str]] = {
    "click.group": "click.Group",
    "click.command": "click.Command",
    "click.Group.group": "click.Group",
    "click.Group.command": "click.Command",
}


def lookup_origin(origin: str) -> RootKind | None:
    """Return the root kind for a fully resolved decorator origin."""
    return DECORATOR_ORIGIN_REGISTRY.get(origin)


def top_level_package(origin: str) -> str:
    return origin.split(".", 1)[0]


def is_known_framework_origin(origin: str) -> bool:
    return top_level_package(origin) in KNOWN_FRAMEWORK_PACKAGES
