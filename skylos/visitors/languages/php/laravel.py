"""Laravel classes that the framework loads by naming convention.

Laravel discovers these classes from where they live rather than from a
reference in PHP code: Artisan auto-registers ``Illuminate\\Console\\Command``
subclasses in ``app/Console/Commands``, event discovery wires ``app/Listeners``
classes whose ``handle*``/``__invoke`` method type-hints the event,
``HasFactory`` maps ``Model`` to ``Database\\Factories\\ModelFactory``, policy
discovery maps ``Model`` to ``ModelPolicy``, ``db:seed`` runs
``DatabaseSeeder``, Blade resolves ``<x-name>`` and ``<livewire:name>`` tags,
and the migrator loads every migration file.

The rules apply only inside a Laravel application root, a directory whose
``composer.json`` requires ``laravel/framework``, and only to classes that
carry the evidence the framework's own discovery needs. Base classes and
traits are resolved through the file's imports and, for project classes,
through the ``composer.json`` PSR-4 autoload map.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

from .core import PhpCore

_COMMANDS_DIR = "app/Console/Commands/"
_LISTENERS_DIR = "app/Listeners/"
_POLICIES_DIR = "app/Policies/"
_FACTORIES_DIR = "database/factories/"
_COMPONENT_DIRECTORIES = (
    "app/Livewire/",
    "app/Http/Livewire/",
    "app/View/Components/",
    "database/migrations/",
)
_CONVENTION_FILES: dict[str, str] = {
    "database/seeders/DatabaseSeeder.php": "DatabaseSeeder",
    "database/seeds/DatabaseSeeder.php": "DatabaseSeeder",
}
_ILLUMINATE_COMMAND = "Illuminate.Console.Command"
_HAS_FACTORY_TRAIT = "HasFactory"
_MAX_PARENT_DEPTH = 16
_MAX_SOURCE_BYTES = 1_000_000

_SHOULD_DISCOVER_EVENTS_TRUE_RE = re.compile(
    r"function\s+shouldDiscoverEvents\s*\(\s*\)\s*(?::\s*\??bool\s*)?"
    r"\{\s*return\s+true\s*;",
    re.IGNORECASE,
)
_APPLICATION_BUILDER_RE = re.compile(r"\bApplication::configure\s*\(")
# ``withEvents(discover: [])`` keeps the default app/Listeners discovery;
# only ``false`` turns it off.
_EVENT_DISCOVERY_DISABLED_RE = re.compile(
    r"\bwithEvents\s*\(\s*(?:discover\s*:\s*)?false\b", re.IGNORECASE
)


@lru_cache(maxsize=4096)
def _composer_data(directory: str) -> dict:
    composer = os.path.join(directory, "composer.json")
    if not os.path.isfile(composer):
        return {}
    try:
        with open(composer, encoding="utf-8") as handle:  # skylos: ignore[SKY-D215] analyzer reads the scanned project's composer.json
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _is_laravel_root(directory: str) -> bool:
    require = _composer_data(directory).get("require")
    return isinstance(require, dict) and "laravel/framework" in require


def _laravel_root_and_path(file_path: str) -> tuple[str, str] | None:
    absolute = os.path.abspath(file_path)
    directory = os.path.dirname(absolute)
    while True:
        if _is_laravel_root(directory):
            relative = os.path.relpath(absolute, directory).replace(os.sep, "/")
            return directory, relative
        parent = os.path.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def _read_source(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:  # skylos: ignore[SKY-D215] analyzer reads a discovered PHP source file
            return handle.read(_MAX_SOURCE_BYTES)
    except OSError:
        return ""


@lru_cache(maxsize=256)
def _event_discovery_enabled(root: str) -> bool:
    """Whether Laravel discovers listeners in ``app/Listeners``.

    Laravel 10 and older discover only when an event service provider's
    ``shouldDiscoverEvents()`` returns true. The Laravel 11
    ``Application::configure()`` builder discovers unless ``withEvents``
    turns discovery off.
    """
    providers = Path(root, "app", "Providers")
    if providers.is_dir():
        for provider in sorted(providers.rglob("*.php")):
            if _SHOULD_DISCOVER_EVENTS_TRUE_RE.search(_read_source(str(provider))):
                return True
    bootstrap = _read_source(os.path.join(root, "bootstrap", "app.php"))
    return bool(
        _APPLICATION_BUILDER_RE.search(bootstrap)
        and not _EVENT_DISCOVERY_DISABLED_RE.search(bootstrap)
    )


@lru_cache(maxsize=256)
def _psr4_directories(root: str) -> tuple[tuple[str, str], ...]:
    """``(dotted namespace prefix, directory)`` pairs from the PSR-4 map."""
    data = _composer_data(root)
    pairs: list[tuple[str, str]] = []
    for section in ("autoload", "autoload-dev"):
        autoload = data.get(section)
        psr4 = autoload.get("psr-4") if isinstance(autoload, dict) else None
        if not isinstance(psr4, dict):
            continue
        for prefix, directories in psr4.items():
            if not isinstance(prefix, str):
                continue
            dotted = prefix.strip("\\").replace("\\", ".")
            for directory in (
                directories if isinstance(directories, list) else [directories]
            ):
                if isinstance(directory, str):
                    pairs.append((dotted, os.path.join(root, directory)))
    return tuple(pairs)


def _is_inside_root(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), root]) == root
    except ValueError:
        return False


def _class_file(root: str, qualified: str) -> str | None:
    # composer.json comes from the scanned project, so a PSR-4 directory can
    # point outside it. Only class files inside the project are read.
    real_root = os.path.realpath(root)
    for prefix, directory in _psr4_directories(root):
        if prefix and not qualified.startswith(f"{prefix}."):
            continue
        rest = qualified[len(prefix) + 1 :] if prefix else qualified
        candidate = os.path.join(directory, *rest.split(".")) + ".php"
        if os.path.isfile(candidate) and _is_inside_root(candidate, real_root):
            return candidate
    return None


@lru_cache(maxsize=2048)
def _class_summaries(
    path: str,
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """``{qualified class: (resolved bases, resolved traits)}`` for one file."""
    try:
        source = Path(path).read_bytes()[:_MAX_SOURCE_BYTES]  # skylos: ignore[SKY-D215] analyzer reads a PHP class file inside the project root
    except OSError:
        return {}
    core = PhpCore(path, source)
    core.scan()
    return {
        definition.name: (
            tuple(getattr(definition, "base_classes", None) or ()),
            tuple(core.traits_of(definition.name)),
        )
        for definition in core.defs
        if definition.type == "class"
    }


def _project_class(root: str, qualified: str):
    path = _class_file(root, qualified)
    if path is None:
        return None
    return _class_summaries(path).get(qualified)


def _is_illuminate_command(base: str) -> bool:
    # Framework commands such as GeneratorCommand extend Illuminate's Command.
    return base == _ILLUMINATE_COMMAND or (
        base.startswith("Illuminate.") and base.endswith("Command")
    )


def _extends_illuminate_command(root: str, bases, depth: int = 0) -> bool:
    if depth > _MAX_PARENT_DEPTH:
        return False
    for base in bases:
        if _is_illuminate_command(base):
            return True
        parent = _project_class(root, base)
        if parent is not None and _extends_illuminate_command(
            root, parent[0], depth + 1
        ):
            return True
    return False


def _uses_has_factory(root: str, bases, traits, depth: int = 0) -> bool:
    if any(trait.rpartition(".")[2] == _HAS_FACTORY_TRAIT for trait in traits):
        return True
    if depth > _MAX_PARENT_DEPTH:
        return False
    for base in bases:
        parent = _project_class(root, base)
        if parent is not None and _uses_has_factory(
            root, parent[0], parent[1], depth + 1
        ):
            return True
    return False


def _model_paths(root: str, subdirectory: str, model: str):
    real_root = os.path.realpath(root)
    for base in ("app/Models", "app"):
        path = os.path.join(root, base, subdirectory, f"{model}.php")
        if os.path.isfile(path) and _is_inside_root(path, real_root):
            yield path


def _model_summary(root: str, subdirectory: str, model: str):
    for path in _model_paths(root, subdirectory, model):
        for qualified, summary in _class_summaries(path).items():
            if qualified.rpartition(".")[2] == model:
                return summary
    return None


def _is_event_listener(root, definition, defs, typed_first_parameter_methods) -> bool:
    # Event discovery maps a listener through the type of the first parameter
    # of its handle*/__invoke method. Without that type, or with discovery
    # off, only an explicit registration (a ::class reference) wires it.
    if not _event_discovery_enabled(root):
        return False
    prefix = f"{definition.name}."
    return any(
        candidate.type == "method"
        and candidate.name.startswith(prefix)
        and (
            candidate.simple_name == "__invoke"
            or candidate.simple_name.startswith("handle")
        )
        and candidate.name in typed_first_parameter_methods
        for candidate in defs
    )


def _is_convention_class(
    definition, root: str, relative: str, defs, typed_first_parameter_methods
) -> bool:
    name = definition.simple_name
    exact = _CONVENTION_FILES.get(relative)
    if exact is not None:
        return name == exact
    if relative.startswith(_COMMANDS_DIR):
        return _extends_illuminate_command(
            root, getattr(definition, "base_classes", None) or ()
        )
    if relative.startswith(_LISTENERS_DIR):
        return _is_event_listener(root, definition, defs, typed_first_parameter_methods)
    if relative.startswith(_POLICIES_DIR):
        subdirectory = os.path.dirname(relative[len(_POLICIES_DIR) :])
        model = name[: -len("Policy")]
        # A policy whose model is itself dead stays live: a known limitation.
        return (
            name.endswith("Policy")
            and bool(model)
            and any(_model_paths(root, subdirectory, model))
        )
    if relative.startswith(_FACTORIES_DIR):
        subdirectory = os.path.dirname(relative[len(_FACTORIES_DIR) :])
        model = name[: -len("Factory")]
        summary = (
            _model_summary(root, subdirectory, model)
            if name.endswith("Factory") and model
            else None
        )
        # HasFactory resolves the factory by name; a model without the trait
        # never asks for it.
        return summary is not None and _uses_has_factory(root, *summary)
    return relative.startswith(_COMPONENT_DIRECTORIES)


def laravel_convention_class_lines(
    file_path: str, defs, typed_first_parameter_methods=frozenset()
) -> set[int]:
    """Lines of the convention classes in ``defs`` and of their public methods.

    The framework calls a convention class through its public surface
    (``handle``, ``__invoke``, ``run``, ``definition``, ``up``, ``render``,
    Livewire actions, policy abilities), so those methods are roots; private
    helpers stay live only when one of them calls the helper.
    """
    located = _laravel_root_and_path(file_path)
    if located is None:
        return set()
    root, relative = located
    classes = {
        definition.name: definition.line
        for definition in defs
        if definition.type == "class"
        and _is_convention_class(
            definition, root, relative, defs, typed_first_parameter_methods
        )
    }
    lines = set(classes.values())
    for definition in defs:
        if (
            definition.type == "method"
            and definition.is_exported
            and definition.name.rpartition(".")[0] in classes
        ):
            lines.add(definition.line)
    return lines
