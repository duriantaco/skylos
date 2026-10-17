"""Which import paths and commands a Python distribution provides.

A distribution name is not an import name: ``beautifulsoup4`` ships ``bs4``
and ``djangorestframework`` ships ``rest_framework``. The answer comes from,
in order of trust:

1. installed metadata (``importlib.metadata``) of the scanning environment;
2. a curated table of well-known mismatches;
3. the pipreqs import-to-distribution table;
4. conservative name heuristics (``django-guardian`` -> ``guardian``).

Namespace roots such as ``google`` are shared by many distributions, so a
bare root is never accepted for them; only a dotted path such as
``google.cloud.translate`` is.

Nothing here imports or executes project code.
"""

from __future__ import annotations

import re
from functools import lru_cache

from skylos.core.python_requirements import normalize_distribution_name

NAMESPACE_ROOTS = frozenset(
    {
        "azure",
        "backports",
        "collective",
        "flufl",
        "google",
        "jaraco",
        "moz",
        "opentelemetry",
        "oslo",
        "plone",
        "repoze",
        "ruamel",
        "sphinxcontrib",
        "zc",
        "zope",
    }
)

# Distribution (normalized) -> import paths it provides. Only entries that
# the name heuristics below cannot derive.
CURATED_IMPORT_PATHS = {
    "attrs": ("attr", "attrs"),
    "beautifulsoup4": ("bs4",),
    "dj-database-url": ("dj_database_url",),
    "django-allauth": ("allauth",),
    "django-cors-headers": ("corsheaders",),
    "django-debug-toolbar": ("debug_toolbar",),
    "django-filter": ("django_filters",),
    "django-money": ("djmoney",),
    "django-notifications-community": ("notifications",),
    "django-notifications-hq": ("notifications",),
    "django-registration-redux": ("registration",),
    "django-storages": ("storages",),
    "django-stubs": ("mypy_django_plugin",),
    "djangorestframework": ("rest_framework",),
    "djangorestframework-simplejwt": ("rest_framework_simplejwt",),
    "dnspython": ("dns",),
    "factory-boy": ("factory",),
    "gitpython": ("git",),
    "google-api-core": ("google.api_core",),
    "google-api-python-client": ("googleapiclient", "apiclient"),
    "google-auth": ("google.auth", "google.oauth2"),
    "google-cloud-core": ("google.cloud.client", "google.cloud.exceptions"),
    "googleapis-common-protos": (
        "google.api",
        "google.cloud.extended_operations_pb2",
        "google.cloud.location",
        "google.logging",
        "google.longrunning",
        "google.rpc",
        "google.type",
    ),
    "grpc-google-iam-v1": ("google.iam",),
    "grpcio": ("grpc",),
    "grpcio-status": ("grpc_status",),
    "msgpack-python": ("msgpack",),
    "mysqlclient": ("MySQLdb",),
    "opencv-contrib-python": ("cv2",),
    "opencv-contrib-python-headless": ("cv2",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "pillow": ("PIL",),
    "protobuf": ("google.protobuf",),
    "psycopg-binary": ("psycopg_binary",),
    "psycopg2-binary": ("psycopg2",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pygithub": ("github",),
    "pyjwt": ("jwt",),
    "pymupdf": ("fitz", "pymupdf"),
    "pyopenssl": ("OpenSSL",),
    # Canonical package trees: github.com/scrapy/pypydispatcher and
    # pypi.org/project/python-consul2/ (a drop-in python-consul fork).
    "pypydispatcher": ("pydispatch",),
    "pytelegrambotapi": ("telebot",),
    "python-dateutil": ("dateutil",),
    "python-consul2": ("consul",),
    "python-dotenv": ("dotenv",),
    "python-jose": ("jose",),
    "python-ldap": ("ldap", "ldif", "slapdtest"),
    "python-magic": ("magic",),
    "python-multipart": ("multipart", "python_multipart"),
    "python-telegram-bot": ("telegram",),
    "pywin32": (
        "pythoncom",
        "pywintypes",
        "win32api",
        "win32com",
        "win32con",
        "win32event",
        "win32file",
        "win32gui",
        "win32process",
        "win32service",
        "win32serviceutil",
    ),
    "pyyaml": ("yaml",),
    "pyserial": ("serial",),
    "pyusb": ("usb",),
    "pyzmq": ("zmq",),
    "scikit-image": ("skimage",),
    "scikit-learn": ("sklearn",),
    "setuptools": ("setuptools", "pkg_resources", "_distutils_hack"),
    "slackclient": ("slack",),
    "translate-toolkit": ("translate",),
    "typing-extensions": ("typing_extensions",),
    "websocket-client": ("websocket",),
}

# Distribution (normalized) -> console commands it installs, for packages
# that are run rather than imported (Procfile, Dockerfile, Makefile).
CURATED_CONSOLE_SCRIPTS = {
    "celery": ("celery",),
    "gunicorn": ("gunicorn",),
    "newrelic": ("newrelic-admin",),
    "uvicorn": ("uvicorn",),
    "daphne": ("daphne",),
    "hypercorn": ("hypercorn",),
    "uwsgi": ("uwsgi",),
    "waitress": ("waitress-serve",),
    "supervisor": ("supervisord", "supervisorctl"),
    "alembic": ("alembic",),
    "zensical": ("zensical",),
    "mkdocs": ("mkdocs",),
    "sphinx": ("sphinx-build", "sphinx-autobuild"),
    "ddtrace": ("ddtrace-run",),
    "honcho": ("honcho",),
}

# flask-login imports as flask_login, so "flask-" is deliberately absent.
_STRIP_PREFIXES = ("django-", "python-", "py-")
_STRIP_SUFFIXES = ("-python", "-py", "-binary")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(candidate: str) -> str | None:
    candidate = candidate.replace("-", "_")
    return candidate if _IDENTIFIER_RE.match(candidate) else None


def heuristic_import_paths(dist: str) -> set:
    """Import paths a distribution name suggests, conservatively."""
    dist = normalize_distribution_name(dist)
    if not dist:
        return set()
    tokens = [token for token in dist.split("-") if token]
    paths = set()
    if tokens and tokens[0] in NAMESPACE_ROOTS and len(tokens) > 1:
        # google-cloud-translate -> google.cloud.translate, moz.l10n -> moz.l10n
        dotted = ".".join(tokens)
        if all(_IDENTIFIER_RE.match(token) for token in tokens):
            paths.add(dotted)
        return paths
    plain = _identifier(dist)
    if plain:
        paths.add(plain)
    for prefix in _STRIP_PREFIXES:
        if dist.startswith(prefix):
            stripped = _identifier(dist[len(prefix) :])
            if stripped:
                paths.add(stripped)
    for suffix in _STRIP_SUFFIXES:
        if dist.endswith(suffix):
            stripped = _identifier(dist[: -len(suffix)])
            if stripped:
                paths.add(stripped)
    # No generic "py" prefix rule: pydantic is not "dantic". Known cases
    # (pyjwt, pyyaml, pyserial, ...) are in the curated table.
    return paths


def _usable(path: str) -> bool:
    root = path.split(".", 1)[0]
    return not (root in NAMESPACE_ROOTS and "." not in path)


def distribution_import_paths(
    dist: str,
    *,
    installed_modules=None,
    import_to_dist=None,
    namespace_roots=frozenset(),
) -> set:
    """Every import path ``dist`` is known or expected to provide.

    ``installed_modules`` maps a top-level module to the distributions that
    ship it (``importlib.metadata.packages_distributions`` shape).
    ``import_to_dist`` maps an import name to one distribution name (pipreqs).
    ``namespace_roots`` adds roots found to be shared in this environment.
    """
    dist = normalize_distribution_name(dist)
    shared = NAMESPACE_ROOTS | set(namespace_roots)
    paths = set(CURATED_IMPORT_PATHS.get(dist, ()))
    for module, dists in (installed_modules or {}).items():
        if module not in shared and dist in {
            normalize_distribution_name(item) for item in dists
        }:
            paths.add(module)
    for module, mapped in (import_to_dist or {}).items():
        if normalize_distribution_name(mapped) == dist:
            paths.add(module)
    paths |= heuristic_import_paths(dist)
    return {
        path
        for path in paths
        if path and (path.split(".", 1)[0] not in shared or "." in path)
    }


def shared_namespace_roots(installed_modules) -> frozenset:
    """Top-level modules that more than one installed distribution ships."""
    roots = set()
    for module, dists in (installed_modules or {}).items():
        if len({normalize_distribution_name(item) for item in dists}) > 1:
            roots.add(module)
    return frozenset(roots)


_VERSIONED_PORTION_RE = re.compile(r"_v\d+(?:(?:alpha|beta|p\d+beta)\d*)?$")


def _unversioned(path: str) -> str:
    """``google.cloud.translate_v3`` -> ``google.cloud.translate``."""
    return ".".join(_VERSIONED_PORTION_RE.sub("", part) for part in path.split("."))


def path_is_provided(path: str, provider_paths) -> bool:
    """``path`` is a provided module, or a module inside one.

    For a namespace root, importing a parent of a provided path is accepted
    too (``from google.cloud import translate``), and so is a versioned
    portion shipped alongside it (``google.cloud.translate_v3``).
    """
    if not path:
        return False
    root = path.split(".", 1)[0]
    candidates = {path}
    if root in NAMESPACE_ROOTS:
        candidates.add(_unversioned(path))
    for provided in provider_paths:
        for candidate in candidates:
            if candidate == provided or candidate.startswith(provided + "."):
                return True
        if root in NAMESPACE_ROOTS and provided.startswith(path + "."):
            return True
    return False


def _console_scripts_of(dist) -> tuple:
    try:
        name = normalize_distribution_name(dist.metadata["Name"])
        entry_points = list(dist.entry_points)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return "", ()
    names = tuple(
        entry_point.name
        for entry_point in entry_points
        if getattr(entry_point, "group", "") in ("console_scripts", "gui_scripts")
    )
    return name, names


@lru_cache(maxsize=1)
def installed_console_scripts() -> dict:
    """Normalized distribution -> console script names, from installed metadata."""
    from importlib.metadata import distributions

    scripts = {}
    try:
        installed = list(distributions())
    except (OSError, ValueError):
        return scripts
    for dist in installed:
        name, names = _console_scripts_of(dist)
        if name and names:
            scripts.setdefault(name, set()).update(names)
    return scripts


def distribution_commands(dist: str, *, installed_scripts=None) -> set:
    dist = normalize_distribution_name(dist)
    commands = {dist}
    commands.update(CURATED_CONSOLE_SCRIPTS.get(dist, ()))
    scripts = (
        installed_console_scripts() if installed_scripts is None else installed_scripts
    )
    commands.update(scripts.get(dist, ()))
    return {command for command in commands if command}
