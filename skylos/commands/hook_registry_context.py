"""Package registries the user's own configuration points installs at.

``npm install @corp/ui`` with ``@corp:registry=https://npm.corp.example`` in
``.npmrc`` fetches from the corporate registry, so "not on npmjs.org" is not
evidence of a hallucination. The install checker uses this context to turn
such a result into "could not verify" (or, for a registry listed in
``trusted_registries``, to skip the public check) instead of a false block.

Sources read (all cheap, no subprocesses):

* npm: ``npm_config_registry`` and similar in the hook's environment,
  ``.npmrc`` from the working directory up to the project root, and the
  user's ``~/.npmrc`` (``registry=`` and ``@scope:registry=``);
* Python: ``PIP_INDEX_URL``/``PIP_EXTRA_INDEX_URL``/``UV_*INDEX*`` in the
  environment, ``pip.conf``/``pip.ini`` in the user and virtualenv locations,
  ``uv.toml``, and ``[tool.uv]``/``[[tool.uv.index]]``/``[[tool.poetry.source]]``
  /``[[tool.pdm.source]]`` in the project's ``pyproject.toml``;
* Go: ``GOPROXY``/``GOPRIVATE``/``GONOPROXY`` from the environment or the
  ``go env -w`` file.
"""

from __future__ import annotations

import configparser
import fnmatch
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from skylos.commands.hook_install_parse import (
    GO,
    NPM,
    PUBLIC_REGISTRY_HOSTS,
    PYPI,
    registry_host,
)

MAX_CONFIG_BYTES = 256_000
_NPMRC_LINE_RE = re.compile(r"^\s*(?P<key>[^=;#\s][^=]*?)\s*=\s*(?P<value>.*?)\s*$")


@dataclass
class RegistryContext:
    npm_default: list[str] = field(default_factory=list)
    npm_scopes: dict[str, str] = field(default_factory=dict)  # "@corp" -> url
    pypi_indexes: list[str] = field(default_factory=list)
    go_proxies: list[str] = field(default_factory=list)
    go_private: list[str] = field(default_factory=list)  # GOPRIVATE patterns

    def alternate(self, ecosystem: str, name: str) -> list[str]:
        """Non-public registries ``name`` may come from."""
        if ecosystem == NPM:
            if name.startswith("@"):
                scope = name.split("/", 1)[0].lower()
                if scope in self.npm_scopes:
                    return [self.npm_scopes[scope]]
            return list(self.npm_default)
        if ecosystem == PYPI:
            return list(self.pypi_indexes)
        if ecosystem == GO:
            return list(self.go_proxies)
        return []

    def scoped(self, ecosystem: str, name: str) -> str | None:
        """The registry a scoped npm package is pinned to, if any."""
        if ecosystem == NPM and name.startswith("@"):
            return self.npm_scopes.get(name.split("/", 1)[0].lower())
        return None

    def go_is_private(self, module: str) -> bool:
        return any(_go_pattern_matches(p, module) for p in self.go_private)


def registry_context(
    root: Path | None, cwd: Path | None, env: dict[str, str], home: Path | None = None
) -> RegistryContext:
    context = RegistryContext()
    try:
        home = home if home is not None else Path.home()
    except (RuntimeError, KeyError):
        home = None
    _npm_context(context, root, cwd, env, home)
    _python_context(context, root, env, home)
    _go_context(context, env, home)
    return context


def is_trusted(url: str, trusted: tuple[str, ...]) -> bool:
    """Whether registry ``url`` matches a ``trusted_registries`` entry: by
    host, and by path prefix when the entry has a path."""
    if not trusted:
        return False
    host = registry_host(url)
    if not host:
        return False
    path = _url_path(url)
    for entry in trusted:
        entry_host = registry_host(entry)
        if entry_host != host:
            continue
        entry_path = _url_path(entry)
        if not entry_path or path.startswith(entry_path):
            return True
    return False


def _url_path(url: str) -> str:
    raw = url.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    _, _, path = raw.partition("/")
    return path.rstrip("/")


def _public(url: str, ecosystem: str) -> bool:
    return registry_host(url) in PUBLIC_REGISTRY_HOSTS.get(ecosystem, frozenset())


# -- npm ------------------------------------------------------------------


def _npm_context(context, root, cwd, env, home) -> None:
    files: list[Path] = []
    if cwd is not None and root is not None:
        current = Path(os.path.normpath(str(cwd)))
        stop = Path(os.path.normpath(str(root)))
        for _ in range(32):
            files.append(current / ".npmrc")
            if current == stop or current.parent == current:
                break
            if stop not in current.parents:
                break
            current = current.parent
    elif root is not None:
        files.append(Path(root) / ".npmrc")
    user = env.get("NPM_CONFIG_USERCONFIG") or env.get("npm_config_userconfig")
    if user:
        files.append(Path(user).expanduser())
    elif home is not None:
        files.append(home / ".npmrc")
    # Nearest file wins, as in npm: read the farthest first.
    for path in reversed(files):
        text = _read(path)
        if text is None:
            continue
        for line in text.splitlines():
            match = _NPMRC_LINE_RE.match(line)
            if not match:
                continue
            key, value = match.group("key").strip(), _unquote(match.group("value"))
            if key == "registry":
                context.npm_default = [value] if not _public(value, NPM) else []
            elif key.startswith("@") and key.endswith(":registry"):
                scope = key[: -len(":registry")].lower()
                if _public(value, NPM):
                    context.npm_scopes.pop(scope, None)
                else:
                    context.npm_scopes[scope] = value
    for name, value in env.items():
        if name.lower() == "npm_config_registry" and value:
            context.npm_default = [value] if not _public(value, NPM) else []


# -- Python ---------------------------------------------------------------


def _python_context(context, root, env, home) -> None:
    indexes: list[str] = []
    for name in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL",
                 "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX"):  # fmt: skip
        indexes.extend(env.get(name, "").split())
    for path in _pip_config_files(env, home):
        text = _read(path)
        if text is None:
            continue
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error:
            continue
        for section in ("global", "install"):
            if not parser.has_section(section):
                continue
            for key in ("index-url", "extra-index-url", "index_url", "extra_index_url"):
                indexes.extend(parser.get(section, key, fallback="").split())
    tomls: list[tuple[Path, tuple[str, ...]]] = []
    if root is not None:
        tomls.append((Path(root) / "pyproject.toml", ("tool",)))
        tomls.append((Path(root) / "uv.toml", ()))
    config_home = env.get("XDG_CONFIG_HOME") or (str(home / ".config") if home else "")
    if config_home:
        tomls.append((Path(config_home) / "uv" / "uv.toml", ()))
    for path, prefix in tomls:
        indexes.extend(_toml_indexes(path, prefix))
    context.pypi_indexes = _dedupe(
        index.split("=", 1)[1]
        if "=" in index and "://" in index.split("=", 1)[1]
        else index
        for index in indexes
        if index and not _public(index.split("=", 1)[-1], PYPI)
    )


def _pip_config_files(env, home) -> list[Path]:
    files: list[Path] = []
    explicit = env.get("PIP_CONFIG_FILE")
    if explicit and explicit != os.devnull:
        files.append(Path(explicit).expanduser())
    files.append(Path("/etc/pip.conf"))
    if home is not None:
        files.append(home / ".pip" / "pip.conf")
        files.append(home / ".config" / "pip" / "pip.conf")
        if sys.platform == "darwin":
            files.append(home / "Library" / "Application Support" / "pip" / "pip.conf")
    xdg = env.get("XDG_CONFIG_HOME")
    if xdg:
        files.append(Path(xdg) / "pip" / "pip.conf")
    appdata = env.get("APPDATA")
    if appdata:
        files.append(Path(appdata) / "pip" / "pip.ini")
    venv = env.get("VIRTUAL_ENV")
    if venv:
        files.append(Path(venv) / "pip.conf")
        files.append(Path(venv) / "pip.ini")
    return files


def _toml_indexes(path: Path, prefix: tuple[str, ...]) -> list[str]:
    text = _read(path)
    if text is None:
        return []
    try:
        try:
            import tomllib
        except ModuleNotFoundError:  # Python < 3.11
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(text)
    except (ValueError, ImportError):  # TOMLDecodeError is a ValueError
        return []
    for key in prefix:
        data = data.get(key, {}) if isinstance(data, dict) else {}
    if not isinstance(data, dict):
        return []
    found: list[str] = []
    uv = data.get("uv", {}) if prefix else data
    if isinstance(uv, dict):
        for key in ("index-url", "extra-index-url"):
            value = uv.get(key)
            if isinstance(value, str):
                found.append(value)
            elif isinstance(value, list):
                found.extend(str(v) for v in value)
        entries = uv.get("index")
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                found.append(entry["url"])
    if prefix:
        for tool in ("poetry", "pdm"):
            table = data.get(tool, {})
            sources = table.get("source", []) if isinstance(table, dict) else []
            for entry in sources if isinstance(sources, list) else []:
                if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                    found.append(entry["url"])
    return found


# -- Go -------------------------------------------------------------------


def _go_context(context, env, home) -> None:
    settings = dict(_go_env_file(env, home))
    for name in ("GOPROXY", "GOPRIVATE", "GONOPROXY", "GOFLAGS"):
        if env.get(name):
            settings[name] = env[name]
    proxies = []
    for entry in re.split(r"[,|]", settings.get("GOPROXY", "")):
        entry = entry.strip()
        if entry and entry not in {"direct", "off"} and not _public(entry, GO):
            proxies.append(entry)
    context.go_proxies = proxies
    patterns = []
    for name in ("GOPRIVATE", "GONOPROXY"):
        patterns.extend(
            p.strip() for p in settings.get(name, "").split(",") if p.strip()
        )
    context.go_private = _dedupe(patterns)


def _go_env_file(env, home) -> list[tuple[str, str]]:
    explicit = env.get("GOENV")
    if explicit == "off":
        return []
    if explicit:
        path = Path(explicit)
    else:
        if home is None:
            return []
        if sys.platform == "darwin":
            base = home / "Library" / "Application Support"
        elif os.name == "nt":
            base = Path(env.get("APPDATA", str(home)))
        else:
            base = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
        path = base / "go" / "env"
    text = _read(path)
    if text is None:
        return []
    pairs = []
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            pairs.append((key.strip(), value.strip()))
    return pairs


def _go_pattern_matches(pattern: str, module: str) -> bool:
    """GOPRIVATE semantics: the glob matches a prefix of the module path,
    element by element."""
    pattern_parts = pattern.strip("/").split("/")
    module_parts = module.split("/")
    if len(module_parts) < len(pattern_parts):
        return False
    return all(
        fnmatch.fnmatchcase(part, glob)
        for part, glob in zip(module_parts, pattern_parts)
    )


# -- helpers ----------------------------------------------------------------


def _read(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _dedupe(values) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


__all__ = ["RegistryContext", "is_trusted", "registry_context"]
