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
* Python, per manager, only what that manager reads: pip (and pipx, pipenv)
  ``PIP_INDEX_URL``/``PIP_EXTRA_INDEX_URL`` and ``pip.conf``/``pip.ini``; uv
  ``UV_*INDEX*``, ``uv.toml`` and ``[tool.uv]``/``[[tool.uv.index]]``; poetry
  ``[[tool.poetry.source]]``; pdm ``[[tool.pdm.source]]``;
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
    pypi_by_manager: dict[str, list[str]] = field(default_factory=dict)
    npm_tag: str = ""

    def alternate(self, ecosystem: str, name: str, tool: str = "") -> list[str]:
        """Non-public registries ``name`` may come from when ``tool`` installs it."""
        if ecosystem == NPM:
            if name.startswith("@"):
                scope = name.split("/", 1)[0].lower()
                if scope in self.npm_scopes:
                    return [self.npm_scopes[scope]]
            return list(self.npm_default)
        if ecosystem == PYPI:
            if not tool:
                return list(self.pypi_indexes)
            return list(self.pypi_by_manager.get(python_manager(tool), []))
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
            if key == "tag" and value:
                context.npm_tag = value
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
        if name.lower() == "npm_config_tag" and value:
            context.npm_tag = value


# -- Python ---------------------------------------------------------------


def python_manager(tool: str) -> str:
    """Which Python manager's configuration applies to an install ``tool``."""
    first = tool.split(" ", 1)[0].lower()
    if first in {"uv", "uvx"}:
        return "uv"
    if first in {"poetry", "pdm"}:
        return first
    if tool.lower().startswith("python -m uv"):
        return "uv"
    return "pip"


def _python_context(context, root, env, home) -> None:
    pip: list[str] = []
    for name in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"):
        pip.extend(env.get(name, "").split())
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
                pip.extend(parser.get(section, key, fallback="").split())
    uv: list[str] = []
    for name in ("UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX"):
        uv.extend(env.get(name, "").split())
    poetry: list[str] = []
    pdm: list[str] = []
    if root is not None:
        uv.extend(_toml_indexes(Path(root) / "uv.toml", ()))
        uv.extend(_toml_indexes(Path(root) / "pyproject.toml", ("tool",)))
        poetry.extend(_tool_sources(Path(root) / "pyproject.toml", "poetry"))
        pdm.extend(_tool_sources(Path(root) / "pyproject.toml", "pdm"))
    config_home = env.get("XDG_CONFIG_HOME") or ""
    if not config_home and home is not None:
        config_home = str(home / ".config")
    if config_home:
        uv.extend(_toml_indexes(Path(config_home) / "uv" / "uv.toml", ()))
    context.pypi_by_manager = {
        "pip": _non_public_indexes(pip),
        "uv": _non_public_indexes(uv),
        "poetry": _non_public_indexes(poetry),
        "pdm": _non_public_indexes(pdm),
    }
    context.pypi_indexes = _dedupe(
        index for indexes in context.pypi_by_manager.values() for index in indexes
    )


def _non_public_indexes(indexes: list[str]) -> list[str]:
    found = []
    for index in indexes:
        value = index
        if "=" in index and "://" in index.split("=", 1)[1]:
            value = index.split("=", 1)[1]
        if value and not _public(value, PYPI):
            found.append(value)
    return _dedupe(found)


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
    return found


def _tool_sources(path: Path, tool: str) -> list[str]:
    text = _read(path)
    if text is None:
        return []
    try:
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(text)
    except (ValueError, ImportError):
        return []
    table = data.get("tool", {})
    if isinstance(table, dict):
        table = table.get(tool, {})
    if not isinstance(table, dict):
        return []
    sources = table.get("source", [])
    if not isinstance(sources, list):
        return []
    return [entry["url"] for entry in sources
            if isinstance(entry, dict) and isinstance(entry.get("url"), str)]  # fmt: skip


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


__all__ = ["RegistryContext", "is_trusted", "python_manager", "registry_context"]
