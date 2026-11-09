"""File-specific dependency declarations in a small, explicit Compose shape.

This models declaration provenance, not installed contents or runtime safety.
Only the exact Python command file gets this evidence. A repository mount does
not assign one environment to its siblings or imported modules. Nothing is run.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path, PurePosixPath

import yaml

from skylos.core.safe_cache_io import read_project_text_no_symlink, strip_utf8_bom
from .environment_dependencies import (
    INSTALL,
    MAX_ENVIRONMENT_FILE_BYTES,
    _dockerfile_instructions,
    _exec_form,
    _requirement_name,
    install_names,
)

_COMPOSE_NAME = re.compile(r"^(?:docker-)?compose(?:[.-][A-Za-z0-9_.-]+)?\.ya?ml$")
_PYTHON_IMAGE = re.compile(r"^(?:docker\.io/library/)?python:3\.[0-9]+(?:\.[0-9]+)?(?:-(?:slim(?:-(?:bookworm|bullseye))?|bookworm|bullseye|alpine(?:[0-9.]+)?))?$")
_ASSIGNMENT = re.compile(r"^([A-Z_][A-Z0-9_]*)=([A-Za-z0-9_.+-]+)$")
_VARIABLE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
_BENIGN_PYTHON_ENV = {"PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}
_REDIRECTING_ENV = {"PATH", "VIRTUAL_ENV", "ENV", "BASH_ENV", "IFS"}
_STAGE_KEYS = {"FROM", "ENV", "WORKDIR", "COPY", "RUN"}
_SERVICE_KEYS = {"build", "init", "working_dir", "command", "environment", "volumes", "ports", "healthcheck"}


class _Unknown(Exception):
    pass


class _UniqueLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise _Unknown
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result or key == "<<":
                raise _Unknown
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _plain(value):
    return isinstance(value, str) and bool(value) and not any(c in value for c in "$`\\\x00\n\r~")


def _relative(value):
    if not _plain(value):
        raise _Unknown
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise _Unknown
    return path


def _absolute(value):
    if not _plain(value):
        raise _Unknown
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise _Unknown
    return path


def _text(root, path):
    value = read_project_text_no_symlink(root, path, max_bytes=MAX_ENVIRONMENT_FILE_BYTES)
    if value is None:
        raise _Unknown
    return value


def _env_file(root, path):
    result = {}
    for line in _text(root, path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if match is None or match[1] in result:
            raise _Unknown
        result[match[1]] = match[2]
    if not result or len(result) > 128 or _redirecting_environment(result):
        raise _Unknown
    return result


def _context_includes(root, dockerfile, source):
    """A deliberately small dockerignore subset; unknown patterns retain advice."""
    specific = Path(str(dockerfile) + ".dockerignore")
    ignore = specific if specific.exists() or specific.is_symlink() else root / ".dockerignore"
    if not ignore.exists() and not ignore.is_symlink():
        return True
    included = True
    wanted = str(source)
    for line in strip_utf8_bom(_text(root, ignore)).splitlines():
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        negate = pattern.startswith("!")
        pattern = pattern[1:] if negate else pattern
        if pattern == "**":
            matches = True
        elif not any(c in pattern for c in "*?[\\"):
            literal = str(_relative(pattern.rstrip("/")))
            matches = wanted == literal or wanted.startswith(literal + "/")
        elif pattern.endswith("/**") and not any(c in pattern[:-3] for c in "*?[\\"):
            prefix = str(_relative(pattern[:-3]))
            matches = wanted.startswith(prefix + "/")
        elif pattern.endswith("/**/__pycache__/") and not any(c in pattern[:-len("/**/__pycache__/")] for c in "*?[\\"):
            prefix = pattern[:-len("/**/__pycache__/")].rstrip("/")
            _relative(prefix)
            matches = wanted.startswith(prefix + "/") and "__pycache__" in source.parts
        elif pattern.endswith("/**/*.pyc") and not any(c in pattern[:-9] for c in "*?[\\"):
            prefix = pattern[:-9].rstrip("/")
            _relative(prefix)
            matches = wanted.startswith(prefix + "/") and wanted.endswith(".pyc")
        else:
            raise _Unknown
        if matches:
            included = negate
    return included


def _shell_commands(body, values):
    # Expand only literal assignments sourced in this RUN, respecting single
    # quotes. Operators, substitutions, redirections and escapes are unsupported.
    expanded = []
    quote = None
    index = 0
    size = 0
    while index < len(body):
        character = body[index]
        if character == "\\" or character == "`":
            raise _Unknown
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            expanded.append(character)
            index += 1
            continue
        if quote is None and character in "&|<>()*?[":
            raise _Unknown
        if character == "$" and quote != "'":
            match = _VARIABLE.match(body, index)
            if match is None or match[1] not in values:
                raise _Unknown
            expanded.append(values[match[1]])
            size += len(values[match[1]])
            if size > MAX_ENVIRONMENT_FILE_BYTES:
                raise _Unknown
            index = match.end()
            continue
        expanded.append(character)
        size += 1
        if size > MAX_ENVIRONMENT_FILE_BYTES:
            raise _Unknown
        index += 1
    if quote:
        raise _Unknown
    lexer = shlex.shlex("".join(expanded), posix=True, punctuation_chars=";")
    lexer.whitespace_split = True
    lexer.commenters = ""
    commands, words = [], []
    for word in lexer:
        if word == ";":
            if not words:
                raise _Unknown
            commands.append(words)
            words = []
        elif ";" in word:
            raise _Unknown
        else:
            words.append(word)
    if words:
        commands.append(words)
    return commands


def _run_names(body, copied, interpreter):
    # A source command introduces values for following commands, not earlier
    # commands or another RUN. Split first without expanding later variables.
    pieces, start, quote = [], 0, None
    for index, character in enumerate(body):
        if character == "\\":
            raise _Unknown
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        elif character == ";" and quote is None:
            piece = body[start:index].strip()
            if not piece:
                raise _Unknown
            pieces.append(piece)
            start = index + 1
    if quote:
        raise _Unknown
    if body[start:].strip():
        pieces.append(body[start:].strip())
    if not pieces or len(pieces) > 8:
        raise _Unknown
    values, names = {}, set()
    for position, piece in enumerate(pieces):
        commands = _shell_commands(piece, values)
        if len(commands) != 1:
            raise _Unknown
        words = commands[0]
        if len(words) > 64 or any(len(word) > 1024 for word in words):
            raise _Unknown
        if words[0] == "set" and position == 0 and len(words) == 2 and words[1].startswith("-") and "e" in words[1] and set(words[1][1:]) <= set("eux"):
            continue
        if words[0] == "." and len(words) == 2 and words[1] in copied:
            values.update(copied[words[1]])
            continue
        if words[0] == "rm" and len(words) == 2 and words[1] in copied:
            del copied[words[1]]
            continue
        if words[:4] != [interpreter, "-m", "pip", "install"]:
            raise _Unknown
        kind, installed = install_names(words)
        if kind != INSTALL or not installed or any(word != "--no-cache-dir" and _requirement_name(word) is None for word in words[4:]):
            raise _Unknown
        names.update(installed)
    return names


def _stage_declarations(root, dockerfile, target, interpreter, working_dir):
    text = _text(root, dockerfile)
    for line in text.splitlines():
        directive = line.lstrip().lower()
        if re.match(r"#\s*escape\s*=", directive) or re.match(r"#\s*syntax\s*=", directive) and not re.fullmatch(r"#\s*syntax\s*=docker/dockerfile:[0-9.]+", directive):
            raise _Unknown
    stages = []
    current = None
    for instruction, body in _dockerfile_instructions(text):
        if instruction == "FROM":
            words = shlex.split(body)
            if len(words) != 3 or words[1].lower() != "as" or not _plain(words[2]):
                current = None
            else:
                current = [words[2], words[0], []]
                stages.append(current)
        elif current is not None:
            current[2].append((instruction, body))
    matches = [stage for stage in stages if stage[0] == target]
    if len({stage[0].lower() for stage in stages}) != len(stages) or len(matches) != 1 or not _PYTHON_IMAGE.fullmatch(matches[0][1]):
        raise _Unknown
    copied, names, stage_workdir = {}, set(), None
    for instruction, body in matches[0][2]:
        if instruction not in _STAGE_KEYS:
            raise _Unknown
        if instruction == "WORKDIR":
            stage_workdir = str(_absolute(body))
        elif instruction == "ENV":
            words = shlex.split(body)
            if not words or any("=" not in word or word.partition("=")[0] not in _BENIGN_PYTHON_ENV or not _plain(word.partition("=")[2]) for word in words):
                raise _Unknown
        elif instruction == "COPY":
            words = _exec_form(body) if body.startswith("[") else shlex.split(body)
            if not words or len(words) != 2 or words[0].startswith("--"):
                raise _Unknown
            source, destination = _relative(words[0]), _absolute(words[1])
            if any(c in str(source) + str(destination) for c in "*?[") or source.suffix != ".env" or destination.suffix != ".env" or not str(destination).startswith("/tmp/") or not _context_includes(root, dockerfile, source):
                raise _Unknown
            copied[str(destination)] = _env_file(root, root / Path(str(source)))
        elif instruction == "RUN":
            names.update(_run_names(body, copied, interpreter))
    if stage_workdir != working_dir or not names:
        raise _Unknown
    return frozenset(names)


def _redirecting_environment(value):
    if value is None:
        return False
    if isinstance(value, dict):
        keys = value.keys()
    elif isinstance(value, list) and all(isinstance(v, str) and "=" in v for v in value):
        keys = [v.partition("=")[0] for v in value]
    else:
        return True
    for key in keys:
        if not isinstance(key, str) or "$" in key:
            return True
        upper = key.upper()
        if upper in _REDIRECTING_ENV or upper.startswith(("PYTHON", "PIP_", "UV_", "CONDA_", "LD_")) and upper not in _BENIGN_PYTHON_ENV:
            return True
    return False


def _service_entry(root, service):
    if not isinstance(service, dict):
        raise _Unknown
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise _Unknown
    mounts = []
    for volume in volumes:
        if not isinstance(volume, str) or not _plain(volume):
            raise _Unknown
        parts = volume.split(":")
        if parts[0] in {".", "./"} and not (len(parts) == 3 and parts[2] == "ro"):
            raise _Unknown
        if len(parts) == 3 and parts[0] in {".", "./"} and parts[2] == "ro":
            destination = _absolute(parts[1])
            if len(destination.parts) < 2 or destination.parts[1] in {"usr", "bin", "sbin", "lib", "lib64", "etc", "proc", "dev", "sys"}:
                raise _Unknown
            mounts.append(destination)
    if not mounts:
        # Another explicit launcher may run the same source through a partial
        # mount, copied image contents or a shell wrapper. Its environment is
        # unknown, so it cannot be ignored in favor of a supported sibling.
        if "command" in service or "entrypoint" in service:
            raise _Unknown
        return None
    if len(mounts) != 1 or len(volumes) != 1:
        raise _Unknown
    command = service.get("command")
    if not isinstance(command, list) or len(command) != 2 or command[0] not in {"python", "python3"}:
        raise _Unknown
    script = _absolute(command[1])
    try:
        relative = script.relative_to(mounts[0])
    except ValueError:
        raise _Unknown from None
    if relative.suffix != ".py":
        raise _Unknown
    entry = root / Path(str(relative))
    _text(root, entry)
    return entry, command[0]


def compose_entrypoint_distributions(root, file_path, cache=None):
    """Literal Compose declaration evidence for one exact Python command file.

    Cache lifetime is one analysis. Unknown/ambiguous configurations return no
    names. Official Python image interpreter/entrypoint defaults are an explicit
    modeled contract; remote image contents are not inspected or vouched for.
    """
    root, file_path = Path(root).absolute(), Path(file_path).absolute()
    cache = {} if cache is None else cache
    key = ("compose-entrypoints", str(root))
    if key not in cache:
        entries = {}
        try:
            files = sorted(path for path in root.iterdir() if _COMPOSE_NAME.fullmatch(path.name))
            dotenv = root / ".env"
            if len(files) != 1 or dotenv.exists() or dotenv.is_symlink():
                raise _Unknown
            for path in files:
                loader = _UniqueLoader(_text(root, path))
                try:
                    data = loader.get_single_data()
                finally:
                    loader.dispose()
                if not isinstance(data, dict) or set(data) - {"name", "version", "services", "volumes", "networks"}:
                    raise _Unknown
                services = data.get("services")
                if not isinstance(services, dict) or len(services) > 64:
                    raise _Unknown
                for service in services.values():
                    entry = _service_entry(root, service)
                    if entry is None:
                        continue
                    entry_file, interpreter = entry
                    if entry_file in entries:
                        raise _Unknown
                    # Mark an invalid selected service too: a valid sibling
                    # must never hide an alternative environment for this file.
                    entries[entry_file] = frozenset()
                    if set(service) - _SERVICE_KEYS or _redirecting_environment(service.get("environment")):
                        continue
                    build = service.get("build")
                    if not isinstance(build, dict) or set(build) != {"context", "dockerfile", "target"} or build["context"] not in {".", "./"} or not _plain(build["target"]):
                        continue
                    dockerfile = root / Path(str(_relative(build["dockerfile"])))
                    working_dir = str(_absolute(service.get("working_dir")))
                    entries[entry_file] = _stage_declarations(root, dockerfile, build["target"], interpreter, working_dir)
        except (_Unknown, OSError, ValueError, TypeError, yaml.YAMLError, RecursionError):
            entries = {}
        cache[key] = entries
    return cache[key].get(file_path, frozenset())
