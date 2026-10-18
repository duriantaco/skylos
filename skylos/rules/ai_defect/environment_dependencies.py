"""Distributions a project's own environment definitions install, counted
only in shapes that can be proven.

``requirements.txt``, ``pyproject.toml``, ``setup.cfg`` and ``setup.py`` are
not the only places a project says what its Python environment contains, but
reading shell scripts and Dockerfiles in general means following shell and
Docker semantics (control flow, functions, ``exit``, environment variables
such as ``PIP_TARGET``, activation, build stages and targets, build-context
ignores), and partial readings hid imports nothing provides. So evidence
counts only in these shapes, and anything else falls back to reporting:

* a ``Pipfile``'s ``[packages]`` entries that are a version string or a
  table with only ``version`` (markers, git, path or extras are conditional
  or not a plain name);
* a conda file named exactly ``environment.yml``/``environment.yaml``: its
  dependencies and ``pip:`` names;
* a setup script (``*.sh``, ``*.bash``), read top to bottom and stopping at
  the first command that is not straight-line (control flow, functions,
  ``&&``/``||``/``;``/``|`` lists, ``exit``/``return``, ``source``/``.``,
  ``exec``, ``export``, assignments, ``cd``, ``conda``, heredocs);
* the one Dockerfile stage that copies the code, when it is the final stage
  of its Dockerfile, no other stage or Dockerfile copies the code, no
  ``.dockerignore`` can leave it out, and its ``RUN`` lines are plain
  ``&&`` chains of installs and harmless commands before any ``ENV``/``ARG``
  that redirects installs (``PIP_*``, ``UV_*``, ``CONDA_*``,
  ``VIRTUAL_ENV``, ``PYTHONUSERBASE``, ``PATH``).

An install counts only as ``pip``/``pip3``/``python -m pip``/``python3 -m
pip``/``uv pip`` + ``install`` with options from a small allowlist known to
target the running interpreter. ``-r``/``-e``/``-c`` and path or URL
arguments choose what to install, not where; they add no names. Scripts and
conda files count only where no Python manifest sits in their directory or
between it and the code: that manifest declares the code's environment, and a
script beside or above it (CI, lint, docs) installs tools.

Lockfiles are deliberately not read: they add transitive distributions, and
code that imports a distribution it only gets through another dependency is
still an undeclared import.

Everything is read as bounded text: nothing is executed, installed or
downloaded, and symlinked files are not read.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from packaging.requirements import InvalidRequirement, Requirement

from skylos.core.python_distributions import (
    CURATED_IMPORT_PATHS,
    NAMESPACE_ROOTS,
    heuristic_import_paths,
)
from skylos.core.python_requirements import normalize_distribution_name
from skylos.core.safe_cache_io import read_project_text_no_symlink

MAX_ENVIRONMENT_FILE_BYTES = 1_000_000
MAX_DIRECTORY_ENTRIES = 4096
MAX_ENVIRONMENT_FILES_PER_DIRECTORY = 32
MAX_ENVIRONMENT_ENTRIES = 50_000

_CONDA_ENVIRONMENT_FILES = frozenset({"environment.yml", "environment.yaml"})
_CONDA_ENVIRONMENT_RE = re.compile(r"^environment(?:[-_.][^/\\]*)?\.ya?ml$")
_DOCKERFILE_RE = re.compile(
    r"^(?:dockerfile|containerfile)(?:\.[^/\\]+)?$|^[^/\\]+\.(?:dockerfile|containerfile)$",
    re.IGNORECASE,
)
_SHELL_SUFFIXES = (".sh", ".bash")
_MANIFEST_FILES = frozenset({"pyproject.toml", "setup.py", "setup.cfg", "Pipfile"})
REQUIREMENTS_DIRECTORY = "requirements"
_DOCKERIGNORE = ".dockerignore"

# conda package names that differ from the PyPI distribution they package.
CONDA_DISTRIBUTION_ALIASES = {
    "pytorch": "torch",
    "pytorch-cpu": "torch",
    "pytorch-gpu": "torch",
    "py-opencv": "opencv-python",
}
_CONDA_SPEC_NAME_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)(?=$|[\s=<>!~\[])")
_NOT_DISTRIBUTIONS = frozenset({"python"})


def _normalized(names) -> set[str]:
    result = set()
    for name in names:
        normalized = normalize_distribution_name(name)
        if normalized and normalized not in _NOT_DISTRIBUTIONS:
            result.add(normalized)
    return result


def is_python_manifest(name: str) -> bool:
    """A file that declares a Python environment: requirements files,
    pyproject, setup, Pipfile, conda environment files."""
    return (
        name in _MANIFEST_FILES
        or (name.startswith("requirements") and name.endswith(".txt"))
        or bool(_CONDA_ENVIRONMENT_RE.match(name))
    )


# -- environment files -------------------------------------------------------


def _toml(text):
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _pipfile_names(text):
    """``[packages]`` entries installed unconditionally by name."""
    table = _toml(text).get("packages")
    if not isinstance(table, dict):
        return set()
    names = []
    for name, value in list(table.items())[:MAX_ENVIRONMENT_ENTRIES]:
        if not isinstance(name, str):
            continue
        if isinstance(value, str) or (
            isinstance(value, dict) and set(value) <= {"version"}
        ):
            names.append(name)
    return _normalized(names)


def _yaml(text):
    import yaml

    try:
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        return None


def _requirement_name(word):
    """The distribution a plain requirement names, or None for paths, URLs,
    archives, markers (conditional) and anything not a requirement."""
    if (
        not isinstance(word, str)
        or not word
        or word.startswith((".", "/", "~", "@", "-"))
        or "://" in word
        or "/" in word
        or "\\" in word
        or word.lower().endswith((".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2"))
    ):
        return None
    try:
        requirement = Requirement(word)
    except InvalidRequirement:
        return None
    if requirement.url or requirement.marker:
        return None
    name = normalize_distribution_name(requirement.name)
    return name if name and name not in _NOT_DISTRIBUTIONS else None


def _pip_requirement_names(specs):
    names = set()
    for spec in specs:
        name = _requirement_name(spec.strip() if isinstance(spec, str) else spec)
        if name:
            names.add(name)
    return names


def conda_spec_name(spec):
    """The package a conda match spec names (``chan::faiss-gpu=1.8``), or None
    for paths, URLs and names only known at run time (``$PKG``)."""
    if not isinstance(spec, str):
        return None
    spec = spec.strip().strip("'\"")
    if "::" in spec:
        spec = spec.rsplit("::", 1)[1]
    if (
        not spec
        or spec.startswith(("-", ".", "/", "~", "$"))
        or "://" in spec
        or spec.endswith((".tar.bz2", ".conda"))
    ):
        return None
    match = _CONDA_SPEC_NAME_RE.match(spec)
    return match.group(1) if match else None


def _conda_names(specs):
    names = set()
    for spec in specs:
        name = normalize_distribution_name(conda_spec_name(spec))
        if name and name not in _NOT_DISTRIBUTIONS:
            names.add(
                normalize_distribution_name(CONDA_DISTRIBUTION_ALIASES.get(name, name))
            )
    return names


def _conda_environment_names(text):
    data = _yaml(text)
    dependencies = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(dependencies, list):
        return set()
    names = set()
    conda_specs = []
    for item in dependencies[:MAX_ENVIRONMENT_ENTRIES]:
        if isinstance(item, str):
            conda_specs.append(item)
        elif isinstance(item, dict) and isinstance(item.get("pip"), list):
            names |= _pip_requirement_names(item["pip"][:MAX_ENVIRONMENT_ENTRIES])
    return names | _conda_names(conda_specs)


# -- install commands ---------------------------------------------------------

_INSTALL_PREFIXES = (
    ("pip", "install"),
    ("pip3", "install"),
    ("python", "-m", "pip", "install"),
    ("python3", "-m", "pip", "install"),
    ("uv", "pip", "install"),
)
# Options known to leave the target interpreter unchanged.
_FLAG_OPTIONS = frozenset(
    {"-U", "--upgrade", "-q", "--quiet", "--no-cache-dir", "--no-input", "--pre"}
)
_VALUE_OPTIONS = frozenset({"--progress-bar", "--upgrade-strategy"})
# Options that choose what to install (no names are read from them).
_SOURCE_OPTIONS = frozenset(
    {"-r", "--requirement", "-e", "--editable", "-c", "--constraint"}
)
_QUIET_RE = re.compile(r"^-q+$")

OTHER, INSTALL, DISALLOWED = "other", "install", "disallowed"


def install_names(words):
    """(kind, distributions) of one command's words.

    ``kind`` is OTHER for a command that is not a pip install, DISALLOWED for
    one whose options or arguments may target another environment (or are
    only known at run time), and INSTALL for an install into the running
    interpreter, with the plain requirement names it installs.
    """
    rest = None
    for prefix in _INSTALL_PREFIXES:
        if tuple(words[: len(prefix)]) == prefix:
            rest = words[len(prefix) :]
            break
    if rest is None:
        return OTHER, frozenset()
    if any("$" in word or "`" in word for word in rest):
        return DISALLOWED, frozenset()
    names = set()
    index = 0
    while index < len(rest):
        word = rest[index]
        if word.startswith("-"):
            key, equals, _value = word.partition("=")
            if word in _FLAG_OPTIONS or _QUIET_RE.match(word):
                index += 1
            elif key in _VALUE_OPTIONS or key in _SOURCE_OPTIONS:
                index += 1 if equals else 2
            elif word[:2] in {"-r", "-e", "-c"} and len(word) > 2:
                index += 1  # ``-rrequirements.txt``
            else:
                return DISALLOWED, frozenset()
            continue
        name = _requirement_name(word)
        if name:
            names.add(name)
        index += 1
    return INSTALL, frozenset(names)


# -- shell scripts: straight-line commands only ---------------------------------

_OPERATOR_CHARS = frozenset("();<>|&")
_REDIRECTS = frozenset({">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<>"})
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_STOP_WORDS = frozenset(
    {"if", "then", "elif", "else", "fi", "case", "esac", "for", "select",
     "while", "until", "do", "done", "function", "{", "}", "!", "[[", "]]",
     "exit", "return", "source", ".", "exec", "export", "declare", "typeset",
     "local", "readonly", "unset", "eval", "alias", "trap", "cd", "pushd",
     "popd", "conda", "mamba", "micromamba"}
)  # fmt: skip


def _logical_lines(text):
    """Lines with ``\\``-newline continuations joined (CRLF read as LF)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    pending = ""
    for line in text.split("\n"):
        line = pending + line
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending = line[:-1]
            continue
        pending = ""
        yield line
    if pending:
        yield pending


def _strip_comment(line):
    """``line`` without a ``#`` comment (one at a word start, outside quotes)."""
    quote = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _tokens(line):
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _is_operator(token):
    return bool(token) and all(char in _OPERATOR_CHARS for char in token)


def _command_lists(line):
    """The ``&&``-separated commands of ``line`` as word lists, with
    redirections dropped; None when the line has any other operator (``;``,
    ``||``, ``|``, ``&``, ``(``, ``)``, a heredoc) or cannot be lexed."""
    try:
        tokens = _tokens(_strip_comment(line))
    except ValueError:
        return None
    commands = [[]]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not _is_operator(token):
            commands[-1].append(token)
            index += 1
        elif token in _REDIRECTS:
            if commands[-1] and commands[-1][-1].isdigit():
                commands[-1].pop()  # ``2>&1``
            index += 2
        elif token == "&&":
            commands.append([])
            index += 1
        else:
            return None
    return commands


def _stops(words):
    return words[0] in _STOP_WORDS or bool(_ASSIGNMENT_RE.match(words[0]))


def shell_install_names(text, directory=None, root=None):
    """Distributions a setup script installs before its first command that
    is not straight-line (``directory``/``root`` are accepted for callers
    that pass the script's location; nothing is resolved against them)."""
    names = set()
    for line in _logical_lines(text):
        head = line.split(None, 1)
        if head and _stops(head):
            break  # decided by the first word; no need to lex a long line
        commands = _command_lists(line)
        if commands is None or len(commands) > 1:
            break  # an operator, an ``&&`` list, or unreadable quoting
        words = commands[0]
        if not words:
            continue
        if _stops(words):
            break
        kind, installed = install_names(words)
        if kind == INSTALL:
            names |= installed
    return frozenset(names)


# -- Dockerfiles -----------------------------------------------------------------

_INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)\s*(?P<body>.*)$", re.DOTALL)
_GLOB_CHARS = frozenset("*?[")
_HEREDOC_MARK_RE = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_HARMLESS_RUN_COMMANDS = frozenset(
    {"apt-get", "apk", "mkdir", "rm", "cp", "echo", "chmod", "chown", "ln",
     "useradd"}
)  # fmt: skip
_REDIRECTING_VARIABLES = frozenset({"VIRTUAL_ENV", "PYTHONUSERBASE", "PATH"})
_REDIRECTING_PREFIXES = ("PIP_", "UV_", "CONDA_")


@dataclass(frozen=True)
class DockerStage:
    """One build stage: the build-context sources its own COPY/ADD bring in,
    what its image installs (base stages included), and whether it is the
    Dockerfile's final stage."""

    sources: tuple = ()
    names: frozenset = frozenset()
    final: bool = False


@dataclass(frozen=True)
class Dockerfile:
    """A Dockerfile's stages and whether a ``.dockerignore`` sits beside it
    (``stages`` is None when it could not be read)."""

    stages: tuple | None = ()
    dockerignore: bool = False


def _dockerfile_instructions(text):
    """(INSTRUCTION, arguments) per logical line; comment lines and here-
    document bodies are skipped (a heredoc RUN keeps its ``<<`` marker)."""
    lines = text.replace("\r\n", "\n").splitlines()
    index = 0
    buffer = []
    while index < len(lines):
        line = lines[index].rstrip()
        index += 1
        if line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            buffer.append(line[:-1])
            continue
        buffer.append(line)
        logical = " ".join(part.strip() for part in buffer)
        buffer = []
        for match in _HEREDOC_MARK_RE.finditer(logical):
            while index < len(lines) and lines[index].strip() != match.group(3):
                index += 1
            index += 1
        match = _INSTRUCTION_RE.match(logical)
        if match:
            yield match.group(1).upper(), match.group("body").strip()
    if buffer:
        match = _INSTRUCTION_RE.match(" ".join(part.strip() for part in buffer))
        if match:
            yield match.group(1).upper(), match.group("body").strip()


def _strip_options(body):
    """``--mount=...``, ``--chown=...``; returns (options, rest)."""
    options = []
    while body.startswith("--"):
        parts = body.split(None, 1)
        options.append(parts[0])
        body = parts[1] if len(parts) > 1 else ""
    return options, body


def _exec_form(body):
    """``["a", "b"]`` as a word list, or None for the shell form."""
    if not body.startswith("["):
        return None
    try:
        argv = json.loads(body)
    except (ValueError, RecursionError):
        return []
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        return []
    return argv


def _run_install_names(body):
    """Distributions a RUN installs when it is a plain ``&&`` chain of
    installs and harmless commands; nothing otherwise."""
    _options, body = _strip_options(body)
    argv = _exec_form(body)
    if argv is not None:
        commands = [argv] if argv else None
    elif "<<" in body:
        commands = None
    else:
        commands = _command_lists(body)
    if not commands:
        return frozenset()
    names = set()
    for words in commands:
        if not words:
            return frozenset()
        kind, installed = install_names(words)
        if kind == INSTALL:
            names |= installed
        elif kind == DISALLOWED or words[0] not in _HARMLESS_RUN_COMMANDS:
            return frozenset()
    return frozenset(names)


def _declared_keys(instruction, body):
    """Variable names an ENV or ARG instruction sets."""
    try:
        words = shlex.split(body)
    except ValueError:
        return {"PATH"}  # unreadable: assume the worst
    if not words:
        return set()
    if instruction == "ENV" and "=" not in words[0]:
        return {words[0]}  # ``ENV KEY value``
    return {word.split("=", 1)[0] for word in words}


def _redirects_installs(key):
    key = key.upper()
    return key in _REDIRECTING_VARIABLES or key.startswith(_REDIRECTING_PREFIXES)


def _copy_sources(body):
    """Build-context sources of a COPY/ADD (none with ``--from``)."""
    options, body = _strip_options(body)
    if any(option.startswith("--from") for option in options):
        return []
    argv = _exec_form(body)
    if argv is None:
        try:
            argv = shlex.split(body)
        except ValueError:
            return []
    return [
        source
        for source in argv[:-1]
        if not source.startswith("<<") and "://" not in source
    ]


def dockerfile_stages(text) -> tuple:
    """Every build stage of a Dockerfile, in order."""
    stages = []
    aliases = {}
    redirected_globally = False
    current = None
    for instruction, body in _dockerfile_instructions(text):
        if instruction == "FROM":
            words = [word for word in body.split() if not word.startswith("--")]
            base = aliases.get(words[0].lower()) if words else None
            current = {
                "sources": [],
                "names": set(base["names"]) if base else set(),
                "redirected": base["redirected"] if base else redirected_globally,
            }
            stages.append(current)
            if len(words) >= 3 and words[1].lower() == "as":
                aliases[words[2].lower()] = current
        elif instruction in {"ENV", "ARG"}:
            if any(_redirects_installs(key) for key in _declared_keys(instruction, body)):
                if current is None:
                    redirected_globally = True
                else:
                    current["redirected"] = True
        elif current is None:
            continue
        elif instruction == "SHELL":
            current["redirected"] = True  # RUN lines are no longer sh
        elif instruction == "RUN":
            if not current["redirected"]:
                current["names"] |= _run_install_names(body)
        elif instruction in {"COPY", "ADD"}:
            current["sources"].extend(_copy_sources(body))
    return tuple(
        DockerStage(
            tuple(stage["sources"]),
            frozenset(stage["names"]),
            final=position == len(stages) - 1,
        )
        for position, stage in enumerate(stages)
    )


def _covers(source, relative_directory):
    """A COPY source (relative to the Dockerfile's directory) brings in the
    files of ``relative_directory``."""
    normalized = posixpath.normpath(source.lstrip("/") or ".")
    if normalized == ".." or normalized.startswith("../"):
        return False
    parts = () if normalized == "." else PurePosixPath(normalized).parts
    wanted = PurePosixPath(*relative_directory.parts).parts
    for position, part in enumerate(parts):
        if _GLOB_CHARS & set(part):
            # ``*.py`` copies the files directly inside its directory.
            return position == len(parts) - 1 and wanted == parts[:position]
    return wanted[: len(parts)] == parts


def image_distributions(dockerfiles, *, root_dockerignore=False) -> frozenset:
    """Distributions the image of the code installs.

    ``dockerfiles`` lists (Dockerfile, the code's directory relative to the
    Dockerfile's directory) for every Dockerfile in a directory that
    contains the code. Exactly one stage in all of them may copy the code;
    it must be its Dockerfile's final stage, with no ``.dockerignore`` in the
    build context (``root_dockerignore`` for the repository root).
    """
    if root_dockerignore:
        return frozenset()
    covering = []
    for dockerfile, relative_directory in dockerfiles:
        if dockerfile.stages is None:
            return frozenset()  # unread: it may copy the code too
        for stage in dockerfile.stages:
            if any(_covers(source, relative_directory) for source in stage.sources):
                covering.append((dockerfile, stage))
    if len(covering) != 1:
        return frozenset()
    dockerfile, stage = covering[0]
    if not stage.final or dockerfile.dockerignore:
        return frozenset()
    return stage.names


# -- per directory --------------------------------------------------------------


def _file_kind(name):
    """Which kind of environment definition a file name is, or None."""
    if name == "Pipfile":
        return name
    if name in _CONDA_ENVIRONMENT_FILES:
        return "environment.yml"
    if _DOCKERFILE_RE.match(name):
        return "Dockerfile"
    if name.endswith(_SHELL_SUFFIXES):
        return "shell"
    return None


def _entries(directory):
    """(regular file names, directory names) directly inside ``directory``."""
    files, directories = [], []
    try:
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_DIRECTORY_ENTRIES:
                    break
                try:
                    if entry.is_file(follow_symlinks=False):
                        files.append(entry.name)
                    elif entry.is_dir(follow_symlinks=False):
                        directories.append(entry.name)
                except OSError:
                    continue
    except OSError:
        return [], []
    return sorted(files), sorted(directories)


@dataclass(frozen=True)
class DirectoryEnvironment:
    """The environment definitions directly inside one directory.

    ``declared``: Pipfile ``[packages]``; ``conda``: ``environment.yml``
    names (``conda_files`` are those files); ``script_installs``: what its
    setup scripts install; ``dockerfiles``: its Dockerfiles; ``manifests``:
    its Python manifests (``requirements/`` for that folder);
    ``dockerignore``: a ``.dockerignore`` sits here.
    """

    declared: frozenset = frozenset()
    conda: frozenset = frozenset()
    conda_files: frozenset = frozenset()
    script_installs: frozenset = frozenset()
    dockerfiles: tuple = ()
    manifests: frozenset = frozenset()
    dockerignore: bool = False


def directory_environment(root, directory) -> DirectoryEnvironment:
    """Environment definitions directly inside ``directory`` (a contained,
    non-symlink directory of ``root``), as normalized distributions."""
    root, directory = Path(root), Path(directory)
    files, directories = _entries(directory)
    manifests = {name for name in files if is_python_manifest(name)}
    if REQUIREMENTS_DIRECTORY in directories:
        manifests.add(REQUIREMENTS_DIRECTORY + "/")
    # ``.dockerignore``, or ``<Dockerfile>.dockerignore`` beside a Dockerfile.
    dockerignore = any(name.endswith(_DOCKERIGNORE) for name in files)
    declared, conda, conda_files, script_installs = set(), set(), set(), set()
    dockerfiles = []
    read = 0
    for name in files:
        kind = _file_kind(name)
        if kind is None:
            continue
        text = None
        if read < MAX_ENVIRONMENT_FILES_PER_DIRECTORY:
            read += 1
            text = read_project_text_no_symlink(
                root,
                directory / name,
                max_bytes=MAX_ENVIRONMENT_FILE_BYTES,
                encoding="utf-8",
                errors="ignore",
            )
        if kind == "Dockerfile":
            stages = dockerfile_stages(text) if text is not None else None
            dockerfiles.append(Dockerfile(stages, dockerignore))
        elif not text:
            continue
        elif kind == "Pipfile":
            declared |= _pipfile_names(text)
        elif kind == "environment.yml":
            conda |= _conda_environment_names(text)
            conda_files.add(name)
        else:
            script_installs |= shell_install_names(text)
    return DirectoryEnvironment(
        frozenset(declared),
        frozenset(conda),
        frozenset(conda_files),
        frozenset(script_installs),
        tuple(dockerfiles),
        frozenset(manifests),
        dockerignore,
    )


# -- import names ---------------------------------------------------------------


def _usable(path, shared):
    return bool(path) and (path.split(".", 1)[0] not in shared or "." in path)


def environment_import_paths(
    dists, *, installed_modules=None, import_to_dist=None, namespace_roots=frozenset()
) -> frozenset:
    """Import paths ``dists`` provide.

    What is known about a distribution wins: installed metadata, the curated
    table and the pipreqs mapping (PyYAML provides ``yaml``, not
    ``pyyaml``). Only a distribution nothing is known about falls back to
    the conservative name heuristic; a variant suffix (``dask-cuda``) is
    never stripped to reach another package's name.
    """
    shared = NAMESPACE_ROOTS | set(namespace_roots)
    installed_by_dist: dict[str, set] = {}
    for module, providers in (installed_modules or {}).items():
        for provider in providers:
            installed_by_dist.setdefault(normalize_distribution_name(provider), set()).add(
                module
            )
    mapped_by_dist: dict[str, set] = {}
    for module, mapped in (import_to_dist or {}).items():
        mapped_by_dist.setdefault(normalize_distribution_name(mapped), set()).add(module)
    paths = set()
    for dist in dists:
        name = normalize_distribution_name(dist)
        known = set(CURATED_IMPORT_PATHS.get(name, ()))
        known |= installed_by_dist.get(name, set())
        known |= mapped_by_dist.get(name, set())
        known = {path for path in known if _usable(path, shared)}
        paths |= known or {
            path for path in heuristic_import_paths(name) if _usable(path, shared)
        }
    return frozenset(paths)
