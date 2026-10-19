"""Source-only annotation requirements from a project's declared mypy policy.

This is an applicability check for T101/T102, not a replacement type checker.
Only a proved, applicable requirement enables default annotation advice.
Unknown settings do not establish an annotation requirement or authorize
skipping security analysis or an entire file.
"""

from __future__ import annotations

from collections import OrderedDict
import configparser
from dataclasses import dataclass
import fnmatch
from functools import lru_cache
import io
import os
from pathlib import Path
import re
import shlex
import threading
import tokenize

from skylos.core.safe_cache_io import read_project_text_no_symlink


_CONFIGS = ("mypy.ini", ".mypy.ini", "pyproject.toml", "setup.cfg")
_BOOL_FLAGS = {
    "strict", "disallow_untyped_defs", "disallow_incomplete_defs", "ignore_errors",
    "namespace_packages", "explicit_package_bases",
}
# Command-line flags that change only reporting, caching or stub installation.
# They neither select files nor change which definitions must be annotated.
_NEUTRAL_FLAGS = frozenset({
    "--show-error-codes", "--hide-error-codes", "--pretty", "--no-pretty",
    "--error-summary", "--no-error-summary", "--show-column-numbers",
    "--show-error-end", "--show-error-context", "--hide-error-context",
    "--show-absolute-path", "--show-traceback", "--tb", "--color-output",
    "--no-color-output", "--install-types", "--non-interactive",
    "--incremental", "--no-incremental", "--sqlite-cache", "--no-sqlite-cache",
    "--warn-unused-configs", "--no-warn-unused-configs",
    "--check-untyped-defs", "--no-check-untyped-defs",
})
_NEUTRAL_VALUE_FLAGS = frozenset({
    "--junit-xml", "--cache-dir", "--junit-format", "--html-report",
    "--txt-report", "--xml-report", "--linecount-report", "--linecoverage-report",
    "--lineprecision-report", "--any-exprs-report", "--cobertura-xml-report",
})
# Literal checker contexts do not change path selection or annotation policy.
_CONTEXT_VALUE_FLAGS = frozenset({"--platform", "--python-version"})
_STRICT_FLAGS = {"disallow_untyped_defs": True, "disallow_incomplete_defs": True}
_UNTYPED_DEF_FLAGS = frozenset({
    "--disallow-untyped-defs", "--allow-untyped-defs",
    "--disallow-incomplete-defs", "--allow-incomplete-defs",
})
# tox: {posargs} and {posargs:DEFAULT}. A nested substitution stays unknown.
_TOX_POSARGS = re.compile(r"\{posargs(?::([^{}]*))?\}")
# tox: {[section]key} copies another value from the same tox.ini.
_TOX_REFERENCE = re.compile(r"\{\[([^\[\]{}]+)\]([^\[\]{}:]+)\}")
_TOX_REFERENCE_DEPTH = 8
_DIRECTORY_CHANGE = re.compile(
    r"(?:^|[;&|])\s*(?:(?:builtin|command)\s+)?(?:cd|pushd|popd)(?:\s|$)",
    re.MULTILINE,
)


@dataclass(frozen=True)
class AnnotationPolicy:
    """Requirements proved for one source file, not type-checker presence.

    Complete requirements cover untyped and partially typed signatures.
    Partial-only requirements apply only to signatures that already contain
    annotation/type-comment intent. Only exact ``True`` proves a requirement;
    ``None`` includes absent declarations and unsupported or unknown scope.
    """

    require_complete: bool | None = None
    require_partial: bool | None = None


def _read(root, relative, reader):
    if reader is not None:
        # A historical reader must raise FileNotFoundError for proved absence;
        # None means unavailable, not permission to consult today's checkout.
        text = reader(Path(relative))
        if not isinstance(text, str) or len(text.encode("utf-8")) > 1_000_000:
            raise OSError("typing policy source unavailable")
        return text
    path = root / relative
    path.lstat()  # Preserve absence versus an unsafe/unreadable config.
    text = read_project_text_no_symlink(root, path, max_bytes=1_000_000)
    if text is None:
        raise OSError("typing policy source unavailable")
    return text


def _boolean(value):
    if type(value) is bool:
        return value
    if isinstance(value, str):
        if value.lower() in {"true", "yes", "1", "on"}:
            return True
        if value.lower() in {"false", "no", "0", "off"}:
            return False
    raise ValueError("invalid typing policy boolean")


def _options(values):
    result = {}
    for key, value in values.items():
        key = key.replace("-", "_")
        invert = key.startswith("no_")
        key = key[3:] if invert else key
        if key.startswith("allow_"):
            key = "disallow_" + key[6:]
            invert = not invert
        if key in _BOOL_FLAGS:
            parsed = _boolean(value)
            result[key] = not parsed if invert else parsed
    return result


def _load(root, reader):
    for relative in _CONFIGS:
        try:
            text = _read(root, relative, reader)
        except FileNotFoundError:
            continue
        if relative == "pyproject.toml":
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib
            config = tomllib.loads(text).get("tool", {}).get("mypy")
            if config is None:
                continue
            if not isinstance(config, dict):
                raise ValueError("invalid mypy configuration")
            overrides = config.get("overrides", [])
            if not isinstance(overrides, list):
                raise ValueError("invalid mypy overrides")
            return config, overrides, relative
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        if not parser.has_section("mypy"):
            if relative in {"mypy.ini", ".mypy.ini"}:
                raise ValueError("selected mypy config has no mypy section")
            continue
        overrides = []
        for section in parser.sections():
            if section.startswith("mypy-"):
                overrides.append({**dict(parser[section]), "module": section[5:].split(",")})
        return dict(parser["mypy"]), overrides, relative
    return None


def _sequence(value):
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list) and all(isinstance(part, str) for part in value):
        return value
    raise ValueError("invalid typing policy selection")


def _path_matches(relative, pattern, root):
    pattern = pattern.replace("${MYPY_CONFIG_FILE_DIR}", str(root)).replace(
        "$MYPY_CONFIG_FILE_DIR", str(root)
    )
    if "$" in pattern or "~" in pattern:
        raise ValueError("environment-dependent typing selection")
    path = Path(pattern)
    if path.is_absolute():
        path = path.relative_to(root)
    if ".." in path.parts:
        raise ValueError("typing selection leaves project root")
    parts = path.parts
    actual = Path(relative).parts

    @lru_cache(maxsize=None)
    def match(i, j):
        if j == len(parts):
            # A literal directory selects descendants, with path boundaries.
            return i == len(actual) or not path.suffix and not any(
                token in str(path) for token in "*?["
            )
        if parts[j] == "**":
            return match(i, j + 1) or i < len(actual) and match(i + 1, j)
        return i < len(actual) and fnmatch.fnmatchcase(actual[i], parts[j]) and match(i + 1, j + 1)

    return match(0, 0)


def _module_matches(module, pattern):
    if pattern == "*":
        return True
    parts = pattern.split(".")
    if not all(part.isidentifier() or part == "*" for part in parts):
        raise ValueError("unsupported module policy pattern")
    if "*" not in parts:
        return module == pattern
    if parts[-1] == "*" and "*" not in parts[:-1]:
        prefix = ".".join(parts[:-1])
        return module == prefix or module.startswith(prefix + ".")
    # Unstructured wildcard precedence differs from structured patterns; do
    # not guess which annotation policy wins in unsupported configurations.
    raise ValueError("unstructured module policy pattern")


def _module_name(relative, config, root, reader):
    """Map a path using declared package markers, never a src-name heuristic."""
    flags = _options(config)
    if flags.get("explicit_package_bases"):
        if reader is not None or os.environ.get("MYPYPATH"):
            # Environment package bases are not a repository declaration;
            # today's environment is never historical policy evidence.
            raise ValueError("environment-dependent typing package base")
        bases = [Path(".")]
        for value in _sequence(config.get("mypy_path", [])):
            value = value.replace("${MYPY_CONFIG_FILE_DIR}", str(root)).replace(
                "$MYPY_CONFIG_FILE_DIR", str(root)
            )
            if any(token in value for token in "$~:*?["):
                raise ValueError("unsupported typing package base")
            base = Path(value)
            if base.is_absolute():
                base = base.relative_to(root)
            if ".." in base.parts:
                raise ValueError("typing package base leaves project")
            bases.append(base)
        matches = [base for base in bases if relative.is_relative_to(base)]
        path = relative.relative_to(max(matches, key=lambda base: len(base.parts)))
    else:
        def package(folder):
            for suffix in ("__init__.py", "__init__.pyi"):
                try:
                    _read(root, str(folder / suffix), reader)
                except FileNotFoundError:
                    continue
                return True
            return False

        if package(Path(".")):
            raise ValueError("typing package crosses project boundary")
        parents = [p for p in relative.parents if p.parts]
        namespace = flags.get("namespace_packages", True)
        selected = None
        for parent in parents:
            if package(parent):
                selected = parent
            elif not namespace:
                break
        path = relative if selected is None else relative.relative_to(selected.parent)
        if selected is None:
            path = Path(relative.name)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _command_targets(text, config_name):
    commands = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        command = re.sub(r"^\s*(?:commands\s*=|(?:-\s*)?run:)\s*", "", line).strip()
        if not re.match(r"(?:mypy|python(?:3(?:\.\d+)?)?\s+-m\s+mypy)(?:\s|$)", command):
            if "{[" in command or (
                not command.startswith("echo ")
                and re.search(r"(?:^|[\s/])mypy(?:\s|$)", command)
            ):
                commands.append(([], None))
            continue
        tail = re.sub(r"^(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?mypy\s*", "", command)
        # The checked-in default is the invocation CI runs; bare {posargs}
        # adds no explicit targets, so the config's files selection applies.
        tail = _TOX_POSARGS.sub(lambda match: match.group(1) or "", tail)
        tokens = shlex.split(tail, comments=True)
        targets, options = [], {}
        strict = False
        index = 0
        while index < len(tokens):
            token = tokens[index]
            flag = token.split("=", 1)[0]
            if token == "--config-file":
                index += 1
                if (
                    config_name is None
                    or index >= len(tokens)
                    or tokens[index] not in {config_name, "./" + config_name}
                ):
                    options = None
                    break
            elif token.startswith("--config-file="):
                if config_name is None or token.split("=", 1)[1] not in {config_name, "./" + config_name}:
                    options = None
                    break
            elif token == "--strict":
                strict = True
            elif token in _UNTYPED_DEF_FLAGS:
                options.update(_options({token[2:]: True}))
            elif flag in _CONTEXT_VALUE_FLAGS:
                if "=" in token:
                    value = token.split("=", 1)[1]
                else:
                    index += 1
                    value = tokens[index] if index < len(tokens) else ""
                pattern = r"[A-Za-z0-9_][A-Za-z0-9_-]*" if flag == "--platform" else r"\d+\.\d+"
                if not re.fullmatch(pattern, value):
                    options = None
                    break
            elif token in _NEUTRAL_FLAGS or flag in _NEUTRAL_VALUE_FLAGS and "=" in token:
                pass
            elif token in _NEUTRAL_VALUE_FLAGS:
                index += 1
                if index >= len(tokens):
                    options = None
                    break
            elif token in {"&&", ";", "|"}:
                break
            elif token.startswith("-") or any(char in token for char in "${}*?[]"):
                options = None
                break
            else:
                targets.append(token)
            index += 1
        if options is not None and strict:
            # mypy applies --strict first; explicit flags override it.
            options = {**_STRICT_FLAGS, **options}
        commands.append((targets, options))
    # A multiline shell block shares directory state. Its later mypy line
    # must not be interpreted using the root directory after a cd/pushd/popd.
    return [([], None)] if commands and _DIRECTORY_CHANGE.search(text) else commands


def _tox_commands(text, root):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(text)

    def expand(value, depth):
        # An unresolved or cyclic reference keeps its "{[" text: unknown.
        if depth >= _TOX_REFERENCE_DEPTH:
            return value

        def replace(match):
            section, option = match.group(1).strip(), match.group(2).strip()
            if not parser.has_section(section) or not parser.has_option(section, option):
                return match.group(0)
            return expand(parser.get(section, option), depth + 1)

        return _TOX_REFERENCE.sub(replace, value)

    def runs_at_root(section):
        directories = []
        for option in ("change_dir", "changedir"):
            if parser.has_option(section, option):
                directories.append(expand(parser.get(section, option), 0).strip())
            elif section.startswith("testenv:") and parser.has_option("testenv", option):
                directories.append(expand(parser.get("testenv", option), 0).strip())
        if not directories:
            return True
        for directory in directories:
            directory = directory.replace("{toxinidir}", str(root)).replace("{tox_root}", str(root))
            if not directory or any(token in directory for token in "${}~"):
                return False
            path = Path(directory)
            if path != Path(".") and path != root:
                return False
        return True

    return [
        (expand(parser.get(section, option), 0), runs_at_root(section))
        for section in parser.sections()
        for option in ("commands", "commands_pre", "commands_post")
        if parser.has_option(section, option)
    ]


def _workflow_runs_at_root(workflow, job, step):
    """Prove the effective run directory before interpreting relative targets."""
    directory = "."
    for owner in (workflow, job):
        defaults = owner.get("defaults", {})
        if not isinstance(defaults, dict):
            return False
        run = defaults.get("run", {})
        if not isinstance(run, dict):
            return False
        if "working-directory" in run:
            directory = run["working-directory"]
    directory = step.get("working-directory", directory)
    # Expressions, absolute paths and non-root relative directories need a
    # different source/config selection context; do not reinterpret them as
    # commands executed at the repository root.
    return isinstance(directory, str) and bool(directory) and Path(directory) == Path(".")


def _project_commands(root, reader, config_name):
    files = ["tox.ini", "Makefile"]
    if reader is None:
        folder = root / ".github" / "workflows"
        # A skipped unsafe directory is unavailable evidence, not an empty one.
        if (root / ".github").is_symlink() or folder.is_symlink():
            raise ValueError("typing command directory is a symlink")
        if folder.is_dir():
            workflows = list(folder.iterdir())
            if len(workflows) > 128:
                raise ValueError("typing command discovery limit")
            files.extend(str(path.relative_to(root)) for path in workflows if path.suffix in {".yml", ".yaml"})
    else:
        inventory = getattr(reader, "workflow_paths", None)
        if inventory is None:
            # A text-only snapshot reader cannot prove historical scope.
            raise ValueError("historical command scope unavailable")
        files.extend(inventory())
    result = []
    for name in files:
        try:
            text = _read(root, name, reader)
        except FileNotFoundError:
            continue
        if name == "tox.ini":
            for command, at_root in _tox_commands(text, root):
                commands = _command_targets(command, config_name)
                if at_root:
                    result.extend(commands)
                elif commands:
                    result.append(([], None))
            continue
        elif name == "Makefile":
            commands = [line[1:].lstrip("@-") for line in text.splitlines() if line.startswith("\t")]
        else:
            import yaml

            try:
                workflow = yaml.safe_load(text)
            except (yaml.YAMLError, RecursionError) as exc:
                raise ValueError("typing workflow unavailable") from exc
            if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs", {}), dict):
                raise ValueError("invalid typing workflow")
            for job in workflow.get("jobs", {}).values():
                if not isinstance(job, dict) or not isinstance(job.get("steps", []), list):
                    continue
                for step in job.get("steps", []):
                    if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                        continue
                    commands = _command_targets(step["run"], config_name)
                    if _workflow_runs_at_root(workflow, job, step):
                        result.extend(commands)
                    elif commands:
                        result.append(([], None))
            continue
        for command in commands:
            result.extend(_command_targets(command, config_name))
    return result


_POLICY_ERRORS = (
    OSError, ValueError, TypeError, KeyError, configparser.Error, ImportError,
)
_POLICY_CACHE = OrderedDict()
_POLICY_CACHE_LIMIT = 64
_POLICY_CACHE_LOCK = threading.Lock()


def _parse_project_policy(root, reader):
    try:
        loaded = _load(root, reader)
        if loaded is None:
            # A checked-in invocation can declare strict annotation policy
            # without a mypy configuration file.
            config, overrides, config_name = {}, [], None
        else:
            config, overrides, config_name = loaded
        commands = _project_commands(root, reader, config_name)
    except _POLICY_ERRORS:
        return None
    return config, overrides, commands


def _stat_signature(path):
    try:
        stat = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return stat.st_mode, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _filesystem_fingerprint(root):
    """Stat of every path the project parse consults, absent ones included."""
    names = [*_CONFIGS, "tox.ini", "Makefile", ".github", ".github/workflows"]
    signature = [(name, _stat_signature(root / name)) for name in names]
    folder = root / ".github" / "workflows"
    if signature[-1][1] is not None and not folder.is_symlink() and folder.is_dir():
        for entry in sorted(os.listdir(folder)):
            name = f".github/workflows/{entry}"
            signature.append((name, _stat_signature(root / name)))
    return tuple(signature)


def _policy_identity(root, reader):
    """Cache key and validity fingerprint, or (None, None) when uncacheable."""
    if reader is None:
        try:
            resolved = str(root.resolve())
            return ("filesystem", resolved, str(root)), _filesystem_fingerprint(root)
        except (OSError, RuntimeError):
            return None, None
    revision = getattr(reader, "revision", None)
    reader_root = getattr(reader, "root", None)
    if not isinstance(revision, str) or not revision or reader_root is None:
        # An opaque reader may change between calls; never reuse its answer.
        return None, None
    return ("revision", type(reader).__qualname__, str(reader_root), revision, str(root)), ()


def _project_policy(root, reader):
    """Parse config, tox.ini, Makefile and workflows once per project state.

    A filesystem entry is reused only while every consulted path keeps its
    (mode, inode, size, mtime_ns, ctime_ns); a historical reader is reused per
    (root, revision). Returns (config, overrides, commands) or None.
    """
    key, fingerprint = _policy_identity(root, reader)
    if key is not None:
        with _POLICY_CACHE_LOCK:
            cached = _POLICY_CACHE.get(key)
            if cached is not None and cached[0] == fingerprint:
                _POLICY_CACHE.move_to_end(key)
                return cached[1]
    policy = _parse_project_policy(root, reader)
    if key is not None:
        with _POLICY_CACHE_LOCK:
            _POLICY_CACHE[key] = (fingerprint, policy)
            _POLICY_CACHE.move_to_end(key)
            while len(_POLICY_CACHE) > _POLICY_CACHE_LIMIT:
                _POLICY_CACHE.popitem(last=False)
    return policy


def _annotation_policy(filename, project_root, source, reader):
    """Return structured requirements and the historical tri-state answer."""
    inline_policy = AnnotationPolicy()
    inline_required = False
    try:
        inline = {}
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.COMMENT or not token.string.startswith("# mypy:"):
                continue
            line = token.string
            values = {}
            for item in line.split(":", 1)[1].split(","):
                key, separator, value = item.strip().partition("=")
                values[key] = value.strip() if separator else True
            inline.update(_options(values))
        if inline.get("ignore_errors"):
            return AnnotationPolicy(False, False), False
        if inline.get("disallow_untyped_defs") is True:
            # Keep the historical wrapper's immediate True answer, while the
            # structured policy still checks applicable ignore_errors below.
            inline_required = True
        if inline.get("disallow_untyped_defs") is False and inline.get("disallow_incomplete_defs") is False:
            return AnnotationPolicy(False, False), False
        inline_policy = AnnotationPolicy(
            inline.get("disallow_untyped_defs"),
            True if inline_required else inline.get("disallow_incomplete_defs"),
        )
        if project_root is None:
            return inline_policy, True if inline_required else None
        root = Path(project_root).absolute()
        relative = Path(filename).absolute().relative_to(root)
        policy = _project_policy(root, reader)
        if policy is None:
            return inline_policy, True if inline_required else None
        config, overrides, commands = policy
        module = _module_name(relative, config, root, reader) if overrides else ""
        settings = _options(config)
        matches = []
        for override in overrides:
            if not isinstance(override, dict):
                raise ValueError("invalid module override")
            for pattern in _sequence(override.get("module", [])):
                if _module_matches(module, pattern):
                    matches.append(("*" not in pattern, len(pattern.split(".")), override))
        # Without a checked-in invocation, only the config's own default
        # selection (a bare ``mypy`` run) can establish where it applies.
        decisions, requirements = [], []
        for targets, cli_options in commands or [([], {})]:
            if cli_options is None:
                decisions.append(None)
                # An unknown command cannot prove a new requirement; it
                # must not bypass a known module/global diagnostic opt-out.
                effective = dict(settings)
                for _, _, override in sorted(matches, key=lambda item: item[:2]):
                    effective.update(_options(override))
                effective.update(inline)
                requirements.append(
                    AnnotationPolicy(False, False)
                    if effective.get("ignore_errors") else inline_policy
                )
                continue
            effective = {**settings, **cli_options}
            for _, _, override in sorted(matches, key=lambda item: item[:2]):
                effective.update(_options(override))
            effective.update(inline)
            # strict enables both flags; strict = false only leaves them unset.
            implied = True if effective.get("strict") is True else None
            required = effective.get("disallow_untyped_defs", implied)
            partial = effective.get("disallow_incomplete_defs", implied)
            # allow_incomplete_defs explicitly accepts partial signatures
            # unless disallow_untyped_defs still rejects every untyped def.
            if effective.get("ignore_errors") or partial is False and required is not True:
                decisions.append(False)
                requirements.append(AnnotationPolicy(False, False))
                continue
            # Explicit command targets replace default discovery settings.
            selection = targets or _sequence(config.get("files", []))
            unknown_discovery = not targets and any(
                config.get(key) for key in ("exclude", "exclude_gitignore", "modules", "packages")
            )
            if not selection or unknown_discovery or not any(
                _path_matches(relative, pattern, root) for pattern in selection
            ):
                # mypy with neither targets nor files checks nothing.
                decisions.append(None)
                requirements.append(inline_policy)
            else:
                decisions.append(True if required is True else None)
                requirements.append(
                    AnnotationPolicy(required, True if required is True else partial)
                )
        def combine(attribute):
            values = [getattr(requirement, attribute) for requirement in requirements]
            if True in values:
                return True
            return None if None in values else False

        requirement = AnnotationPolicy(combine("require_complete"), combine("require_partial"))
        # Every checked-in invocation can impose a requirement. Unknown scope
        # cannot establish an additional annotation requirement.
        if inline_required or True in decisions:
            return requirement, True
        return requirement, None if None in decisions else False
    except (*_POLICY_ERRORS, tokenize.TokenError):
        return inline_policy, True if inline_required else None


def annotation_policy(filename, project_root, source="", *, reader=None):
    """Return complete and partial-only requirements for this file.

    Mypy presence and ``check_untyped_defs`` alone impose neither requirement.
    A partial-only requirement must additionally be checked against each
    signature's actual annotations/type comments by the caller. Unknown scope
    never establishes project-wide enforcement.
    """
    return _annotation_policy(filename, project_root, source, reader)[0]


def annotation_requirement(filename, project_root, source="", *, reader=None):
    """Legacy tri-state: complete requirement, explicit opt-out, or unknown.

    This preserves the pre-existing API. New callers must use
    :func:`annotation_policy` to distinguish an applicable partial-only policy
    from absent or unknown policy; both historically returned ``None`` here.
    """
    return _annotation_policy(filename, project_root, source, reader)[1]
