"""pytest plugin Skylos copies next to a test run (``skylos done``).

Never imported by Skylos itself: the runner copies this file into its own
temporary directory as ``skylos_done_pytest_plugin.py`` and loads it with
``-p``, so it must import nothing from Skylos and run in any environment the
project's tests run in. Every feature is off unless its environment variable
names an input or output file.

* SKYLOS_DONE_DESELECTED: write the node ids pytest deselected.
* SKYLOS_DONE_TRACE: record which tests execute which target lines (the
  changed lines Skylos will check), to map lines to the tests that cover
  them. Uses sys.monitoring (Python 3.12+) so untouched code runs at full
  speed; falls back to sys.settrace.
* SKYLOS_DONE_MUTANT: load one module from a mutated copy of its source, in
  memory. The file on disk is never modified and no bytecode is written.
* SKYLOS_DONE_SELECT: run only the listed node ids, and record every node id
  pytest collected (the base-commit rerun of failing tests: a test that is not
  collected does not exist there, and asking for it must not abort the run).
* SKYLOS_DONE_MODULES: record which file each imported module came from, so
  a base-commit run that imported the working tree's code is not trusted.
* SKYLOS_DONE_EVIDENCE: once every other ``pytest_sessionfinish`` has run
  (the JUnit report is written by then), record the report's digest, the
  session's exit status, where pytest and pluggy were imported from, the
  rootdir and config file, and the plugin files pytest loaded. A report
  rewritten later, or a run in which this probe never loaded, cannot match.
"""

import hashlib
import importlib.machinery
import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

_deselected = []
_CURRENT = [None]  # node id of the running test, or None between tests
# The runner removes these; set again inside the test process (by a
# sitecustomize or .pth file), they changed how pytest was configured.
_INJECTED = sorted(
    name for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS") if os.environ.get(name)
)
_PATHS = {}
_CHANNEL_DIR = Path(__file__).parent.resolve(strict=True)
_MAX_CHANNEL_BYTES = 64 * 1024 * 1024


def _channel_path(path):
    """Only direct children of the runner's private probe directory."""
    try:
        candidate = Path(path)
        if candidate.parent != _CHANNEL_DIR:
            return None
        candidate.resolve(strict=False).relative_to(_CHANNEL_DIR)
        if candidate.is_symlink():
            return None
        return candidate
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _channel_directory():
    """Pin the real parent before tests can replace a directory component."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open(_CHANNEL_DIR.anchor, flags)
        for part in _CHANNEL_DIR.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        return None


_CHANNEL_FD = _channel_directory()


def _real(path):
    cached = _PATHS.get(path)
    if cached is None:
        try:
            cached = os.path.realpath(path)
        except (OSError, ValueError):
            cached = path
        _PATHS[path] = cached
    return cached


def _read_channel(path):
    """A regular file's bytes from the probe directory, or None."""
    candidate = _channel_path(path)
    if candidate is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        candidate.resolve(strict=False).relative_to(_CHANNEL_DIR)
        before = candidate.lstat()
        if not stat.S_ISREG(before.st_mode):
            return None
        if _CHANNEL_FD is not None:
            descriptor = os.open(candidate.name, flags, dir_fd=_CHANNEL_FD)
        else:
            descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > _MAX_CHANNEL_BYTES
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            return None
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(_MAX_CHANNEL_BYTES + 1)
        return raw if len(raw) <= _MAX_CHANNEL_BYTES else None
    except (OSError, ValueError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_json(variable):
    path = os.environ.get(variable)
    raw = _read_channel(path) if path else None
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None


def _write_json(path, data):
    candidate = _channel_path(path)
    if candidate is None:
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        candidate.resolve(strict=False).relative_to(_CHANNEL_DIR)
        if _CHANNEL_FD is not None:
            descriptor = os.open(candidate.name, flags, 0o600, dir_fd=_CHANNEL_FD)
        else:
            descriptor = os.open(candidate, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = None
            json.dump(data, handle)
    except (OSError, RuntimeError, ValueError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


# ---------------------------------------------------------------------------
# Mutant loading
# ---------------------------------------------------------------------------

_MUTANT = _read_json("SKYLOS_DONE_MUTANT")


class _MutantLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        # Compile the mutant directly: never read or write cached bytecode,
        # which would either skip the mutant or leak it into later runs.
        flag = _MUTANT.get("loaded_flag")
        if flag:
            _write_json(flag, {"module": fullname})
        return compile(_MUTANT["source"], self.path, "exec", dont_inherit=True)

    def get_source(self, fullname):
        return _MUTANT["source"]


class _MutantFinder:
    """Ask the real finders first; swap the loader only for the target file."""

    def find_spec(self, name, path=None, target=None):
        for finder in sys.meta_path:
            if finder is self:
                continue
            find_spec = getattr(finder, "find_spec", None)
            if find_spec is None:
                continue
            spec = find_spec(name, path, target)
            if spec is None:
                continue
            origin = getattr(spec, "origin", None)
            if (
                origin
                and _real(origin) == _MUTANT["file"]
                and isinstance(spec.loader, importlib.machinery.SourceFileLoader)
            ):
                spec.loader = _MutantLoader(spec.loader.name, origin)
            return spec
        return None

    def invalidate_caches(self):
        return None


if isinstance(_MUTANT, dict) and isinstance(_MUTANT.get("source"), str):
    _MUTANT["file"] = _real(str(_MUTANT.get("file", "")))
    sys.meta_path.insert(0, _MutantFinder())
else:
    _MUTANT = None


# ---------------------------------------------------------------------------
# Line tracing
# ---------------------------------------------------------------------------

_TRACE = _read_json("SKYLOS_DONE_TRACE")
_TARGETS = {}
_HITS = {}
_STATE = {"backend": None, "tool": None, "lost": False}
_MONITORED_CODES = set()


def _record(path, line):
    lines = _TARGETS.get(path)
    if lines is not None and line in lines:
        _HITS.setdefault(_CURRENT[0] or "", set()).add((path, line))


def _start_monitoring():
    monitoring = getattr(sys, "monitoring", None)
    if monitoring is None or os.environ.get("SKYLOS_DONE_TRACE_BACKEND") == "settrace":
        return False
    tool = next((t for t in (3, 4) if monitoring.get_tool(t) is None), None)
    if tool is None:
        return False
    monitoring.use_tool_id(tool, "skylos-done")
    events = monitoring.events

    def on_start(code, offset):
        if _real(code.co_filename) in _TARGETS:
            monitoring.set_local_events(tool, code, events.LINE)
            _MONITORED_CODES.add(code)
        return monitoring.DISABLE

    def on_line(code, line):
        _record(_real(code.co_filename), line)
        # Each line reports once per test; restart_events() re-arms it.
        return monitoring.DISABLE

    monitoring.register_callback(tool, events.PY_START, on_start)
    monitoring.register_callback(tool, events.LINE, on_line)
    monitoring.set_events(tool, events.PY_START)
    _STATE.update(backend="sys.monitoring", tool=tool)
    return True


def _local_trace(frame, event, arg):
    if event == "line":
        _record(_real(frame.f_code.co_filename), frame.f_lineno)
    return _local_trace


def _global_trace(frame, event, arg):
    if event == "call" and _real(frame.f_code.co_filename) in _TARGETS:
        return _local_trace
    return None


def _start_settrace():
    sys.settrace(_global_trace)
    threading.settrace(_global_trace)
    _STATE["backend"] = "settrace"


if isinstance(_TRACE, dict) and isinstance(_TRACE.get("targets"), dict):
    for target, lines in _TRACE["targets"].items():
        if isinstance(lines, list):
            _TARGETS[_real(target)] = {int(n) for n in lines if isinstance(n, int)}
    if _TARGETS and not _start_monitoring():
        _start_settrace()
else:
    _TRACE = None


def _check_trace_ownership():
    """Do not turn a replaced tracer's missing hits into coverage findings."""
    if _TRACE is None:
        return
    if _STATE["backend"] == "settrace":
        owned = sys.gettrace() is _global_trace
    elif _STATE["backend"] == "sys.monitoring":
        monitoring = getattr(sys, "monitoring", None)
        tool = _STATE["tool"]
        try:
            owned = (
                monitoring is not None
                and monitoring.get_tool(tool) == "skylos-done"
                and bool(monitoring.get_events(tool) & monitoring.events.PY_START)
                and all(
                    monitoring.get_local_events(tool, code) & monitoring.events.LINE
                    for code in _MONITORED_CODES
                )
            )
        except (AttributeError, RuntimeError, TypeError, ValueError):
            owned = False
    else:
        owned = False
    if not owned:
        _STATE["lost"] = True


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    if _TRACE is None:
        yield
        return
    _CURRENT[0] = item.nodeid
    _check_trace_ownership()
    if _STATE["backend"] == "sys.monitoring":
        sys.monitoring.restart_events()
    try:
        yield
    finally:
        _check_trace_ownership()
        _CURRENT[0] = None


# ---------------------------------------------------------------------------
# Selecting node ids that may not exist
# ---------------------------------------------------------------------------

_SELECT = _read_json("SKYLOS_DONE_SELECT")
if not (isinstance(_SELECT, dict) and isinstance(_SELECT.get("ids"), list)):
    _SELECT = None
_MAX_IDS = 200000


def _per_process(path):
    # pytest-xdist workers each collect and import: one file per process.
    return f"{path}.{os.getpid()}"


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    if _SELECT is None:
        return
    out = _SELECT.get("collected")
    if isinstance(out, str) and out:
        _write_json(_per_process(out), [item.nodeid for item in items][:_MAX_IDS])
    wanted = {node for node in _SELECT["ids"] if isinstance(node, str)}
    kept = [item for item in items if item.nodeid in wanted]
    removed = [item for item in items if item.nodeid not in wanted]
    if removed:
        config.hook.pytest_deselected(items=removed)
    items[:] = kept


def pytest_deselected(items):
    _deselected.extend(item.nodeid for item in items)


def _write_modules():
    path = os.environ.get("SKYLOS_DONE_MODULES")
    if not path:
        return
    files = {}
    for name, module in list(sys.modules.items()):
        module_file = getattr(module, "__file__", None)
        if isinstance(name, str) and isinstance(module_file, str) and module_file:
            files[name] = _real(module_file)
            if len(files) >= _MAX_IDS:
                break
    _write_json(_per_process(path), files)


def _module_file(name):
    module_file = getattr(sys.modules.get(name), "__file__", None)
    return _real(module_file) if isinstance(module_file, str) and module_file else None


def _write_evidence(session):
    path = os.environ.get("SKYLOS_DONE_EVIDENCE")
    config = session.config
    # pytest-xdist workers run this plugin too; only the controller writes
    # the JUnit report and the evidence.
    if not path or hasattr(config, "workerinput"):
        return
    report = getattr(config.option, "xmlpath", None)
    raw = _read_channel(os.path.abspath(report)) if report else None
    # pytest >= 6.1 names these inipath and rootpath.
    if hasattr(config, "inipath"):
        inifile, rootdir = config.inipath, config.rootpath
    else:
        inifile, rootdir = getattr(config, "inifile", None), config.rootdir
    try:
        exitstatus = int(session.exitstatus)
    except (TypeError, ValueError):
        exitstatus = None
    plugin_files = (
        getattr(plugin, "__file__", None)
        for plugin in config.pluginmanager.get_plugins()
    )
    plugins = {_real(name) for name in plugin_files if isinstance(name, str)}
    _write_json(
        path,
        {
            "version": 1,
            "probe": _real(__file__),
            "exitstatus": exitstatus,
            "junit_sha256": hashlib.sha256(raw).hexdigest()
            if raw is not None
            else None,
            "modules": {
                name: _module_file(name) for name in ("pytest", "_pytest", "pluggy")
            },
            "prefix": sorted({_real(sys.prefix), _real(sys.base_prefix)}),
            "rootdir": _real(str(rootdir)),
            "inifile": _real(str(inifile)) if inifile else None,
            "plugins": sorted(plugins)[:_MAX_IDS],
            "injected": _INJECTED,
        },
    )


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    # The outermost wrapper: everything below runs after every other
    # pytest_sessionfinish, including the one that writes the JUnit report.
    yield
    _write_modules()
    _write_evidence(session)
    path = os.environ.get("SKYLOS_DONE_DESELECTED")
    if path:
        _write_json(path, _deselected[:100000])
    if _TRACE is not None and _TRACE.get("out"):
        _check_trace_ownership()
        loaded = set()
        others = {}
        tails = {target: target.replace(os.sep, "/") for target in _TARGETS}
        for module in list(sys.modules.values()):
            module_file = getattr(module, "__file__", None)
            if not module_file:
                continue
            real = _real(module_file)
            if real in _TARGETS:
                loaded.add(real)
                continue
            name = getattr(module, "__name__", "") or ""
            if not name or name == "__main__":
                continue
            stem = "/" + name.replace(".", "/")
            for target, tail in tails.items():
                # The same module imported from another place (an installed
                # copy): the repository's file is not what the tests ran.
                if tail.endswith((stem + ".py", stem + "/__init__.py")):
                    others[target] = real
        config = session.config
        _write_json(
            _TRACE["out"],
            {
                "version": 1,
                "backend": _STATE["backend"],
                "lost": _STATE["lost"],
                "rootdir": str(config.rootpath),
                "hits": {
                    node: sorted([path, line] for path, line in hits)
                    for node, hits in _HITS.items()
                },
                "loaded": sorted(loaded),
                "shadowed": others,
            },
        )
