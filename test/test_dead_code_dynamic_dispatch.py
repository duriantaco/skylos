"""Dead-code liveness for Python dynamic dispatch and direct-call edge cases."""

import ast
import json
import textwrap
from collections import defaultdict

from test.fixture_paths import make_fixture_directory, write_fixture

from skylos.analysis.implicit_refs import (
    ImplicitRefTracker,
    is_specific_name_pattern,
)
from skylos.analyzer import Skylos, analyze
from skylos.scale import parallel_static
from skylos.visitors.base import Definition, Visitor


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _unused(result):
    names = set()
    for key in ("unused_functions", "unused_classes", "unused_variables"):
        names.update(item["full_name"] for item in result.get(key, []))
    return names


def _scan(tmp_path):
    return _unused(json.loads(analyze(str(tmp_path), conf=0, grep_verify=False)))


def _printf_dispatch_project(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/arbiter.py',
        """
        import signal


        class Arbiter:
            SIG_NAMES = {getattr(signal, n): n[3:].lower() for n in dir(signal)}

            def run(self, sig):
                signame = self.SIG_NAMES.get(sig)
                handler = getattr(self, "handle_%s" % signame, None)
                if handler:
                    handler()

            def handle_term(self):
                raise StopIteration

            def handle_ttin(self):
                return 1

            handle_cld = handle_ttin

            def stale_helper(self):
                return 2


        Arbiter().run(15)
        """,
    )


def test_printf_formatted_getattr_name_reaches_prefixed_methods(tmp_path):
    _printf_dispatch_project(tmp_path)

    unused = _scan(tmp_path)

    assert "pkg.arbiter.Arbiter.handle_term" not in unused
    assert "pkg.arbiter.Arbiter.handle_ttin" not in unused
    assert "pkg.arbiter.Arbiter.handle_cld" not in unused
    assert "pkg.arbiter.Arbiter.stale_helper" in unused


def _setter_dispatch_project(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/state.py',
        """
        from dataclasses import dataclass


        @dataclass
        class State:
            mode: str = ""

            def __setattr__(self, name, value):
                super().__setattr__(name, value)
                if hasattr(self, f"set_{name}"):
                    getattr(self, f"set_{name}")(value)

            def set_mode(self, value):
                return value

            def unused_state_helper(self):
                return 1
        """,
    )
    _write(
        tmp_path, 'pkg/app.py',
        """
        from pkg.state import State


        def start():
            state = State()
            state.mode = "debug"
            return state


        start()
        """,
    )


def test_fstring_setter_dispatch_marks_setters(tmp_path):
    _setter_dispatch_project(tmp_path)

    unused = _scan(tmp_path)

    assert "pkg.state.State.set_mode" not in unused
    assert "pkg.state.State.unused_state_helper" in unused


def test_parallel_scan_keeps_dynamic_patterns_found_in_workers(tmp_path, monkeypatch):
    _setter_dispatch_project(tmp_path)
    _printf_dispatch_project(make_fixture_directory(tmp_path, "other"))
    # Tests normally force serial analysis; exercise the process pool so the
    # patterns come back from worker processes.
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("SKYLOS_JOBS", "2")
    pools = []
    run_pool = parallel_static._run_pool

    def recording_run_pool(files, *args, **kwargs):
        pools.append(len(files))
        return run_pool(files, *args, **kwargs)

    monkeypatch.setattr(parallel_static, "_run_pool", recording_run_pool)

    unused = _scan(tmp_path)

    assert pools and pools[0] > 1
    assert "pkg.state.State.set_mode" not in unused
    assert "pkg.state.State.unused_state_helper" in unused
    assert "other.pkg.arbiter.Arbiter.handle_term" not in unused
    assert "other.pkg.arbiter.Arbiter.stale_helper" in unused


def test_dir_prefix_from_class_attribute_marks_prefixed_members(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/funcs.py',
        """
        class cached_classproperty:
            def __init__(self, getter):
                self.getter = getter

            def __get__(self, instance, owner):
                return self.getter(owner)


        class TemplateFunctions:
            _prefix = "tmpl_"

            @cached_classproperty
            def _func_names(cls):
                return [s for s in dir(cls) if s.startswith(cls._prefix)]

            def functions(self):
                out = {}
                for key in self._func_names:
                    out[key[len(self._prefix):]] = getattr(self, key)
                return out

            @staticmethod
            def tmpl_lower(s):
                return s.lower()

            def tmpl_first(self, s):
                return s[:1]

            @staticmethod
            def unrelated_static(s):
                return s


        def render():
            return TemplateFunctions().functions()


        render()
        """,
    )

    unused = _scan(tmp_path)

    assert "pkg.funcs.TemplateFunctions.tmpl_lower" not in unused
    assert "pkg.funcs.TemplateFunctions.tmpl_first" not in unused
    assert "pkg.funcs.TemplateFunctions.unrelated_static" in unused


def test_dir_loop_with_startswith_scopes_reflection_to_prefix(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/server.py',
        """
        COMMAND_PREFIX = "cmd_"


        class Server:
            @staticmethod
            def early_unused(conn):
                return conn

            def commands(self):
                for func in dir(self):
                    if not func.startswith(COMMAND_PREFIX):
                        continue
                    yield func[4:]

            @staticmethod
            def cmd_ping(conn):
                return "pong"

            @staticmethod
            def late_unused(conn):
                return conn


        list(Server().commands())
        """,
    )

    unused = _scan(tmp_path)

    assert "pkg.server.Server.cmd_ping" not in unused
    assert "pkg.server.Server.early_unused" in unused
    assert "pkg.server.Server.late_unused" in unused


def test_self_prefix_dispatch_reaches_subclass_members_in_other_modules(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/base.py',
        """
        class Widget:
            def __init__(self):
                self.handlers = {}

            def emit(self, event):
                handler = getattr(self, f"on_{event}", None)
                if handler is not None:
                    handler()
        """,
    )
    _write(
        tmp_path, 'pkg/widgets.py',
        """
        from pkg.base import Widget


        class Button(Widget):
            def on_click(self):
                return "clicked"

            def unused_button_helper(self):
                return 1


        Button().emit("click")
        """,
    )

    unused = _scan(tmp_path)

    assert "pkg.widgets.Button.on_click" not in unused
    assert "pkg.widgets.Button.unused_button_helper" in unused


def test_getattr_on_typed_receiver_reaches_subclass_attributes(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/plugins.py',
        """
        from collections.abc import Iterable


        class BasePlugin:
            pass


        _instances = []


        def find_plugins() -> Iterable[BasePlugin]:
            return _instances


        def named_queries(model_cls):
            attr_name = f"{model_cls.__name__.lower()}_queries"
            return {
                field: query
                for plugin in find_plugins()
                for field, query in getattr(plugin, attr_name, {}).items()
            }


        def notify(plugin: BasePlugin | None, event):
            return getattr(plugin, f"on_{event}")()
        """,
    )
    _write(
        tmp_path, 'pkg/playlist.py',
        """
        from pkg.plugins import BasePlugin, _instances, named_queries, notify


        class PlaylistPlugin(BasePlugin):
            item_queries = {"playlist": object}
            unused_setting = {"x": 1}

            def on_import(self):
                return 1

            def stale_method(self):
                return 2


        plugin = PlaylistPlugin()
        _instances.append(plugin)
        named_queries(PlaylistPlugin)
        notify(plugin, "import")
        """,
    )

    unused = _scan(tmp_path)

    assert "pkg.playlist.PlaylistPlugin.item_queries" not in unused
    assert "pkg.playlist.PlaylistPlugin.on_import" not in unused
    assert "pkg.playlist.PlaylistPlugin.unused_setting" in unused
    assert "pkg.playlist.PlaylistPlugin.stale_method" in unused


def test_module_reflection_through_parameter_keeps_filtered_subclasses(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/template.py',
        """
        class File:
            pass


        def find_template_files(module):
            for name in dir(module):
                obj = getattr(module, name)
                if obj is File:
                    continue
                if isinstance(obj, type) and issubclass(obj, File):
                    yield obj
        """,
    )
    _write(
        tmp_path, 'pkg/files_default.py',
        """
        from pkg.template import File


        class Readme(File):
            pass


        class PyProject(File):
            pass


        class NotATemplate:
            pass
        """,
    )
    _write(
        tmp_path, 'pkg/default.py',
        """
        from pkg import files_default
        from pkg.template import find_template_files


        def files():
            return list(find_template_files(files_default))


        files()
        """,
    )

    unused = _scan(tmp_path)

    assert "pkg.files_default.Readme" not in unused
    assert "pkg.files_default.PyProject" not in unused
    assert "pkg.files_default.NotATemplate" in unused


def test_dataclass_post_init_callees_are_used(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/segment.py',
        """
        from dataclasses import dataclass


        @dataclass(kw_only=True)
        class Segment:
            uri: str = ""
            ad: bool = False

            def __post_init__(self):
                self.ad = self._is_ad()

            def _is_ad(self):
                return "ad" in self.uri

            def _never_called(self):
                return False


        def parse(uri):
            return Segment(uri=uri).ad


        parse("x")
        """,
    )

    unused = _scan(tmp_path)

    assert "pkg.segment.Segment._is_ad" not in unused
    assert "pkg.segment.Segment._never_called" in unused


def test_fully_computed_getattr_name_registers_no_wildcard_pattern():
    code = textwrap.dedent(
        """
        class Router:
            def route(self, name, prefix):
                getattr(self, f"{name}")()
                getattr(self, "_" + name)()
                getattr(self, "%s" % name)()
                getattr(self, f"{prefix}_{name}")()
                getattr(self, f"view_{name}")()
        """
    )
    tracker = ImplicitRefTracker()
    visitor = Visitor("pkg.router", "/repo/pkg/router.py")
    visitor.pattern_tracker = tracker
    visitor.visit(ast.parse(code))
    visitor.finalize()

    assert [entry[2] for entry in tracker._compiled_patterns] == ["view_*"]
    assert [entry[2:] for entry in tracker._class_patterns] == [
        ("view_*", "pkg.router.Router")
    ]


def _definition(name, kind, line, called_by=(), references=0):
    defn = Definition(name, kind, "/repo/pkg/cmd.py", line)
    defn.references = references
    defn.called_by = set(called_by)
    return defn


def test_rescued_caller_restores_transitively_dead_callees():
    skylos = Skylos()
    handle = _definition("pkg.cmd.Command.handle", "method", 2)
    run_import = _definition(
        "pkg.cmd.Command._run_import",
        "method",
        5,
        called_by={"pkg.cmd.Command.handle"},
        references=1,
    )
    load = _definition(
        "pkg.cmd.Command._load",
        "method",
        8,
        called_by={"pkg.cmd.Command._run_import"},
        references=1,
    )
    unrelated = _definition(
        "pkg.cmd.helper",
        "function",
        11,
        called_by={"pkg.cmd.stale"},
        references=1,
    )
    stale = _definition("pkg.cmd.stale", "function", 14)
    command = _definition("pkg.cmd.Command", "class", 1, references=1)
    skylos.defs = {
        d.name: d for d in (command, handle, run_import, load, unrelated, stale)
    }

    skylos._propagate_transitive_dead()
    assert run_import.references == 0
    assert load.references == 0
    assert unrelated.references == 0

    # A later pass (grep verification) finds a use of the caller.
    handle.references = 1
    assert skylos._restore_transitive_dead_callees() == 2

    assert run_import.references == 1
    assert load.references == 1
    assert unrelated.references == 0


def test_tracker_merge_and_class_scoped_patterns():
    parent = ImplicitRefTracker()
    worker = ImplicitRefTracker()
    worker.known_refs.add("dispatch")
    worker.add_pattern_ref("set_*", 70, source_module="pkg.state")
    worker.add_class_pattern_ref("on_*", 70, "pkg.base.Widget")
    worker.reflected_modules.add(("pkg.files", (frozenset(), frozenset())))

    parent.merge(worker)
    parent.merge(worker)

    assert parent.known_refs == {"dispatch"}
    assert [entry[2:] for entry in parent._compiled_patterns] == [
        ("set_*", "pkg.state")
    ]
    assert len(parent._class_patterns) == 1
    assert parent.reflected_modules == worker.reflected_modules

    children = defaultdict(set, {"pkg.base.Widget": {"pkg.ui.Button"}})
    parent.set_class_hierarchy(children)
    subclass_member = Definition("pkg.ui.Button.on_click", "method", "/r/ui.py", 3)
    other_class_member = Definition("pkg.ui.Label.on_click", "method", "/r/ui.py", 9)
    assert parent.should_mark_as_used(subclass_member)[0] is True
    assert parent.should_mark_as_used(other_class_member)[0] is False


def test_specific_name_patterns():
    assert is_specific_name_pattern("handle_*")
    assert is_specific_name_pattern("*_queries")
    assert is_specific_name_pattern("do_*_action")
    assert not is_specific_name_pattern("*")
    assert not is_specific_name_pattern("_*")
    assert not is_specific_name_pattern("*.*")
    assert not is_specific_name_pattern("x*")
