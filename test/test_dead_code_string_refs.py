"""Dead-code liveness for string references, template references, re-exports
and registries."""

import ast
import json
import textwrap

from test.fixture_paths import write_fixture

from skylos.analyzer import analyze
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode.registration_liveness import find_method_registered_targets
from skylos.visitors.base import Definition


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _scan(tmp_path, conf=0):
    return json.loads(analyze(str(tmp_path), conf=conf, grep_verify=False))


def _names(result, category):
    return {item["full_name"] for item in result.get(category, [])}


def _js_function_names(result):
    return {
        item.get("simple_name") or item.get("name")
        for item in result.get("unused_functions", [])
        if str(item.get("file", "")).endswith(".js")
    }


def _unused_file_paths(result, tmp_path):
    paths = set()
    for item in result.get("unused_files", []):
        path = str(item.get("file", "")).replace("\\", "/")
        root = str(tmp_path.resolve()).replace("\\", "/") + "/"
        paths.add(path[len(root) :] if path.startswith(root) else path)
    return paths


def _rescue_reasons(result):
    rescued = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    return {item["name"]: item["reason"] for item in rescued}


# Dotted-path strings added to Django settings in place


_SETTINGS_HEADER = """
import os

INSTALLED_APPS = ["django.contrib.auth"]
ROOT_URLCONF = "shop.urls"
MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": []}
"""


def _auth_module(tmp_path):
    _write(tmp_path, 'shop/__init__.py', "")
    _write(
        tmp_path, 'shop/urls.py',
        "from django.urls import path\n\nurlpatterns = []\n",
    )
    _write(
        tmp_path, 'shop/auth.py',
        """
        class TokenAuthentication:
            def authenticate(self, request):
                return None


        class RemoteUserMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response


        class RemoteUserAuthentication:
            def authenticate(self, request):
                return None


        class StaleAuthentication:
            def authenticate(self, request):
                return None
        """,
    )


def test_settings_appended_in_place_name_live_classes(tmp_path):
    _auth_module(tmp_path)
    _write(
        tmp_path, 'shop/settings.py',
        _SETTINGS_HEADER
        + """
if os.getenv("DEBUG"):
    REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"].append(
        "shop.auth.TokenAuthentication",
    )


def _parse_remote_user_settings():
    global MIDDLEWARE
    if os.getenv("REMOTE_USER"):
        MIDDLEWARE.append("shop.auth.RemoteUserMiddleware")
        REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"].insert(
            0,
            "shop.auth.RemoteUserAuthentication",
        )
    return "HTTP_REMOTE_USER"


REMOTE_USER_HEADER = _parse_remote_user_settings()
""",
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_classes")
    assert "shop.auth.TokenAuthentication" not in unused
    assert "shop.auth.RemoteUserMiddleware" not in unused
    assert "shop.auth.RemoteUserAuthentication" not in unused
    assert "shop.auth.StaleAuthentication" in unused
    assert _rescue_reasons(result)["shop.auth.TokenAuthentication"] == (
        "django_web_setting_reference"
    )


def test_settings_mutations_need_settings_module_and_import_time_call(tmp_path):
    _auth_module(tmp_path)
    _write(
        tmp_path, 'shop/settings.py',
        _SETTINGS_HEADER
        + """
def _never_called():
    MIDDLEWARE.append("shop.auth.RemoteUserMiddleware")
""",
    )
    _write(
        tmp_path, 'shop/plugins.py',
        """
        HANDLERS = []
        HANDLERS.append("shop.auth.TokenAuthentication")
        """,
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_classes")
    assert "shop.auth.RemoteUserMiddleware" in unused
    assert "shop.auth.TokenAuthentication" in unused


# getattr(import_module(...), name) over a literal table


def test_class_loaded_from_literal_table_by_import_module_is_live(tmp_path):
    _write(
        tmp_path, 'sync/__init__.py',
        """
        from importlib import import_module

        PACKAGE = "sync"
        SOURCES = {"amarok": "Amarok"}


        def load_sources():
            loaded = {}
            for module_path, class_name in SOURCES.items():
                module = import_module(f"{PACKAGE}.{module_path}")
                loaded[class_name.lower()] = getattr(module, class_name)
            return loaded


        SOURCES_BY_NAME = load_sources()
        """,
    )
    _write(
        tmp_path, 'sync/amarok.py',
        """
        class Amarok:
            def sync(self, item):
                return item


        class Unlisted:
            def sync(self, item):
                return item
        """,
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_classes")
    assert "sync.amarok.Amarok" not in unused
    assert "sync.amarok.Unlisted" in unused
    assert _rescue_reasons(result)["sync.amarok.Amarok"] == "dynamic_module_attribute"


def test_unreachable_import_module_loader_does_not_rescue(tmp_path):
    _write(
        tmp_path, 'sync/__init__.py',
        """
        import importlib

        SOURCES = [("sync.amarok", "Amarok")]


        def load_sources():
            for module_path, class_name in SOURCES:
                module = importlib.import_module(module_path)
                yield getattr(module, class_name)
        """,
    )
    _write(
        tmp_path, 'sync/amarok.py',
        """
        class Amarok:
            pass
        """,
    )

    result = _scan(tmp_path)

    assert "sync.amarok.Amarok" in _names(result, "unused_classes")


# Registration through decorators defined in another module


_TAG_PARSER = """
    _TAG = "__PARSE_TAG_NAME"


    def parse_tag(tag):
        def decorator(func):
            setattr(func, _TAG, tag)
            return func

        return decorator


    class ParserMeta(type):
        def __init__(cls, name, bases, namespace, **kwargs):
            super().__init__(name, bases, namespace, **kwargs)
            tags = dict(getattr(cls, "_TAGS", {}))
            for member in namespace.values():
                tag = getattr(member, _TAG, None)
                if isinstance(tag, str):
                    tags[tag] = member
            cls._TAGS = tags


    class Parser(metaclass=ParserMeta):
        def parse_line(self, tag, value):
            handler = self._TAGS.get(tag)
            if handler:
                handler(self, value)
    """


def test_tag_decorator_collected_by_metaclass_registers_imported_uses(tmp_path):
    _write(tmp_path, 'hls/parser.py', _TAG_PARSER)
    _write(
        tmp_path, 'hls/__init__.py',
        "from hls.parser import Parser, parse_tag\n",
    )
    _write(
        tmp_path, 'plugins/custom.py',
        """
        from hls import Parser, parse_tag


        class CustomParser(Parser):
            @parse_tag("EXT-X-CUSTOM")
            def parse_custom(self, value):
                return value

            def stale_helper(self):
                return 1


        def run():
            CustomParser().parse_line("EXT-X-CUSTOM", "1")


        run()
        """,
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_functions")
    assert "plugins.custom.CustomParser.parse_custom" not in unused
    assert "plugins.custom.CustomParser.stale_helper" in unused
    assert _rescue_reasons(result)["plugins.custom.CustomParser.parse_custom"] == (
        "registered_by_decorator"
    )


def test_tag_decorator_without_a_collector_does_not_register(tmp_path):
    _write(
        tmp_path, 'tools/marks.py',
        """
        def mark(label):
            def decorator(func):
                func.label = label
                return func

            return decorator
        """,
    )
    _write(
        tmp_path, 'tools/jobs.py',
        """
        from tools.marks import mark


        class Jobs:
            @mark("nightly")
            def nightly(self):
                return 1


        def run():
            return Jobs()


        run()
        """,
    )

    result = _scan(tmp_path)

    assert "tools.jobs.Jobs.nightly" in _names(result, "unused_functions")


def test_registry_decorator_imported_from_another_module_registers(tmp_path):
    _write(
        tmp_path, 'app/registry.py',
        """
        PROVIDERS = []


        def provides(func):
            PROVIDERS.append(func)
            return func


        def logged(func):
            def inner(*args):
                return func(*args)

            return inner
        """,
    )
    _write(
        tmp_path, 'app/providers.py',
        """
        from app.registry import logged, provides


        @provides
        def database_provider():
            return "db"


        @logged
        def never_called():
            return "x"
        """,
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_functions")
    assert "app.providers.database_provider" not in unused
    assert "app.providers.never_called" in unused


_LISTENER_MIXIN = """
from functools import wraps


class FutureListener:
    def __init__(self, listener, event):
        self.listener = listener
        self.event = event


class ListenerMixin:
    def __init__(self):
        self._future_listeners = []

    def listener(self, listener, event):
        def register_listener(handler, name):
            future = FutureListener(handler, name)
            self._future_listeners.append(future)
            return handler

        return register_listener(listener, event)

    def _setup_listener(self, listener, event):
        return self.listener(listener, event)

    def main_process_ready(self, listener):
        return self._setup_listener(listener, "main_process_ready")

    def memoize(self, func):
        @wraps(func)
        def inner(*args):
            return func(*args)

        inner.__wrapped__ = func
        return inner
"""

_LISTENER_CLI = """
from web.listeners import ListenerMixin


class CLI:
    def start(self, app: ListenerMixin):
        @app.main_process_ready
        async def start_repl(app):
            return app

        @app.memoize
        def cached_value():
            return 1

        return app
"""


def test_nested_function_registered_through_forwarding_method_is_live(tmp_path):
    parsed = []
    definitions = {}
    for module, source in (
        ("web.listeners", _LISTENER_MIXIN),
        ("web.cli", _LISTENER_CLI),
    ):
        path = tmp_path / (module.replace(".", "/") + ".py")
        tree = ast.parse(source)
        parsed.append(ParsedPythonFile(path, tree))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{module}.{node.name}"
                definitions[name] = Definition(
                    name, "function", path, node.lineno, node
                )

    targets = find_method_registered_targets(definitions, parsed)

    assert [target.name for target in targets] == ["web.cli.start_repl"]


# Instances patched onto an external module


def test_instance_patched_into_external_module_keeps_public_methods(tmp_path):
    _write(
        tmp_path, 'net/http.py',
        """
        import re

        import urllib3


        class PercentReOverride:
            _pattern = re.compile("%[a-fA-F0-9]{2}")

            def subn(self, repl, string, count=None):
                return string, len(self._pattern.findall(string))

            def _unused_private(self):
                return None


        urllib3.util.url._PERCENT_RE = PercentReOverride()


        class NotPatched:
            def subn(self, repl, string, count=None):
                return string, 0


        local_value = NotPatched()
        """,
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_functions")
    assert "net.http.PercentReOverride.subn" not in unused
    assert "net.http.PercentReOverride._unused_private" in unused
    assert "net.http.NotPatched.subn" in unused


# Names other modules import from a module that imports them


def test_reexported_fallback_import_is_used_by_importers(tmp_path):
    _write(tmp_path, 'pkg/__init__.py', "")
    _write(
        tmp_path, 'pkg/crypto.py',
        """
        from os import sep

        try:
            from json import dumps, loads
        except ImportError:
            from simplejson import dumps, loads
        """,
    )
    _write(
        tmp_path, 'pkg/client.py',
        """
        from pkg.crypto import dumps


        def encode(value):
            return dumps(value)


        encode(1)
        """,
    )
    _write(
        tmp_path, 'pkg/reader.py',
        """
        from pkg import crypto


        def decode(value):
            return crypto.loads(value)


        decode("1")
        """,
    )

    result = _scan(tmp_path)

    unused = _names(result, "unused_imports")
    assert "simplejson.dumps" not in unused
    assert "simplejson.loads" not in unused
    assert "json.dumps" not in unused
    assert "json.loads" not in unused
    assert "os.sep" in unused


# Callbacks held only by a method its base class dispatches to


def test_callback_from_dispatched_override_is_live(tmp_path):
    _write(
        tmp_path, 'beets/plugins.py',
        """
        class BasePlugin:
            def commands(self):
                return []


        def load(plugin_class):
            return plugin_class().commands()
        """,
    )
    _write(
        tmp_path, 'beets/util.py',
        """
        def par_map(transform, items):
            for item in items:
                transform(item)
        """,
    )
    _write(
        tmp_path, 'beetsplug/submit.py',
        """
        from beets import util
        from beets.plugins import BasePlugin


        class Command:
            func = None


        class SubmitPlugin(BasePlugin):
            def commands(self):
                cmd = Command()
                cmd.func = self.command
                return [cmd]

            def command(self, items):
                util.par_map(self.analyze_submit, items)

            def analyze_submit(self, item):
                return item

            def orphan(self):
                return None
        """,
    )
    _write(
        tmp_path, 'main.py',
        """
        from beets.plugins import load
        from beetsplug.submit import SubmitPlugin

        load(SubmitPlugin)
        """,
    )

    result = _scan(tmp_path, conf=60)

    unused = _names(result, "unused_functions")
    assert "beetsplug.submit.SubmitPlugin.command" not in unused
    assert "beetsplug.submit.SubmitPlugin.analyze_submit" not in unused
    assert "beetsplug.submit.SubmitPlugin.orphan" in unused


# Scripts and page functions referenced from templates and strings


def test_template_literal_script_src_loads_theme_script(tmp_path):
    _write(
        tmp_path, 'themes/basic/base.html',
        """
        <html><body>
        <script src="{{ 'js/base.js'|url }}"></script>
        </body></html>
        """,
    )
    _write(tmp_path, 'themes/basic/js/base.js', "var ready = 1;\n")
    _write(tmp_path, 'themes/basic/js/orphan.js', "var left = 1;\n")
    _write(tmp_path, 'app.py', "def main():\n    return 1\n\n\nmain()\n")

    result = _scan(tmp_path, conf=60)

    paths = _unused_file_paths(result, tmp_path)
    assert "themes/basic/js/base.js" not in paths
    assert "themes/basic/js/orphan.js" in paths


def test_script_named_by_path_string_is_loaded(tmp_path):
    _write(
        tmp_path, 'search/plugin.py',
        """
        def scripts():
            return ["search/main.js"]


        scripts()
        """,
    )
    _write(
        tmp_path, 'search/templates/search/main.js',
        """
        var worker = new Worker(joinUrl(base_url, "search/worker.js"));
        """,
    )
    _write(
        tmp_path, 'search/templates/search/worker.js',
        "onmessage = function (e) { postMessage(e.data); };\n",
    )
    _write(
        tmp_path, 'search/templates/search/stale.js',
        "var stale = 1;\n",
    )

    result = _scan(tmp_path, conf=60)

    paths = _unused_file_paths(result, tmp_path)
    assert "search/templates/search/main.js" not in paths
    assert "search/templates/search/worker.js" not in paths
    assert "search/templates/search/stale.js" in paths


def test_import_specifier_in_unused_file_does_not_load_its_target(tmp_path):
    _write(
        tmp_path, 'web/dead.js',
        'import { helper } from "./lib/helper.js";\nhelper();\n',
    )
    _write(tmp_path, 'web/lib/helper.js', "export function helper() {}\n")
    _write(tmp_path, 'app.py', "def main():\n    return 1\n\n\nmain()\n")

    result = _scan(tmp_path, conf=60)

    paths = _unused_file_paths(result, tmp_path)
    assert "web/dead.js" in paths
    assert "web/lib/helper.js" in paths


def test_page_function_named_by_python_rendered_onclick_is_live(tmp_path):
    _write(
        tmp_path, 'webapp/markdown.py',
        """
        def render_copy_button(builder):
            return '<button class="code-block__copy" onclick="copyCode(this)">copy</button>'


        def render_link():
            return '<a href="#" onClick=\\'openMenu(event)\\'>menu</a>'


        render_copy_button(None)
        render_link()
        """,
    )
    _write(tmp_path, 'index.html', '<script src="public/assets/docs.js"></script>\n')
    _write(
        tmp_path, 'public/assets/docs.js',
        """
        function copyCode(element) {
            return element;
        }

        function openMenu(event) {
            return event;
        }

        function unusedHelper() {
            return 1;
        }
        """,
    )

    result = _scan(tmp_path, conf=0)

    names = _js_function_names(result)
    assert "copyCode" not in names
    assert "openMenu" not in names
    assert "unusedHelper" in names


def test_commented_out_python_onclick_does_not_keep_a_page_function(tmp_path):
    _write(
        tmp_path, 'webapp/markdown.py',
        """
        def render_copy_button(builder):
            # builder.div(onclick="retiredCopy(this)")
            return '<button class="code-block__copy" onclick="copyCode(this)">copy</button>'


        render_copy_button(None)
        """,
    )
    _write(tmp_path, 'index.html', '<script src="public/assets/docs.js"></script>\n')
    _write(
        tmp_path, 'public/assets/docs.js',
        """
        function copyCode(element) {
            return element;
        }

        function retiredCopy(element) {
            return element;
        }
        """,
    )

    result = _scan(tmp_path, conf=0)

    names = _js_function_names(result)
    assert "copyCode" not in names
    assert "retiredCopy" in names


def test_page_functions_named_by_python_strings_are_live(tmp_path):
    _write(
        tmp_path,
        "webui/ui.py",
        """
        import gradio as gr


        def build(tab, name):
            \"\"\"Docs may mention retiredHelper() without calling it.\"\"\"
            button = gr.Button()
            button.click(_js="submitForm")
            button.click(_js="function(){ setSeed('" + name + "'); }")
            button.click(_js=f"switch_to_{tab}")
            button.click(_js="update_" + tab + "_tokens()")
            return f"<script>applyTheme('{name}');</script>"


        build("txt", "x")
        """,
    )
    _write(tmp_path, "index.html", '<script src="javascript/ui.js"></script>\n')
    _write(
        tmp_path,
        "javascript/ui.js",
        """
        function submitForm() { return 1; }
        function setSeed(id) { return id; }
        function switch_to_txt() { return 2; }
        function update_txt_tokens() { return 3; }
        function applyTheme(name) { return name; }
        function retiredHelper() { return 4; }
        function unusedHelper() { return 5; }
        """,
    )

    names = _js_function_names(_scan(tmp_path, conf=0))
    assert {
        "submitForm",
        "setSeed",
        "switch_to_txt",
        "update_txt_tokens",
        "applyTheme",
    }.isdisjoint(names)
    assert {"retiredHelper", "unusedHelper"} <= names


def test_python_strings_do_not_reach_module_script_functions(tmp_path):
    _write(
        tmp_path, 'webui/ui.py',
        'def build(button):\n    button.click(_js="moduleOnly")\n\n\nbuild(None)\n',
    )
    _write(
        tmp_path, 'web/app.js',
        'import { x } from "./lib.js";\nfunction moduleOnly() { return x; }\n',
    )
    _write(tmp_path, 'web/lib.js', 'export const x = 1;\n')

    assert "moduleOnly" in _js_function_names(_scan(tmp_path, conf=0))


def test_scripts_rendered_from_a_python_folder_listing_are_loaded(tmp_path):
    _write(
        tmp_path,
        "webui/head.py",
        """
        import os


        def list_scripts(folder, extension):
            return os.scandir(folder)


        def javascript_html(root):
            main = os.path.join(root, "script.js")
            head = f'<script src="{main}"></script>'
            for script in list_scripts("javascript", ".js"):
                head += f'<script type="text/javascript" src="{script.path}"></script>'
            return head


        javascript_html(".")
        """,
    )
    _write(tmp_path, "script.js", "var ready = 1;\n")
    _write(tmp_path, "javascript/ui.js", "var ui = 1;\n")
    _write(tmp_path, "extensions/zoom/javascript/zoom.js", "var zoom = 1;\n")
    _write(tmp_path, "assets/stale.js", "var stale = 1;\n")

    paths = _unused_file_paths(_scan(tmp_path, conf=60), tmp_path)
    assert {"script.js", "javascript/ui.js"}.isdisjoint(paths)
    assert {"assets/stale.js", "extensions/zoom/javascript/zoom.js"} <= paths


def test_classes_found_by_subclass_discovery_are_live(tmp_path):
    _write(
        tmp_path,
        "app/plugins.py",
        """
        import importlib
        import inspect


        class Plugin:
            pass


        class Upscaler:
            pass


        def load():
            module = importlib.import_module("plugins.extra")
            found = []
            for value in module.__dict__.values():
                if inspect.isclass(value) and issubclass(value, Plugin):
                    found.append(value)
            import plugins.extra
            return found + [cls() for cls in Upscaler.__subclasses__()]


        load()
        """,
    )
    _write(
        tmp_path,
        "plugins/extra.py",
        """
        from app.plugins import Plugin, Upscaler


        class ExtraPlugin(Plugin):
            pass


        class FastUpscaler(Upscaler):
            pass


        class Unrelated:
            pass
        """,
    )

    unused = _names(_scan(tmp_path, conf=0), "unused_classes")
    assert {"plugins.extra.ExtraPlugin", "plugins.extra.FastUpscaler"}.isdisjoint(
        unused
    )
    assert "plugins.extra.Unrelated" in unused


def test_a_computed_string_without_literal_text_does_not_keep_functions(tmp_path):
    _write(
        tmp_path, 'app/mod.py',
        """
        def handle_refund():
            return 1


        def dead_helper(x):
            return x


        def dispatch(obj, action):
            name = f"handle_{action}"
            label = f"{obj}{action}"
            message = "%s: %s" % (obj, action)
            return getattr(obj, name)(), label, message


        dispatch(None, "refund")
        """,
    )

    unused = _names(_scan(tmp_path, conf=0), "unused_functions")
    assert "app.mod.handle_refund" not in unused
    assert "app.mod.dead_helper" in unused
