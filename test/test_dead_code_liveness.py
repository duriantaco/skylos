import json
import textwrap

from skylos.analyzer import analyze


def _write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _unused_function_names(result):
    return {item["full_name"] for item in result.get("unused_functions", [])}


def test_optional_import_fallback_is_live(tmp_path):
    _write(
        tmp_path / "pkg" / "mod.py",
        """
        class InvalidSchema(Exception):
            pass

        try:
            from optional_package import OptionalFactory
        except ImportError:
            def OptionalFactory(*args, **kwargs):
                raise InvalidSchema("missing optional package")

        def build():
            return OptionalFactory()

        build()
        """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "pkg.mod.OptionalFactory" not in _unused_function_names(result)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(item["reason"] == "optional_import_fallback" for item in rescues)


def test_optional_import_fallback_tuple_handler_is_live(tmp_path):
    _write(
        tmp_path / "pkg" / "mod.py",
        """
        class InvalidSchema(Exception):
            pass

        try:
            from optional_package import OptionalFactory
        except (ImportError, ModuleNotFoundError):
            def OptionalFactory(*args, **kwargs):
                raise InvalidSchema("missing optional package")

        def build():
            return OptionalFactory()

        build()
        """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "pkg.mod.OptionalFactory" not in _unused_function_names(result)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(item["reason"] == "optional_import_fallback" for item in rescues)


def test_protocol_override_method_is_live(tmp_path):
    _write(
        tmp_path / "handlers.py",
        """
        from logging import Handler

        class RichHandler(Handler):
            def emit(self, record):
                return None

        handler = RichHandler()
        """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "handlers.RichHandler.emit" not in _unused_function_names(result)


def test_registration_api_method_is_live(tmp_path):
    _write(
        tmp_path / "app.py",
        """
        def setupmethod(func):
            return func

        class App:
            def __init__(self):
                self.shell_context_processors = []

            @setupmethod
            def shell_context_processor(self, f):
                self.shell_context_processors.append(f)
                return f

        app = App()
        """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "app.App.shell_context_processor" not in _unused_function_names(result)


def test_documented_public_method_is_live(tmp_path):
    _write(
        tmp_path / "app.py",
        """
        class App:
            def open_instance_resource(self, name):
                return name

        app = App()
        """,
    )
    _write(
        tmp_path / "docs" / "config.rst",
        """
        Applications can read instance files with ``app.open_instance_resource("x")``.
        """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "app.App.open_instance_resource" not in _unused_function_names(result)


def test_framework_proxy_attr_call_is_live(tmp_path):
    _write(
        tmp_path / "app.py",
        """
        class App:
            def make_shell_context(self):
                return {}

        app = App()
        """,
    )
    _write(
        tmp_path / "cli.py",
        """
        class Proxy:
            pass

        current_app = Proxy()

        def run_shell():
            return current_app.make_shell_context()

        run_shell()
        """,
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "app.App.make_shell_context" not in _unused_function_names(result)


def test_literal_plugin_registry_targets_are_live(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        """
        [project]
        name = "plugin-registry-fixture"
        version = "0.0.0"

        [project.scripts]
        runner = "app:main"
        """,
    )
    _write(
        tmp_path / "app.py",
        """
        from dispatcher import dispatch_event

        def main(event=None):
            return dispatch_event(event or {"type": "pay", "payload": {}})
        """,
    )
    _write(
        tmp_path / "registry.py",
        """
        HANDLER_PATHS = {
            "pay": "plugins.payments:charge_card",
            "invoice": "plugins.payments:archived_invoice",
        }
        """,
    )
    _write(
        tmp_path / "dispatcher.py",
        """
        import importlib

        from registry import HANDLER_PATHS

        def dispatch_event(event):
            handler_path = HANDLER_PATHS[event.get("type", "pay")]
            module_name, func_name = handler_path.split(":")
            handler = getattr(importlib.import_module(module_name), func_name)
            return handler(event.get("payload", {}))
        """,
    )
    _write(tmp_path / "plugins" / "__init__.py", "")
    _write(
        tmp_path / "plugins" / "payments.py",
        """
        def charge_card(payload):
            return payload

        def archived_invoice(payload):
            return payload

        def debug_query(payload):
            return payload
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _unused_function_names(result)

    assert "plugins.payments.charge_card" not in unused
    assert "plugins.payments.archived_invoice" not in unused
    assert "plugins.payments.debug_query" in unused
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(item["reason"] == "literal_plugin_registry" for item in rescues)


def test_unused_literal_plugin_registry_does_not_rescue_targets(tmp_path):
    _write(
        tmp_path / "registry.py",
        """
        HANDLER_PATHS = {
            "pay": "plugins.payments:charge_card",
        }
        """,
    )
    _write(
        tmp_path / "dispatcher.py",
        """
        import importlib

        from registry import HANDLER_PATHS

        def dispatch_event(event):
            handler_path = HANDLER_PATHS[event.get("type", "pay")]
            module_name, func_name = handler_path.split(":")
            handler = getattr(importlib.import_module(module_name), func_name)
            return handler(event.get("payload", {}))
        """,
    )
    _write(tmp_path / "plugins" / "__init__.py", "")
    _write(
        tmp_path / "plugins" / "payments.py",
        """
        def charge_card(payload):
            return payload
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert "plugins.payments.charge_card" in _unused_function_names(result)


def test_literal_plugin_registry_requires_importlib_getattr_flow(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        """
        [project]
        name = "plugin-registry-fixture"
        version = "0.0.0"

        [project.scripts]
        runner = "app:main"
        """,
    )
    _write(
        tmp_path / "registry.py",
        """
        HANDLER_PATHS = {
            "pay": "plugins.payments:charge_card",
        }
        """,
    )
    _write(
        tmp_path / "app.py",
        """
        from registry import HANDLER_PATHS

        def main():
            return HANDLER_PATHS["pay"]
        """,
    )
    _write(tmp_path / "plugins" / "__init__.py", "")
    _write(
        tmp_path / "plugins" / "payments.py",
        """
        def charge_card(payload):
            return payload
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert "plugins.payments.charge_card" in _unused_function_names(result)
