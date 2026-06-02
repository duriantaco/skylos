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
