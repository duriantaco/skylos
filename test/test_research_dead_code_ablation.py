from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from skylos.research.dead_code import (
    CandidateClassification,
    ResearchVariant,
    run_ablation,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def _route_fixture(tmp_path: Path) -> Path:
    _write(
        tmp_path / "app.py",
        """
        app = object()

        @app.get("/")
        def index():
            return render_dashboard()

        def render_dashboard():
            return "ok"

        def stale_helper():
            return "dead"
        """,
    )
    return tmp_path


def test_ablation_v1_roots_only_does_not_rescue_helper(tmp_path: Path):
    root = _route_fixture(tmp_path)

    result = run_ablation(root, variant=ResearchVariant.ROOTS_ONLY)

    assert result.classify("app.index") == CandidateClassification.ALIVE
    assert result.classify("app.render_dashboard") == CandidateClassification.LIKELY_DEAD
    assert result.classify("app.stale_helper") == CandidateClassification.LIKELY_DEAD


def test_ablation_v2_reachability_rescues_helper_only(tmp_path: Path):
    root = _route_fixture(tmp_path)

    result = run_ablation(root, variant=ResearchVariant.ROOTS_REACHABILITY)

    assert result.classify("app.index") == CandidateClassification.ALIVE
    assert result.classify("app.render_dashboard") == CandidateClassification.ALIVE
    assert result.classify("app.stale_helper") == CandidateClassification.LIKELY_DEAD


def test_ablation_v3_top_level_execution_rescues_module_call(tmp_path: Path):
    _write(
        tmp_path / "service.py",
        """
        def dispatch():
            return "live"

        LIVE_RESULT = dispatch()
        """,
    )

    v2 = run_ablation(tmp_path, variant=ResearchVariant.ROOTS_REACHABILITY)
    v3 = run_ablation(tmp_path, variant=ResearchVariant.TOP_LEVEL_REACHABILITY)

    assert v2.classify("service.dispatch") == CandidateClassification.LIKELY_DEAD
    assert v3.classify("service.dispatch") == CandidateClassification.ALIVE


def test_ablation_v4_factory_return_summary_rescues_method(tmp_path: Path):
    _write(
        tmp_path / "pyproject.toml",
        """
        [project.scripts]
        demo = "orders.cli:main"
        """,
    )
    _write(
        tmp_path / "orders" / "cli.py",
        """
        from orders.service import make_processor

        def main():
            processor = make_processor()
            return processor.run()
        """,
    )
    _write(
        tmp_path / "orders" / "service.py",
        """
        class Processor:
            def run(self):
                return "live"

        class RemovedProcessor:
            def run(self):
                return "dead"

        def make_processor():
            return Processor()
        """,
    )

    v3 = run_ablation(tmp_path, variant=ResearchVariant.TOP_LEVEL_REACHABILITY)
    v4 = run_ablation(tmp_path, variant=ResearchVariant.FACTORY_RETURN_SUMMARIES)

    assert v3.classify("orders.service.Processor.run") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert v4.classify("orders.service.Processor.run") == CandidateClassification.ALIVE
    assert v4.classify("orders.service.RemovedProcessor.run") == (
        CandidateClassification.LIKELY_DEAD
    )


def test_v4_rescues_nested_returns_dynamic_calls_and_decorators(tmp_path: Path):
    _write(
        tmp_path / "code.py",
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper

        @decorator
        def decorated():
            return "live"

        def outer():
            def returned():
                return "live"

            def stale_inner():
                return "dead"

            return returned

        def called_via_getattr():
            return "live"

        def called_via_globals():
            return "live"

        def stale():
            return "dead"

        func_name = "called_via_getattr"
        dynamic_func = getattr(__import__(__name__), func_name)
        dynamic_func()

        global_name = "called_via_globals"
        globals()[global_name]()

        returned_func = outer()
        returned_func()
        decorated()
        """,
    )

    v4 = run_ablation(tmp_path, variant=ResearchVariant.FACTORY_RETURN_SUMMARIES)

    assert v4.classify("code.decorator") == CandidateClassification.ALIVE
    assert v4.classify("code.called_via_getattr") == CandidateClassification.ALIVE
    assert v4.classify("code.called_via_globals") == CandidateClassification.ALIVE
    assert v4.classify("code.outer.returned") == CandidateClassification.ALIVE
    assert v4.classify("code.outer.stale_inner") == CandidateClassification.LIKELY_DEAD
    assert v4.classify("code.stale") == CandidateClassification.LIKELY_DEAD


def test_v4_resolves_package_reexports_and_exported_methods(tmp_path: Path):
    _write(
        tmp_path / "package" / "__init__.py",
        """
        from .submodule import ExportedClass, exported_function

        PACKAGE_CONSTANT = "live"

        def stale_package_function():
            return "dead"
        """,
    )
    _write(
        tmp_path / "package" / "submodule.py",
        """
        def exported_function():
            return "live"

        def stale_function():
            return "dead"

        class ExportedClass:
            def __init__(self):
                self.value = "live"

            def method(self):
                return self.value

            def stale_method(self):
                return "dead"
        """,
    )
    _write(
        tmp_path / "use_package.py",
        """
        import package
        from package import ExportedClass, exported_function

        def main():
            print(package.PACKAGE_CONSTANT)
            exported_function()
            obj = ExportedClass()
            return obj.method()

        main()
        """,
    )

    v4 = run_ablation(tmp_path, variant=ResearchVariant.FACTORY_RETURN_SUMMARIES)

    assert v4.classify("package.PACKAGE_CONSTANT") == CandidateClassification.ALIVE
    assert v4.classify("package.submodule.exported_function") == (
        CandidateClassification.ALIVE
    )
    assert v4.classify("package.submodule.ExportedClass") == CandidateClassification.ALIVE
    assert v4.classify("package.submodule.ExportedClass.method") == (
        CandidateClassification.ALIVE
    )
    assert v4.classify("package.stale_package_function") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert v4.classify("package.submodule.stale_function") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert v4.classify("package.submodule.ExportedClass.stale_method") == (
        CandidateClassification.LIKELY_DEAD
    )


def test_v4_rescues_protocol_argument_method_calls(tmp_path: Path):
    _write(
        tmp_path / "service.py",
        """
        from typing import Protocol

        class Handler(Protocol):
            def handle(self, payload: str) -> str:
                ...

        class EmailHandler:
            def handle(self, payload: str) -> str:
                return payload.upper()

        def dispatch(handler: Handler) -> str:
            return handler.handle("welcome")

        LIVE_RESULT = dispatch(EmailHandler())
        """,
    )

    v4 = run_ablation(tmp_path, variant=ResearchVariant.FACTORY_RETURN_SUMMARIES)
    v5 = run_ablation(tmp_path, variant=ResearchVariant.CONSERVATIVE_REPORTING)

    assert v4.classify("service.dispatch") == CandidateClassification.ALIVE
    assert v4.classify("service.EmailHandler.handle") == CandidateClassification.ALIVE
    assert v5.classify("service.Handler") == CandidateClassification.UNCERTAIN
    assert v5.classify("service.Handler.handle") == CandidateClassification.UNCERTAIN


def test_v5_abstains_on_weak_unlabeled_artifacts(tmp_path: Path):
    _write(
        tmp_path / "code.py",
        """
        def unused_decorator(func):
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper

        class UnusedClass:
            def __init__(self):
                self.value = 1

            def method(self):
                return self.value

        result = "temporary"
        internal_result = "temporary"
        __version__ = "1.0.0"
        LIVE_RESULT = "temporary"
        BOOT_RESULT = "temporary"

        def format_status():
            return "temporary"

        def direct_processor_name():
            return "temporary"
        """,
    )

    v4 = run_ablation(tmp_path, variant=ResearchVariant.FACTORY_RETURN_SUMMARIES)
    v5 = run_ablation(tmp_path, variant=ResearchVariant.CONSERVATIVE_REPORTING)

    assert v4.classify("code.UnusedClass.__init__") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert v5.classify("code.UnusedClass.__init__") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.unused_decorator.wrapper") == (
        CandidateClassification.UNCERTAIN
    )
    assert v5.classify("code.result") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.internal_result") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.__version__") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.LIVE_RESULT") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.BOOT_RESULT") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.format_status") == CandidateClassification.UNCERTAIN
    assert v5.classify("code.direct_processor_name") == (
        CandidateClassification.UNCERTAIN
    )
    assert v5.classify("code.UnusedClass") == CandidateClassification.LIKELY_DEAD
    assert v5.classify("code.UnusedClass.method") == (
        CandidateClassification.LIKELY_DEAD
    )


def test_v6_abstains_on_general_interface_and_action_policy_cases(tmp_path: Path):
    _write(
        tmp_path / "code.py",
        """
        from abc import ABC, abstractmethod
        from typing import TypeAlias, NewType
        from typing_extensions import TypeAliasType

        class Processor(ABC):
            @abstractmethod
            def process(self, data):
                pass

        class NotificationBase:
            def send(self):
                raise NotImplementedError

        class Widget:
            def on_click(self):
                pass

            def watch_value(self):
                pass

            def compose(self):
                pass

            def stale_method(self):
                return "dead"

        Ignored = 1  # pragma: no skylos
        UserId = NewType("UserId", int)
        Vector = TypeAliasType("Vector", list[int])
        JsonValue: TypeAlias = dict[str, str]

        def stale_function():
            return "dead"
        """,
    )

    v6 = run_ablation(tmp_path, variant=ResearchVariant.GENERAL_ACTION_REPORTING)

    assert v6.classify("code.Processor.process") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.NotificationBase.send") == (
        CandidateClassification.UNCERTAIN
    )
    assert v6.classify("code.Widget.on_click") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.Widget.watch_value") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.Widget.compose") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.Ignored") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.UserId") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.Vector") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.JsonValue") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.Widget") == CandidateClassification.LIKELY_DEAD
    assert v6.classify("code.Widget.stale_method") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert v6.classify("code.stale_function") == CandidateClassification.LIKELY_DEAD


def test_v6_tracks_dynamic_globals_getattr_and_metaclass_side_effects(tmp_path: Path):
    _write(
        tmp_path / "code.py",
        """
        class MyClass:
            def dynamic_method(self):
                return "live"

        def dynamic_func():
            return "live"

        class Meta(type):
            def __new__(mcs, name, bases, namespace):
                cls = super().__new__(mcs, name, bases, namespace)
                cls.attr = 100
                return cls

        class UsesMeta(metaclass=Meta):
            pass

        class Registry(type):
            plugins = {}

            def __new__(mcs, name, bases, namespace):
                cls = super().__new__(mcs, name, bases, namespace)
                if bases:
                    mcs.plugins[name] = cls
                return cls

        class BasePlugin(metaclass=Registry):
            pass

        class ConcretePlugin(BasePlugin):
            pass

        class DeadModel:
            def validate_name(self, name):
                return isinstance(name, str)

        def main():
            obj = MyClass()
            if hasattr(obj, "dynamic_method"):
                getattr(obj, "dynamic_method")()

            g = globals()
            g["dynamic_func"]()
            return UsesMeta.attr, list(Registry.plugins)

        main()
        """,
    )

    v6 = run_ablation(tmp_path, variant=ResearchVariant.GENERAL_ACTION_REPORTING)

    assert v6.classify("code.MyClass") == CandidateClassification.ALIVE
    assert v6.classify("code.MyClass.dynamic_method") == CandidateClassification.ALIVE
    assert v6.classify("code.dynamic_func") == CandidateClassification.ALIVE
    assert v6.classify("code.Meta") == CandidateClassification.ALIVE
    assert v6.classify("code.Meta.__new__") == CandidateClassification.ALIVE
    assert v6.classify("code.BasePlugin") == CandidateClassification.ALIVE
    assert v6.classify("code.Registry") == CandidateClassification.ALIVE
    assert v6.classify("code.Registry.__new__") == CandidateClassification.ALIVE
    assert v6.classify("code.ConcretePlugin") == CandidateClassification.UNCERTAIN
    assert v6.classify("code.DeadModel") == CandidateClassification.LIKELY_DEAD
    assert v6.classify("code.DeadModel.validate_name") == (
        CandidateClassification.LIKELY_DEAD
    )


def test_v6_abstains_on_single_symbol_deletion_hazards(tmp_path: Path):
    _write(
        tmp_path / "code.py",
        """
        def used_as_value():
            return "callback"

        alias = used_as_value

        def referenced_by_dead():
            return "helper"

        def dead_caller():
            return referenced_by_dead()

        class Handler:
            def callback(self):
                return "callback"

            alias = callback

        class Deferred:
            def run(self):
                return "maybe dispatched through an instance attribute"

            def invoke(self):
                return self.target.run()

        handler = Handler()
        handler.callback

        class ExternalName:
            pass

        def unknown_external_reference():
            return plugin.ExternalName

        value = 1
        other = source.value

        def genuinely_stale():
            return "dead"
        """,
    )

    v7 = run_ablation(tmp_path, variant=ResearchVariant.REFERENCE_SAFE_REPORTING)

    assert v7.classify("code.used_as_value") == CandidateClassification.UNCERTAIN
    assert v7.classify("code.referenced_by_dead") == CandidateClassification.UNCERTAIN
    assert v7.classify("code.Handler.callback") == CandidateClassification.UNCERTAIN
    assert v7.classify("code.Deferred.run") == CandidateClassification.UNCERTAIN
    assert v7.classify("code.ExternalName") == CandidateClassification.UNCERTAIN
    assert v7.classify("code.value") == CandidateClassification.UNCERTAIN
    assert v7.classify("code.genuinely_stale") == CandidateClassification.LIKELY_DEAD


def test_test_roots_are_file_sensitive(tmp_path: Path):
    _write(
        tmp_path / "case.py",
        """
        def test_func():
            return "not automatically a test"
        """,
    )
    _write(
        tmp_path / "tests" / "test_app.py",
        """
        def test_kept():
            return "pytest entrypoint"
        """,
    )

    v6 = run_ablation(tmp_path, variant=ResearchVariant.GENERAL_ACTION_REPORTING)

    assert v6.classify("case.test_func") == CandidateClassification.LIKELY_DEAD
    assert v6.classify("tests.test_app.test_kept") == CandidateClassification.ALIVE


def test_ablation_export_contains_summary_and_evidence(tmp_path: Path):
    root = _route_fixture(tmp_path)

    result = run_ablation(root, variant=ResearchVariant.ROOTS_REACHABILITY)
    payload = result.to_dict()

    assert payload["variant"] == "v2-roots-reachability"
    assert payload["summary"]["symbol_count"] == 4
    symbols = {entry["qualified_name"]: entry for entry in payload["symbols"]}
    assert symbols["app.app"]["kind"] == "variable"
    assert symbols["app.index"]["is_root"] is True
    assert symbols["app.render_dashboard"]["is_reachable"] is True
    assert symbols["app.stale_helper"]["classification"] == "likely_dead"
    assert symbols["app.render_dashboard"]["evidence"]


def test_ablation_cli_outputs_json(tmp_path: Path):
    root = _route_fixture(tmp_path)
    script = Path(__file__).resolve().parents[1] / "scripts" / "research_dead_code_ablation.py"

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            str(root),
            "--variant",
            "v1-roots-only",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert payload["variant"] == "v1-roots-only"
    symbols = {entry["qualified_name"]: entry for entry in payload["symbols"]}
    assert symbols["app.render_dashboard"]["classification"] == "likely_dead"
