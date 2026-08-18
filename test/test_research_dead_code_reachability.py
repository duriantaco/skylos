from __future__ import annotations

import textwrap
from pathlib import Path

from skylos.research.dead_code import (
    CandidateClassification,
    EvidenceKind,
    RootKind,
    analyze_reachability,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def test_route_root_reaches_helper_but_not_stale_helper(tmp_path: Path):
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

    result = analyze_reachability(tmp_path)

    assert result.is_reachable("app.index")
    assert result.is_reachable("app.render_dashboard")
    assert not result.is_reachable("app.stale_helper")
    assert result.classify("app.index") == CandidateClassification.ALIVE
    assert result.classify("app.render_dashboard") == CandidateClassification.ALIVE
    assert result.classify("app.stale_helper") == CandidateClassification.LIKELY_DEAD
    assert result.ledger.has_kind(
        result.symbol("app.render_dashboard"),
        EvidenceKind.REACHABLE_FROM_ROOT,
    )


def test_pyproject_entrypoint_reaches_service_and_repository_chain(tmp_path: Path):
    _write(
        tmp_path / "pyproject.toml",
        """
        [project.scripts]
        demo = "demo.cli:main"
        """,
    )
    _write(
        tmp_path / "demo" / "cli.py",
        """
        from demo import service

        def main():
            return service.run()
        """,
    )
    _write(
        tmp_path / "demo" / "service.py",
        """
        from demo import repository

        def run():
            return repository.save()

        def stale_service_helper():
            return False
        """,
    )
    _write(
        tmp_path / "demo" / "repository.py",
        """
        def save():
            return True

        def stale_repository_helper():
            return False
        """,
    )

    result = analyze_reachability(tmp_path)

    assert result.is_reachable("demo.cli.main")
    assert result.is_reachable("demo.service.run")
    assert result.is_reachable("demo.repository.save")
    assert not result.is_reachable("demo.service.stale_service_helper")
    assert not result.is_reachable("demo.repository.stale_repository_helper")
    assert result.classify("demo.repository.save") == CandidateClassification.ALIVE
    assert (
        result.classify("demo.repository.stale_repository_helper")
        == CandidateClassification.LIKELY_DEAD
    )


def test_task_root_reaches_nested_helpers(tmp_path: Path):
    _write(
        tmp_path / "tasks.py",
        """
        from celery import shared_task

        @shared_task
        def rebuild_index():
            records = load_records()
            return normalize(records)

        def load_records():
            return ["A"]

        def normalize(records):
            return [item.lower() for item in records]

        def old_task_helper():
            return []
        """,
    )

    result = analyze_reachability(tmp_path)

    assert result.is_reachable("tasks.rebuild_index")
    assert result.is_reachable("tasks.load_records")
    assert result.is_reachable("tasks.normalize")
    assert not result.is_reachable("tasks.old_task_helper")


def test_plugin_root_reaches_registered_handler(tmp_path: Path):
    _write(
        tmp_path / "plugin.py",
        """
        hookimpl = object()

        @hookimpl
        def demo_plugin_hook():
            return registered_handler()

        def registered_handler():
            return "handled"

        def old_handler():
            return "dead"
        """,
    )

    result = analyze_reachability(tmp_path)
    roots_by_name = {root.symbol.qualified_name: root for root in result.roots.roots}

    assert roots_by_name["plugin.demo_plugin_hook"].kind == RootKind.PLUGIN_HOOK
    assert result.is_reachable("plugin.registered_handler")
    assert not result.is_reachable("plugin.old_handler")


def test_same_name_helper_in_other_file_is_not_rescued(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        app = object()

        @app.get("/")
        def index():
            return render_dashboard()

        def render_dashboard():
            return "ok"
        """,
    )
    _write(
        tmp_path / "other.py",
        """
        def render_dashboard():
            return "not referenced"
        """,
    )

    result = analyze_reachability(tmp_path)

    assert result.is_reachable("app.render_dashboard")
    assert not result.is_reachable("other.render_dashboard")
    assert result.classify("other.render_dashboard") == CandidateClassification.LIKELY_DEAD


def test_top_level_execution_rescues_module_level_call(tmp_path: Path):
    _write(
        tmp_path / "service.py",
        """
        def dispatch():
            return "live"

        LIVE_RESULT = dispatch()

        def stale_helper():
            return "dead"
        """,
    )

    without_top_level = analyze_reachability(tmp_path)
    with_top_level = analyze_reachability(tmp_path, include_top_level=True)

    assert without_top_level.classify("service.dispatch") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert with_top_level.classify("service.dispatch") == CandidateClassification.ALIVE
    assert with_top_level.ledger.has_kind(
        with_top_level.symbol("service.dispatch"),
        EvidenceKind.TOP_LEVEL_EXECUTION,
    )
    assert with_top_level.classify("service.stale_helper") == (
        CandidateClassification.LIKELY_DEAD
    )


def test_top_level_instance_method_call_rescues_method(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        def register(func):
            return func

        @register
        def handle_event(event):
            return event["id"]

        class LivePlugin:
            def process(self, event):
                return handle_event(event)

        class RemovedPlugin:
            def process(self, event):
                return event

        LIVE_PLUGIN = LivePlugin()
        BOOTSTRAP_RESULT = LIVE_PLUGIN.process({"id": "boot"})
        """,
    )

    without_top_level = analyze_reachability(tmp_path)
    with_top_level = analyze_reachability(tmp_path, include_top_level=True)

    assert without_top_level.classify("app.LivePlugin.process") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert without_top_level.classify("app.LivePlugin") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert with_top_level.classify("app.LivePlugin.process") == (
        CandidateClassification.ALIVE
    )
    assert with_top_level.classify("app.LivePlugin") == CandidateClassification.ALIVE
    assert with_top_level.classify("app.RemovedPlugin") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert with_top_level.classify("app.RemovedPlugin.process") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert with_top_level.ledger.has_kind(
        with_top_level.symbol("app.LivePlugin.process"),
        EvidenceKind.TOP_LEVEL_EXECUTION,
    )


def test_factory_return_summary_rescues_method_on_returned_instance(tmp_path: Path):
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

    without_factory_returns = analyze_reachability(tmp_path)
    with_factory_returns = analyze_reachability(
        tmp_path,
        include_factory_returns=True,
    )

    assert without_factory_returns.classify("orders.service.Processor.run") == (
        CandidateClassification.LIKELY_DEAD
    )
    assert with_factory_returns.classify("orders.service.Processor.run") == (
        CandidateClassification.ALIVE
    )
    assert with_factory_returns.classify("orders.service.RemovedProcessor.run") == (
        CandidateClassification.LIKELY_DEAD
    )


def test_reachable_constructor_rescues_class(tmp_path: Path):
    _write(
        tmp_path / "pyproject.toml",
        """
        [project.scripts]
        demo = "cli:main"
        """,
    )
    _write(
        tmp_path / "cli.py",
        """
        def main():
            return make_plugin()

        class LivePlugin:
            def run(self):
                return "live"

        class DeadPlugin:
            def run(self):
                return "dead"

        def make_plugin():
            return LivePlugin()
        """,
    )

    result = analyze_reachability(tmp_path)

    assert result.classify("cli.LivePlugin") == CandidateClassification.ALIVE
    assert result.classify("cli.DeadPlugin") == CandidateClassification.LIKELY_DEAD
    assert result.ledger.has_kind(
        result.symbol("cli.LivePlugin"),
        EvidenceKind.REACHABLE_FROM_ROOT,
    )


def test_reachable_function_read_rescues_module_variable(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        CONFIG = {"status": "ok"}
        STALE_CACHE = {"status": "old"}

        app = object()

        @app.get("/")
        def index():
            return CONFIG["status"]
        """,
    )

    result = analyze_reachability(tmp_path)

    assert result.classify("app.CONFIG") == CandidateClassification.ALIVE
    assert result.classify("app.STALE_CACHE") == CandidateClassification.LIKELY_DEAD
    assert result.ledger.has_kind(
        result.symbol("app.CONFIG"),
        EvidenceKind.REACHABLE_FROM_ROOT,
    )
