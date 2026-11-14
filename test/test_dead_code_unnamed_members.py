"""Members nothing in the project can name.

An instance that escapes exposes a method only to code that spells its name,
and a private function that is only ever called directly has no caller that
could require a parameter its body never reads.
"""

import json
import textwrap

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _unused(tmp_path, section):
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=True))
    return {item.get("full_name") or item["name"] for item in result.get(section, [])}


def test_unnamed_methods_of_an_escaped_instance_are_reported(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        class Cache:
            def __init__(self):
                self.items = {}

            def get(self, key):
                return self.items.get(key)

            def is_cached(self, key):
                return key in self.items

            def _evict(self, key):
                self.items.pop(key, None)


        class Holder:
            def __init__(self):
                self.cache = Cache()

            def use(self):
                return self.cache.get("k")


        print(Holder().use())
        """,
    )

    unused = _unused(tmp_path, "unused_functions")
    assert "app.Cache.is_cached" in unused
    assert "app.Cache._evict" in unused
    assert "app.Cache.get" not in unused


def test_methods_an_unresolved_receiver_can_name_stay_unreported(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        import sys
        from typing import Protocol


        class Cache:
            def by_literal(self):
                return 1

            def handle_open(self):
                return 2

            def _named_in_table(self):
                return 3

            def _through_proxy(self):
                return 4

            def _as_callback(self):
                return 5

            def register(self, registry):
                registry.append(self._as_callback)


        class Proxy:
            def __init__(self, target):
                self._target = target

            def __getattr__(self, name):
                return getattr(self._target, name)


        class Sink(Protocol):
            def _flush(self): ...


        class FileSink:
            def _flush(self):
                return None

            def write(self, text):
                return len(text)


        class First:
            def launch(self):
                return 1


        class Second:
            def launch(self):
                return 2


        TABLE = {"table": "_named_in_table"}


        def dispatch(cache, kind, key):
            getattr(cache, "handle_" + kind)()
            return getattr(cache, TABLE[key])()


        def run(registry):
            cache = Cache()
            cache.register(registry)
            getattr(cache, "by_literal")()
            dispatch(cache, "open", "table")
            Proxy(cache)._through_proxy()
            sys.stdout = FileSink()
            registry.extend([First(), Second()])
            return registry


        print(run([]))
        """,
    )

    assert not _unused(tmp_path, "unused_functions")


def test_unread_parameter_of_a_private_directly_called_function_is_reported(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        def _scale(value, factor):
            return value * 2


        class Report:
            def _line(self, text, width):
                return text

            def render(self):
                return self._line("x", 80)


        print(_scale(1, 2), Report().render())
        """,
    )

    assert _unused(tmp_path, "unused_parameters") == {
        "app._scale.factor",
        "app.Report._line.width",
    }


def test_parameters_a_caller_or_contract_can_require_stay_unreported(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        import functools
        from abc import ABC, abstractmethod


        def _on_event(event, context):
            return event


        def _wrapped(payload, meta):
            return payload


        def _variadic(value, *args, **kwargs):
            return value


        def public_api(value, reserved):
            return value


        def _by_name(value, extra):
            return value


        def _default_hook(value, recorder):
            "Leave empty by default."
            return None


        if hasattr(functools, "cache"):
            def _alternative(value, extra):
                return value
        else:
            def _alternative(value, extra):
                return value + extra


        class Base(ABC):
            @abstractmethod
            def _step(self, item, options): ...


        class Impl(Base):
            def _step(self, item, options):
                return item

            def _helper(self, item, spare):
                return item


        class Served:
            def _run(self, item, mode):
                return item


        def serve(start):
            return start(lambda: Served())


        class Plain:
            def _hook(self, item, spare):
                return item


        class Special(Plain):
            def _hook(self, item, spare):
                return item + spare


        def apply(callback):
            return callback("event", "context")


        print(
            apply(_on_event),
            functools.partial(_wrapped, 1)(2),
            _variadic(1, 2, key=3),
            public_api(1, 2),
            globals()["_by_name"](1, 2),
            _default_hook(1, 2),
            _alternative(1, 2),
            Impl()._step(1, 2),
            Impl()._helper(1, 2),
            Plain()._hook(1, 2),
            Special()._hook(1, 2),
            serve(print),
        )
        """,
    )

    assert not _unused(tmp_path, "unused_parameters")


def test_unnamed_method_of_an_instance_captured_by_a_closure_is_reported(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        class Browser:
            def open(self, url):
                return url

            def scroll_bottom(self):
                return 0


        def make_handler(registry):
            browser = Browser()

            def handler(url):
                registry.append(browser)
                return browser.open(url)

            registry.append(handler)
            return registry


        print(make_handler([])[0]("x"))
        """,
    )

    unused = _unused(tmp_path, "unused_functions")
    assert "app.Browser.scroll_bottom" in unused
    assert "app.Browser.open" not in unused


def test_parameters_of_a_method_called_on_an_unknown_receiver_stay_unreported(tmp_path):
    _write(
        tmp_path,
        "tools.py",
        """
        def build(start):
            class LocalTool:
                def _run(self, path, prompt, focus):
                    return path

            class Sizer:
                def _measure(self, text, unit):
                    return len(text)

            return start(lambda: LocalTool(), lambda: Sizer())
        """,
    )
    _write(
        tmp_path,
        "runner.py",
        """
        from tools import build


        def run_job(tool, job):
            return tool._run(**job["params"])


        def measure(sizer, text):
            return sizer._measure(text, "px")


        def start(make_tool, make_sizer):
            return run_job(make_tool(), {"params": {}}), measure(make_sizer(), "x")


        print(build(start))
        """,
    )

    assert not _unused(tmp_path, "unused_parameters")
