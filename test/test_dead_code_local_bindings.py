"""Function-local bindings: a local can only be read by its own function.

Uses of the same spelling elsewhere in the project, a qualified use of an
import's target in another file, attribute access ``obj.name`` and commented
out calls are not uses. Dynamic reads (``locals()``, another frame's
``f_locals``) and imports scoped to a function still count.
"""

import json
import textwrap

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _unused(tmp_path, section):
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
    return {
        (
            item["file"].replace("\\\\", "/").rsplit("/", 1)[-1],
            item.get("simple_name") or item["name"],
        )
        for item in result.get(section, [])
    }


def test_unused_local_is_reported_when_other_functions_use_the_same_name(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        def first():
            count = 1
            return 2


        def second():
            count = 3
            return count


        print(first(), second())
        """,
    )
    _write(
        tmp_path,
        "b.py",
        """
        def third():
            count = 4
            return count


        print(third())
        """,
    )

    unused = _unused(tmp_path, "unused_variables")
    assert ("a.py", "count") in unused
    assert ("b.py", "count") not in unused


def test_local_read_through_locals_is_kept(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        def render():
            shown = 5
            return "{shown}".format(**locals())


        def plain():
            hidden = 1
            return 2


        print(render(), plain())
        """,
    )

    unused = _unused(tmp_path, "unused_variables")
    assert ("a.py", "shown") not in unused
    assert ("a.py", "hidden") in unused


def test_local_read_by_another_frame_through_f_locals_is_kept(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        import sys


        def guarded():
            _demo_guard = True
            _not_inspected = True
            return inspect_caller()


        def inspect_caller():
            frame = sys._getframe(1)
            return frame.f_locals.get("_demo_guard", False)


        print(guarded())
        """,
    )

    unused = _unused(tmp_path, "unused_variables")
    assert ("a.py", "_demo_guard") not in unused
    assert ("a.py", "_not_inspected") in unused


def test_import_is_not_kept_alive_by_its_target_used_in_another_file(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/a.py",
        """
        from pathlib import Path


        def main():
            return 1


        main()
        """,
    )
    _write(
        tmp_path,
        "pkg/b.py",
        """
        import pathlib
        from pathlib import PurePath


        def main():
            return pathlib.Path("."), PurePath(".")


        main()
        """,
    )

    unused = _unused(tmp_path, "unused_imports")
    assert ("a.py", "Path") in unused
    assert ("b.py", "pathlib") not in unused
    assert ("b.py", "PurePath") not in unused


def test_reexported_import_used_through_its_module_is_kept(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/tools.py", "from pathlib import Path\n")
    _write(
        tmp_path,
        "pkg/main.py",
        """
        from pkg.tools import Path


        print(Path("."))
        """,
    )

    unused = _unused(tmp_path, "unused_imports")
    assert ("tools.py", "Path") not in unused


def test_local_import_named_like_its_function_is_used(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        def prune(model):
            from os import path as prune
            return prune.join(model, "x")


        def main(**kwargs):
            from json import dumps as main
            return main(kwargs)


        def leftover():
            from collections import OrderedDict
            return 1


        print(prune("a"), main(a=1), leftover())
        """,
    )

    unused = _unused(tmp_path, "unused_imports")
    names = {name for _file, name in unused}
    assert "path" not in names
    assert "dumps" not in names
    assert ("a.py", "OrderedDict") in unused


def test_branch_imports_read_by_a_nested_function_are_used(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        def choose(flag):
            if flag:
                from json import loads as reader
            else:
                from pickle import loads as reader

            def build():
                return reader

            return build()


        print(choose(True))
        """,
    )

    unused = _unused(tmp_path, "unused_imports")
    assert not {name for _file, name in unused} & {"loads", "reader"}


def test_rebinding_an_import_reads_the_import_first(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        def cookies():
            from http import cookiejar
            cookiejar = cookiejar.CookieJar()
            return cookiejar


        def rebound(value):
            temp = value
            temp = 2
            return value


        print(cookies(), rebound(1))
        """,
    )

    assert ("a.py", "cookiejar") not in _unused(tmp_path, "unused_imports")
    assert ("a.py", "temp") in _unused(tmp_path, "unused_variables")


def test_attribute_access_does_not_keep_a_local_but_keeps_a_class_attribute(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        class Holder:
            value = 3


        def compute():
            value = 1
            return 2


        print(Holder().value, compute())
        """,
    )

    unused = _unused(tmp_path, "unused_variables")
    assert ("a.py", "value") in {(file, name) for file, name in unused}
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
    lines = {
        item["line"]
        for item in result.get("unused_variables", [])
        if (item.get("simple_name") or item["name"]) == "value"
    }
    assert lines == {6}


def test_class_attributes_sharing_a_name_keep_their_previous_policy(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        class First:
            flag = True


        class Second:
            flag = False


        def pick(obj):
            return obj.flag


        print(pick(First()), pick(Second()))
        """,
    )

    assert ("a.py", "flag") not in _unused(tmp_path, "unused_variables")


def test_module_variables_sharing_a_name_are_reported_independently(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        default_timeout = 30


        def make_schema():
            class Payload:
                queries = []

            return Payload


        print(make_schema())
        """,
    )
    _write(
        tmp_path,
        "b.py",
        """
        default_timeout = 60
        queries = None
        """,
    )

    unused = _unused(tmp_path, "unused_variables")
    assert ("a.py", "default_timeout") in unused
    assert ("b.py", "default_timeout") in unused
    assert ("b.py", "queries") in unused
    assert ("a.py", "queries") not in unused


def test_variables_whose_same_named_attributes_read_other_objects_are_reported(
    tmp_path,
):
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/settings.py", "RETRY_LIMIT = 3\nTIMEOUT = 10\n")
    _write(
        tmp_path,
        "app/client.py",
        """
        from app.settings import TIMEOUT


        class Policy:
            def __init__(self):
                self.RETRY_LIMIT = 5

            def limit(self):
                return self.RETRY_LIMIT


        def call(policy):
            return policy.RETRY_LIMIT + TIMEOUT + policy.limit()


        print(call(Policy()))
        """,
    )
    _write(tmp_path, "app/flags.py", "DEBUG_MODE = False\n")
    _write(tmp_path, "app/env.py", "DEBUG_MODE = True\n")
    _write(tmp_path, "app/tuning.py", "SPEED = 1\n")
    _write(
        tmp_path,
        "app/use.py",
        """
        from app import env


        def speed(settings):
            return settings.SPEED


        class Circle:
            SIDES = 0


        class Polygon:
            def __init__(self):
                self.SIDES = 3

            def sides(self):
                return self.SIDES


        print(env.DEBUG_MODE, speed(object()), Circle(), Polygon().sides())
        """,
    )

    unused = _unused(tmp_path, "unused_variables")

    assert ("settings.py", "RETRY_LIMIT") in unused
    assert ("flags.py", "DEBUG_MODE") in unused
    assert ("tuning.py", "SPEED") in unused
    assert ("use.py", "SIDES") in unused
    assert ("settings.py", "TIMEOUT") not in unused
    assert ("env.py", "DEBUG_MODE") not in unused


def test_attribute_reads_that_may_reach_the_variable_keep_it(tmp_path):
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/conf_passed.py", "MAX_ITEMS = 5\n")
    _write(tmp_path, "app/base_conf.py", "PAGE_SIZE = 50\n")
    _write(tmp_path, "app/conf_star.py", "from app.base_conf import *\n")
    _write(tmp_path, "app/dj_settings.py", "CUSTOM_FLAG = True\n")
    _write(tmp_path, "app/celeryconfig.py", 'broker_url = "redis://"\n')
    _write(tmp_path, "app/quota_conf.py", "QUOTA = 7\n")
    _write(
        tmp_path,
        "app/models.py",
        """
        from somelib import Shape


        class Base:
            LABEL = "base"

            def unit(self):
                return self.UNIT


        class Square(Base):
            UNIT = "m2"


        class Theme:
            COLOR = "red"


        class Hexagon(Shape):
            CORNERS = 6


        class Article:
            class Meta:
                ordering = ["-id"]


        class Comment:
            class Meta:
                ordering = ["id"]
        """,
    )
    _write(
        tmp_path,
        "app/use.py",
        """
        from django.conf import settings
        from app import conf_passed, conf_star, quota_conf as settings_module
        from app.models import Article, Comment, Hexagon, Square, Theme


        class SettingsProxy:
            def __getattr__(self, name):
                return getattr(settings_module, name)

            def quota(self):
                return self.QUOTA


        class Grid:
            def __init__(self):
                self.CORNERS = 4

            def corners(self):
                return self.CORNERS


        def size(cfg):
            return cfg.MAX_ITEMS


        def color(obj):
            return obj.COLOR


        def broker(worker_app):
            worker_app.config_from_object("app.celeryconfig")
            return worker_app.conf.broker_url


        print(
            size(conf_passed),
            conf_star.PAGE_SIZE,
            settings.CUSTOM_FLAG,
            broker(object()),
            SettingsProxy().quota(),
            Square().unit(),
            Square().LABEL,
            color(Theme()),
            Hexagon(),
            Grid().corners(),
            Article,
            Comment,
        )
        """,
    )

    unused = {name for _file, name in _unused(tmp_path, "unused_variables")}

    assert not unused & {
        "MAX_ITEMS",
        "PAGE_SIZE",
        "CUSTOM_FLAG",
        "broker_url",
        "QUOTA",
        "LABEL",
        "UNIT",
        "COLOR",
        "CORNERS",
        "ordering",
    }


def test_commented_out_call_does_not_keep_a_function(tmp_path):
    _write(
        tmp_path,
        "a.py",
        """
        class Client:
            def fetch(self):
                return 1

            def fetch_fans(self):
                return 2


        def run():
            client = Client()
            # client.fetch_fans()
            return client.fetch()


        run()
        """,
    )

    unused = _unused(tmp_path, "unused_functions")
    assert ("a.py", "fetch_fans") in unused
    assert ("a.py", "fetch") not in unused
