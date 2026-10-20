"""Primitive flags retain module bindings; mutable projections still escape."""

import ast

import pytest

from skylos.security.receiver_resolution import ReceiverResolver
from test.fixture_paths import write_fixture


@pytest.mark.parametrize(
    "source, module_name",
    [
        ("import os\nconsume(os.O_RDONLY)\n", "os"),
        ("import os as fs\nconsume(fs.O_RDONLY | fs.O_CLOEXEC)\n", "fs"),
        ("import os\nflags = os.O_RDONLY\nconsume(flags)\n", "os"),
        ("from os import O_RDONLY as flags\nconsume(flags)\n", "flags"),
        ("import os\nconsume([os.O_RDONLY])\n", "os"),
    ],
)
def test_documented_integer_flag_does_not_escape_module(tmp_path, source, module_name):
    path = write_fixture(tmp_path, "app.py", source)
    resolver = ReceiverResolver(ast.parse(source), path, project_root=tmp_path)
    assert module_name not in resolver.main.mutated


@pytest.mark.parametrize(
    "flag",
    [
        "O_NOINHERIT",
        "O_EVTONLY",
        "O_FSYNC",
        "O_SYMLINK",
        "O_NOFOLLOW_ANY",
        "O_ASYNC",
        "O_SHLOCK",
        "O_EXLOCK",
    ],
)
def test_platform_integer_flags_preserve_aliased_module_binding(tmp_path, flag):
    # Parse target syntax; never access flags on the host platform.
    source = "import os as fs\nflags = fs." + flag + "\nconsume(flags)\n"
    path = write_fixture(tmp_path, "app.py", source)
    resolver = ReceiverResolver(ast.parse(source), path, project_root=tmp_path)
    assert "fs" not in resolver.main.mutated
    assert "flags" not in resolver.main.mutated


@pytest.mark.parametrize(
    "source, module_name",
    [
        ("import os\nconsume(os.unknown_value)\n", "os"),
        ("import os\nconsume(os.O_UNKNOWN_UPPERCASE)\n", "os"),
        ("from opentelemetry import propagate as os\nconsume(os.O_RDONLY)\n", "os"),
        ("import os\nos.O_RDONLY = replacement\nconsume(os.O_RDONLY)\n", "os"),
        ("import os\nconsume([os])\n", "os"),
        ("import os\nconsume({'api': os})\n", "os"),
        (
            "import sys\nsys.modules['os'] = provider\nimport os\nconsume(os.O_RDONLY)\n",
            "os",
        ),
        (
            "import sys\nsys.meta_path.insert(0, provider)\nimport os\nconsume(os.O_RDONLY)\n",
            "os",
        ),
    ],
)
def test_unresolved_mutable_projection_retains_escape(tmp_path, source, module_name):
    path = write_fixture(tmp_path, "app.py", source)
    resolver = ReceiverResolver(ast.parse(source), path, project_root=tmp_path)
    assert module_name in resolver.main.mutated


def test_project_local_os_provider_cannot_use_standard_flag_contract(tmp_path):
    write_fixture(tmp_path, "os.py", "O_RDONLY = custom_object\n")
    source = "import os\nconsume(os.O_RDONLY)\n"
    path = write_fixture(tmp_path, "app.py", source)
    resolver = ReceiverResolver(ast.parse(source), path, project_root=tmp_path)
    assert "os" in resolver.main.mutated
