"""Autoreload execution needs a real provider and a reachable registration."""

import json

import pytest

from skylos.analyzer import Skylos


def _scan(root, sources, *, conf=80, grep=False):
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(root), thr=conf, grep_verify=grep))
    assert not result.get("analysis_errors")
    return result, {
        definition.name: definition for definition in analyzer.defs.values()
    }


_FUNCTIONS = """
def callback():
    return helper()

def helper():
    return 1
"""


@pytest.mark.parametrize("conf", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_uncalled_autoreload_owner_does_not_execute_callback(tmp_path, conf, grep):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": "from django.utils import autoreload\n"
            + _FUNCTIONS
            + "\ndef unused_start():\n    autoreload.run_with_reloader(callback)\n"
        },
        conf=conf,
        grep=grep,
    )
    assert {item["full_name"] for item in result["unused_functions"]} == {
        "app.callback",
        "app.helper",
        "app.unused_start",
    }
    assert "framework_root" not in definitions["app.callback"].heuristic_refs


@pytest.mark.parametrize(
    "imports, registration",
    [
        (
            "from django.utils import autoreload",
            "autoreload.run_with_reloader(callback)",
        ),
        (
            "import django.utils.autoreload as reload",
            "reload.run_with_reloader(callback)",
        ),
        (
            "from django.utils.autoreload import run_with_reloader as reload",
            "reload(callback)",
        ),
        (
            "from django.utils import autoreload",
            "def start(target):\n    autoreload.run_with_reloader(target)\nstart(callback)",
        ),
    ],
)
def test_called_autoreload_and_argument_wrappers_keep_callback(
    tmp_path, imports, registration
):
    result, definitions = _scan(
        tmp_path, {"app.py": imports + "\n" + _FUNCTIONS + "\n" + registration + "\n"}
    )
    assert not result["unused_functions"]
    assert definitions["app.callback"].heuristic_refs.get("framework_root") == 1.0


@pytest.mark.parametrize(
    "setup, registration, extra",
    [
        (
            "import django\nclass Local:\n    def run_with_reloader(self, target): pass\nloader = Local()",
            "loader.run_with_reloader(callback)",
            {},
        ),
        (
            "from django.utils import autoreload\nclass Local:\n    def run_with_reloader(self, target): pass\nautoreload = Local()",
            "autoreload.run_with_reloader(callback)",
            {},
        ),
        (
            "from django.utils import autoreload\ndef replacement(target): pass\nautoreload.run_with_reloader = replacement",
            "autoreload.run_with_reloader(callback)",
            {},
        ),
        (
            "from django.utils import autoreload\ndef replacement(target): pass\nsetattr(autoreload, 'run_with_reloader', replacement)",
            "autoreload.run_with_reloader(callback)",
            {},
        ),
        (
            "from django.utils import autoreload\nclass Local:\n    def run_with_reloader(self, target): pass",
            "def start(autoreload):\n    autoreload.run_with_reloader(callback)\nstart(Local())",
            {},
        ),
        (
            "from django.utils import autoreload",
            "autoreload.run_with_reloader(callback)",
            {"django/__init__.py": "", "django/utils.py": "autoreload = object()\n"},
        ),
    ],
)
def test_fake_rebound_and_shadowed_autoreload_are_not_framework_roots(
    tmp_path, setup, registration, extra
):
    _, definitions = _scan(
        tmp_path,
        {"app.py": setup + "\n" + _FUNCTIONS + "\n" + registration + "\n", **extra},
    )
    assert "framework_root" not in definitions["app.callback"].heuristic_refs


def test_autoreload_in_management_command_handle_is_live(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/management/__init__.py": "",
            "shop/management/commands/__init__.py": "",
            "shop/management/commands/hello.py": (
                "from django.core.management.base import BaseCommand\n"
                "from django.utils import autoreload\n"
                + _FUNCTIONS
                + "\nclass Command(BaseCommand):\n"
                "    def handle(self, *args, **options):\n"
                "        autoreload.run_with_reloader(callback)\n"
            ),
        },
    )
    assert "shop.management.commands.hello.callback" not in {
        item["full_name"] for item in result["unused_functions"]
    }
    assert (
        definitions["shop.management.commands.hello.callback"].heuristic_refs.get(
            "framework_root"
        )
        == 1.0
    )


@pytest.mark.parametrize(
    "body",
    [
        "class BaseCommand: pass\nclass Command(BaseCommand):\n    def handle(self): autoreload.run_with_reloader(callback)\n",
        "class Command(BaseCommand):\n    def handle(self): autoreload.run_with_reloader(callback)\nCommand = object()\n",
        "class Command(BaseCommand):\n    def handle(self): autoreload.run_with_reloader(callback)\nCommand.handle = lambda self: None\n",
        "class Command(BaseCommand):\n    def handle(self):\n        if False:\n            autoreload.run_with_reloader(callback)\n",
    ],
)
def test_inactive_or_replaced_command_handle_is_not_callback_execution(tmp_path, body):
    _, definitions = _scan(
        tmp_path,
        {
            "shop/management/commands/hello.py": (
                "from django.core.management.base import BaseCommand\n"
                "from django.utils import autoreload\n" + _FUNCTIONS + "\n" + body
            )
        },
    )
    assert (
        "framework_root"
        not in definitions["shop.management.commands.hello.callback"].heuristic_refs
    )


def test_autoreload_wrapper_in_imported_module_uses_actual_callback_argument(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": "from reloads import start\n"
            + _FUNCTIONS
            + "\nstart(callback)\n",
            "reloads.py": "from django.utils import autoreload\ndef start(target):\n    autoreload.run_with_reloader(target)\n",
        },
    )
    assert not result["unused_functions"]
    assert definitions["app.callback"].heuristic_refs.get("framework_root") == 1.0


def test_management_command_bound_wrapper_uses_the_callback_argument(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "shop/management/commands/hello.py": (
                "from django.core.management.base import BaseCommand\n"
                "from django.utils import autoreload\n"
                + _FUNCTIONS
                + "\nclass Command(BaseCommand):\n"
                "    def handle(self, **options):\n"
                "        self.start(callback)\n"
                "    def start(self, target):\n"
                "        autoreload.run_with_reloader(target)\n"
            )
        },
    )
    assert "shop.management.commands.hello.callback" not in {
        item["full_name"] for item in result["unused_functions"]
    }
    assert (
        definitions["shop.management.commands.hello.callback"].heuristic_refs.get(
            "framework_root"
        )
        == 1.0
    )


def test_captured_reloader_remains_real_after_provider_attribute_is_replaced(tmp_path):
    result, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from django.utils import autoreload\n"
                "reload = autoreload.run_with_reloader\n"
                "autoreload.run_with_reloader = lambda target: None\n"
                + _FUNCTIONS
                + "\nreload(callback)\n"
            )
        },
    )
    assert not result["unused_functions"]
    assert definitions["app.callback"].heuristic_refs.get("framework_root") == 1.0


def test_no_registration_keeps_callback_and_helper_unused(tmp_path):
    result, definitions = _scan(
        tmp_path, {"app.py": "from django.utils import autoreload\n" + _FUNCTIONS}
    )
    assert {item["full_name"] for item in result["unused_functions"]} == {
        "app.callback",
        "app.helper",
    }
    assert "framework_root" not in definitions["app.callback"].heuristic_refs


@pytest.mark.parametrize(
    "mutation, capture",
    [
        ("setattr(autoreload, 'run_with_reloader', replacement)", True),
        ("delattr(autoreload, 'run_with_reloader')", True),
        (
            "import builtins\nbuiltins.setattr(autoreload, 'run_with_reloader', replacement)",
            False,
        ),
        (
            "from builtins import setattr as change\nchange(autoreload, 'run_with_reloader', replacement)",
            False,
        ),
    ],
)
def test_replaced_provider_cannot_be_recaptured_as_the_real_reloader(
    tmp_path, mutation, capture
):
    registration = "autoreload.run_with_reloader(callback)"
    if capture:
        registration = "reload = autoreload.run_with_reloader\nreload(callback)"
    _, definitions = _scan(
        tmp_path,
        {
            "app.py": (
                "from django.utils import autoreload\n"
                "def replacement(target): pass\n"
                + _FUNCTIONS
                + "\n"
                + mutation
                + "\n"
                + registration
                + "\n"
            )
        },
    )
    assert "framework_root" not in definitions["app.callback"].heuristic_refs


@pytest.mark.parametrize(
    "replacement",
    [
        "\nCommand.start = lambda self, target: None\n",
        "\nsetattr(Command, 'start', lambda self, target: None)\n",
        "    start = lambda self, target: None\n",
    ],
)
def test_replaced_bound_command_wrapper_cannot_execute_its_retired_body(
    tmp_path, replacement
):
    _, definitions = _scan(
        tmp_path,
        {
            "shop/management/commands/hello.py": (
                "from django.core.management.base import BaseCommand\n"
                "from django.utils import autoreload\n"
                + _FUNCTIONS
                + "\nclass Command(BaseCommand):\n"
                "    def handle(self, **options):\n"
                "        self.start(callback)\n"
                "    def start(self, target):\n"
                "        autoreload.run_with_reloader(target)\n" + replacement
            )
        },
    )
    assert (
        "framework_root"
        not in definitions["shop.management.commands.hello.callback"].heuristic_refs
    )


@pytest.mark.parametrize("capture_before", [False, True])
def test_bound_wrapper_alias_preserves_the_capture_order(tmp_path, capture_before):
    capture = "        saved = self.start\n"
    replacement = "        self.start = lambda target: None\n"
    operations = replacement + capture
    if capture_before:
        operations = capture + replacement
    _, definitions = _scan(
        tmp_path,
        {
            "shop/management/commands/hello.py": (
                "from django.core.management.base import BaseCommand\n"
                "from django.utils import autoreload\n"
                + _FUNCTIONS
                + "\nclass Command(BaseCommand):\n"
                "    def handle(self, **options):\n"
                + operations
                + "        saved(callback)\n"
                "    def start(self, target):\n"
                "        autoreload.run_with_reloader(target)\n"
            )
        },
    )
    rooted = (
        "framework_root"
        in definitions["shop.management.commands.hello.callback"].heuristic_refs
    )
    assert rooted is capture_before
