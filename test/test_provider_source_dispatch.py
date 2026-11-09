"""Source-owned provider dispatch requires an executing, bounded consumer."""

import json

import pytest

from skylos.analyzer import analyze


PROVIDERS = """
class Provider:
    def scoreboard(self, day):
        raise NotImplementedError

class NcaaClient(Provider):
    def schedule_dates(self, season):
        return [season]
    def scoreboard(self, day):
        return day
    def old_helper(self):
        return 'unused'

class NjcaaClient(Provider):
    def schedule_dates(self, season):
        return [season]
    def scoreboard(self, day):
        return day

class UnrelatedClient:
    def schedule_dates(self, season):
        return []
    def scoreboard(self, day):
        return None

unrelated = UnrelatedClient()

def get_client(slug):
    if slug == 'ncaa':
        return NcaaClient()
    return NjcaaClient()
"""

PIPELINES = {
    "registry": """
from providers import NcaaClient, NjcaaClient
CLIENTS = {'ncaa': NcaaClient, 'njcaa': NjcaaClient}
def get_client(slug):
    return CLIENTS[slug]()
def update(slug):
    client = get_client(slug)
    return client.schedule_dates(2026), client.scoreboard('today')
RESULT = update(input())
""",
    "field": """
from providers import get_client
class Pipeline:
    def __init__(self, client):
        self.client = client
    def update(self):
        return self.client.schedule_dates(2026), self.client.scoreboard('today')
RESULT = Pipeline(get_client(input())).update()
""",
    "property": """
from providers import get_client
class Pipeline:
    @property
    def client(self):
        return get_client(input())
    def update(self):
        return self.client.schedule_dates(2026), self.client.scoreboard('today')
RESULT = Pipeline().update()
""",
    "map": """
from providers import get_client
def update(slug):
    client = get_client(slug)
    return list(map(client.schedule_dates, [2026])), client.scoreboard('today')
RESULT = update(input())
""",
}


def _scan(tmp_path, pipeline, confidence=80):
    (tmp_path / "providers.py").write_text(PROVIDERS)
    (tmp_path / "pipeline.py").write_text(pipeline)
    result = json.loads(
        analyze(str(tmp_path), conf=confidence, grep_verify=False, grep_cache=False)
    )
    assert not result.get("analysis_errors")
    unused = {row["full_name"] for row in result["unused_functions"]}
    evidence = {
        row["qualified_name"]: row for row in result["dead_code_evidence"]["symbols"]
    }
    return unused, evidence


def _alive(evidence, name):
    row = evidence[name]
    assert row["classification"] == "alive"
    assert {"top_level_execution", "reachable_from_root"} & {
        event["kind"] for event in row["evidence"]
    }


def _dead(unused, evidence, name):
    assert name in unused
    assert evidence[name]["classification"] == "likely_dead"


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("shape", PIPELINES)
def test_actual_source_dispatch_retains_only_the_receiver_methods(
    tmp_path, shape, confidence
):
    unused, evidence = _scan(tmp_path, PIPELINES[shape], confidence)
    for client in ["NcaaClient", "NjcaaClient"]:
        for method in ["schedule_dates", "scoreboard"]:
            name = f"providers.{client}.{method}"
            assert name not in unused
            _alive(evidence, name)
    for name in [
        "providers.NcaaClient.old_helper",
        "providers.UnrelatedClient.schedule_dates",
        "providers.UnrelatedClient.scoreboard",
    ]:
        _dead(unused, evidence, name)


@pytest.mark.parametrize("shape", PIPELINES)
def test_unexecuted_dispatch_owner_does_not_prove_provider_use(tmp_path, shape):
    pipeline = "\n".join(
        line
        for line in PIPELINES[shape].splitlines()
        if not line.startswith("RESULT =")
    )
    unused, evidence = _scan(tmp_path, pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


def test_literal_registry_selection_does_not_consume_unselected_entry(tmp_path):
    pipeline = PIPELINES["registry"].replace(
        "return CLIENTS[slug]()", "return CLIENTS['ncaa']()"
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _alive(evidence, "providers.NcaaClient.schedule_dates")
    _dead(unused, evidence, "providers.NjcaaClient.schedule_dates")


def test_field_resolution_uses_the_called_instance_not_another_constructor(tmp_path):
    pipeline = """
from providers import NcaaClient, UnrelatedClient
class Pipeline:
    def __init__(self, client):
        self.client = client
    def update(self):
        return self.client.schedule_dates(2026)
unused_pipeline = Pipeline(NcaaClient())
RESULT = Pipeline(UnrelatedClient()).update()
"""
    unused, evidence = _scan(tmp_path, pipeline)
    _alive(evidence, "providers.UnrelatedClient.schedule_dates")
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


def test_replaced_instance_field_does_not_dispatch_the_constructor_argument(tmp_path):
    pipeline = PIPELINES["field"].replace(
        "from providers import get_client",
        "from providers import get_client, UnrelatedClient",
    )
    pipeline = pipeline.replace(
        "self.client = client",
        "self.client = client\n        self.client = UnrelatedClient()",
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _alive(evidence, "providers.UnrelatedClient.schedule_dates")
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


@pytest.mark.parametrize(
    "prefix",
    [
        "def map(callback, values):\n    return []\n",
        "",
    ],
)
def test_shadowed_or_unconsumed_map_does_not_invoke_the_callback(tmp_path, prefix):
    pipeline = PIPELINES["map"]
    if not prefix:
        pipeline = pipeline.replace(
            "return list(map(client.schedule_dates, [2026])), client.scoreboard('today')",
            "callbacks = map(client.schedule_dates, [2026])\n    return client.scoreboard('today')",
        )
    unused, evidence = _scan(tmp_path, prefix + pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


def test_empty_map_does_not_invoke_the_callback(tmp_path):
    unused, evidence = _scan(tmp_path, PIPELINES["map"].replace("[2026]", "[]"))
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


def test_shadowed_property_does_not_make_its_function_result_an_instance(tmp_path):
    pipeline = "def property(callback):\n    return callback\n" + PIPELINES["property"]
    unused, evidence = _scan(tmp_path, pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


@pytest.mark.parametrize(
    "change",
    [
        "raise",
        "non_none_return",
        "slots",
        "new",
        "lookup",
        "descriptor",
        "subclass_hook",
        "invalid_arguments",
        "conditional_new",
    ],
)
def test_nonstandard_or_abrupt_construction_does_not_prove_field_dispatch(
    tmp_path, change
):
    pipeline = PIPELINES["field"]
    if change == "raise":
        pipeline = pipeline.replace(
            "self.client = client", "self.client = client\n        raise ValueError()"
        )
    elif change == "non_none_return":
        pipeline = pipeline.replace(
            "self.client = client", "self.client = client\n        return 1"
        )
    elif change == "slots":
        pipeline = pipeline.replace(
            "class Pipeline:", "class Pipeline:\n    __slots__ = ()"
        )
    elif change == "new":
        pipeline = pipeline.replace(
            "class Pipeline:",
            "class Pipeline:\n    def __new__(cls, client):\n        return None",
        )
    elif change == "lookup":
        pipeline = pipeline.replace(
            "class Pipeline:",
            "class Pipeline:\n    def __getattribute__(self, name):\n        raise AttributeError(name)",
        )
    elif change == "descriptor":
        pipeline = pipeline.replace(
            "class Pipeline:",
            "class Pipeline:\n    @property\n    def client(self):\n        return get_client(input())",
        )
    elif change == "invalid_arguments":
        pipeline = pipeline.replace(
            "def __init__(self, client):\n        self.client = client",
            "def __init__(self):\n        self.client = get_client(input())",
        )
    elif change == "conditional_new":
        pipeline = pipeline.replace(
            "class Pipeline:",
            "class Pipeline:\n    if True:\n        __new__ = staticmethod(lambda cls, client: None)",
        )
    else:
        pipeline = pipeline.replace(
            "class Pipeline:",
            "class Base:\n    def __init_subclass__(cls):\n        cls.update = lambda self: None\nclass Pipeline(Base):",
        )
    unused, evidence = _scan(tmp_path, pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


def test_escaped_instance_field_does_not_supply_a_stable_receiver(tmp_path):
    pipeline = PIPELINES["field"].replace(
        "RESULT = Pipeline(get_client(input())).update()",
        "pipeline = Pipeline(get_client(input()))\nopaque(pipeline)\nRESULT = pipeline.update()",
    )
    unused, evidence = _scan(tmp_path, pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


@pytest.mark.parametrize("import_style", ["from", "qualified"])
def test_external_registry_mutation_does_not_prove_its_stale_provider(
    tmp_path, import_style
):
    pipeline = "\n".join(
        line
        for line in PIPELINES["registry"].splitlines()
        if not line.startswith("RESULT =")
    )
    patch = (
        "from pipeline import CLIENTS\nCLIENTS['ncaa'] = UnrelatedClient\n"
        if import_style == "from"
        else "import pipeline\npipeline.CLIENTS['ncaa'] = UnrelatedClient\n"
    )
    (tmp_path / "patcher.py").write_text(
        "from providers import UnrelatedClient\n" + patch
    )
    (tmp_path / "app.py").write_text(
        "import patcher\nfrom pipeline import update\nRESULT = update('ncaa')\n"
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


def test_mutated_builtin_property_namespace_does_not_prove_getter_result(tmp_path):
    pipeline = (
        "import builtins\nbuiltins.property = lambda callback: callback\n"
        + PIPELINES["property"]
    )
    unused, evidence = _scan(tmp_path, pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        _dead(unused, evidence, f"providers.{client}.schedule_dates")


@pytest.mark.parametrize(
    "header",
    [
        "class Trigger:\n    ignored = replace(CLIENTS)\n",
        "def ignored(value=replace(CLIENTS)):\n    return value\n",
        "def ignored(*, value=replace(CLIENTS)):\n    return value\n",
        "def ignored(value: replace(CLIENTS)):\n    return value\n",
        "class Marker:\n    pass\ndef base():\n    replace(CLIENTS)\n    return Marker\nclass Trigger(base()):\n    pass\n",
        "def metaclass():\n    replace(CLIENTS)\n    return type\nclass Trigger(metaclass=metaclass()):\n    pass\n",
        "def decorator(value):\n    replace(CLIENTS)\n    return value\n@decorator\ndef ignored():\n    pass\n",
        "def decorator(value):\n    replace(CLIENTS)\n    return value\n@decorator\nclass Trigger:\n    pass\n",
    ],
)
def test_definition_header_effects_do_not_prove_stale_registry_entry(tmp_path, header):
    pipeline = (
        """
from providers import NcaaClient, UnrelatedClient
CLIENTS = {'active': NcaaClient}
def replace(table):
    table['active'] = UnrelatedClient
"""
        + header
        + "client = CLIENTS['active']()\nRESULT = client.schedule_dates(2026)\n"
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize(
    "expression",
    [
        "replace(CLIENTS) or 0",
        "(ignored := replace(CLIENTS))",
        "{replace(CLIENTS): 0}",
    ],
)
def test_declined_expression_values_retain_evaluated_effects(tmp_path, expression):
    pipeline = (
        """
from providers import NcaaClient, UnrelatedClient
CLIENTS = {'active': NcaaClient}
def replace(table):
    table['active'] = UnrelatedClient
"""
        + f"ignored = {expression}\nclient = CLIENTS['active']()\nRESULT = client.schedule_dates(2026)\n"
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize(
    "expression", ["False and replace(CLIENTS)", "True or replace(CLIENTS)"]
)
def test_short_circuited_registry_writer_has_no_effect(tmp_path, expression):
    pipeline = (
        """
from providers import NcaaClient, UnrelatedClient
CLIENTS = {'active': NcaaClient}
def replace(table):
    table['active'] = UnrelatedClient
"""
        + f"ignored = {expression}\nclient = CLIENTS['active']()\nRESULT = client.schedule_dates(2026)\n"
    )
    _, evidence = _scan(tmp_path, pipeline)
    _alive(evidence, "providers.NcaaClient.schedule_dates")


def test_function_default_keeps_its_definition_time_receiver(tmp_path):
    pipeline = """
from providers import NcaaClient, UnrelatedClient
selected = UnrelatedClient()
def update(client=selected):
    return client.schedule_dates(2026)
selected = NcaaClient()
RESULT = update()
"""
    unused, evidence = _scan(tmp_path, pipeline)
    _alive(evidence, "providers.UnrelatedClient.schedule_dates")
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize(
    "termination",
    [
        "raise RuntimeError('not ready')",
        "def stop():\n    raise RuntimeError('not ready')\nstop()",
    ],
)
def test_incomplete_module_cannot_supply_partial_registry_exports(
    tmp_path, termination
):
    (tmp_path / "registry.py").write_text(
        "from providers import NcaaClient\nTABLE = {'active': NcaaClient}\n"
        + termination
        + "\n"
    )
    pipeline = "from registry import TABLE\nclient = TABLE['active']()\nRESULT = client.schedule_dates(2026)\n"
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize(
    "effect",
    [
        "TABLE.update(active=UnrelatedClient)",
        "TABLE.clear()",
        "TABLE.pop('active')",
        "writer = TABLE.update\nwriter(active=UnrelatedClient)",
        "def replace(table):\n    for item in [1]:\n        table['active'] = UnrelatedClient\nreplace(TABLE)",
        "def replace(table):\n    del table['active']\nreplace(TABLE)",
    ],
)
def test_unknown_bound_or_incomplete_writer_invalidates_its_receiver(tmp_path, effect):
    pipeline = (
        "from providers import NcaaClient, UnrelatedClient\nTABLE = {'active': NcaaClient}\n"
        + effect
        + "\nclient = TABLE['active']()\nRESULT = client.schedule_dates(2026)\n"
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize(
    "read", ["TABLE.get('active')", "reader = TABLE.get\nreader('active')"]
)
def test_native_dictionary_read_preserves_actual_registry_dispatch(tmp_path, read):
    pipeline = (
        "from providers import NcaaClient\nTABLE = {'active': NcaaClient}\n"
        + read
        + "\nclient = TABLE['active']()\nRESULT = client.schedule_dates(2026)\n"
    )
    _, evidence = _scan(tmp_path, pipeline)
    _alive(evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize("keyword", [False, True])
def test_positional_only_constructor_requires_actual_argument_binding(
    tmp_path, keyword
):
    pipeline = PIPELINES["field"].replace(
        "def __init__(self, client):", "def __init__(self, client, /):"
    )
    pipeline = pipeline.replace(
        "Pipeline(get_client(input()))",
        "Pipeline(client=get_client(input()))"
        if keyword
        else "Pipeline(get_client(input()))",
    )
    unused, evidence = _scan(tmp_path, pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        name = f"providers.{client}.schedule_dates"
        if keyword:
            _dead(unused, evidence, name)
        else:
            _alive(evidence, name)


@pytest.mark.parametrize("location", ["constructor", "module"])
@pytest.mark.parametrize("shadowed", [False, True])
def test_only_actual_nonreturning_provider_stops_dispatch(tmp_path, location, shadowed):
    prefix = "import sys\n"
    if shadowed:
        prefix += "class Normal:\n    def exit(self, status):\n        return None\nsys = Normal()\n"
    pipeline = PIPELINES["field"]
    if location == "constructor":
        pipeline = pipeline.replace(
            "self.client = client", "self.client = client\n        sys.exit(0)"
        )
    else:
        pipeline = pipeline.replace("RESULT = ", "sys.exit(0)\nRESULT = ")
    unused, evidence = _scan(tmp_path, prefix + pipeline)
    for client in ["NcaaClient", "NjcaaClient"]:
        name = f"providers.{client}.schedule_dates"
        if shadowed:
            _alive(evidence, name)
        else:
            _dead(unused, evidence, name)


@pytest.mark.parametrize(
    "entry", ["command", "wrong_location_command", "routed_view", "unrouted_view"]
)
def test_only_explicit_framework_entries_consume_source_provider_pipeline(
    tmp_path, entry
):
    pipeline = PIPELINES["field"].replace(
        "RESULT = Pipeline(get_client(input())).update()",
        "def dispatch():\n    return Pipeline(get_client('ncaa')).update()",
    )
    if "command" in entry:
        path = tmp_path / (
            "app/management/commands/fetch.py" if entry == "command" else "ordinary.py"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "from django.core.management.base import BaseCommand\nfrom pipeline import dispatch\nclass Command(BaseCommand):\n    def handle(self, *args, **options):\n        return dispatch()\n"
        )
        for relative in [
            "app/__init__.py",
            "app/management/__init__.py",
            "app/management/commands/__init__.py",
        ]:
            (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / relative).write_text("")
    else:
        (tmp_path / "manage.py").write_text(
            'import os\nfrom django.core.management import execute_from_command_line\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")\nexecute_from_command_line([])\n'
        )
        (tmp_path / "settings.py").write_text(
            'ROOT_URLCONF="urls"\nINSTALLED_APPS=[]\n'
        )
        (tmp_path / "views.py").write_text(
            "from pipeline import dispatch\ndef view(request):\n    return dispatch()\n"
        )
        routes = '[path("items/", view)]' if entry == "routed_view" else "[]"
        (tmp_path / "urls.py").write_text(
            "from django.urls import path\nfrom views import view\nurlpatterns = "
            + routes
            + "\n"
        )
    unused, evidence = _scan(tmp_path, pipeline)
    if entry in {"command", "routed_view"}:
        _alive(evidence, "providers.NcaaClient.schedule_dates")
    else:
        _dead(unused, evidence, "providers.NcaaClient.schedule_dates")
    _dead(unused, evidence, "providers.NjcaaClient.schedule_dates")


@pytest.mark.parametrize("alias", [False, True])
def test_framework_entry_cannot_use_replaced_method_code(tmp_path, alias):
    path = tmp_path / "app/management/commands/fetch.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    replacement = (
        "selected = Command.handle\nselected.__code__ = replacement.__code__\n"
        if alias
        else "Command.handle.__code__ = replacement.__code__\n"
    )
    path.write_text(
        "from django.core.management.base import BaseCommand\nfrom pipeline import dispatch\nclass Command(BaseCommand):\n    def handle(self, *args, **options):\n        return dispatch()\ndef replacement(self, *args, **options):\n    return None\n"
        + replacement
    )
    for relative in [
        "app/__init__.py",
        "app/management/__init__.py",
        "app/management/commands/__init__.py",
    ]:
        (tmp_path / relative).write_text("")
    pipeline = PIPELINES["field"].replace(
        "RESULT = Pipeline(get_client(input())).update()",
        "def dispatch():\n    return Pipeline(get_client('ncaa')).update()",
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NcaaClient.schedule_dates")


@pytest.mark.parametrize("guard", ["empty_comprehension", "false_branch"])
def test_unevaluated_writer_does_not_replace_the_actual_instance(tmp_path, guard):
    statement = (
        "[replace(pipeline) for item in ()]"
        if guard == "empty_comprehension"
        else "None\nif False:\n    replace(pipeline)"
    )
    pipeline = PIPELINES["field"].replace(
        "RESULT = Pipeline(get_client(input())).update()",
        "pipeline = Pipeline(get_client('ncaa'))\ndef replace(value):\n    value.client = get_client('njcaa')\nignored = "
        + statement
        + "\nRESULT = pipeline.update()",
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NjcaaClient.schedule_dates")
    _alive(evidence, "providers.NcaaClient.schedule_dates")


def test_abrupt_branch_heap_writes_do_not_reach_the_continuing_branch(tmp_path):
    pipeline = PIPELINES["field"].replace(
        "RESULT = Pipeline(get_client(input())).update()",
        "def run(flag):\n    pipeline = Pipeline(get_client('ncaa'))\n    if flag:\n        pipeline.client = get_client('njcaa')\n        raise RuntimeError()\n    return pipeline.update()\nRESULT = run(input())",
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NjcaaClient.schedule_dates")


def test_abrupt_branch_cannot_mutate_an_instance_in_an_imported_module(tmp_path):
    pipeline = "\n".join(
        line
        for line in PIPELINES["field"].splitlines()
        if not line.startswith("RESULT =")
    )
    (tmp_path / "state.py").write_text(
        "from pipeline import Pipeline\nfrom providers import get_client\npipeline = Pipeline(get_client('ncaa'))\n"
    )
    (tmp_path / "app.py").write_text(
        "import state\nfrom providers import get_client\ndef run(flag):\n    if flag:\n        state.pipeline.client = get_client('njcaa')\n        raise RuntimeError()\n    return state.pipeline.update()\nRESULT = run(input())\n"
    )
    unused, evidence = _scan(tmp_path, pipeline)
    _dead(unused, evidence, "providers.NjcaaClient.schedule_dates")
