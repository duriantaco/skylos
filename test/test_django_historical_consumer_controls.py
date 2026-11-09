"""Keep the original provider and importlib consumers alongside newer shapes."""

from test.test_django_app_repro_liveness import _assert_quiet, _scan, _unused_names


_PROVIDER_IFACE = {
    "provider_iface/__init__.py": "",
    "provider_iface/provider.py": '''\
"""Provider interface — duck-typed calls on base type.

schedule_dates is part of the live provider contract but never named at the
call site below.
"""


class Provider:
    def schedule_dates(self, season: int):
        raise NotImplementedError

    def scoreboard(self, day: str):
        raise NotImplementedError


class ConcreteProvider(Provider):
    def schedule_dates(self, season: int):
        return [f"{season}-01-01"]

    def scoreboard(self, day: str):
        return {"day": day, "games": []}


def fetch_day(provider: Provider, day: str):
    return provider.scoreboard(day)


# Entry keeps ConcreteProvider / scoreboard live; schedule_dates stays contract-only.
RESULT = fetch_day(ConcreteProvider(), "2026-10-23")
''',
}


def test_original_declared_provider_contract_remains_live(tmp_path):
    result = _scan(tmp_path, _PROVIDER_IFACE)
    # Concrete implementer method must stay live; abstract base may still look unused.
    unused = _unused_names(result)
    assert "ConcreteProvider.schedule_dates" not in unused
    assert "provider_iface.provider.ConcreteProvider.schedule_dates" not in unused


_PROCESSOR_PLUGIN = {
    "processor_plugin/__init__.py": "",
    "processor_plugin/plugins/__init__.py": "",
    "processor_plugin/loader.py": '''\
"""Convention loader: processor path chosen by name string only.

No module-level RESULT= that proves IntegrateSessions live — the class is only
reachable when a runtime name selects the dotted path.
"""

from importlib import import_module

# Registry of logical name → module path (class name is conventional).
PROCESSORS = {
    "integrate_sessions": "processor_plugin.plugins.integrate",
}


def load_processor(name: str):
    module_path = PROCESSORS[name]
    module = import_module(module_path)
    return getattr(module, "IntegrateSessions")


def run_named(name: str, session):
    cls = load_processor(name)
    return cls(session).process()
''',
    "processor_plugin/plugins/integrate.py": '''\
"""Bare processor class — product convention load, no static importers of the class."""


class IntegrateSessions:
    def __init__(self, session, debug=False, **kwargs):
        self.session = session
        self.debug = debug

    def process(self):
        return {"session": self.session, "integrated": True}
''',
}


def test_original_importlib_processor_contract_remains_live(tmp_path):
    result = _scan(tmp_path, _PROCESSOR_PLUGIN)
    _assert_quiet(result, "IntegrateSessions")
