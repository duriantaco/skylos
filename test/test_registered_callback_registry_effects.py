import ast

import pytest

from skylos.rules.danger.danger_fs.path_provenance import _Project
from skylos.rules.danger.registered_callback_sources import _contains_dispatcher


SOURCE = """
class EngineProcessor:
    def __init__(self, engine):
        self.engine = engine
    def initialize(self, callback):
        callback(self, True)

class Dispatcher(EngineProcessor):
    engine_type = 'offline'

class Registry(dict):
    processor_types = {'offline': Dispatcher}
    def init(self, engine):
        factory = self.processor_types.get(engine.engine_type)
        processor = factory(engine)
        processor.initialize(self.register)
    def register(self, processor, okay):
        if okay:
            self[processor.engine.name] = processor

REGISTRY = Registry()
REGISTRY.init(engine)
"""


def _registered(tmp_path, source):
    path = tmp_path / "registry.py"
    path.write_text(source)
    project = _Project.load(tmp_path)
    unit = project.by_path[path]
    classes = {
        node.name: node for node in unit.tree.body if isinstance(node, ast.ClassDef)
    }
    return _contains_dispatcher(
        project, unit, classes["Registry"], classes["Dispatcher"]
    )


def test_registry_factory_callback_and_storage_establish_dispatcher(tmp_path):
    assert _registered(tmp_path, SOURCE)


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace("processor.initialize(self.register)", "pass"),
        SOURCE.replace("self[processor.engine.name] = processor", "pass"),
        SOURCE.replace("callback(self, True)", "callback(other, True)"),
        SOURCE.replace("processor = factory(engine)", "processor = other(engine)"),
        SOURCE + "Registry.processor_types['offline'] = Other\n",
        SOURCE.replace("REGISTRY.init(engine)", "pass"),
        SOURCE + "types = Registry.processor_types\ntypes['offline'] = Other\n",
    ],
)
def test_a_dictionary_of_dispatcher_types_is_not_registration(tmp_path, source):
    assert not _registered(tmp_path, source)
