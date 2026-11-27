import ast
import os

import pytest

from skylos.analysis.worker_cache import SecurityUnitCache, security_units
from skylos.rules.danger.danger_fs import path_provenance
from skylos.rules.danger.project_security_sources import ProjectSources
from skylos.rules.danger.python_security_gaps import scan


def project(tmp_path, remote=True, annotation="str", override="", model_defs=""):
    (tmp_path / "loader.py").write_text(
        "import importlib\ndef load(name):\n    module, cls = name.rsplit('.',1)\n    return importlib.import_module(module)\n"
    )
    (tmp_path / "models.py").write_text(
        "from pydantic import BaseModel\nfrom typing import Literal\nfrom enum import Enum\n"
        + model_defs
        + "\nclass Config(BaseModel):\n    plugin: "
        + annotation
        + "\n"
        + override
    )
    source = (
        "from urllib.request import urlopen\nimport json\ndef data():\n    return json.loads(urlopen('https://example.com/config').read())\n"
        if remote
        else "def data():\n    return {'plugin':'safe.Module'}\n"
    )
    (tmp_path / "source.py").write_text(source)
    (tmp_path / "app.py").write_text(
        "from source import data\nfrom models import Config\nfrom loader import load\ncfg=Config.model_validate(data())\nload(cfg.plugin)\n"
    )
    path = tmp_path / "loader.py"
    findings = []
    scan(ast.parse(path.read_text()), path, findings, project_root=tmp_path)
    return [row for row in findings if row["rule_id"] == "SKY-D357"]


def test_cross_file_remote_model_plugin_reaches_import(tmp_path):
    hits = project(tmp_path)
    assert [row["line"] for row in hits] == [4]
    trace = hits[0]["security_evidence"]["path"]
    assert any("network response" in step for step in trace)
    assert any("Pydantic validates" in step for step in trace)


def test_static_configuration_is_not_a_remote_source(tmp_path):
    assert not project(tmp_path, remote=False)


def test_model_literal_allowlist_does_not_carry_arbitrary_module_name(tmp_path):
    assert not project(tmp_path, annotation="Literal['safe.Module']")


def test_model_enum_allowlist_does_not_carry_arbitrary_module_name(tmp_path):
    assert not project(
        tmp_path,
        annotation="Allowed",
        model_defs="class Allowed(str,Enum):\n    SAFE='safe.Module'\n",
    )


def test_custom_enum_acceptance_is_not_a_finite_allowlist_proof(tmp_path):
    model_defs = "class Allowed(str,Enum):\n    SAFE='safe.Module'\n    @classmethod\n    def _missing_(cls,value):\n        return custom_member(value)\n"
    assert project(tmp_path, annotation="Allowed", model_defs=model_defs)


def test_overridden_model_validator_returning_fixed_config_stays_quiet(tmp_path):
    override = "    @classmethod\n    def model_validate(cls, value):\n        return cls(plugin='safe.Module')\n"
    assert not project(tmp_path, override=override)


def test_model_field_validator_is_not_assumed_to_preserve_input(tmp_path):
    override = "    from pydantic import field_validator\n    @field_validator('plugin', mode='before')\n    @classmethod\n    def fixed(cls, value):\n        return 'safe.Module'\n"
    assert not project(tmp_path, override=override)


def test_other_returned_tuple_component_does_not_taint_module_name(tmp_path):
    (tmp_path / "source.py").write_text(
        "from urllib.request import urlopen\ndef values():\n    return 'safe.module',urlopen('https://example.com').read()\n"
    )
    path = tmp_path / "app.py"
    path.write_text(
        "import importlib\nfrom source import values\nmodule, data = values()\nimportlib.import_module(module)\n"
    )
    findings = []
    scan(ast.parse(path.read_text()), path, findings, project_root=tmp_path)
    assert not [row for row in findings if row["rule_id"] == "SKY-D357"]


def test_same_position_different_ast_is_not_source_grounding(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("import importlib\nimportlib.import_module('safe.module')\n")
    other = (
        ast.parse("import importlib\nimportlib.import_module(remote_name)\n")
        .body[1]
        .value
    )
    assert ProjectSources(tmp_path).import_evidence(path, other) is None


@pytest.fixture
def worker_units():
    token = security_units.set(SecurityUnitCache())
    try:
        yield
    finally:
        security_units.reset(token)


def test_project_unit_reuse_keeps_resolution_failures_private(
    tmp_path, worker_units, monkeypatch
):
    path = tmp_path / "module.py"
    path.write_text("value = 'fixed'\n")
    first = ProjectSources(tmp_path)
    second = ProjectSources(tmp_path)
    first_unit = first.project.by_path[path]
    second_unit = second.project.by_path[path]
    assert first_unit.tree is second_unit.tree
    assert first_unit.module.binds is second_unit.module.binds

    def stop(*args):
        raise RecursionError

    with monkeypatch.context() as patch:
        patch.setattr(path_provenance, "module_rebinding", stop)
        assert first_unit.rebinding()[0]
    assert not second_unit.rebinding()[0]
    assert first_unit.rebinding()[0]

    monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 1)
    first.project._charge_resolution()
    with pytest.raises(path_provenance._ResolutionLimit):
        first.project._charge_resolution()
    second.project._charge_resolution()
    assert first.project._resolution_work == 2
    assert second.project._resolution_work == 1


def test_project_unit_reuse_reads_changed_source_and_inventory(tmp_path, worker_units):
    root = tmp_path / "src"
    root.mkdir()
    path = root / "module.py"
    path.write_text("value = 'first'\n")
    metadata = path.stat()
    first = ProjectSources(root).project.by_path[path]
    path.write_text("value = 'other'\n")
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    changed = ProjectSources(root).project.by_path[path]
    assert changed.tree.body[0].value.value == "other"
    assert changed.tree is not first.tree

    (tmp_path / "__init__.py").touch()
    (root / "__init__.py").touch()
    packaged = ProjectSources(root).project.by_path[path]
    assert tmp_path.name + ".src.module" in packaged.module_names
    assert packaged.module_names != first.module_names
    outside = tmp_path / "elsewhere.py"
    path.rename(outside)
    path.symlink_to(outside)
    assert path not in ProjectSources(root).project.by_path


@pytest.mark.parametrize(
    "limit",
    ["_MAX_CACHED_FILES", "_MAX_CACHED_SCOPE_NODES", "_MAX_CACHED_SOURCE_CHARS"],
)
def test_project_index_cache_budget_keeps_uncached_sources_in_graph(
    tmp_path, worker_units, monkeypatch, limit
):
    from skylos.rules.danger import project_security_sources

    monkeypatch.setattr(project_security_sources, limit, 0)
    path = tmp_path / "providers.py"
    path.write_text("def provider(): return 42\n")
    first = ProjectSources(tmp_path).project
    second = ProjectSources(tmp_path).project
    assert first.by_path[path].tree is not second.by_path[path].tree
    assert first.function_info and second.function_info
    assert not security_units.get().entries


def test_serial_worker_reuses_index_and_follows_changed_cross_file_source(
    tmp_path, monkeypatch
):
    from skylos.scale.parallel_static import run_proc_file_parallel

    path = tmp_path / "loader.py"
    path.write_text(
        "import importlib\ndef load(name):\n    return importlib.import_module(name)\n"
    )
    caller = tmp_path / "entry.py"
    caller.write_text(
        "from urllib.request import urlopen\n"
        "from loader import load\n"
        "load(urlopen('https://example.org').read().decode())\n"
    )
    indexed = []
    original = path_provenance._Unit._index

    def track(unit):
        indexed.append(unit.path)
        return original(unit)

    def update(done, total, completed):
        if done == 1:
            caller.write_text("from loader import load\nload('fixed.module')\n")

    monkeypatch.setattr(path_provenance._Unit, "_index", track)
    results = run_proc_file_parallel(
        [path, path],
        {path: "loader"},
        jobs=1,
        progress_callback=update,
        project_root=tmp_path,
    )
    positives = [
        [f for f in result[7] if f["rule_id"] == "SKY-D357"] for result in results
    ]
    assert [len(group) for group in positives] == [1, 0]
    assert indexed.count(path) == 1
    assert indexed.count(caller) == 2
    assert security_units.get() is None
