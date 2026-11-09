import ast

from skylos.rules.danger.python_security_gaps import scan
from skylos.rules.danger.project_security_sources import ProjectSources


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
