import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


_PLAIN = "import yaml\nclass Strict(yaml.SafeLoader):\n    pass\n"
_READ = "def read(stream):\n    return yaml.load(stream, Loader=Strict)\n"


def _check_both(tmp_path, code, reported):
    path = tmp_path / "loader.py"
    path.write_text(code)
    checker = LinterVisitor([DangerousCallsRule()], str(path))
    checker.visit(ast.parse(code))
    for rows in [scan_ctx(tmp_path, [path]), checker.findings]:
        findings = [row for row in rows if row["rule_id"] == "SKY-D206"]
        assert bool(findings) is reported
        if reported:
            assert all(row["severity"] == "HIGH" for row in findings)
            assert all(row["file"] == str(path) for row in findings)


@pytest.mark.parametrize(
    "code",
    [
        "import yaml\nfrom yaml import SafeLoader as Base\nBase=yaml.UnsafeLoader\nclass Strict(Base):\n    pass\n"
        + _READ,
        "import yaml\nfrom yaml import SafeLoader as Base\nif legacy:\n    Base=yaml.UnsafeLoader\nclass Strict(Base):\n    pass\n"
        + _READ,
        "import yaml\nfrom yaml import SafeLoader as Base\nglobals()['Base']=yaml.UnsafeLoader\nclass Strict(Base):\n    pass\n"
        + _READ,
        "import yaml\nsetattr(yaml,'SafeLoader',yaml.UnsafeLoader)\nclass Strict(yaml.SafeLoader):\n    pass\n"
        + _READ,
        "import yaml\ny=yaml\nsetattr(y,'SafeLoader',yaml.UnsafeLoader)\nclass Strict(yaml.SafeLoader):\n    pass\n"
        + _READ,
        "import yaml\nfrom external import *\nclass Strict(yaml.SafeLoader):\n    pass\n"
        + _READ,
        "import yaml\nfrom yaml import UnsafeLoader as Other\nclass Strict(yaml.SafeLoader):\n    def __new__(cls,stream):\n        return Other(stream)\n"
        + _READ,
        "import yaml\nfrom yaml import unsafe_load as parse\nclass Parent(yaml.SafeLoader):\n    def construct_scalar(self,node):\n        return parse(node.value)\nclass Strict(Parent):\n    pass\n"
        + _READ,
        "import yaml\nfrom yaml import unsafe_load as parse\nclass Strict(yaml.SafeLoader):\n    def construct_mapping(self,node,deep=False):\n        return parse(node.value)\n"
        + _READ,
        "import yaml\nclass Strict(yaml.SafeLoader):\n    def construct_mapping(self,node,deep=False):\n        self.construct_object=callback\n        return self.construct_object(node)\n"
        + _READ,
        "import yaml\nset=lambda: dangerous_registry_change()\nclass Strict(yaml.SafeLoader):\n    def construct_mapping(self,node,deep=False):\n        keys=set()\n        return super().construct_mapping(node,deep)\n"
        + _READ,
    ],
)
def test_local_uncertainty_does_not_prove_yaml_loader_safe(tmp_path, code):
    _check_both(tmp_path, code, True)


@pytest.mark.parametrize(
    "method",
    [
        "    def construct_mapping(self,node,deep=False):\n        result={}\n        for key_node,value_node in node.value:\n            key=self.construct_object(key_node,deep=deep)\n            if key in result:\n                raise ValueError(key)\n            result[key]=self.construct_object(value_node,deep=deep)\n        return result\n",
        "    def construct_mapping(self,node,deep=False):\n        mapping=super().construct_mapping(node,deep)\n        keys=set()\n        for key_node,_ in node.value:\n            key=self.construct_object(key_node,deep=deep)\n            if key in keys:\n                raise yaml.constructor.ConstructorError(None,None,'duplicate',key_node.start_mark)\n            keys.add(key)\n        return mapping\n",
    ],
)
def test_data_only_duplicate_key_mapping_remains_safe(tmp_path, method):
    code = "import yaml\nclass Strict(yaml.SafeLoader):\n" + method + _READ
    _check_both(tmp_path, code, False)


@pytest.mark.parametrize("call", ["load", "load_all"])
@pytest.mark.parametrize("loader", ["yaml.SafeLoader", "yaml.UnsafeLoader"])
def test_yaml_dotted_imports_and_document_streams(tmp_path, call, loader):
    code = (
        "import yaml\nimport yaml.constructor\ndef read(stream):\n    return yaml."
        + call
        + "(stream,"
        + loader
        + ")\n"
    )
    _check_both(tmp_path, code, loader == "yaml.UnsafeLoader")


@pytest.mark.parametrize(
    "external",
    [
        "import loader\nimport yaml\nloader.Strict.__new__=staticmethod(lambda cls,stream:yaml.UnsafeLoader(stream))\n",
        "from loader import Strict as L\nfrom yaml import UnsafeLoader as Other\nL.__new__=staticmethod(lambda cls,stream:Other(stream))\n",
        "import yaml\nyaml.SafeLoader.add_constructor('!x',eval)\n",
        "import yaml\nyaml.SafeLoader.yaml_constructors['!x']=eval\n",
        "import sys\nvars(sys.modules['loader'])['Strict']=replacement\n",
        "import importlib as i\ni.import_module('loader').Strict.__new__=factory\n",
    ],
)
def test_project_mutations_keep_yaml_finding_listed(tmp_path, external):
    (tmp_path / "loader.py").write_text(_PLAIN + _READ)
    (tmp_path / "server.py").write_text(external)
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D206"]
    assert len(rows) == 1
    assert rows[0]["line"] == 5
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["listing"]["listed"] is True


def test_unrelated_subclass_registration_does_not_change_safe_loader(tmp_path):
    (tmp_path / "loader.py").write_text(_PLAIN + _READ)
    (tmp_path / "other.py").write_text(
        "import yaml\nclass Other(yaml.SafeLoader):\n    pass\nOther.add_constructor('!x',str)\n"
    )
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    assert not [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D206"]


@pytest.mark.parametrize(
    "external",
    [
        "import yaml\nsetattr(yaml,'SafeLoader',yaml.UnsafeLoader)\n",
        "import yaml\nfrom builtins import setattr as change\nchange(yaml,'SafeLoader',yaml.UnsafeLoader)\n",
        "import yaml\ngetattr(yaml,'SafeLoader').construct_scalar=callback\n",
        "import yaml\nclass Other(yaml.SafeLoader):\n    pass\nOther.yaml_constructors['!x']=callback\n",
        "import yaml\nclass Other(yaml.SafeLoader):\n    pass\nOther.yaml_multi_constructors.update({'!':callback})\n",
        "import yaml\nclass Other(yaml.SafeLoader):\n    pass\nregistry=Other.yaml_constructors\nregistry['!x']=callback\n",
    ],
)
def test_project_reflection_and_shared_base_registries_are_not_safe(tmp_path, external):
    (tmp_path / "loader.py").write_text(_PLAIN + _READ)
    (tmp_path / "plugin.py").write_text(external)
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D206"]
    assert len(rows) == 1
    assert rows[0]["line"] == 5
    assert rows[0]["listing"]["listed"] is True


@pytest.mark.parametrize(
    "code",
    [
        "from external_runtime import install\ninstall()\n" + _PLAIN + _READ,
        _PLAIN
        + "def read(stream,callback):\n    callback()\n    return yaml.load(stream,Loader=Strict)\n",
        _PLAIN
        + "def read(stream,callback):\n    prepare=callback\n    prepare()\n    return yaml.load(stream,Loader=Strict)\n",
    ],
)
def test_unknown_effects_before_loading_are_not_a_safety_proof(tmp_path, code):
    _check_both(tmp_path, code, True)


@pytest.mark.parametrize("shadow", ["yaml.py", "yaml/__init__.py"])
def test_project_yaml_shadow_does_not_prove_library_identity(tmp_path, shadow):
    target = tmp_path / shadow
    target.parent.mkdir(exist_ok=True)
    target.write_text("from unsafe_backend import Loader as SafeLoader\n")
    _check_both(tmp_path, _PLAIN + _READ, True)


def test_duplicate_mapping_exception_constructor_must_keep_library_identity(tmp_path):
    (tmp_path / "loader.py").write_text(
        "import yaml\nclass Strict(yaml.SafeLoader):\n"
        "    def construct_mapping(self,node,deep=False):\n"
        "        mapping=super().construct_mapping(node,deep)\n"
        "        keys=set()\n"
        "        for key_node,_ in node.value:\n"
        "            key=self.construct_object(key_node,deep=deep)\n"
        "            if key in keys:\n"
        "                raise yaml.constructor.ConstructorError(None,None,'duplicate',key_node.start_mark)\n"
        "            keys.add(key)\n"
        "        return mapping\n" + _READ
    )
    (tmp_path / "plugin.py").write_text(
        "import yaml\nyaml.constructor.ConstructorError=callback\n"
    )
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    assert any(
        row["rule_id"] == "SKY-D206" and row["listing"]["listed"]
        for row in result.get("danger", [])
    )


def test_shared_registry_imported_from_package_initializer_keeps_finding(tmp_path):
    (tmp_path / "loader.py").write_text(_PLAIN + _READ)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text(
        "import yaml\nclass Other(yaml.SafeLoader):\n    pass\n"
    )
    (tmp_path / "server.py").write_text(
        "from pkg import Other\nOther.yaml_constructors['!x']=callback\n"
    )
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    assert any(
        row["rule_id"] == "SKY-D206" and row["listing"]["listed"]
        for row in result.get("danger", [])
    )


def test_reexported_shared_registry_keeps_finding(tmp_path):
    (tmp_path / "loader.py").write_text(_PLAIN + _READ)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/base.py").write_text(
        "import yaml\nclass Other(yaml.SafeLoader):\n    pass\n"
    )
    (tmp_path / "pkg/__init__.py").write_text("from .base import Other\n")
    (tmp_path / "server.py").write_text(
        "from pkg import Other\nOther.yaml_constructors['!x']=callback\n"
    )
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    assert any(
        row["rule_id"] == "SKY-D206" and row["listing"]["listed"]
        for row in result.get("danger", [])
    )


@pytest.mark.parametrize("layout", ["src", "package-root"])
def test_project_import_roots_resolve_loader_mutation(tmp_path, layout):
    package = tmp_path / "pkg"
    if layout == "src":
        package = tmp_path / "src/pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "loader.py").write_text(_PLAIN + _READ)
    root = tmp_path if layout == "src" else package
    (root / "server.py").write_text(
        "import yaml\nfrom pkg.loader import Strict\nStrict.__new__=staticmethod(lambda cls,stream:yaml.UnsafeLoader(stream))\n"
    )
    result = json.loads(analyze(str(root), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    assert any(
        row["rule_id"] == "SKY-D206" and row["listing"]["listed"]
        for row in result.get("danger", [])
    )


@pytest.mark.parametrize(
    "external",
    [
        "import sys,yaml\nsys.modules['loader'].Strict.__new__=staticmethod(lambda cls,stream:yaml.UnsafeLoader(stream))\n",
        "from sys import modules as loaded\nimport yaml\nloaded['loader'].Strict.__new__=staticmethod(lambda cls,stream:yaml.UnsafeLoader(stream))\n",
        "import inspect,loader,yaml\ninspect.getmodule(loader.read).Strict.__new__=staticmethod(lambda cls,stream:yaml.UnsafeLoader(stream))\n",
    ],
)
def test_reflective_module_capabilities_cannot_hide_loader_mutations(
    tmp_path, external
):
    (tmp_path / "loader.py").write_text(_PLAIN + _READ)
    (tmp_path / "server.py").write_text(external)
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D206"]
    assert len(rows) == 1
    assert rows[0]["line"] == 5
    assert rows[0]["listing"]["listed"] is True
