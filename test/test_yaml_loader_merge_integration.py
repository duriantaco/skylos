"""Keep expanded YAML loader support within the native-provider boundary."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


def _both(tmp_path, source):
    path = tmp_path / "loader.py"
    path.write_text(source)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(source))
    return [
        [row for row in findings if row["rule_id"] == "SKY-D206"]
        for findings in (scan_ctx(tmp_path, [path]), linter.findings)
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.load(data, Loader=yaml.BaseLoader)\n",
        "import yaml as y\ny.load_all(data, y.CBaseLoader)\n",
        "from yaml.loader import BaseLoader\nimport yaml\nyaml.load(data, Loader=BaseLoader)\n",
        "from yaml.cyaml import CBaseLoader\nimport yaml\nyaml.load(data, Loader=CBaseLoader)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\ndef run(data):\n    return yaml.load(data, Loader=FAST)\n",
        "import yaml as y\ny.load(data, Loader=getattr(y, 'CBaseLoader', y.BaseLoader))\n",
    ],
    ids=[
        "base-loader",
        "cbase-loader-module-alias",
        "base-loader-import",
        "cbase-loader-import",
        "getattr-assignment-fallback",
        "getattr-direct-fallback",
    ],
)
def test_native_data_only_loaders_and_builtin_fallback_stay_quiet(tmp_path, source):
    assert _both(tmp_path, source) == [[], []]


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\ndef getattr(*args):\n    return yaml.UnsafeLoader\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\ndef run(data, getattr):\n    return yaml.load(data, Loader=getattr(yaml, 'CSafeLoader', yaml.SafeLoader))\n",
        "import yaml\nyaml.BaseLoader = yaml.UnsafeLoader\nyaml.load(data, Loader=yaml.BaseLoader)\n",
        "import yaml\nyaml.CSafeLoader = yaml.UnsafeLoader\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nyaml.SafeLoader = yaml.UnsafeLoader\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nglobals()['FAST'] = yaml.UnsafeLoader\nyaml.load(data, Loader=FAST)\n",
        "import sys\nimport yaml\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nsys.modules[__name__].FAST = yaml.UnsafeLoader\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nfrom vendor import CSafeLoader as FAST\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nFAST.add_constructor('!unsafe', eval)\nyaml.load(data, Loader=FAST)\n",
        "import builtins\nimport yaml\nbuiltins.getattr = lambda *args: yaml.UnsafeLoader\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', yaml.UnsafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nname = 'CSafeLoader'\nFAST = getattr(yaml, name, yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import sys\nimport yaml\nsys.meta_path.insert(0, hook)\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import sys\nimport yaml\nsys.modules['yaml'] = replacement\nFAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', *defaults)\nyaml.load(data, Loader=FAST)\n",
        "import yaml\nFAST = getattr(yaml, 'CSafeLoader', default=yaml.SafeLoader)\nyaml.load(data, Loader=FAST)\n",
    ],
    ids=[
        "fake-getattr",
        "getattr-parameter",
        "patched-base-loader",
        "patched-getattr-target",
        "patched-getattr-default",
        "globals-alias-rebind",
        "module-alias-rebind",
        "import-alias-rebind",
        "loader-constructor-patch",
        "patched-builtin-getattr",
        "unsafe-getattr-default",
        "computed-getattr-name",
        "import-hook",
        "provider-cache-replacement",
        "starred-getattr-default",
        "keyword-getattr-default",
    ],
)
def test_unproved_loader_and_fallback_bindings_keep_finding(tmp_path, source):
    for findings in _both(tmp_path, source):
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"


def test_project_owned_yaml_provider_cannot_prove_fallback_safe(tmp_path):
    (tmp_path / "yaml.py").write_text(
        "class SafeLoader: pass\n"
        "class CSafeLoader: pass\n"
        "def load(data, Loader=None): return Loader(data)\n"
    )
    source = (
        "import yaml\n"
        "FAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\n"
        "yaml.load(data, Loader=FAST)\n"
    )
    for findings in _both(tmp_path, source):
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"


def test_imported_project_patch_of_builtin_getattr_keeps_finding(tmp_path):
    (tmp_path / "hook.py").write_text(
        "import builtins\n"
        "def fake(*args):\n    return args[0].UnsafeLoader\n"
        "builtins.getattr = fake\n"
    )
    source = (
        "import hook\n"
        "import yaml\n"
        "FAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\n"
        "yaml.load(data, Loader=FAST)\n"
    )
    for findings in _both(tmp_path, source):
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"


def test_imported_getattr_mutator_cannot_prove_later_direct_loader_safe(tmp_path):
    (tmp_path / "hook.py").write_text(
        "import builtins\n"
        "from subprocess import check_output\n"
        "def execute(loader, node):\n"
        "    return check_output(loader.construct_scalar(node), shell=True)\n"
        "def replacement(module, name, default):\n"
        "    module.SafeLoader.add_constructor('!execute', execute)\n"
        "    return default\n"
        "builtins.getattr = replacement\n"
    )
    source = (
        "import hook\n"
        "import yaml\n"
        "getattr(yaml, 'SafeLoader', yaml.SafeLoader)\n"
        "def parse(payload):\n"
        "    return yaml.load(payload, Loader=yaml.SafeLoader)\n"
    )
    for findings in _both(tmp_path, source):
        assert [(row["line"], row["severity"]) for row in findings] == [(5, "HIGH")]
