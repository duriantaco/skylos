"""A SafeLoader suffix alone cannot prove YAML deserialization safe."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


def _both(tmp_path, source):
    root = tmp_path.resolve()
    path = root / "loader.py"
    path.write_text(source)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(source))
    return [
        [row for row in findings if row["rule_id"] == "SKY-D206"]
        for findings in (scan_ctx(root, [path]), linter.findings)
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.SafeLoader = yaml.UnsafeLoader\nyaml.load(data, Loader=yaml.SafeLoader)\n",
        "import yaml\nclass Fake:\n    SafeLoader = yaml.UnsafeLoader\nyaml.load(data, Loader=Fake.SafeLoader)\n",
        "import yaml\nfrom yaml import SafeLoader\ndef run(SafeLoader):\n    return yaml.load(data, Loader=SafeLoader)\nrun(yaml.UnsafeLoader)\n",
        "import yaml\ndef run(yaml):\n    return yaml.load(data, Loader=yaml.SafeLoader)\n",
        "import yaml\nfrom yaml import SafeLoader\nSafeLoader = yaml.UnsafeLoader\nyaml.load(data, Loader=SafeLoader)\n",
        "import yaml\nclass SafeLoader(yaml.UnsafeLoader):\n    pass\nyaml.load(data, Loader=SafeLoader)\n",
        "import yaml\nyaml.CSafeLoader = yaml.UnsafeLoader\nyaml.load_all(data, yaml.CSafeLoader)\n",
    ],
)
def test_unsafe_or_unproved_loader_binding_keeps_finding(tmp_path, source):
    for findings in _both(tmp_path, source):
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n",
        "import yaml as y\ny.load_all(data, y.CSafeLoader)\n",
        "from yaml import load as parse, SafeLoader as Loader\nparse(data, Loader=Loader)\n",
        "from yaml.loader import SafeLoader\nimport yaml\nyaml.load(data, Loader=SafeLoader)\n",
    ],
)
def test_native_safe_loader_imports_and_aliases_stay_quiet(tmp_path, source):
    assert _both(tmp_path, source) == [[], []]
