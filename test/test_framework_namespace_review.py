"""Independent namespace-carrier checks; fixture code is parsed, never run."""

import ast

import pytest

from skylos.rules.quality.route_read_proof import source_read_only_route
from skylos.security.framework_contracts import native_http_pipeline_is_intact
from test.fixture_paths import write_fixture

SOURCE = """from fastapi import FastAPI
app=FastAPI()
class Controller:
    def preview(self, radius):
        return {'radius': radius + 1}
controller=Controller()
@app.post('/control/orbit/preview')
def orbit_preview(radius: float):
    return controller.preview(radius)
"""


def _proofs(tmp_path, extra=""):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="namespace-review"\n')
    source = SOURCE + extra
    path = write_fixture(tmp_path, "app.py", source)
    tree = ast.parse(source, filename=str(path))
    route = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "orbit_preview"
    )
    return (
        native_http_pipeline_is_intact(tree, path, tmp_path),
        source_read_only_route(tree, route, path, tmp_path),
    )


@pytest.mark.parametrize(
    "extra",
    ["", "\ndef helper():\n    return 1\nvalue=helper()\n"],
)
def test_native_route_and_direct_scalar_helper_keep_preview_proof(tmp_path, extra):
    assert _proofs(tmp_path, extra) == (True, True)


@pytest.mark.parametrize(
    "carrier",
    [
        "helper",
        "alias",
        "[helper]",
        "{'callback': helper}",
        "lambda: 1",
        "Marker",
        "Marker()",
    ],
)
def test_opaque_consumer_of_python_namespace_carrier_blocks_proof(tmp_path, carrier):
    extra = (
        "\nimport foreign\ndef helper():\n    return 1\n"
        "alias=helper\nclass Marker:\n    pass\n"
        "foreign.install(" + carrier + ")\n"
    )
    assert _proofs(tmp_path, extra) == (False, False)


@pytest.mark.parametrize(
    "definition",
    [
        "@foreign.wrap\ndef helper():\n    return 1\n",
        "@foreign.wrap\nclass Marker:\n    pass\n",
    ],
)
def test_opaque_decorator_implicitly_receives_python_namespace(tmp_path, definition):
    assert _proofs(tmp_path, "\nimport foreign\n" + definition) == (False, False)
