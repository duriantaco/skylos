"""A readonly route proof binds actual call values and all owned delegates."""

import ast

import pytest

from skylos.rules.quality.route_read_proof import source_read_only_route

SOURCE = """from fastapi import FastAPI
app=FastAPI()
class Controller:
    def preview(self, radius):
        return {'radius': radius + 1, 'state': 'preview'}
controller=Controller()
@app.post('/control/orbit/preview')
def orbit_preview(radius: float):
    return controller.preview(radius)
"""


def _proof(tmp_path, source=SOURCE, *, extra=None):
    target = tmp_path / "app.py"
    target.write_text(source)
    for name, text in (extra or {}).items():
        (tmp_path / name).write_text(text)
    tree = ast.parse(source)
    route = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "orbit_preview"
    )
    return source_read_only_route(tree, route, target, tmp_path)


def test_native_http_scalar_is_bound_through_owned_receiver(tmp_path):
    assert _proof(tmp_path)


@pytest.mark.parametrize(
    "body",
    [
        "global STATE\n        STATE=radius\n        return {'radius':radius}",
        "self.radius=radius\n        return {'radius':radius}",
        "STATE['radius']=radius\n        return {'radius':radius}",
        "STATE.append(radius)\n        return {'radius':radius}",
        "return bridge.mav.command_long_send(radius)",
        "return foreign.value()",
        "return foreign",
        "return Unknown()",
        "assert radius > 0\n        return {'radius':radius}",
        "import foreign\n        return {'radius':radius}",
        "try:\n            return {'radius':radius}\n        except Exception:\n            return {}",
        "with foreign.context():\n            return {'radius':radius}",
        "def compute():\n            return radius\n        return {'radius':radius}",
    ],
)
def test_owned_delegate_effects_and_unmodeled_serialization_stay_visible(
    tmp_path, body
):
    assert not _proof(
        tmp_path,
        SOURCE.replace("return {'radius': radius + 1, 'state': 'preview'}", body),
    )


@pytest.mark.parametrize(
    "change",
    [
        "controller=foreign.factory()",
        "controller=Controller()\nController.preview=foreign.preview",
        "controller=Controller()\ncontroller.preview=foreign.preview",
        "controller=Controller()\nforeign.register(controller)",
        "controller=Controller()\nforeign.register([controller])",
        "controller=Controller()\nforeign.register(controller.preview)",
        "controller=Controller()\ncallback=lambda: controller\nforeign.register(callback)",
    ],
)
def test_receiver_factory_patch_and_nested_escape_cannot_be_called_readonly(
    tmp_path, change
):
    assert not _proof(
        tmp_path, SOURCE.replace("controller=Controller()", "import foreign\n" + change)
    )


def test_helper_annotations_do_not_supply_native_argument_values(tmp_path):
    source = SOURCE.replace("class Controller:", "import foreign\nclass Controller:")
    source = source.replace(
        "controller.preview(radius)", "controller.preview(foreign.value())"
    )
    assert not _proof(tmp_path, source)


def test_same_helper_is_proved_in_each_call_context(tmp_path):
    source = SOURCE.replace(
        "class Controller:",
        "import foreign\ndef calculate(value):\n    return {'radius': value+1}\ncalculate(foreign.value())\nclass Controller:",
    )
    source = source.replace(
        "return {'radius': radius + 1, 'state': 'preview'}", "return calculate(radius)"
    )
    assert _proof(tmp_path, source)


def test_owned_delegate_global_store_is_checked_through_another_delegate(tmp_path):
    source = SOURCE.replace(
        "class Controller:",
        "STATE=0\ndef calculate(value):\n    global STATE\n    STATE=value\n    return {'radius':value}\nclass Controller:",
    )
    source = source.replace(
        "return {'radius': radius + 1, 'state': 'preview'}", "return calculate(radius)"
    )
    assert not _proof(tmp_path, source)


@pytest.mark.parametrize(
    "change",
    [
        "radius: Fake",
        "radius: float = foreign.value()",
        "radius",
    ],
)
def test_unvalidated_type_contracts_do_not_establish_native_values(tmp_path, change):
    assert not _proof(tmp_path, SOURCE.replace("radius: float", change))


def test_imported_instance_patch_invalidates_owned_method_binding(tmp_path):
    assert not _proof(
        tmp_path,
        SOURCE + "\nimport patcher\n",
        extra={"patcher.py": "import app\napp.controller.preview=opaque\n"},
    )


def test_imported_builtin_patch_invalidates_framework_scalar_contract(tmp_path):
    assert not _proof(
        tmp_path,
        SOURCE + "\nimport patcher\n",
        extra={"patcher.py": "import builtins\nbuiltins.float=opaque\n"},
    )


@pytest.mark.parametrize("target", ["orbit_preview.__code__", "app.post"])
def test_imported_route_or_application_patch_invalidates_readonly_contract(
    tmp_path, target
):
    assert not _proof(
        tmp_path,
        SOURCE + "\nimport patcher\n",
        extra={"patcher.py": "import app\napp." + target + "=opaque\n"},
    )


def test_receiver_alias_budget_exhaustion_is_not_escape_absence(tmp_path):
    aliases = "import foreign\ncallback0=lambda: controller\n"
    for index in range(1, 15):
        aliases += f"callback{index}=lambda: callback{index - 1}\n"
    aliases += "foreign.register(callback14)\n"
    assert not _proof(tmp_path, SOURCE + aliases)


def test_every_possible_container_binding_is_checked_for_receiver_escape(tmp_path):
    assert not _proof(
        tmp_path,
        SOURCE
        + "\nimport foreign\nbox=[controller]\nif foreign.enabled:\n    box=[]\nforeign.register(box)\n",
    )


def test_unknown_application_callback_keeps_request_effects_unresolved(tmp_path):
    source = SOURCE.replace("radius + 1", "1 / radius")
    source += (
        "\nimport foreign\napp.add_exception_handler(Exception, foreign.dispatch)\n"
    )
    assert not _proof(tmp_path, source)


@pytest.mark.parametrize(
    "patch",
    [
        "import fastapi.routing\nfastapi.routing.APIRoute.get_route_handler=opaque\n",
        "import fastapi.routing\nfastapi.routing.get_request_handler=opaque\n",
        "import pydantic\npydantic.TypeAdapter.validate_python=opaque\n",
        "import json\njson.dumps=opaque\n",
    ],
)
def test_used_framework_validation_and_serialization_capabilities_must_be_untampered(
    tmp_path, patch
):
    assert not _proof(
        tmp_path, SOURCE + "\nimport patcher\n", extra={"patcher.py": patch}
    )


def test_global_receiver_rebinding_in_another_owned_function_is_not_a_stable_binding(
    tmp_path,
):
    source = (
        SOURCE
        + "\nimport foreign\ndef replace_receiver():\n    global controller\n    controller=foreign.factory()\nreplace_receiver()\n"
    )
    assert not _proof(tmp_path, source)


def test_aliased_dynamic_code_is_not_an_intact_framework_context(tmp_path):
    source = (
        SOURCE
        + "\nimport foreign\nfrom builtins import exec as run\nrun('Controller.preview=foreign.preview')\n"
    )
    assert not _proof(tmp_path, source)


@pytest.mark.parametrize(
    "change",
    [
        "run=__builtins__['exec']\nrun('Controller.preview=foreign.preview')\n",
        "from builtins import globals as namespace\nnamespace()['controller']=foreign.factory()\n",
    ],
)
def test_reflective_namespace_aliases_do_not_preserve_readonly_binding(
    tmp_path, change
):
    assert not _proof(tmp_path, SOURCE + "\nimport foreign\n" + change)


def test_builtin_namespace_value_alias_does_not_preserve_readonly_binding(tmp_path):
    assert not _proof(
        tmp_path,
        SOURCE
        + "\nimport foreign\nnamespace=globals\nnamespace()['controller']=foreign.factory()\n",
    )
