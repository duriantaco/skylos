"""Only configurations that can survive startup supply protocol entrypoints."""

import json

import pytest

from skylos.analyzer import analyze


def _scan(root, setting, tail, grep):
    if setting == "LOGGING":
        configured = (
            "{'version': 1, 'filters': {'chosen': {'()': 'app.backend.Backend'}}}"
        )
        method = "filter"
    else:
        configured = "{'default': {'BACKEND': 'app.backend.Backend'}}"
        method = "save"
    sources = {
        "app/__init__.py": "\n",
        "app/settings.py": (
            "INSTALLED_APPS = []\nSECRET_KEY = 'example-value'\n"
            + f"{setting} = {configured}\n"
            + tail.format(setting=setting, configured=configured)
        ),
        "app/backend.py": (
            "class Backend:\n"
            + f"    def {method}(self, *args):\n"
            + "        return protocol_helper()\n\n"
            + "def protocol_helper():\n    return True\n"
        ),
    }
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = json.loads(analyze(str(root), conf=80, grep_verify=grep))
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    rescued = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    return unused, rescued, f"app.backend.Backend.{method}"


@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize("setting", ["LOGGING", "STORAGES"])
@pytest.mark.parametrize(
    "tail",
    ["{setting} = {{}}\n", "if True:\n    {setting} = {{}}\n"],
)
def test_replaced_dictionary_does_not_supply_protocol_roots(
    tmp_path, setting, tail, grep
):
    unused, rescued, method = _scan(tmp_path, setting, tail, grep)
    assert method in unused
    assert "app.backend.protocol_helper" in unused
    assert not any(item["name"] == method for item in rescued)


@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize("setting", ["LOGGING", "STORAGES"])
@pytest.mark.parametrize("tail", ["", "if enabled:\n    {setting} = {{}}\n"])
def test_active_or_possibly_active_dictionary_keeps_protocol_roots(
    tmp_path, setting, tail, grep
):
    unused, rescued, method = _scan(tmp_path, setting, tail, grep)
    assert method not in unused
    assert "app.backend.protocol_helper" not in unused
    assert any(item["name"] == method for item in rescued)


@pytest.mark.parametrize("setting", ["LOGGING", "STORAGES"])
def test_replacement_keeps_newly_added_protocol_factory(tmp_path, setting):
    tail = "{setting} = {{}}\n{setting}.update({configured})\n"
    unused, rescued, method = _scan(tmp_path, setting, tail, False)
    assert method not in unused
    assert any(item["name"] == method for item in rescued)


@pytest.mark.parametrize("setting", ["LOGGING", "STORAGES"])
@pytest.mark.parametrize(
    "tail",
    [
        "{setting} = {{}}\nif False:\n    {setting} = {configured}\n",
        "{setting} = {{}}\nif False:\n    {setting}.update({configured})\n",
    ],
)
def test_dead_configuration_branch_does_not_supply_protocol_roots(
    tmp_path, setting, tail
):
    unused, rescued, method = _scan(tmp_path, setting, tail, True)
    assert method in unused
    assert "app.backend.protocol_helper" in unused
    assert not any(item["name"] == method for item in rescued)


@pytest.mark.parametrize("setting", ["LOGGING", "STORAGES"])
@pytest.mark.parametrize("called_after_reset", [False, True])
def test_helper_mutation_uses_call_order_instead_of_definition_order(
    tmp_path, setting, called_after_reset
):
    tail = "def configure():\n    {setting}.update({configured})\n"
    if called_after_reset:
        tail += "{setting} = {{}}\nconfigure()\n"
    else:
        tail += "configure()\n{setting} = {{}}\n"
    unused, rescued, method = _scan(tmp_path, setting, tail, True)
    assert (method not in unused) is called_after_reset
    assert ("app.backend.protocol_helper" not in unused) is called_after_reset
    assert any(item["name"] == method for item in rescued) is called_after_reset


@pytest.mark.parametrize("setting", ["LOGGING", "STORAGES"])
@pytest.mark.parametrize(
    "tail",
    [
        "{setting} = {{}}\ndef configure({setting}):\n"
        "    {setting}.update({configured})\nconfigure({{}})\n",
        "{setting} = {{}}\ndef configure():\n    {setting} = {{}}\n"
        "    {setting}.update({configured})\nconfigure()\n",
    ],
)
def test_helper_local_dictionary_does_not_configure_global_protocol(
    tmp_path, setting, tail
):
    unused, rescued, method = _scan(tmp_path, setting, tail, True)
    assert method in unused
    assert "app.backend.protocol_helper" in unused
    assert not any(item["name"] == method for item in rescued)
