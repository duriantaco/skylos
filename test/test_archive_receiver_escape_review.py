"""Independent adversarial controls for imported API contracts."""

import ast

import pytest

from skylos.rules.danger.danger_fs.path_flow import _PathFlowChecker


@pytest.mark.parametrize(
    "mutation",
    [
        "patch([propagate])",
        "patch({'api': propagate})",
        "patch((propagate,))",
        "patch(*(propagate,))",
        "registry = [propagate]\npatch(registry)",
        "registry = {'api': propagate}\nregistry['api'].extract = archive.extract",
        "registry.api = propagate\nregistry.api.extract = archive.extract",
        "def provider():\n    return propagate\npatch(provider())",
        "def patcher(api=propagate):\n    api.extract = archive.extract\npatcher()",
        "alias, unused = propagate, 0\nalias.extract = archive.extract",
        "patch(item for item in (propagate,))",
        "class Holder:\n    api = propagate\nHolder.api.extract = archive.extract",
        "def patcher():\n    global propagate\n    propagate = archive\npatcher()",
    ],
)
def test_imported_api_escape_through_aggregate_or_return_remains_unknown(
    tmp_path, mutation
):
    source = "from opentelemetry import propagate\n" + mutation
    source += "\npropagate.extract(member)\n"
    findings = []
    checker = _PathFlowChecker(str(tmp_path / "application.py"), findings)
    checker.visit(ast.parse(source))
    archive_rows = []
    for finding in findings:
        if finding["rule_id"] == "SKY-D326":
            archive_rows.append(finding)
    assert len(archive_rows) == 1
    assert (
        archive_rows[0]["metadata"]["receiver_resolution"]["archive_operation"]
        == "unresolved"
    )


def test_nonlocal_rebinding_does_not_reuse_outer_import_alias(tmp_path):
    source = (
        "from opentelemetry import propagate\n"
        "def unpack(member):\n"
        "    context_api = propagate\n"
        "    def patcher():\n"
        "        nonlocal context_api\n"
        "        context_api = archive\n"
        "    patcher()\n"
        "    context_api.extract(member)\n"
    )
    findings = []
    checker = _PathFlowChecker(str(tmp_path / "application.py"), findings)
    checker.visit(ast.parse(source))
    rules = set()
    for finding in findings:
        rules.add(finding["rule_id"])
    assert "SKY-D326" in rules


@pytest.mark.parametrize(
    "setup",
    [
        "sys.modules['opentelemetry'] = provider",
        "sys.modules.update({'opentelemetry': provider})",
        "sys.meta_path.insert(0, provider)",
    ],
)
def test_replaced_import_provider_is_not_documented_external_api(tmp_path, setup):
    source = (
        "import sys\n" + setup + "\n"
        "from opentelemetry import propagate\n"
        "propagate.extract(member)\n"
    )
    findings = []
    checker = _PathFlowChecker(str(tmp_path / "application.py"), findings)
    checker.visit(ast.parse(source))
    rules = set()
    for finding in findings:
        rules.add(finding["rule_id"])
    assert "SKY-D326" in rules
