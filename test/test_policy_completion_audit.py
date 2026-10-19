"""Missing policies need actual missing files/tools, not spelling guesses."""

import ast
import json

import pytest

from test.fixture_paths import write_fixture

from skylos.rules.quality.policy import analyze_repo_policy
from skylos.rules.quality.practices import FrameworkPracticeRule


def _policies(root, changed=None):
    write_fixture(root, "app.py", "def app(): return True\n", overwrite=True)
    return {row["rule_id"] for row in analyze_repo_policy(root, changed_files=changed)}


@pytest.mark.parametrize(
    "source", ["[mypy]\n", "[mypy]\nstrict=True\n", "[mypy]\nfiles=app.py\n"]
)
def test_native_hidden_mypy_config_is_a_real_policy(tmp_path, source):
    (tmp_path / ".mypy.ini").write_text(source)
    assert "SKY-R101" not in _policies(tmp_path)


@pytest.mark.parametrize(
    "source",
    ["# [mypy] not configured\n", "[metadata]\nname=mypy\n", "not an ini file"],
)
def test_mypy_lookalike_content_does_not_hide_missing_policy(tmp_path, source):
    (tmp_path / ".mypy.ini").write_text(source)
    assert "SKY-R101" in _policies(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        "[tool.pylint.main]\njobs=2\n",
        '[tool.pylint."messages control"]\ndisable="fixme"\n',
        "[tool.pylint.format]\nmax-line-length=100\n",
    ],
)
def test_native_pylint_toml_is_a_real_lint_policy(tmp_path, source):
    (tmp_path / "pylintrc.toml").write_text(source)
    assert "SKY-R102" not in _policies(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        "# tool.pylint.main\n",
        '[metadata]\nname="pylint"\n',
        "[tool.black]\nline-length=80\n",
    ],
)
def test_pylint_toml_lookalikes_keep_missing_lint_policy(tmp_path, source):
    (tmp_path / "pylintrc.toml").write_text(source)
    assert "SKY-R102" in _policies(tmp_path)


@pytest.mark.parametrize("name", [".mypy.ini", "setup.cfg", "pylintrc.toml"])
def test_native_policy_file_changes_trigger_repo_policy_review(tmp_path, name):
    assert {"SKY-R101", "SKY-R102"} <= _policies(tmp_path, {name})


def _typescript(root, script, *, package=None, config=None):
    write_fixture(root, "tsconfig.json", "{}", overwrite=True)
    write_fixture(root, "package.json",
        json.dumps(package if package is not None else {"scripts": {"check": script}}),
        overwrite=True,
    )
    if config is not None:
        write_fixture(root, "next.config.js", config, overwrite=True)
    return {row["rule_id"] for row in analyze_repo_policy(root)}


@pytest.mark.parametrize(
    "script",
    [
        "tsc --noEmit",
        "vue-tsc --noEmit",
        "npx tsc --noEmit",
        "npm exec -- tsc -b",
        "yarn tsc --noEmit",
        "pnpm exec tsc --noEmit",
        "cross-env NODE_ENV=test tsc --noEmit",
        "sh -c 'tsc --noEmit'",
        "echo preparing\ntsc --noEmit",
        "node_modules/.bin/tsc --noEmit",
        '".\\node_modules\\.bin\\tsc.cmd" --noEmit',
        "tsc --noCheck false --noEmit",
    ],
)
def test_actual_typescript_executable_is_recognized(tmp_path, script):
    assert "SKY-R105" not in _typescript(tmp_path, script)


@pytest.mark.parametrize(
    "script",
    [
        "echo tsc --noEmit",
        "printf 'tsc --noEmit'",
        "node scripts/testscript.js",
        "tsc --version",
        "tsc --showConfig",
        "tsc --noCheck",
    ],
)
def test_tool_names_as_data_or_nonchecking_commands_are_not_policy(tmp_path, script):
    assert "SKY-R105" in _typescript(tmp_path, script)


@pytest.mark.parametrize("package", [[], "not a manifest", 42])
def test_nonobject_package_manifest_does_not_crash_or_invent_a_typecheck(
    tmp_path, package
):
    assert "SKY-R105" in _typescript(tmp_path, None, package=package)


@pytest.mark.parametrize(
    "script",
    ["echo next build", "printf 'next build'", "node -e 'console.log(\"next build\")'"],
)
def test_next_build_as_data_is_not_a_typecheck(tmp_path, script):
    assert "SKY-R105" in _typescript(
        tmp_path,
        None,
        package={"scripts": {"build": script}, "dependencies": {"next": "^16"}},
    )


@pytest.mark.parametrize(
    "comment",
    [
        "// ignoreBuildErrors: true\n",
        "/* ignoreBuildErrors: true */\n",
        "// typescript: { ignoreBuildErrors: true }\n",
    ],
)
def test_next_typecheck_is_not_disabled_by_a_comment(tmp_path, comment):
    package = {"scripts": {"build": "next build"}, "dependencies": {"next": "^16"}}
    assert "SKY-R105" not in _typescript(
        tmp_path,
        None,
        package=package,
        config=comment + "export default { reactStrictMode: true };\n",
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "const pattern = /[//]/;",
        "const text = 'https://example.test';",
        "const text = `https://example.test`;",
    ],
)
def test_js_comment_syntax_inside_literals_does_not_hide_disabled_typechecking(
    tmp_path, prefix
):
    package = {"scripts": {"build": "next build"}, "dependencies": {"next": "^16"}}
    assert "SKY-R105" in _typescript(
        tmp_path,
        None,
        package=package,
        config=prefix + " export default { typescript: { ignoreBuildErrors: true } };",
    )


@pytest.mark.parametrize("name", ["tsconfig.json", "next.config.js", "next.config.ts"])
def test_typescript_policy_inputs_trigger_diff_review(tmp_path, name):
    _typescript(tmp_path, "next dev")
    ids = {
        row["rule_id"] for row in analyze_repo_policy(tmp_path, changed_files={name})
    }
    assert "SKY-R105" in ids


@pytest.mark.parametrize(
    "filename", [".pre-commit-config.yaml", ".pre-commit-config.yml"]
)
def test_precommit_directory_is_not_a_policy_file(tmp_path, filename):
    (tmp_path / filename).mkdir()
    assert "SKY-R104" in _policies(tmp_path)


@pytest.mark.parametrize(
    "source,present",
    [
        ("[tool.skylos.gate]\nmax_quality=2\n", True),
        ("[tool.skylos]\n# [tool.skylos.gate]\n", False),
        ('[tool.skylos]\ngate="disabled"\n', False),
    ],
)
def test_skylos_gate_policy_requires_an_actual_table(tmp_path, source, present):
    (tmp_path / "pyproject.toml").write_text(source)
    assert ("SKY-R103" not in _policies(tmp_path)) is present


@pytest.mark.parametrize(
    "name,present",
    [
        (".pre-commit-config.yaml", True),
        (".pre-commit-config.yml", True),
        ("pre-commit-config.yaml", False),
    ],
)
def test_precommit_policy_file_presence_is_explicit(tmp_path, name, present):
    (tmp_path / name).write_text("repos: []\n")
    assert ("SKY-R104" not in _policies(tmp_path)) is present


@pytest.mark.parametrize(
    "kind,expected", [("file", True), ("directory", False), ("missing", False)]
)
def test_tsconfig_requires_a_file_before_typecheck_policy_applies(
    tmp_path, kind, expected
):
    (tmp_path / "package.json").write_text('{"scripts":{}}')
    path = tmp_path / "tsconfig.json"
    if kind == "file":
        path.write_text("{}")
    elif kind == "directory":
        path.mkdir()
    assert (
        "SKY-R105" in {row["rule_id"] for row in analyze_repo_policy(tmp_path)}
    ) is expected


def _framework(source, root=None):
    context = {
        "filename": str(root / "app.py") if root else "app.py",
        "project_root": str(root) if root else None,
    }
    return FrameworkPracticeRule().visit_node(ast.parse(source), context) or []


@pytest.mark.parametrize(
    "prefix,receiver",
    [
        ("from fastapi import FastAPI\napp=FastAPI()", "app"),
        ("from fastapi import APIRouter as Routes\nendpoints=Routes()", "endpoints"),
        ("import fastapi as framework\nserver=framework.FastAPI()", "server"),
    ],
)
def test_proven_fastapi_constructor_preserves_missing_contract_finding(
    prefix, receiver
):
    rows = _framework(prefix + f"\n@{receiver}.get('/items')\ndef items(): return []\n")
    assert [row["rule_id"] for row in rows] == ["SKY-F101"]


@pytest.mark.parametrize(
    "prefix",
    [
        "from flask import Flask\napp=Flask(__name__)",
        "class Collector:\n def get(self, path): return register\napp=Collector()",
        "app=unknown_factory()",
    ],
)
def test_other_or_unproved_receiver_is_not_claimed_to_be_fastapi(prefix):
    assert _framework(prefix + "\n@app.get('/items')\ndef items(): return []\n") == []


@pytest.mark.parametrize(
    "mutation", ["app=custom", "app.get=replacement", "modify(app)"]
)
def test_changed_fastapi_binding_is_not_proven_framework_identity(mutation):
    source = (
        "from fastapi import FastAPI\napp=FastAPI()\n"
        + mutation
        + "\n@app.get('/items')\ndef items(): return []\n"
    )
    assert _framework(source) == []


def test_genuine_router_included_on_genuine_app_keeps_missing_contract(tmp_path):
    source = "from fastapi import FastAPI,APIRouter\napp=FastAPI()\nrouter=APIRouter()\n@router.get('/items')\ndef items(): return []\napp.include_router(router)\n"
    assert [row["rule_id"] for row in _framework(source)] == ["SKY-F101"]


def test_local_fastapi_named_provider_does_not_authorize_framework_claim(tmp_path):
    (tmp_path / "fastapi.py").write_text("FastAPI=custom\n")
    source = "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/items')\ndef items(): return []\n"
    assert _framework(source, tmp_path) == []


def test_explicit_response_contract_and_actual_state_change_security_behavior_remain():
    source = "from fastapi import FastAPI\napp=FastAPI()\n@app.put('/items', response_model=dict)\ndef items():\n repository.save(item)\n return {}\n"
    assert [row["rule_id"] for row in _framework(source)] == ["SKY-F102"]
