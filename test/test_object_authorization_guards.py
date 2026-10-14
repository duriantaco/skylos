import ast
import json
import sys
from textwrap import dedent, indent

import pytest

from skylos.rules.quality.practices import FrameworkPracticeRule


PRELUDE = """\
from types import SimpleNamespace
import fastapi
from fastapi import Depends, FastAPI, HTTPException, Request
app = FastAPI()
documents = {1: SimpleNamespace(id=1, owner_id=7), 2: SimpleNamespace(id=2, owner_id=8)}
def get_current_user():
    return SimpleNamespace(id=7, tenant_id=70)
def parse_input(value):
    return int(value)
def noop():
    return None
"""


def _source(body):
    return (
        PRELUDE
        + '\n@app.get("/documents/{document_id}/preview/{preview_id}", response_model=None)\n'
        + "def endpoint(document_id: int, preview_id: int, request: Request, current_user=Depends(get_current_user)) -> dict:\n"
        + indent(dedent(body).strip(), "    ")
        + "\n"
    )


CHECK = """\
if document.owner_id != current_user.id:
    raise HTTPException(status_code=403)
"""

CASES = [
    pytest.param(
        "document = documents[document_id]\nactor = current_user\nalias = actor\n"
        'alias.id = int(request.query_params["actor_id"])\n'
        + CHECK
        + "return document",
        True,
        id="principal-alias-mutation",
    ),
    pytest.param(
        "document = documents[document_id]\nprincipal_id = current_user.id\n"
        'actor = current_user\nactor.id = int(request.query_params["actor_id"])\n'
        "if document.owner_id != principal_id:\n    raise HTTPException(status_code=403)\nreturn document",
        False,
        id="scalar-snapshot-survives-mutation",
    ),
    pytest.param(
        'document = documents[document_id]\nactor = current_user\nactor.display_name = "changed"\n'
        + CHECK
        + "return document",
        False,
        id="unrelated-principal-field",
    ),
    pytest.param(
        "document = documents[document_id]\nactor = current_user\nactor = request\nactor.id = 8\n"
        + CHECK
        + "return document",
        False,
        id="rebound-alias-does-not-mutate-user",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "document = documents[preview_id]\nreturn document",
        True,
        id="rebound-object",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "def render():\n    return document\ndocument = documents[preview_id]\nreturn render()",
        True,
        id="closure-late-binding",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "render = lambda: document\ndocument = documents[preview_id]\nreturn render()",
        True,
        id="lambda-late-binding",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "def render(value=document):\n    return value\ndocument = documents[preview_id]\nreturn render()",
        False,
        id="closure-default-snapshot",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "def render(value=document):\n    return value\ndocument = documents[preview_id]\nreturn render(document)",
        True,
        id="closure-default-overridden",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "def render():\n    return document\nsaved = render()\ndocument = documents[preview_id]\nreturn saved",
        False,
        id="early-closure-result-snapshot",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "document = documents[preview_id]\n"
        + CHECK
        + "return document",
        False,
        id="rebound-object-rechecked",
    ),
    pytest.param(
        "document = documents[document_id]\nif document.owner_id == current_user.id:\n    return document\nreturn None",
        False,
        id="positive-owner-branch",
    ),
    pytest.param(
        "document = documents[document_id]\nif document.owner_id == current_user.id:\n    return document\nreturn document",
        True,
        id="positive-owner-fallthrough",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n"
        + indent(CHECK, "    ")
        + "except HTTPException:\n    pass\nreturn document",
        True,
        id="caught-denial",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n"
        + indent(CHECK + "return document\n", "    ")
        + 'finally:\n    audit = "done"',
        False,
        id="finally-preserves-denial",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n"
        + indent(CHECK, "    ")
        + "finally:\n    return document",
        True,
        id="finally-overrides-denial",
    ),
    pytest.param(
        "document = documents[document_id]\nif document.tenant_id != current_user.id:\n"
        "    raise HTTPException(status_code=403)\nreturn document",
        True,
        id="user-id-is-not-tenant-id",
    ),
    pytest.param(
        "document = documents[document_id]\nif document.tenant_id != current_user.tenant_id:\n"
        "    raise HTTPException(status_code=403)\nreturn document",
        False,
        id="matching-tenant-identity",
    ),
    pytest.param(
        "document = documents[document_id]\nactor = current_user\nactor.id = current_user.id\n"
        + CHECK
        + "return document",
        False,
        id="unchanged-principal-id",
    ),
    pytest.param(
        "document = documents[document_id]\noriginal_id = current_user.id\ncurrent_user.id = preview_id\n"
        "current_user.id = original_id\n" + CHECK + "return document",
        False,
        id="restored-principal-id",
    ),
    pytest.param(
        "document = documents[document_id]\nsetattr(current_user, 'id', preview_id)\n"
        + CHECK
        + "return document",
        True,
        id="setattr-identity-mutation",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n"
        + indent(CHECK, "    ")
        + "except (HTTPException, ValueError):\n    pass\nreturn document",
        True,
        id="tuple-caught-denial",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n    parse_input(request.query_params['value'])\n"
        + indent(CHECK, "    ")
        + "except ValueError:\n    pass\nreturn document",
        True,
        id="exception-before-owner-check",
    ),
    pytest.param(
        "def selected():\n    return documents[preview_id]\ndocument = selected()\n"
        + CHECK
        + "preview_id = document_id\nreturn selected()",
        True,
        id="repeated-lookup-with-rebound-selector",
    ),
    pytest.param(
        "def selected():\n    return documents[document_id]\ndocument = selected()\n"
        + CHECK
        + "return selected()",
        False,
        id="stable-dictionary-lookup",
    ),
    pytest.param(
        "def selected():\n    return documents[document_id]\ndocument = selected()\n"
        + CHECK
        + "noop = int(7)\nreturn selected()",
        False,
        id="pure-literal-call-preserves-dictionary",
    ),
    pytest.param(
        "document = documents[document_id]\ndef parse(document):\n    return int('bad')\n"
        "try:\n    parse(None)\n"
        + indent(CHECK, "    ")
        + "except ValueError:\n    pass\nreturn document",
        True,
        id="helper-exception-keeps-caller-object",
    ),
    pytest.param(
        "if documents[document_id].owner_id != current_user.id:\n"
        "    raise HTTPException(status_code=403)\nreturn documents[document_id]",
        False,
        id="direct-stable-dictionary-guard",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n    if int('bad'):\n        pass\n"
        + indent(CHECK, "    ")
        + "except ValueError:\n    pass\nreturn document",
        True,
        id="condition-exception-before-check",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n    noop()\n"
        + indent(CHECK, "    ")
        + "except ValueError:\n    pass\nreturn document",
        False,
        id="total-literal-helper-preserves-guard",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "try:\n    raise KeyboardInterrupt\nexcept Exception:\n    document = documents[preview_id]\n"
        "return document",
        False,
        id="exception-does-not-catch-keyboard-interrupt",
    ),
    pytest.param(
        "document = documents[document_id]\nactor = current_user if current_user is not None else None\n"
        "actor.id = preview_id\n" + CHECK + "return document",
        True,
        id="conditional-principal-alias",
    ),
    pytest.param(
        "document = documents[document_id]\nprincipal_id = current_user.id if current_user is not None else None\n"
        "actor = current_user\nactor.id = preview_id\n"
        "if document.owner_id != principal_id:\n    raise HTTPException(status_code=403)\nreturn document",
        False,
        id="conditional-scalar-snapshot",
    ),
    pytest.param(
        "document = documents[document_id]\ntry:\n"
        "    if document.owner_id != current_user.id:\n        raise fastapi.HTTPException(status_code=403)\n"
        "except fastapi.HTTPException:\n    pass\nreturn document",
        True,
        id="qualified-caught-denial",
    ),
    pytest.param(
        "def selected():\n    return documents.get(document_id, None)\ndocument = selected()\n"
        + CHECK
        + "return selected()",
        False,
        id="literal-dictionary-get-none-default",
    ),
    pytest.param(
        "document = documents[document_id]\n"
        + CHECK
        + "if False:\n    document = documents[preview_id]\nreturn document",
        False,
        id="unreachable-object-replacement",
    ),
    pytest.param(
        "document = documents[document_id]\nprincipal_id = current_user.id if preview_id == 1 else preview_id\n"
        "if document.owner_id != principal_id:\n    raise HTTPException(status_code=403)\nreturn document",
        True,
        id="caller-identity-conditional-branch",
    ),
    pytest.param(
        "first = documents.get(document_id, documents[preview_id])\n"
        "if first.owner_id != current_user.id:\n    raise HTTPException(status_code=403)\n"
        "return documents.get(document_id, documents[int(request.query_params['other_id'])])",
        True,
        id="different-mutable-dictionary-default",
    ),
]


@pytest.mark.parametrize("body,expected", CASES)
def test_defeated_ownership_guards(body, expected):
    findings = (
        FrameworkPracticeRule().visit_node(
            ast.parse(_source(body)), {"filename": "app.py"}
        )
        or []
    )
    actual = [f for f in findings if f["rule_id"] == "SKY-F102"]
    assert bool(actual) == expected
    if expected:
        assert [(f["name"], f["severity"], f["value"]) for f in actual] == [
            ("endpoint", "HIGH", "defeated_owner_guard")
        ]


@pytest.mark.parametrize("body,expected", [CASES[0].values, CASES[7].values])
def test_ownership_finding_reaches_cli_json(
    tmp_path, monkeypatch, capsys, body, expected
):
    from skylos.cli import main

    app = tmp_path / "app.py"
    app.write_text(_source(body))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--quality",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
        ],
    )
    main()
    report = json.loads(capsys.readouterr().out)
    assert report["analysis_summary"]["total_files"] == 1
    assert not report.get("analysis_errors")
    findings = [f for f in report.get("quality", []) if f["rule_id"] == "SKY-F102"]
    assert bool(findings) == expected
    if expected:
        assert findings[0]["file"] == str(app)
        assert findings[0]["name"] == "endpoint"


@pytest.mark.parametrize(
    "first_cache,second_cache,expected",
    [
        (True, True, True),
        (True, False, False),
        (False, True, True),
    ],
)
def test_cached_dependency_parameters_share_principal(
    first_cache, second_cache, expected
):
    source = (
        PRELUDE
        + '\n@app.get("/documents/{document_id}", response_model=None)\n'
        + f"def endpoint(document_id: int, actor_id: int, current_user=Depends(get_current_user, use_cache={first_cache}), "
        + f"other_user=Depends(get_current_user, use_cache={second_cache})) -> dict:\n"
        + "    document = documents[document_id]\n    current_user.id = actor_id\n"
        + "    if document.owner_id != other_user.id:\n        raise HTTPException(status_code=403)\n"
        + "    return document\n"
    )
    findings = (
        FrameworkPracticeRule().visit_node(ast.parse(source), {"filename": "app.py"})
        or []
    )
    assert any(f["rule_id"] == "SKY-F102" for f in findings) == expected


def test_query_selected_replacement_needs_its_own_check():
    source = _source(
        "document = documents[document_id]\n"
        + CHECK
        + "document = documents[preview_id]\nreturn document"
    )
    source = source.replace("/preview/{preview_id}", "")
    findings = (
        FrameworkPracticeRule().visit_node(ast.parse(source), {"filename": "app.py"})
        or []
    )
    assert any(f["rule_id"] == "SKY-F102" for f in findings)
