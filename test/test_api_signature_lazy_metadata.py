"""Unrelated imports and prose do not require installed API inspection."""

import pytest

from skylos.rules.ai_defect import api_signature_hallucination as api


@pytest.mark.parametrize(
    "source",
    [
        'import json\nmessage = "requests.get documentation"\n',
        'import requests_other\nmessage = "requests.get documentation"\n',
        'from .requests import get\nget("url")\n',
        "value = 1\n",
    ],
)
def test_no_installed_metadata_without_an_allowed_import(tmp_path, monkeypatch, source):
    path = tmp_path / "app.py"
    path.write_text(source)
    lookups = []
    monkeypatch.setattr(
        api, "_unverifiable_roots", lambda *args: lookups.append(args) or {}
    )
    result = api.scan_python_api_signature_hallucinations(
        tmp_path, [path], surface_loader=lambda *_: pytest.fail("unexpected inspection")
    )
    assert result == []
    assert result.check["outcome"] == "pass"
    assert result.check["references"] == 0
    assert result.check["applicable_files"] == 1
    assert lookups == []


@pytest.mark.parametrize("name", ["requests", "ｒｅｑｕｅｓｔｓ"])
def test_real_import_after_unrelated_file_keeps_bad_keyword_finding(
    tmp_path, monkeypatch, name
):
    prose = tmp_path / "prose.py"
    prose.write_text('message = "requests.get documentation"\n')
    app = tmp_path / "app.py"
    app.write_text(f'import {name} as req\nreq.get("url", imaginary=True)\n')
    lookups = []
    inspected = []
    monkeypatch.setattr(
        api, "_unverifiable_roots", lambda *args: lookups.append(args) or {}
    )

    def surface(root, module):
        inspected.append(module)
        return {
            "members": {
                "get": {
                    "kind": "function",
                    "parameters": [{"name": "url", "kind": "POSITIONAL_OR_KEYWORD"}],
                }
            }
        }

    result = api.scan_python_api_signature_hallucinations(
        tmp_path, [prose, app], surface_loader=surface
    )
    assert [(f["rule_id"], f["line"]) for f in result] == [("SKY-D224", 2)]
    assert "imaginary" in result[0]["message"]
    assert result.check["outcome"] == "fail"
    assert result.check["applicable_files"] == 2
    assert inspected == ["requests"]
    assert len(lookups) == 1
