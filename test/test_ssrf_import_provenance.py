"""Static regression checks for mutable urllib.request import bindings."""

import pytest

from skylos.rules.danger.danger import scan_ctx


_SOURCE = (
    "import urllib.request as u\n"
    "from flask import request\n"
    "Original = u.Request\n"
    "def EvilRequest(url, data=None):\n"
    "    return Original(data)\n"
)
_SINK = (
    "def fetch():\n"
    "    return u.urlopen(u.Request(\n"
    "        'https://safe.example/', data=request.args['url']))\n"
)


def _ssrf_findings(tmp_path, mutation):
    path = tmp_path / "module_mutation.py"
    path.write_text(_SOURCE + mutation + "\n" + _SINK, encoding="utf-8")
    return [
        finding
        for finding in scan_ctx(tmp_path, [path])
        if finding["rule_id"] == "SKY-D216"
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "u.__dict__.update({'Request': EvilRequest})",
        "u.__dict__.__setitem__('Request', EvilRequest)",
        "u.__dict__['Request'] = EvilRequest",
        "symbols = u.__dict__\nsymbols.update({'Request': EvilRequest})",
        "vars(u).update({'Request': EvilRequest})",
    ],
)
def test_mutated_module_dict_does_not_hide_request_body_source(tmp_path, mutation):
    findings = _ssrf_findings(tmp_path, mutation)
    assert len(findings) == 1
    assert findings[0]["metadata"]["untrusted_source"] == "request data `request.args`"


def test_unmodified_urllib_request_keeps_post_body_separate_from_url(tmp_path):
    assert _ssrf_findings(tmp_path, "") == []


@pytest.mark.parametrize(
    "mutation",
    [
        "vars(urllib.request).update({'Request': EvilRequest})",
        "setattr(urllib.request, 'Request', EvilRequest)",
    ],
)
def test_nested_module_mutation_does_not_hide_request_body_source(tmp_path, mutation):
    code = (
        "import urllib.request\n"
        "from flask import request\n"
        "Original = urllib.request.Request\n"
        "def EvilRequest(url, data=None):\n"
        "    return Original(data)\n"
        f"{mutation}\n"
        "def fetch():\n"
        "    return urllib.request.urlopen(urllib.request.Request(\n"
        "        'https://safe.example/', data=request.args['url']))\n"
    )
    path = tmp_path / "nested_module_mutation.py"
    path.write_text(code, encoding="utf-8")
    findings = [
        finding
        for finding in scan_ctx(tmp_path, [path])
        if finding["rule_id"] == "SKY-D216"
    ]
    assert len(findings) == 1
    assert findings[0]["metadata"]["untrusted_source"] == "request data `request.args`"
