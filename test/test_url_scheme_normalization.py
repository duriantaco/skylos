"""Normalize only a proven native parser's scheme, retaining audit boundaries."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger import scan_ctx


CALLER_NOTE = "Caller-side URL scheme validation is not analysed."
BASE_MESSAGE = (
    "Audit URL schemes: urllib can open local files and other non-HTTP resources; "
    "validate dynamic URLs against the intended schemes."
)
IMPORTS = (
    "from urllib.request import Request, urlopen\nfrom urllib.parse import urlsplit\n"
)


@pytest.fixture(autouse=True)
def _single_worker(monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")


def _function(body, *, signature="url, other", imports=IMPORTS):
    return (
        imports
        + f"\ndef fetch({signature}):\n"
        + textwrap.indent(textwrap.dedent(body).strip() + "\n", "    ")
    )


def _scan(tmp_path, source):
    path = tmp_path / "download.py"
    path.write_text(source)
    raw = scan_ctx(tmp_path, [path])
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
        )
    )
    assert not report.get("analysis_errors")
    return {"raw": raw, "report": report}


def _audits(result):
    raw = [row for row in result["raw"] if row["rule_id"] == "SKY-D218"]
    listed = [
        row
        for row in result["report"].get("danger", [])
        if row["rule_id"] == "SKY-D218"
    ]
    assert len(raw) == len(listed)
    for row in listed:
        assert row["severity"] == "MEDIUM"
        assert row["finding_type"] == "review"
        assert row["listing"]["listed"] is True
        assert row["listing"]["reason"] == "finding"
    return raw


@pytest.mark.parametrize("parser", ["urlparse", "urlsplit"])
@pytest.mark.parametrize(
    "shape", ["inline", "parsed_alias", "request", "request_variable"]
)
def test_native_normalized_scheme_guard_is_quiet(tmp_path, parser, shape):
    imports = IMPORTS.replace("import urlsplit", f"import {parser} as parse")
    setup = "parsed = parse(url)\n" if shape == "parsed_alias" else ""
    scheme = "parsed.scheme.lower()" if setup else "parse(url).scheme.lower()"
    sink = "urlopen(Request(url))" if shape == "request" else "urlopen(url)"
    if shape == "request_variable":
        setup += "request = Request(url)\n"
        sink = "urlopen(request)"
    body = (
        setup
        + f"if {scheme} not in ('http', 'https'):\n    raise ValueError()\nreturn {sink}"
    )
    assert not _audits(_scan(tmp_path, _function(body, imports=imports)))


@pytest.mark.parametrize(
    "body",
    [
        "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
        "if urlsplit(url).scheme.lower() in {'http', 'https'}:\n    return urlopen(url)\nreturn None",
        "if other and urlsplit(url).scheme.lower() == 'https':\n    return urlopen(url)\nreturn None",
    ],
)
def test_normalized_guard_retains_existing_continuing_path_proof(tmp_path, body):
    assert not _audits(_scan(tmp_path, _function(body)))


@pytest.mark.parametrize(
    "body",
    [
        "if urlsplit(other).scheme.lower() not in ('http', 'https'):\n    raise ValueError()\nreturn urlopen(url)",
        "if urlsplit(url).scheme.lower() not in ('http', 'https'):\n    raise ValueError()\nurl = other\nreturn urlopen(url)",
        "parsed = urlsplit(url)\nurl = other\nif parsed.scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
        "parsed = urlsplit(url)\nparsed = other\nif parsed.scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
        "if urlsplit(url).scheme.lower() not in ('http', 'file'):\n    raise ValueError()\nreturn urlopen(url)",
        "if other.scheme.lower() not in ('http', 'https'):\n    raise ValueError()\nreturn urlopen(url)",
        "try:\n    if urlsplit(url).scheme.lower() != 'https':\n        raise ValueError()\nexcept ValueError:\n    pass\nreturn urlopen(url)",
        "if urlsplit(url).scheme.lower() != 'https':\n    pass\nreturn urlopen(url)",
        "if urlsplit(url).scheme.lower() in ('http', 'https') or other:\n    return urlopen(url)\nreturn None",
        "request = Request(url)\nif urlsplit(url).scheme.lower() != 'https':\n    return None\nrequest.full_url = other\nreturn urlopen(request)",
    ],
)
def test_wrong_or_ineffective_normalized_guards_keep_audit(tmp_path, body):
    findings = _audits(_scan(tmp_path, _function(body)))
    assert len(findings) == 1
    assert findings[0]["symbol"] == "fetch"


@pytest.mark.parametrize(
    "expression",
    [
        "urlsplit(url).scheme.lower(1)",
        "urlsplit(url).scheme.lower(other=True)",
        "urlsplit(url).scheme.lower(*other)",
        "urlsplit(url).scheme.lower(**other)",
        "urlsplit(url).scheme.lower",
        "urlsplit(url).scheme.lower().lower()",
        "urlsplit(url).scheme.casefold()",
        "urlsplit(url, 'https').scheme.lower()",
        "urlsplit(url=url).scheme.lower()",
    ],
)
def test_unsupported_calls_cannot_supply_normalization_proof(tmp_path, expression):
    body = f"if {expression} not in ('http', 'https'):\n    raise ValueError()\nreturn urlopen(url)"
    assert len(_audits(_scan(tmp_path, _function(body)))) == 1


@pytest.mark.parametrize(
    "source",
    [
        _function(
            "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
            signature="url, urlsplit",
        ),
        _function(
            "urlsplit = other\nif urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)"
        ),
        "import urllib.parse as p\nfrom types import SimpleNamespace\np.urlsplit = lambda value: SimpleNamespace(scheme='https')\n"
        + _function(
            "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)"
        ),
        "from unittest.mock import patch\n"
        + IMPORTS
        + "@patch('urllib.parse.urlsplit')\ndef fetch(url):\n    if urlsplit(url).scheme.lower() != 'https':\n        return None\n    return urlopen(url)\n",
    ],
)
def test_normalization_keeps_parser_identity_and_mutation_checks(tmp_path, source):
    assert len(_audits(_scan(tmp_path, source))) == 1


@pytest.mark.parametrize("suffix", ["", ".lower()"])
def test_scheme_proof_does_not_remove_attacker_proven_ssrf(tmp_path, suffix):
    source = _function(
        f"url = input()\nif urlsplit(url).scheme{suffix} != 'https':\n    return None\nreturn urlopen(url)",
        signature="",
    )
    result = _scan(tmp_path, source)
    assert not _audits(result)
    assert len([row for row in result["raw"] if row["rule_id"] == "SKY-D216"]) == 1
    assert (
        len(
            [
                row
                for row in result["report"].get("danger", [])
                if row["rule_id"] == "SKY-D216"
            ]
        )
        == 1
    )


def test_guarded_callers_keep_helper_audit_and_existing_evidence(tmp_path):
    source = (
        IMPORTS
        + "def _open_checked(url):\n    return urlopen(url)\ndef guarded(url):\n    if urlsplit(url).scheme.lower() != 'https':\n        return None\n    return _open_checked(url)\n"
    )
    findings = _audits(_scan(tmp_path, source))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["symbol"] == "_open_checked"
    assert finding["message"] == BASE_MESSAGE + " " + CALLER_NOTE
    assert finding["metadata"]["security_evidence"] == {
        "evidence_kind": "url_scheme_audit",
        "source": "dynamic URL; attacker control is not established",
        "sink": "urlopen",
        "guards_missing": ["proven HTTP/HTTPS scheme restriction"],
        "assumption": "The URL can originate outside the application's trust boundary.",
    }


def test_module_audit_does_not_claim_caller_analysis(tmp_path):
    findings = _audits(_scan(tmp_path, IMPORTS + "url = input()\nurlopen(url)\n"))
    assert len(findings) == 1
    assert findings[0]["message"] == BASE_MESSAGE


def test_wildcard_import_cannot_hide_native_result_type(tmp_path):
    source = (
        "from sys import *\n"
        "from types import SimpleNamespace\n"
        "from urllib.parse import urlsplit\n"
        "from urllib.request import urlopen\n"
        "result_type = modules['urllib.parse'].SplitResult\n"
        "result_type.scheme = property(lambda self: SimpleNamespace(lower=lambda: 'https'))\n"
        "def fetch(url):\n"
        "    if urlsplit(url).scheme.lower() != 'https':\n"
        "        raise ValueError()\n"
        "    return urlopen(url)\n"
    )
    assert len(_audits(_scan(tmp_path, source))) == 1


FORGED = "class ForgedScheme:\n    def lower(self):\n        return 'https'\n"


@pytest.mark.parametrize(
    "parser,setup",
    [
        (
            "urlsplit",
            "from urllib.parse import SplitResult\nSplitResult.scheme = property(lambda self: ForgedScheme())\n",
        ),
        (
            "urlparse",
            "from urllib.parse import ParseResult\nParseResult.scheme = property(lambda self: ForgedScheme())\n",
        ),
        (
            "urlsplit",
            "from urllib import parse as p\nResult = p.SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        ),
        (
            "urlsplit",
            "import urllib.parse as p\np._SplitResultBase.scheme = property(lambda self: ForgedScheme())\n",
        ),
        (
            "urlsplit",
            "Result = type(urlsplit('https://example.invalid/'))\nResult.scheme = property(lambda self: ForgedScheme())\n",
        ),
        (
            "urlsplit",
            "parsed = urlsplit('https://example.invalid/')\nResult = parsed.__class__\nResult.scheme = property(lambda self: ForgedScheme())\n",
        ),
        (
            "urlsplit",
            "from urllib.parse import SplitResult\nSplitResult.__getattribute__ = unknown\n",
        ),
        (
            "urlsplit",
            "from urllib.parse import SplitResult\nSplitResult.__new__ = unknown\n",
        ),
        ("urlsplit", "import urllib.parse as p\nunknown(p)\n"),
        ("urlsplit", "unknown(urlsplit)\n"),
        ("urlsplit", "import urllib.parse as p\nalias = p\nunknown(alias)\n"),
        (
            "urlsplit",
            "import urllib.parse as p\np.SplitResult.scheme = property(lambda self: ForgedScheme())\nimport foreign as p\n",
        ),
        (
            "urlsplit",
            "import urllib.parse as p\np.SplitResult.scheme = property(lambda self: ForgedScheme())\ndef unrelated():\n    import foreign as p\n",
        ),
        (
            "urlsplit",
            "import urllib.parse as p\ndef change(module):\n    module.SplitResult.scheme = property(lambda self: ForgedScheme())\nchange(p)\ndef unrelated():\n    import foreign as p\n",
        ),
    ],
)
def test_native_result_family_exposure_keeps_normalization_audit(
    tmp_path, parser, setup
):
    imports = IMPORTS.replace("import urlsplit", f"import {parser}")
    source = (
        imports
        + FORGED
        + setup
        + f"def fetch(url):\n    if {parser}(url).scheme.lower() != 'https':\n        return None\n    return urlopen(url)\n"
    )
    assert len(_audits(_scan(tmp_path, source))) == 1


def test_parsed_result_escape_does_not_prove_builtin_lower(tmp_path):
    body = "parsed = urlsplit(url)\nunknown(parsed)\nif parsed.scheme.lower() != 'https':\n    return None\nreturn urlopen(url)"
    assert len(_audits(_scan(tmp_path, _function(body)))) == 1


def test_native_result_refusal_does_not_change_direct_scheme_policy(tmp_path):
    source = (
        IMPORTS
        + FORGED
        + "from urllib.parse import SplitResult\nSplitResult.scheme = property(lambda self: ForgedScheme())\n"
        + _function(
            "if urlsplit(url).scheme != 'https':\n    return None\nreturn urlopen(url)",
            imports="",
        )
    )
    assert not _audits(_scan(tmp_path, source))


def test_unrelated_instance_writes_keep_native_normalization_proof(tmp_path):
    body = "other.scheme = 'file'\nother.lower = unknown\nif urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)"
    assert not _audits(_scan(tmp_path, _function(body)))


def test_local_string_protocol_cannot_forge_builtin_scheme_lower(tmp_path):
    source = (
        IMPORTS
        + FORGED
        + "class SchemeSlice(str):\n    def lower(self):\n        return ForgedScheme()\nclass URL(str):\n    def lstrip(self, chars=None):\n        return self\n    def replace(self, old, new, count=-1):\n        return self\n    def __getitem__(self, key):\n        value = super().__getitem__(key)\n        if isinstance(key, slice) and key.start is None:\n            return SchemeSlice(value)\n        return value\n"
        + _function(
            "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
            imports="",
        )
    )
    assert len(_audits(_scan(tmp_path, source))) == 1


@pytest.mark.parametrize(
    "setup",
    [
        "import sys\nfrom types import SimpleNamespace\nResult = sys.modules['urllib.parse'].SplitResult\nResult.scheme = property(lambda self: SimpleNamespace(lower=lambda: 'https'))\n",
        "from sys import modules as cache\nfrom types import SimpleNamespace\nResult = cache['urllib.parse'].SplitResult\nResult.scheme = property(lambda self: SimpleNamespace(lower=lambda: 'https'))\n",
        "from importlib import import_module as load\nResult = load('urllib.parse').SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        "Result = globals()['__builtins__']['__import__']('urllib.parse', fromlist=['SplitResult']).SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
    ],
)
def test_dynamic_native_result_namespace_keeps_normalization_audit(tmp_path, setup):
    source = (
        IMPORTS
        + FORGED
        + setup
        + _function(
            "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
            imports="",
        )
    )
    assert len(_audits(_scan(tmp_path, source))) == 1


@pytest.mark.parametrize(
    "setup",
    [
        "import sys\ncache = sys\nResult = cache.modules['urllib.parse'].SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        "import sys\nResult = sys.__dict__['modules']['urllib.parse'].SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        "import sys\ncache = sys\nResult = cache.__dict__['modules']['urllib.parse'].SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        "import importlib\nloader = importlib\nResult = loader.import_module('urllib.parse').SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        "import builtins\nnamespace = builtins\nResult = namespace.__import__('urllib.parse', fromlist=['SplitResult']).SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        "import builtins\nResult = builtins.__dict__['__import__']('urllib.parse', fromlist=['SplitResult']).SplitResult\nResult.scheme = property(lambda self: ForgedScheme())\n",
        'exec("from urllib.parse import SplitResult; SplitResult.scheme = property(lambda self: ForgedScheme())")\n',
        "eval(\"setattr(__import__('urllib.parse', fromlist=['SplitResult']).SplitResult, 'scheme', property(lambda self: ForgedScheme()))\")\n",
        "code = compile(\"from urllib.parse import SplitResult; SplitResult.scheme = property(lambda self: ForgedScheme())\", '<generated>', 'exec')\n",
        'from builtins import exec as run\nrun("from urllib.parse import SplitResult; SplitResult.scheme = property(lambda self: ForgedScheme())")\n',
        "import builtins as b\nb.eval(\"setattr(__import__('urllib.parse', fromlist=['SplitResult']).SplitResult, 'scheme', property(lambda self: ForgedScheme()))\")\n",
        "import builtins as b\ncode = b.compile('pass', '<generated>', 'exec')\n",
    ],
)
def test_whole_namespace_and_dynamic_code_cannot_prove_native_lower(tmp_path, setup):
    source = (
        IMPORTS
        + FORGED
        + setup
        + _function(
            "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
            imports="",
        )
    )
    assert len(_audits(_scan(tmp_path, source))) == 1


def test_ordinary_sys_attribute_read_preserves_normalization_proof(tmp_path):
    source = "import sys\nversion = sys.version\n" + _function(
        "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)"
    )
    assert not _audits(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "setup",
    [
        "import inspect\nResult = inspect.currentframe().f_globals['urlsplit'].__wrapped__.__globals__['SplitResult']\n",
        "import inspect\nread = getattr\nnamespace = read(inspect.currentframe(), 'f_globals')\nwrapped = read(namespace['urlsplit'], '__wrapped__')\nResult = read(wrapped, '__globals__')['SplitResult']\n",
        "import inspect\nfrom builtins import getattr as read\nnamespace = read(inspect.currentframe(), 'f_globals')\nwrapped = read(namespace['urlsplit'], '__wrapped__')\nResult = read(wrapped, '__globals__')['SplitResult']\n",
        "import inspect\nfrom operator import attrgetter as read\nnamespace = read('f_globals')(inspect.currentframe())\nwrapped = read('__wrapped__')(namespace['urlsplit'])\nResult = read('__globals__')(wrapped)['SplitResult']\n",
        "import inspect\nfrom operator import methodcaller as call\nnamespace = call('__getattribute__', 'f_globals')(inspect.currentframe())\nwrapped = call('__getattribute__', '__wrapped__')(namespace['urlsplit'])\nResult = call('__getattribute__', '__globals__')(wrapped)['SplitResult']\n",
    ],
)
def test_reflective_native_namespace_keeps_normalization_audit(tmp_path, setup):
    source = (
        IMPORTS
        + "from types import SimpleNamespace\n"
        + setup
        + "Result.scheme = property(lambda self: SimpleNamespace(lower=lambda: 'https'))\n"
        + _function(
            "if urlsplit(url).scheme.lower() != 'https':\n    return None\nreturn urlopen(url)",
            imports="",
        )
    )
    assert len(_audits(_scan(tmp_path, source))) == 1
