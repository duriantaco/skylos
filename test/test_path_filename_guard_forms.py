"""A helper that rejects every value except a filename-only one is a guard."""

import ast
from pathlib import Path

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import (
    resolve_helper_parameter_findings,
)


STORAGE = """def load(path):
    with open(path, 'r') as stream:
        return stream.read()
def save(path):
    with open(path, 'w') as stream:
        stream.write('record')
"""
PATTERN = """NAME = re.compile(r'[A-Za-z0-9_-]+')
def checked(raw):
    if not NAME.fullmatch(raw):
        raise ValueError('invalid')
    return raw
"""


def _scan(tmp_path, helper, *, annotation=": str", suffix=""):
    source = (
        "import re\nfrom pathlib import Path\nfrom fastapi import FastAPI\n"
        "from storage import load, save\napp = FastAPI()\n"
        + helper
        + "@app.get('/files/{raw}')\ndef view(raw"
        + annotation
        + "):\n"
        + "    path = Path('/srv/flights') / checked(raw) / 'manifest.json'\n"
        + "    save(path)\n    return load(path)\n"
        + suffix
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nname="guard-forms"\n')
    findings = []
    for filename, text in [("app.py", source), ("storage.py", STORAGE)]:
        path = tmp_path / filename
        path.write_text(text)
        scan(ast.parse(text), path, findings)
    suppressed = []
    kept = resolve_helper_parameter_findings(
        findings, scan_path=tmp_path, project_root=tmp_path, suppressed=suppressed
    )
    assert {
        (f["rule_id"], Path(f["file"]).name, f["line"])
        for f in kept
        if f["rule_id"] in {"SKY-D324", "SKY-D325"}
    } == {("SKY-D324", "storage.py", 5), ("SKY-D325", "storage.py", 2)}
    statuses = sorted(
        f["metadata"]["path_provenance"]["status"]
        for f in suppressed
        if f["rule_id"] == "SKY-D215"
    )
    return [f for f in kept if f["rule_id"] == "SKY-D215"], statuses


@pytest.mark.parametrize(
    "helper",
    [
        PATTERN,
        PATTERN.replace("r'[A-Za-z0-9_-]+'", "r'[\\w-]{1,64}', re.ASCII"),
        "def checked(raw):\n    if re.fullmatch(r'[a-z0-9_-]+', raw, flags=re.I) is None:\n"
        "        raise ValueError('invalid')\n    return raw\n",
        "def checked(raw):\n    if raw not in {'daily', 'weekly.json'}:\n"
        "        raise ValueError('invalid')\n    return raw\n",
        "KINDS = ('daily', 'weekly')\ndef checked(raw):\n    if raw not in KINDS:\n"
        "        raise ValueError('invalid')\n    return raw\n",
    ],
    ids=[
        "compiled-pattern",
        "pattern-with-flag",
        "fullmatch-is-none",
        "literal-allowlist",
        "constant-allowlist",
    ],
)
def test_filename_only_match_or_allowlist_in_a_helper_is_a_guard(tmp_path, helper):
    kept, statuses = _scan(tmp_path, helper)
    assert kept == []
    assert statuses == ["safe", "safe"]


@pytest.mark.parametrize(
    "helper",
    [
        PATTERN.replace("[A-Za-z0-9_-]", "[A-Za-z0-9/_-]"),
        PATTERN.replace("[A-Za-z0-9_-]", "[\\w.-]"),
        PATTERN.replace("r'[A-Za-z0-9_-]+'", "r'.+'"),
        PATTERN.replace("r'[A-Za-z0-9_-]+'", "r'[^/]+'"),
        PATTERN.replace("r'[A-Za-z0-9_-]+'", "r'[a-z]+ # .', re.VERBOSE"),
        PATTERN.replace("NAME.fullmatch(raw)", "NAME.match(raw)"),
        PATTERN.replace("NAME.fullmatch(raw)", "NAME.search(raw)"),
        PATTERN.replace("if not NAME.fullmatch(raw):", "if NAME.fullmatch(raw):"),
        PATTERN.replace("raise ValueError('invalid')", "print('invalid')"),
        PATTERN.replace(
            "    if not NAME.fullmatch(raw):\n        raise ValueError('invalid')\n",
            "    NAME.fullmatch(raw)\n",
        ),
        PATTERN.replace(
            "    if not NAME.fullmatch(raw):\n",
            "    other = raw.strip()\n    if not NAME.fullmatch(other):\n",
        ),
        PATTERN.replace("    return raw\n", "    raw = raw + '/..'\n    return raw\n"),
        PATTERN.replace(
            "    if not NAME.fullmatch(raw):\n        raise ValueError('invalid')\n",
            "    if len(raw) > 3:\n        if not NAME.fullmatch(raw):\n"
            "            raise ValueError('invalid')\n",
        ),
        PATTERN + "NAME = re.compile(r'.+')\n",
        "def make(text):\n    return re.compile(text)\n"
        + PATTERN.replace("NAME = re.compile(", "NAME = make("),
        "re.compile = lambda text: None\n" + PATTERN,
        "def checked(raw):\n    if not re.fullmatch(r'[a-z]+', raw):\n"
        "        raise ValueError('invalid')\n    return raw\n"
        "re.fullmatch = lambda pattern, value: True\n",
        "def checked(raw):\n    if raw not in {'daily', '../escape'}:\n"
        "        raise ValueError('invalid')\n    return raw\n",
        "KINDS = {'daily'}\nKINDS.add(input())\ndef checked(raw):\n"
        "    if raw not in KINDS:\n        raise ValueError('invalid')\n    return raw\n",
        "def checked(raw):\n    if raw not in {'daily'}:\n        pass\n    return raw\n",
        "def checked(raw):\n    raw in {'daily'}\n    return raw\n",
    ],
    ids=[
        "pattern-allows-separator",
        "pattern-allows-dot",
        "pattern-any-character",
        "negated-set",
        "verbose-pattern",
        "prefix-match",
        "search",
        "inverted-check",
        "check-does-not-reject",
        "result-ignored",
        "checks-another-value",
        "rebound-after-check",
        "check-on-one-branch",
        "pattern-rebound",
        "pattern-from-helper",
        "pattern-api-replaced",
        "module-api-replaced",
        "allowlist-with-traversal",
        "allowlist-changed",
        "allowlist-does-not-reject",
        "allowlist-result-ignored",
    ],
)
def test_checks_that_prove_nothing_still_report(tmp_path, helper):
    kept, _ = _scan(tmp_path, helper)
    assert [f["metadata"]["path_provenance"]["status"] for f in kept] == [
        "untrusted",
        "untrusted",
    ]


def test_guard_needs_a_native_string_like_the_character_filter(tmp_path):
    kept, _ = _scan(tmp_path, PATTERN, annotation="")
    assert [f["metadata"]["path_provenance"]["status"] for f in kept] == [
        "untrusted",
        "untrusted",
    ]
    custom = (
        "class Custom(str):\n    def startswith(self, prefix):\n        return True\n"
    )
    kept, _ = _scan(tmp_path, PATTERN, suffix=custom + "view(Custom('x'))\n")
    assert [f["metadata"]["path_provenance"]["status"] for f in kept] == [
        "untrusted",
        "untrusted",
    ]
