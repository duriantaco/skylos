"""Removing every path separator is a basename-strength proof for SKY-D215.

``str.replace('/', literal)`` without a count, or ``str.translate`` with a
literal table that maps ``ord('/')`` away, leaves a single path component,
like ``os.path.basename``. The proof is dropped when a later step can make
separators again (decoding, a format string, a replacement that adds one),
when the table or replacement is not a literal, and when the code targets
Windows without also removing ``\\`` and ``:``. SKY-D324/SKY-D325 keep their
behaviour: a single component can still be a symlink.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}

WEB = """\
from flask import Flask, request

from app import store

app = Flask(__name__)


@app.route("/save")
def save():
    store.target(request.args["title"], request.args["lang"])
    return "ok"
"""


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    assert write_text_no_symlink(root / "pyproject.toml", '[project]\nname = "proj"\n')
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)
    return root


def _scan(tmp_path, store, extra=None):
    files = {"app/__init__.py": "", "app/web.py": WEB, "app/store.py": store}
    files.update(extra or {})
    result = json.loads(analyze(str(_project(tmp_path, files)), enable_danger=True))
    reported = {
        finding["rule_id"]
        for finding in result.get("danger") or []
        if finding.get("rule_id") in PATH_RULES and finding.get("symbol") == "target"
    }
    suppressed = {
        finding["rule_id"]: finding
        for finding in result.get("suppressed") or []
        if finding.get("rule_id") in PATH_RULES and finding.get("symbol") == "target"
    }
    return reported, suppressed


HEADER = "import os\nfrom urllib.parse import unquote\n\nBASE = '/srv/reports'\n\n\n"


def _store(body, header=HEADER):
    return header + "def target(title, lang):\n" + body


SAFE_FORMS = {
    "replace": "    name = title.replace('/', '_')\n",
    "translate_ord_table": "    name = title.translate({ord('/'): '-', 0: None})\n",
    "translate_maketrans_pair": "    name = title.translate(str.maketrans('/|', '--'))\n",
    "translate_maketrans_dict": "    name = title.translate(str.maketrans({'/': None}))\n",
    "translate_then_trim_in_steps": (
        "    name = title.translate({ord('/'): '-', ord('|'): '-'})\n"
        "    if lang == 'mac':\n"
        "        name = name.translate({ord(':'): '-'})\n"
        "    if name.startswith('.'):\n"
        "        name = name[1:]\n"
        "    name = name[:80].strip()\n"
    ),
    "template_argument": "    name = '{user}.csv'.format(user=title.replace('/', '_'))\n",
}


@pytest.mark.parametrize("form", sorted(SAFE_FORMS))
def test_separator_removal_proves_one_component_for_traversal_only(tmp_path, form):
    body = SAFE_FORMS[form] + (
        "    with open(os.path.join(BASE, name), 'w') as handle:\n"
        "        handle.write('x')\n"
    )
    reported, suppressed = _scan(tmp_path, _store(body))
    assert "SKY-D215" not in reported
    assert suppressed["SKY-D215"]["metadata"]["path_provenance"]["status"] == "safe"
    assert "SKY-D324" in reported


def test_wrapper_that_removes_separators_is_followed_into_its_callers(tmp_path):
    body = (
        "    with open(os.path.join(BASE, slug(title))) as handle:\n"
        "        return handle.read()\n"
    )
    store = _store(body, HEADER.replace("BASE =", "from app.text import slug\n\nBASE ="))
    reported, suppressed = _scan(
        tmp_path,
        store,
        {"app/text.py": "def slug(text):\n    return text.strip().replace('/', '-')\n"},
    )
    assert "SKY-D215" not in reported
    assert suppressed["SKY-D215"]["metadata"]["path_provenance"]["status"] == "safe"
    assert "SKY-D325" in reported


WINDOWS_SAFE = (
    "import os\n\nBASE = 'C:\\\\reports'\nSEP = '\\\\' if os.name == 'nt' else '/'\n\n\n"
)


def test_windows_code_that_removes_every_windows_separator_is_safe(tmp_path):
    body = (
        "    name = title.translate({ord('/'): '_', ord('\\\\'): '_', ord(':'): '_'})\n"
        "    return open(os.path.join(BASE, name)).read()\n"
    )
    reported, _ = _scan(tmp_path, _store(body, WINDOWS_SAFE))
    assert "SKY-D215" not in reported


STILL_REPORTED = {
    "removes_dot_dot_slash_only": "    name = title.replace('../', '')\n",
    "replaces_first_slash_only": "    name = title.replace('/', '_', 1)\n",
    "replaces_first_slash_by_keyword": "    name = title.replace('/', '_', count=1)\n",
    "turns_backslashes_into_slashes": "    name = title.replace('\\\\', '/')\n",
    "adds_slashes_back_after_removal": "    name = title.replace('/', '_').replace('\\\\', '/')\n",
    "replacement_text_has_a_separator": "    name = title.replace('/', '\\\\')\n",
    "decodes_after_removal": "    clean = title.replace('/', '_')\n    name = unquote(clean)\n",
    "removed_value_is_a_format_string": "    clean = title.replace('/', '_')\n    name = clean.format('/')\n",
    "removed_value_is_a_percent_format": "    clean = title.replace('/', '_')\n    name = clean % ('/',)\n",
    "removed_value_is_a_strftime_format": (
        "    clean = title.replace('/', '_')\n"
        "    import datetime\n"
        "    name = datetime.datetime.now().strftime(clean)\n"
    ),
    "string_keys_are_ignored_by_translate": "    name = title.translate({'/': '-'})\n",
    "table_maps_another_character_to_slash": "    name = title.translate({ord('/'): '-', ord('|'): '/'})\n",
    "table_from_a_variable": "    name = title.translate(TABLE)\n",
    "table_key_from_a_variable": "    sep = os.sep\n    name = title.translate({ord(sep): '-'})\n",
    "replacement_that_may_be_request_data": (
        "    fill = '_'\n"
        "    if lang:\n"
        "        fill = lang\n"
        "    name = title.replace('/', fill)\n"
    ),
    "second_raw_part_is_joined": "    name = os.path.join(lang, title.replace('/', '_'))\n",
}


@pytest.mark.parametrize("form", sorted(STILL_REPORTED))
def test_unproved_or_undone_separator_removal_still_reports(tmp_path, form):
    body = STILL_REPORTED[form] + "    return open(os.path.join(BASE, name)).read()\n"
    header = HEADER + "TABLE = {ord('/'): '-'}\n\n\n"
    reported, _ = _scan(tmp_path, _store(body, header))
    assert "SKY-D215" in reported


def test_decoding_inside_a_called_helper_still_reports(tmp_path):
    body = (
        "    name = decode(title.replace('/', '_'))\n"
        "    return open(os.path.join(BASE, name)).read()\n"
    )
    store = _store(body, HEADER.replace("BASE =", "from app.codec import decode\n\nBASE ="))
    reported, _ = _scan(
        tmp_path,
        store,
        {"app/codec.py": "from urllib.parse import unquote as dec\n\n\ndef decode(value):\n    return dec(value)\n"},
    )
    assert "SKY-D215" in reported


def test_project_object_with_its_own_replace_still_reports(tmp_path):
    header = HEADER + (
        "class Name:\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n\n"
        "    def replace(self, old, new):\n"
        "        return self.value\n\n\n"
    )
    body = (
        "    name = Name(title).replace('/', '_')\n"
        "    return open(os.path.join(BASE, name)).read()\n"
    )
    reported, _ = _scan(tmp_path, _store(body, header))
    assert "SKY-D215" in reported


WINDOWS_HEADERS = {
    "tests_os_name": "import os\n\nBASE = 'C:\\\\reports'\nIS_WINDOWS = os.name == 'nt'\n\n\n",
    "tests_sys_platform": "import os\nimport sys\n\nBASE = '/srv'\nWIN = sys.platform.startswith('win')\n\n\n",
    "uses_windows_paths": "import os\nfrom pathlib import PureWindowsPath\n\nBASE = PureWindowsPath('C:/reports')\n\n\n",
}


@pytest.mark.parametrize("header", sorted(WINDOWS_HEADERS))
def test_slash_only_removal_in_windows_code_still_reports(tmp_path, header):
    body = (
        "    name = title.replace('/', '_')\n"
        "    return open(os.path.join(BASE, name)).read()\n"
    )
    reported, _ = _scan(tmp_path, _store(body, WINDOWS_HEADERS[header]))
    assert "SKY-D215" in reported


def test_windows_path_type_after_slash_removal_still_reports(tmp_path):
    header = "import os\nimport pathlib\n\nBASE = '/srv/reports'\n\n\n"
    body = (
        "    name = pathlib.PureWindowsPath(title.replace('/', '_'))\n"
        "    return open(os.path.join(BASE, str(name))).read()\n"
    )
    reported, _ = _scan(tmp_path, _store(body, header))
    assert "SKY-D215" in reported
