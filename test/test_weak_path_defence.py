"""Path traversal defences that do not hold, and defences that do."""

import json

import pytest

from skylos.rules.danger.danger import scan_ctx

RULE = "SKY-D378"


def scan(tmp_path, code):
    path = tmp_path / "server.py"
    path.write_text(code)
    return [f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == RULE]


STRIP_ONCE = """import os

def read(name):
    name = name.replace("../", "")
    with open(os.path.join(BASE, name)) as handle:
        return handle.read()
"""

STRIP_BACKSLASH = """from pathlib import Path

def read(filename):
    clean = filename.replace("..\\\\", "")
    return Path(ROOT, clean).read_text()
"""

STRIP_CHAINED = """import os

def remove(name):
    cleaned = name.replace("../", "").replace("..\\\\", "")
    os.remove(UPLOADS + "/" + cleaned)
"""

STRIP_INLINE = """def read(name):
    return open(BASE + name.replace("../", "")).read()
"""

REJECT_THEN_JOIN = """import os

def save(name, data):
    if ".." in name:
        raise ValueError("bad name")
    with open(os.path.join(UPLOADS, name), "wb") as handle:
        handle.write(data)
"""

REJECT_STARTSWITH = """from pathlib import Path

def load(base, name):
    if name.startswith(".."):
        return None
    return (Path(base) / name).read_bytes()
"""

REJECT_ASSERT = """import os

def delete(directory, name):
    assert ".." not in name
    os.remove(os.path.join(directory, name))
"""

REJECT_BOTH_SEPARATORS = """import os
from flask import abort, send_file

def download(name):
    if "../" in name or "..\\\\" in name:
        abort(400)
    return send_file(os.path.join(FILES, name))
"""

REMOVE_ALL_THEN_JOIN = """import os

def fetch(name):
    name = name.replace("..", "")
    target = os.path.join(CACHE, name)
    return open(target, "rb").read()
"""

REJECT_THEN_DERIVED = """import os

def write(name, text):
    if ".." in name:
        return False
    target = os.path.join(OUTPUT, name)
    folder = os.path.dirname(target)
    os.makedirs(folder)
    with open(target, "w") as handle:
        handle.write(text)
    return True
"""


@pytest.mark.parametrize(
    ("code", "line", "kind"),
    [
        (STRIP_ONCE, 5, "single_pass_strip"),
        (STRIP_BACKSLASH, 5, "single_pass_strip"),
        (STRIP_CHAINED, 5, "single_pass_strip"),
        (STRIP_INLINE, 2, "single_pass_strip"),
        (REJECT_THEN_JOIN, 6, "absolute_path"),
        (REJECT_STARTSWITH, 6, "absolute_path"),
        (REJECT_ASSERT, 5, "absolute_path"),
        (REJECT_BOTH_SEPARATORS, 7, "absolute_path"),
        (REMOVE_ALL_THEN_JOIN, 6, "absolute_path"),
        (REJECT_THEN_DERIVED, 8, "absolute_path"),
    ],
)
def test_defences_that_do_not_hold_are_reported(tmp_path, code, line, kind):
    findings = scan(tmp_path, code)

    assert [(f["line"], f["metadata"]["path_defence"]["kind"]) for f in findings] == [
        (line, kind)
    ]
    assert findings[0]["severity"] == "MEDIUM"
    assert "path traversal defence" in findings[0]["message"]
    assert json.dumps(findings)


CONTAINED = """import os

def read(name):
    if ".." in name:
        raise ValueError
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(BASE + os.sep):
        raise ValueError
    return open(target).read()
"""

RELATIVE_TO = """from pathlib import Path

def read(name):
    name = name.replace("../", "")
    target = (Path(BASE) / name).resolve()
    target.relative_to(BASE)
    return target.read_text()
"""

STRIP_IN_LOOP = """def read(name):
    while "../" in name:
        name = name.replace("../", "")
    return open(BASE + name).read()
"""

ABSOLUTE_REJECTED = """import os

def save(name, data):
    if ".." in name or os.path.isabs(name):
        raise ValueError
    with open(os.path.join(UPLOADS, name), "wb") as handle:
        handle.write(data)
"""

LEADING_SLASH_REJECTED = """import os

def save(name, data):
    if ".." in name or name.startswith("/"):
        raise ValueError
    with open(os.path.join(UPLOADS, name), "wb") as handle:
        handle.write(data)
"""

LEADING_SLASH_STRIPPED = """import os

def save(name, data):
    if ".." in name:
        raise ValueError
    name = name.lstrip("/")
    with open(os.path.join(UPLOADS, name), "wb") as handle:
        handle.write(data)
"""

IS_ABSOLUTE_REJECTED = """from pathlib import Path

def load(base, name):
    if ".." in name or Path(name).is_absolute():
        return None
    return (Path(base) / name).read_bytes()
"""

BASENAME = """import os

def save(name, data):
    if ".." in name:
        raise ValueError
    name = os.path.basename(name)
    with open(os.path.join(UPLOADS, name), "wb") as handle:
        handle.write(data)
"""

SECURE_FILENAME = """import os
from werkzeug.utils import secure_filename

def save(name, data):
    name = secure_filename(name.replace("../", ""))
    with open(os.path.join(UPLOADS, name), "wb") as handle:
        handle.write(data)
"""

JOINED_FIRST = """import os

def listing(folder):
    if ".." in folder:
        raise ValueError
    return os.listdir(os.path.join(folder, "public"))
"""

CONCATENATED_AFTER_BASE = """def read(name):
    if ".." in name:
        raise ValueError
    return open(BASE + "/" + name).read()
"""

NO_FILE_OPERATION = """import os

def url_for(name):
    if ".." in name:
        raise ValueError
    return os.path.join("/static", name)
"""

STRIP_FOR_DISPLAY = """def label(name):
    return name.replace("../", "")
"""

STRIP_THEN_REQUEST = """import requests

def fetch(url):
    url = url.replace("../", "")
    return requests.get(BASE_URL + url)
"""

OTHER_VARIABLE = """import os

def save(name, other):
    if ".." in other:
        raise ValueError
    return open(os.path.join(UPLOADS, name)).read()
"""

ALLOWLISTED = """import os

def read(name):
    if ".." in name or name not in ALLOWED:
        raise ValueError
    return open(os.path.join(BASE, name)).read()
"""

PATTERN_CHECKED = """import os
import re

def read(name):
    if ".." in name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError
    return open(os.path.join(BASE, name)).read()
"""

VALIDATOR_CALLED = """import os

def read(name):
    if ".." in name or not valid_name(name):
        raise ValueError
    return open(os.path.join(BASE, name)).read()
"""

REPLACED_WITH_TEXT = """def read(name):
    name = name.replace("../", "_")
    return open(BASE + name).read()
"""

DIFFERENT_FUNCTION = """import os

def check(name):
    if ".." in name:
        raise ValueError

def read(name):
    return open(os.path.join(BASE, name)).read()
"""

SPLIT_COMPONENTS = """import os

def read(name):
    if ".." in name.split("/"):
        raise ValueError
    return open(os.path.join(BASE, name)).read()
"""


@pytest.mark.parametrize(
    "code",
    [
        CONTAINED,
        RELATIVE_TO,
        STRIP_IN_LOOP,
        ABSOLUTE_REJECTED,
        LEADING_SLASH_REJECTED,
        LEADING_SLASH_STRIPPED,
        IS_ABSOLUTE_REJECTED,
        BASENAME,
        SECURE_FILENAME,
        JOINED_FIRST,
        CONCATENATED_AFTER_BASE,
        NO_FILE_OPERATION,
        STRIP_FOR_DISPLAY,
        STRIP_THEN_REQUEST,
        OTHER_VARIABLE,
        ALLOWLISTED,
        PATTERN_CHECKED,
        VALIDATOR_CALLED,
        REPLACED_WITH_TEXT,
        DIFFERENT_FUNCTION,
        SPLIT_COMPONENTS,
    ],
)
def test_real_defences_and_lookalikes_stay_quiet(tmp_path, code):
    assert scan(tmp_path, code) == []


def test_one_finding_per_defence(tmp_path):
    code = """import os

def save(name, data):
    if ".." in name:
        raise ValueError
    target = os.path.join(UPLOADS, name)
    if os.path.exists(target):
        os.remove(target)
    with open(target, "wb") as handle:
        handle.write(data)
"""

    assert [f["line"] for f in scan(tmp_path, code)] == [8]


def test_defences_in_test_files_stay_quiet(tmp_path):
    folder = tmp_path / "tests"
    folder.mkdir()
    path = folder / "test_files.py"
    path.write_text(
        "def test_read():\n" + STRIP_INLINE.replace("def read", "def helper")
    )

    assert [f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == RULE] == []
