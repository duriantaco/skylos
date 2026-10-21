"""Per-file path operation facts used by the path rules.

``ZipFile.extract`` and ``TarFile.extract`` need a member, so a call that
cannot pass one is another API (BeautifulSoup's ``tag.extract()``). An
exclusive create (``open(p, "x")``, ``os.open`` with ``O_CREAT | O_EXCL``)
fails on an existing final component, a symlink included, so it cannot
follow one; traversal is still checked. Helper-parameter findings carry the
location of their path operand for the repository provenance pass.
"""

from pathlib import Path

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.danger import scan_ctx


def _scan(tmp_path: Path, code: str, name: str = "mod.py"):
    path = tmp_path / name
    assert write_text_no_symlink(path, code, encoding="utf-8")
    return scan_ctx(tmp_path, [path])


def _lines(findings, rule):
    return [f["line"] for f in findings if f["rule_id"] == rule]


def test_beautifulsoup_extract_without_member_is_not_archive_extraction(tmp_path):
    out = _scan(
        tmp_path,
        "from bs4 import BeautifulSoup\n\n\n"
        "def clean(html):\n"
        "    soup = BeautifulSoup(html, 'html.parser')\n"
        "    for tag in soup.find_all('script'):\n"
        "        tag.extract()\n"
        "    return soup\n",
    )
    assert _lines(out, "SKY-D326") == []


def test_archive_extract_with_a_member_or_mapping_is_still_reported(tmp_path):
    out = _scan(
        tmp_path,
        "import zipfile\n\n\n"
        "def unpack(upload, member, options):\n"
        "    with zipfile.ZipFile(upload) as zf:\n"
        "        zf.extract(member)\n"
        "        zf.extract(member=member)\n"
        "        zf.extract(**options)\n"
        "        zf.extractall()\n",
    )
    assert _lines(out, "SKY-D326") == [6, 7, 8, 9]


def test_exclusive_create_mode_is_not_a_symlink_following_write(tmp_path):
    out = _scan(
        tmp_path,
        "from pathlib import Path\n\n\n"
        "def mark(folder):\n"
        "    marker = Path(folder) / 'run.lock'\n"
        "    with marker.open('x') as fh:\n"
        "        fh.write('1')\n"
        "    with open(Path(folder) / 'other.lock', 'x') as fh:\n"
        "        fh.write('2')\n",
    )
    assert _lines(out, "SKY-D324") == []
    assert _lines(out, "SKY-D325") == []
    assert 8 in _lines(out, "SKY-D215")


def test_exclusive_os_open_flags_are_not_a_symlink_following_write(tmp_path):
    out = _scan(
        tmp_path,
        "import os\n\n\n"
        "def lock(path):\n"
        "    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)\n"
        "    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL\n"
        "    other = os.open(path + '.2', flags)\n"
        "    return fd, other\n",
    )
    assert _lines(out, "SKY-D324") == []
    assert _lines(out, "SKY-D325") == []


def test_non_exclusive_or_conditional_flags_still_report_the_write(tmp_path):
    out = _scan(
        tmp_path,
        "import os\n\n\n"
        "def lock(path, strict):\n"
        "    a = os.open(path, os.O_CREAT | os.O_WRONLY)\n"
        "    b = os.open(path, os.O_CREAT | (os.O_EXCL if strict else 0) | os.O_WRONLY)\n"
        "    return a, b\n",
    )
    assert _lines(out, "SKY-D324") == [5, 6]


def test_mixed_exclusive_and_write_modes_still_report_the_write(tmp_path):
    out = _scan(
        tmp_path,
        "def save(path, fresh):\n"
        "    mode = 'w'\n"
        "    if fresh:\n"
        "        mode = 'x'\n"
        "    with open(path, mode) as fh:\n"
        "        fh.write('x')\n",
    )
    assert _lines(out, "SKY-D324") == [5]


def test_helper_parameter_finding_records_its_path_operand(tmp_path):
    out = _scan(
        tmp_path,
        "from pathlib import Path\n\n"
        "BASE = Path('/srv')\n\n\n"
        "def read(name):\n"
        "    return (BASE / name).read_text()\n",
    )
    finding = next(f for f in out if f["rule_id"] == "SKY-D215")
    assert finding["metadata"]["path_source"] == "helper_parameter"
    assert finding["metadata"]["path_operand"] == {"line": 7, "col": 12, "end_line": 7, "end_col": 23}


def test_flag_names_that_are_not_the_os_constants_do_not_prove_exclusive_create(tmp_path):
    out = _scan(
        tmp_path,
        "import os\n\n\n"
        "def lock(path, O_EXCL=0):\n"
        "    return os.open(path, os.O_CREAT | O_EXCL | os.O_WRONLY)\n\n\n"
        "def patched(path):\n"
        "    return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)\n\n\n"
        "os.O_EXCL = 0\n",
    )
    assert _lines(out, "SKY-D324") == [5, 9]


def test_os_constants_imported_by_name_prove_exclusive_create(tmp_path):
    out = _scan(
        tmp_path,
        "import os\nfrom os import O_CREAT, O_EXCL, O_WRONLY\n\n\n"
        "def lock(path):\n"
        "    return os.open(path, O_CREAT | O_EXCL | O_WRONLY)\n",
    )
    assert _lines(out, "SKY-D324") == []
