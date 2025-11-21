from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def test_sqlalchemy_text_tainted_flags(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip):\n"
        "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
    )
    out = _scan_one(tmp_path, "raw_sa.py", code)
    assert "SKY-D217" in _rule_ids(out)


def test_pandas_read_sql_tainted_flags(tmp_path):
    code = (
        "import pandas as pd\n"
        "def f(conn, name):\n"
        "    pd.read_sql(f\"SELECT * FROM users WHERE name='{name}'\", conn)\n"
    )
    out = _scan_one(tmp_path, "raw_pd.py", code)
    assert "SKY-D217" in _rule_ids(out)


def test_django_objects_raw_tainted_flags(tmp_path):
    code = (
        "class _O:\n"
        "    def raw(self, *a, **k):\n"
        "        return []\n"
        "class User:\n"
        "    objects = _O()\n"
        "def f(u):\n"
        "    User.objects.raw('SELECT * FROM auth_user WHERE username=' + u)\n"
    )
    out = _scan_one(tmp_path, "raw_dj.py", code)
    assert "SKY-D217" in _rule_ids(out)


def test_raw_constant_ok(tmp_path):
    code = "import pandas as pd\ndef f(conn):\n    pd.read_sql('SELECT 1 AS x', conn)\n"
    out = _scan_one(tmp_path, "raw_ok.py", code)
    assert "SKY-D217" not in _rule_ids(out)
