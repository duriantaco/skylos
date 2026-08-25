from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


SQLALCHEMY_TEXT_RULE_IDS = {"SKY-D211", "SKY-D217"}


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
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_sqlalchemy_text_import_aliases_remain_sql_sinks(tmp_path):
    cases = {
        "direct": (
            "from sqlalchemy import text as draw_text\n"
            "def direct(ip):\n"
            "    draw_text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "qualified": (
            "import sqlalchemy as plt\n"
            "def qualified(ip):\n"
            "    plt.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
    }
    for symbol, code in cases.items():
        out = _scan_one(tmp_path, f"raw_sa_{symbol}.py", code)
        ids = {finding["rule_id"] for finding in out}
        assert SQLALCHEMY_TEXT_RULE_IDS <= ids


def test_sqlalchemy_text_requires_unshadowed_absolute_import(tmp_path):
    safe_cases = {
        "unbound_global": (
            "def f(ip):\n    sqlalchemy.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "bare_parameter": (
            "def f(sqlalchemy, ip):\n"
            "    sqlalchemy.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "relative_import": (
            "from .sqlalchemy import text as draw_text\n"
            "def f(ip):\n"
            "    draw_text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "shadowed_alias": (
            "import sqlalchemy as sa\n"
            "def f(sa, ip):\n"
            "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "assigned_local": (
            "import sqlalchemy as sa\n"
            "def f(plot, ip):\n"
            "    sa = plot\n"
            "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "unrelated_module_alias": (
            "import matplotlib.pyplot as sqlalchemy\n"
            "def f(ip):\n"
            "    sqlalchemy.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "unrelated_text_import": (
            "from matplotlib.pyplot import text\n"
            "def f(ip):\n"
            "    text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "reassigned_alias": (
            "import sqlalchemy as sa\n"
            "sa = object()\n"
            "def f(ip):\n"
            "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
    }
    for name, code in safe_cases.items():
        out = _scan_one(tmp_path, f"safe_sa_{name}.py", code)
        assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_sqlalchemy_text_module_import_is_visible_before_ast_visit(tmp_path):
    code = (
        "def f(ip):\n"
        "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        "import sqlalchemy as sa\n"
    )
    out = _scan_one(tmp_path, "late_module_sa_import.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_sqlalchemy_text_local_absolute_import_before_call_flags(tmp_path):
    code = (
        "def f(ip):\n"
        "    from sqlalchemy import text\n"
        "    text('DELETE FROM logs WHERE ip=' + ip)\n"
    )
    out = _scan_one(tmp_path, "local_sa_import.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_comprehension_target_does_not_shadow_enclosing_sqlalchemy_alias(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip, rows):\n"
        "    [x for sa in rows for x in (sa,)]\n"
        "    sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_after_comprehension.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_comprehension_target_shadows_sqlalchemy_alias_inside_scope(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip, rows):\n"
        "    return [sa.text('SELECT ' + ip) for sa in rows]\n"
    )
    out = _scan_one(tmp_path, "sa_inside_comprehension.py", code)
    assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_final_unconditional_module_import_provides_sqlalchemy_provenance(tmp_path):
    vulnerable_cases = {
        "after_assignment": (
            "sa = None\n"
            "import sqlalchemy as sa\n"
            "def f(ip):\n"
            "    sa.text('SELECT ' + ip)\n"
        ),
        "after_unrelated_import": (
            "import matplotlib.pyplot as sa\n"
            "import sqlalchemy as sa\n"
            "def f(ip):\n"
            "    sa.text('SELECT ' + ip)\n"
        ),
    }
    for name, code in vulnerable_cases.items():
        out = _scan_one(tmp_path, f"sa_final_import_{name}.py", code)
        assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_final_unrelated_module_binding_removes_sqlalchemy_provenance(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "import matplotlib.pyplot as sa\n"
        "def f(ip):\n"
        "    sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_final_unrelated_import.py", code)
    assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_lambda_parameter_shadows_sqlalchemy_alias(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip):\n"
        "    return lambda sa: sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_shadowed_in_lambda.py", code)
    assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_lambda_with_unshadowed_sqlalchemy_alias_flags(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip):\n"
        "    return lambda plot: sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_used_in_lambda.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_non_sqlalchemy_text_receiver_is_not_a_sql_sink(tmp_path):
    code = (
        "import matplotlib.pyplot as plt\n"
        "import pandas as pd\n"
        "def render(df: pd.DataFrame, read_col: str, labels: list[str]) -> None:\n"
        "    fig, ax = plt.subplots()\n"
        "    for i, (_, row) in enumerate(df.iterrows()):\n"
        "        value = row[read_col]\n"
        "        if value:\n"
        "            ax.text(i - 0.17, value / 2, labels[i], ha='center')\n"
    )
    out = _scan_one(tmp_path, "matplotlib_text.py", code)
    assert not ({"SKY-D211", "SKY-D217"} & _rule_ids(out))


def test_non_sqlalchemy_text_receiver_stays_safe_when_sqlalchemy_is_imported(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def render(ax, value, label):\n"
        "    ax.text(0, value / 2, label)\n"
    )
    out = _scan_one(tmp_path, "mixed_text_receivers.py", code)
    assert not ({"SKY-D211", "SKY-D217"} & _rule_ids(out))


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
