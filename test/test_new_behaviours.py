import json
from skylos.analyzer import analyze


def test_dataclass_fields(tmp_path):
    p = tmp_path / "dc.py"
    p.write_text(
        "from dataclasses import dataclass\n"
        "@dataclass\n"
        "class C:\n"
        "    x: int = 1\n"
        "    y: int = 2\n"
        "def f(c: C):\n"
        "    return c.x + c.y\n"
        "f(C())\n"
    )
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert result["unused_variables"] == []


def test_dead_store_guard(tmp_path):
    p = tmp_path / "dstore.py"
    p.write_text(
        "lst=[1,2,3]\ndir=0\nif 'a' in lst:\n    pass\nelse:\n    dir=1\nprint(dir)\n"
    )
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert result["unused_variables"] == []


def test_unused_constant_reported(tmp_path):
    p = tmp_path / "pool.py"
    p.write_text(
        "from concurrent.futures import ProcessPoolExecutor\n"
        "PROCESS_POOL=None\n"
        "NEVER_USED=123\n"
        "def get_pool():\n"
        "    global PROCESS_POOL\n"
        "    if PROCESS_POOL is None:\n"
        "        PROCESS_POOL=ProcessPoolExecutor(max_workers=2)\n"
        "    return PROCESS_POOL\n"
        "get_pool()\n"
    )
    result = json.loads(analyze(str(tmp_path), conf=0))
    names = set()
    for v in result["unused_variables"]:
        names.add(v["name"])

    assert "NEVER_USED" in names
    assert "PROCESS_POOL" not in names
