import os
import zlib
from pathlib import Path

from skylos.scale.cache import SkylosProcCache


class Unpicklable:
    def __getstate__(self):
        raise TypeError("nope")


def write_file(p: Path, content: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


def test_cache_creates_db_and_schema(tmp_path):
    db_path = tmp_path / "cache" / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    assert db_path.exists()

    row = cache.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='proc_cache'"
    ).fetchone()
    assert row is not None

    cache.close()


def test_get_returns_none_if_missing_file(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    missing = tmp_path / "nope.py"
    assert cache.get(missing) is None

    cache.close()


def test_get_returns_none_if_no_cache_row(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = write_file(tmp_path / "a.py", b"print('hi')\n")
    assert cache.get(f) is None

    cache.close()


def test_put_then_get_roundtrip(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = write_file(tmp_path / "a.py", b"print('hi')\n")

    result = (["defs"], ["refs"], set(), set(), {"t": 1})
    cache.put(f, result)

    out = cache.get(f)
    assert out == result

    cache.close()


def test_put_skips_if_file_missing(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = tmp_path / "missing.py"

    # should not throw
    cache.put(f, {"x": 1})
    assert cache.get(f) is None

    cache.close()


def test_put_skips_if_result_unpicklable(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = write_file(tmp_path / "a.py", b"print('hi')\n")

    # should not throw
    cache.put(f, Unpicklable())

    # nothing stored
    assert cache.get(f) is None

    cache.close()


def test_cache_invalidates_when_mtime_or_size_changes(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = write_file(tmp_path / "a.py", b"abc")
    cache.put(f, {"ok": True})

    # sanity
    assert cache.get(f) == {"ok": True}

    write_file(f, b"abcd")
    assert cache.get(f) is None

    cache.close()


def test_cache_invalidates_when_sha_changes_but_mtime_and_size_same(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    # size=3
    f = write_file(tmp_path / "a.py", b"AAA")
    cache.put(f, {"cached": 1})

    assert cache.get(f) == {"cached": 1}

    st0 = f.stat()
    original_mtime_ns = getattr(st0, "st_mtime_ns", int(st0.st_mtime * 1e9))

    # still size=3
    write_file(f, b"BBB")

    try:
        os.utime(f, ns=(original_mtime_ns, original_mtime_ns))
    except Exception:
        os.utime(f, (st0.st_mtime, st0.st_mtime))

    # mtime + size match cached row, sha must fail
    assert cache.get(f) is None

    cache.close()


def test_corrupted_payload_returns_none(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = write_file(tmp_path / "a.py", b"hello")

    cache.put(f, {"x": 1})
    assert cache.get(f) == {"x": 1}

    cache.conn.execute(
        "UPDATE proc_cache SET payload=? WHERE file_path=?",
        (b"not-a-valid-zlib", str(f.resolve())),
    )
    cache.conn.commit()

    assert cache.get(f) is None

    cache.close()


def test_bad_pickle_after_decompress_returns_none(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    f = write_file(tmp_path / "a.py", b"hello")
    cache.put(f, {"x": 1})
    assert cache.get(f) == {"x": 1}

    bad_pickled_bytes = b"this is not pickle data"
    bad_payload = zlib.compress(bad_pickled_bytes, level=6)

    cache.conn.execute(
        "UPDATE proc_cache SET payload=? WHERE file_path=?",
        (bad_payload, str(f.resolve())),
    )
    cache.conn.commit()

    assert cache.get(f) is None

    cache.close()


def test_close_is_safe(tmp_path):
    db_path = tmp_path / "proc_cache.db"
    cache = SkylosProcCache(db_path)

    cache.close()
    cache.close()
