from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from skylos.grep_cache import (
    CACHE_DIR,
    CACHE_FILE,
    MAX_ENTRIES,
    GrepCache,
    _make_key,
    file_content_hash,
)


class TestFileContentHash:
    def test_existing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "hello.py"
        f.write_text("print('hello')")
        h = file_content_hash(f)
        assert isinstance(h, str)
        assert len(h) == 16
        # Same content -> same hash
        assert file_content_hash(f) == h

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("aaa")
        h1 = file_content_hash(f)
        f.write_text("bbb")
        h2 = file_content_hash(f)
        assert h1 != h2

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        h = file_content_hash(tmp_path / "does_not_exist.py")
        assert h == ""

    def test_large_file_uses_prefix(self, tmp_path: Path) -> None:
        f = tmp_path / "big.bin"
        data = b"A" * 16384
        f.write_bytes(data)
        h1 = file_content_hash(f)
        data2 = b"A" * 8192 + b"B" * 8192
        f.write_bytes(data2)
        h2 = file_content_hash(f)
        assert h1 == h2

    def test_large_file_different_size(self, tmp_path: Path) -> None:
        f = tmp_path / "big.bin"
        f.write_bytes(b"A" * 16384)
        h1 = file_content_hash(f)
        f.write_bytes(b"A" * 16385)
        h2 = file_content_hash(f)
        assert h1 != h2

    def test_accepts_str_path(self, tmp_path: Path) -> None:
        f = tmp_path / "s.py"
        f.write_text("x = 1")
        assert file_content_hash(str(f)) == file_content_hash(f)


class TestMakeKey:
    def test_format(self) -> None:
        key = _make_key("imports", "foo", "mod.foo", "function", "abc123")
        assert key == "imports:foo:mod.foo:function:abc123"

    def test_empty_parts(self) -> None:
        key = _make_key("", "", "", "", "")
        assert key == "::::"

    def test_different_strategies_different_keys(self) -> None:
        k1 = _make_key("imports", "n", "f", "t", "h")
        k2 = _make_key("calls", "n", "f", "t", "h")
        assert k1 != k2


class TestGetPut:
    def test_get_miss(self) -> None:
        cache = GrepCache()
        assert cache.get("nonexistent") is None

    def test_put_and_get(self) -> None:
        cache = GrepCache()
        cache.put("k1", ["line1", "line2"])
        assert cache.get("k1") == ["line1", "line2"]

    def test_put_overwrites(self) -> None:
        cache = GrepCache()
        cache.put("k1", ["old"])
        cache.put("k1", ["new"])
        assert cache.get("k1") == ["new"]

    def test_empty_results(self) -> None:
        cache = GrepCache()
        cache.put("k1", [])
        assert cache.get("k1") == []

    def test_get_updates_last_access(self) -> None:
        cache = GrepCache()
        cache.put("k1", ["a"])
        t1 = cache._entries["k1"]["last_access"]
        time.sleep(0.01)
        cache.get("k1")
        t2 = cache._entries["k1"]["last_access"]
        assert t2 > t1


class TestEviction:
    def test_evicts_lru_when_over_limit(self) -> None:
        cache = GrepCache()
        for i in range(MAX_ENTRIES + 5):
            cache.put(f"key_{i}", [f"result_{i}"])
        assert cache.size == MAX_ENTRIES

    def test_evicts_oldest_accessed(self) -> None:
        cache = GrepCache()
        for i in range(MAX_ENTRIES):
            cache.put(f"key_{i}", [f"r_{i}"])
        cache.get("key_0")
        cache.put("new_key", ["new"])
        assert cache.get("key_0") is not None
        assert cache.get("key_1") is None

    def test_no_eviction_under_limit(self) -> None:
        cache = GrepCache()
        for i in range(10):
            cache.put(f"k{i}", [])
        assert cache.size == 10


class TestInvalidateByHash:
    def test_removes_matching_entries(self) -> None:
        cache = GrepCache()
        cache.put("strategy:name:full:func:HASH123", ["a"])
        cache.put("strategy:name:full:func:HASH456", ["b"])
        cache.put("other:x:y:z:HASH123", ["c"])
        removed = cache.invalidate_by_hash("HASH123")
        assert removed == 2
        assert cache.size == 1
        assert cache.get("strategy:name:full:func:HASH456") == ["b"]

    def test_no_match_returns_zero(self) -> None:
        cache = GrepCache()
        cache.put("k1", ["a"])
        assert cache.invalidate_by_hash("NOPE") == 0
        assert cache.size == 1

    def test_empty_cache(self) -> None:
        cache = GrepCache()
        assert cache.invalidate_by_hash("x") == 0


class TestClear:
    def test_clears_all(self) -> None:
        cache = GrepCache()
        cache.put("a", ["1"])
        cache.put("b", ["2"])
        cache.clear()
        assert cache.size == 0
        assert cache.get("a") is None

    def test_clear_empty_cache(self) -> None:
        cache = GrepCache()
        cache.clear()
        assert cache.size == 0


class TestSize:
    def test_empty(self) -> None:
        assert GrepCache().size == 0

    def test_after_puts(self) -> None:
        cache = GrepCache()
        cache.put("a", [])
        cache.put("b", [])
        assert cache.size == 2

    def test_after_invalidation(self) -> None:
        cache = GrepCache()
        cache.put("x:hash1", [])
        cache.put("y:hash2", [])
        cache.invalidate_by_hash("hash1")
        assert cache.size == 1


class TestLoadSave:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        cache = GrepCache()
        cache.put("k1", ["r1", "r2"])
        cache.put("k2", ["r3"])
        cache.save(tmp_path)

        cache2 = GrepCache()
        cache2.load(tmp_path)
        assert cache2.get("k1") == ["r1", "r2"]
        assert cache2.get("k2") == ["r3"]
        assert cache2.size == 2

    def test_save_creates_directory(self, tmp_path: Path) -> None:
        cache = GrepCache()
        cache.put("k", ["v"])
        cache.save(tmp_path)
        assert (tmp_path / CACHE_DIR / CACHE_FILE).exists()

    def test_save_skips_when_not_dirty(self, tmp_path: Path) -> None:
        cache = GrepCache()
        cache.put("k", ["v"])
        cache.save(tmp_path)
        path = tmp_path / CACHE_DIR / CACHE_FILE
        path.write_text('{"version": 1, "entries": {}}')
        cache.save(tmp_path)
        data = json.loads(path.read_text())
        assert data["entries"] == {}

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        cache = GrepCache()
        # should not raise
        cache.load(tmp_path)
        assert cache.size == 0

    def test_load_corrupt_json(self, tmp_path: Path) -> None:
        path = tmp_path / CACHE_DIR / CACHE_FILE
        path.parent.mkdir(parents=True)
        path.write_text("NOT VALID JSON!!!")
        cache = GrepCache()
        # should not raise
        cache.load(tmp_path)
        assert cache.size == 0

    def test_load_missing_entries_key(self, tmp_path: Path) -> None:
        path = tmp_path / CACHE_DIR / CACHE_FILE
        path.parent.mkdir(parents=True)
        path.write_text('{"version": 1}')
        cache = GrepCache()
        cache.load(tmp_path)
        assert cache.size == 0

    def test_save_file_contains_version(self, tmp_path: Path) -> None:
        cache = GrepCache()
        cache.put("k", ["v"])
        cache.save(tmp_path)
        data = json.loads((tmp_path / CACHE_DIR / CACHE_FILE).read_text())
        assert data["version"] == 1

    def test_load_clears_dirty_flag(self, tmp_path: Path) -> None:
        cache = GrepCache()
        cache.put("k", ["v"])
        cache.save(tmp_path)
        cache2 = GrepCache()
        cache2.load(tmp_path)
        assert cache2._dirty is False


class TestCachedSearch:
    def _finding(
        self,
        simple_name: str = "func",
        full_name: str = "mod.func",
        finding_type: str = "function",
    ) -> dict:
        return {
            "simple_name": simple_name,
            "full_name": full_name,
            "type": finding_type,
        }

    def test_cache_miss_calls_search_fn(self) -> None:
        cache = GrepCache()
        calls: list[int] = []

        def search_fn() -> list[str]:
            calls.append(1)
            return ["match1"]

        result = cache.cached_search("imports", self._finding(), "hash1", search_fn)
        assert result == ["match1"]
        assert len(calls) == 1
        assert cache.size == 1

    def test_cache_hit_skips_search_fn(self) -> None:
        cache = GrepCache()
        calls: list[int] = []

        def search_fn() -> list[str]:
            calls.append(1)
            return ["match1"]

        cache.cached_search("imports", self._finding(), "hash1", search_fn)
        result = cache.cached_search("imports", self._finding(), "hash1", search_fn)
        assert result == ["match1"]
        assert len(calls) == 1

    def test_different_hash_triggers_new_search(self) -> None:
        cache = GrepCache()
        call_count = 0

        def search_fn() -> list[str]:
            nonlocal call_count
            call_count += 1
            return [f"result_{call_count}"]

        r1 = cache.cached_search("imports", self._finding(), "hash_v1", search_fn)
        r2 = cache.cached_search("imports", self._finding(), "hash_v2", search_fn)
        assert r1 == ["result_1"]
        assert r2 == ["result_2"]
        assert call_count == 2

    def test_uses_name_fallback(self) -> None:
        cache = GrepCache()
        finding = {"name": "fallback_name", "full_name": "m.f", "type": "class"}
        result = cache.cached_search("strat", finding, "h", lambda: ["ok"])
        key = _make_key("strat", "fallback_name", "m.f", "class", "h")
        assert cache.get(key) == ["ok"]

    def test_missing_fields_default_empty(self) -> None:
        cache = GrepCache()
        finding: dict = {}
        result = cache.cached_search("s", finding, "h", lambda: ["x"])
        assert result == ["x"]


class TestThreadSafety:
    def test_concurrent_put_get(self) -> None:
        cache = GrepCache()
        errors: list[Exception] = []
        barrier = threading.Barrier(10)

        def worker(idx: int) -> None:
            try:
                barrier.wait(timeout=5)
                for j in range(100):
                    key = f"thread_{idx}_item_{j}"
                    cache.put(key, [f"v_{idx}_{j}"])
                    cache.get(key)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == []
        assert cache.size == 1000

    def test_concurrent_invalidate(self) -> None:
        cache = GrepCache()
        for i in range(200):
            cache.put(f"key_{i % 2}_hash{i}", [])

        errors: list[Exception] = []

        def invalidator() -> None:
            try:
                cache.invalidate_by_hash("_hash")
            except Exception as exc:
                errors.append(exc)

        def writer() -> None:
            try:
                for i in range(50):
                    cache.put(f"new_{i}", [])
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=invalidator)
        t2 = threading.Thread(target=writer)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)
        assert errors == []
