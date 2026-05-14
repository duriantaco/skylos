from skylos.core.result_cache import (
    TRACE_CACHE_DIR,
    build_trace_cache_key,
    load_trace_cache,
    save_trace_cache,
)


def test_trace_cache_key_is_stable_for_same_inputs(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    key1 = build_trace_cache_key(tmp_path, [tmp_path])
    key2 = build_trace_cache_key(tmp_path, [tmp_path])

    assert key1 == key2


def test_trace_cache_key_changes_for_relevant_content(tmp_path):
    app = tmp_path / "app.py"
    pyproject = tmp_path / "pyproject.toml"
    lockfile = tmp_path / "uv.lock"
    app.write_text("def f():\n    return 1\n", encoding="utf-8")
    pyproject.write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    lockfile.write_text("version = 1\n", encoding="utf-8")

    source_key = build_trace_cache_key(tmp_path, [tmp_path])
    app.write_text("def f():\n    return 2\n", encoding="utf-8")
    assert build_trace_cache_key(tmp_path, [tmp_path]) != source_key

    config_key = build_trace_cache_key(tmp_path, [tmp_path])
    pyproject.write_text(
        "[tool.pytest.ini_options]\naddopts = '-q'\n",
        encoding="utf-8",
    )
    assert build_trace_cache_key(tmp_path, [tmp_path]) != config_key

    lock_key = build_trace_cache_key(tmp_path, [tmp_path])
    lockfile.write_text("version = 2\n", encoding="utf-8")
    assert build_trace_cache_key(tmp_path, [tmp_path]) != lock_key


def test_corrupt_trace_cache_entry_is_a_miss(tmp_path):
    (tmp_path / "app.py").write_text("def f(): pass\n", encoding="utf-8")
    key = build_trace_cache_key(tmp_path, [tmp_path])
    cache_path = tmp_path / TRACE_CACHE_DIR / f"{key}.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text("{not-json", encoding="utf-8")

    assert load_trace_cache(tmp_path, key) is None


def test_trace_cache_save_and_load_round_trips_payload(tmp_path):
    (tmp_path / "app.py").write_text("def f(): pass\n", encoding="utf-8")
    key, fingerprint = build_trace_cache_key(
        tmp_path,
        [tmp_path],
        return_fingerprint=True,
    )
    payload = {
        "version": 1,
        "calls": [
            {
                "file": str(tmp_path / "app.py"),
                "function": "f",
                "line": 1,
                "count": 1,
            }
        ],
    }

    path = save_trace_cache(
        tmp_path,
        key,
        payload,
        pytest_returncode=0,
        fingerprint_summary=fingerprint,
    )
    entry = load_trace_cache(tmp_path, key)

    assert path is not None
    assert entry is not None
    assert entry["trace"] == payload
    assert entry["pytest_returncode"] == 0


def test_trace_cache_excludes_generated_directories(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "ignored.py").write_text("def ignored(): pass\n", encoding="utf-8")

    key = build_trace_cache_key(tmp_path, [tmp_path])
    (ignored / "ignored.py").write_text(
        "def ignored():\n    return 42\n",
        encoding="utf-8",
    )

    assert build_trace_cache_key(tmp_path, [tmp_path]) == key


def test_trace_cache_does_not_save_failed_trace_runs(tmp_path):
    payload = {"version": 1, "calls": []}
    path = save_trace_cache(
        tmp_path,
        "abc",
        payload,
        pytest_returncode=1,
        fingerprint_summary={},
    )

    assert path is None
    assert not (tmp_path / TRACE_CACHE_DIR / "abc.json").exists()
