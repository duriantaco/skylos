from skylos.rules.sca import vulnerability_scanner as sca


def test_parse_requirements_txt_rejects_symlink(tmp_path):
    target = tmp_path / "outside-requirements.txt"
    target.write_text("requests==2.31.0\n", encoding="utf-8")
    link = tmp_path / "requirements.txt"
    try:
        link.symlink_to(target)
    except OSError:
        return

    assert sca.parse_requirements_txt(link) == []


def test_scan_dependencies_rejects_symlinked_osv_cache_file(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    monkeypatch.setattr(sca, "_requests", object())

    def fake_query(deps, cache):
        cache["PyPI:requests:2.31.0"] = []
        return []

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "osv_cache.json"
    target.write_text('{"_ts": 9999999999, "PyPI:requests:2.31.0": []}', encoding="utf-8")
    cache_path = repo / ".skylos" / "cache" / "osv_cache.json"
    cache_path.parent.mkdir(parents=True)
    try:
        cache_path.symlink_to(target)
    except OSError:
        import pytest

        pytest.skip("filesystem does not allow symlink creation")

    findings = sca.scan_dependencies(repo)

    assert findings == []
    assert target.read_text(encoding="utf-8") == (
        '{"_ts": 9999999999, "PyPI:requests:2.31.0": []}'
    )
    assert cache_path.is_symlink()
