from pathlib import Path

import pytest

from skylos.scale import parallel_static


@pytest.mark.parametrize("jobs", [1, 3])
def test_go_workers_receive_only_the_admitted_source_scope(monkeypatch, tmp_path, jobs):
    import skylos.analyzer

    app = tmp_path / "app" / "main.go"
    provider = tmp_path / "provider" / "value.go"
    files = [app, tmp_path / "notes.py", provider]
    seen = {}

    def process(file, module, **kwargs):
        seen[Path(file)] = kwargs
        return module

    monkeypatch.setattr(skylos.analyzer, "proc_file", process)
    # Keep this test about source admission rather than process creation.
    monkeypatch.setattr(
        parallel_static,
        "_run_pool",
        lambda files, modmap, changed, jobs, worker, kwargs, progress: (
            {str(file): process(file, modmap[file], **kwargs) for file in files},
            [],
        ),
    )
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    result = parallel_static.run_proc_file_parallel(
        files,
        {file: str(index) for index, file in enumerate(files)},
        jobs=jobs,
        project_root=tmp_path,
    )
    assert result == ["0", "1", "2"]
    expected = (str(tmp_path), (str(app), str(provider)))
    assert seen[app]["go_scan_scope"] == expected
    assert seen[provider]["go_scan_scope"] == expected
    assert "go_scan_scope" not in seen[tmp_path / "notes.py"]


def test_direct_go_worker_preserves_the_supplied_scope(monkeypatch, tmp_path):
    from skylos.analysis import file_processing
    from skylos.analysis.file_worker import process_file

    source = tmp_path / "main.go"
    scope = (str(tmp_path), (str(source),))
    captured = []

    def scan(file, config, *, go_scan_scope=None):
        captured.append((file, go_scan_scope))
        return file_processing._scan_config_only_file(file, config)

    monkeypatch.setattr(file_processing, "scan_go_file", scan)
    process_file(source, "main", project_root=tmp_path, go_scan_scope=scope)
    assert captured == [(source, scope)]
