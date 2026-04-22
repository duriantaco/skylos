from importlib import metadata

import skylos


def test_resolve_version_prefers_installed_metadata(monkeypatch):
    monkeypatch.setattr(skylos, "_version_from_pyproject", lambda: None)
    monkeypatch.setattr(skylos.metadata, "version", lambda name: "9.9.9")

    assert skylos._resolve_version() == "9.9.9"


def test_resolve_version_falls_back_to_pyproject(monkeypatch):
    monkeypatch.setattr(skylos, "_version_from_pyproject", lambda: "4.4.1")

    assert skylos._resolve_version() == "4.4.1"


def test_resolve_version_returns_unknown_without_local_or_metadata(monkeypatch):
    def _raise_package_not_found(name):
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(skylos, "_version_from_pyproject", lambda: None)
    monkeypatch.setattr(skylos.metadata, "version", _raise_package_not_found)

    assert skylos._resolve_version() == "0+unknown"
