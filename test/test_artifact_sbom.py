import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from tools.release.artifact_sbom import ENGINE_ARCNAME, make_sbom

METADATA = (
    b"Metadata-Version: 2.4\n"
    b"Name: skylos\nVersion: 5.8.0\n"
    b"Requires-Dist: Foo_Bar>=2; python_version >= '3.11'\n"
    b"Requires-Dist: test-helper; extra == 'test'\n"
)


def _write_sdist(path):
    with tarfile.open(path, "w:gz") as archive:
        for name, content in {
            "PKG-INFO": METADATA,
            "benchmarks/requirements.txt": b"fixture-dependency==0.1",
        }.items():
            info = tarfile.TarInfo(f"skylos-5.8.0/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


@pytest.mark.parametrize("filename", ["skylos.whl", "skylos.tar.gz"])
def test_python_sbom_matches_distribution_metadata_and_digest(tmp_path, filename):
    path = tmp_path / filename
    if path.suffix == ".whl":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("skylos-5.8.0.dist-info/METADATA", METADATA)
            archive.writestr("benchmarks/requirements.txt", "fixture-dependency==0.1")
    else:
        _write_sdist(path)
    bom = make_sbom(path)
    root = bom["metadata"]["component"]
    assert root["hashes"][0]["content"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert root["version"] == "5.8.0"
    dependencies = {item["name"]: item for item in bom["components"]}
    assert set(dependencies) == {"foo-bar", "test-helper"}
    assert "version" not in dependencies["foo-bar"]
    assert "python_version" in dependencies["foo-bar"]["properties"][0]["value"]
    assert bom["compositions"][0]["aggregate"] == "incomplete"


def test_native_wheel_sbom_reads_actual_embedded_go_build_info(tmp_path, monkeypatch):
    path = tmp_path / "skylos-platform.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("skylos-5.8.0.dist-info/METADATA", METADATA)
        archive.writestr(ENGINE_ARCNAME, "engine bytes")

    def read_build_info(command, **kwargs):
        from pathlib import Path
        from subprocess import CompletedProcess

        assert command[:4] == ["go", "version", "-m", "-json"]
        assert Path(command[-1]).read_text() == "engine bytes"
        return CompletedProcess(command, 0, json.dumps({"GoVersion": "go1.26.11"}))

    monkeypatch.setattr("tools.release.artifact_sbom.subprocess.run", read_build_info)
    bom = make_sbom(path)
    dependencies = {item["name"]: item for item in bom["components"]}
    assert dependencies["stdlib"]["version"] == "1.26.11"
    assert (
        dependencies["skylos-go"]["hashes"][0]["content"]
        == hashlib.sha256(b"engine bytes").hexdigest()
    )


def test_vsix_sbom_excludes_build_tools_and_includes_packaged_modules(tmp_path):
    path = tmp_path / "skylos.vsix"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "extension/package.json",
            json.dumps(
                {
                    "publisher": "oha",
                    "name": "skylos-vscode-extension",
                    "version": "0.6.1",
                    "dependencies": {"@example/runtime": "^2.0.0"},
                    "devDependencies": {"tooling": "^1.0.0"},
                }
            ),
        )
        archive.writestr(
            "extension/node_modules/@example/runtime/package.json",
            json.dumps(
                {
                    "name": "@example/runtime",
                    "version": "2.1.0",
                }
            ),
        )
    bom = make_sbom(path)
    assert [item["name"] for item in bom["components"]] == ["@example/runtime"]
    assert bom["dependencies"][0]["dependsOn"] == ["pkg:npm/%40example/runtime@2.1.0"]
