"""Regression tests for the npm mirror verification stage."""

import base64
import hashlib
import json
from pathlib import Path

from skylos.rules.sca.lockfile_types import LockfileInventory
from skylos.rules.sca.npm_mirror_candidates import add_npm_mirror_candidate
from skylos.rules.sca.npm_mirrors import _cache_directory, verify_npm_mirrors
from skylos.rules.sca.vulnerability_scanner import DependencyInventory
from skylos.supply_chain.policy import SupplyChainPolicy

_MIRROR = "https://mirror.example/npm"


class _UnusedTransport:
    def get(self, url, **kwargs):  # pragma: no cover - no identities to fetch
        raise AssertionError("no metadata request expected")


class _Response:
    def __init__(self, body):
        self.body = body
        self.status_code = 200
        self.headers = {}

    def iter_content(self, chunk_size=None):
        yield self.body

    def close(self):
        pass


class _Transport:
    def __init__(self, mapping):
        self.mapping = mapping
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return _Response(self.mapping.get(url, b""))


def _no_home(*_args, **_kwargs):
    raise RuntimeError("Could not determine home directory.")


def _integrity(data=b"artifact"):
    digest = hashlib.sha512(data).digest()
    return f"sha512-{base64.b64encode(digest).decode()}"


def _lock_with_candidate(name, version, integrity):
    lock = LockfileInventory(format_version=2)
    skipped = {"name": name, "reason": "non_registry_source", "source_type": "url"}
    lock.not_checked.append(skipped)
    dependency = {
        "name": name,
        "version": version,
        "ecosystem": "npm",
        "file": "/tmp/project/package-lock.json",
        "line": 3,
        "snippet": f"{name}@{version}",
        "lockfile_version": 3,
        "source_type": "external",
        "integrity": integrity,
    }
    add_npm_mirror_candidate(
        lock,
        path=Path("/tmp/project/package-lock.json"),
        text='{"lockfileVersion": 3}',
        occurrence_id=("npm", f"node_modules/{name}"),
        dependency=dependency,
        source_url=f"{_MIRROR}/{name}/-/{name}-{version}.tgz",
        not_checked=skipped,
    )
    return lock


def _metadata(name, version, integrity):
    return json.dumps(
        {"name": name, "version": version, "dist": {"integrity": integrity}}
    ).encode()


def test_cache_directory_without_home_is_disabled(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", _no_home)

    assert _cache_directory(tmp_path) is None


def test_verify_npm_mirrors_without_home_does_not_raise(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", _no_home)
    inventory = DependencyInventory()
    policy = SupplyChainPolicy(npm_registry_mirrors=(_MIRROR,))

    result = verify_npm_mirrors(tmp_path, inventory, policy, _UnusedTransport())

    assert result.receipt["status"] == "complete"
    assert result.proofs == {}


def test_verified_identity_is_cached_and_reused(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    project = tmp_path / "project"
    project.mkdir()
    integrity = _integrity()
    lock = _lock_with_candidate("left-pad", "1.3.0", integrity)
    transport = _Transport(
        {
            "https://registry.npmjs.org/left-pad/1.3.0": _metadata(
                "left-pad", "1.3.0", integrity
            )
        }
    )
    policy = SupplyChainPolicy(npm_registry_mirrors=(_MIRROR,))

    first = verify_npm_mirrors(
        project,
        DependencyInventory(npm_mirror_candidates=lock.npm_mirror_candidates),
        policy,
        transport,
    )
    cache_file = tmp_path / "cache" / "skylos" / "npm-mirror-identities.json"
    assert cache_file.is_file()

    second = verify_npm_mirrors(
        project,
        DependencyInventory(npm_mirror_candidates=lock.npm_mirror_candidates),
        policy,
        transport,
    )

    assert first.receipt["metadata_requests"] == 1
    assert second.receipt["metadata_requests"] == 0
    assert second.receipt["cache_hits"] == 1
    assert len(transport.urls) == 1
