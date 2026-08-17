"""SKY-C401 clone-type labels must not depend on the interpreter hash seed.

`_group_connected` picks a group's clone type by majority vote over its pair
types. When that vote ties, the winner used to be decided by `set` iteration
order, which CPython randomizes per process via `PYTHONHASHSEED`, so identical
input could be reported as `type1` on one run and `type2` on the next.

The fixture below is reduced from `httpx/_api.py`, where the tie was first
observed: four request helpers whose bodies normalize identically (so every
pair is type2-similar), three of which share a keyword-only parameter order
(so those three pairs are also type1-similar). That splits the six pair votes
exactly 3/3.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from skylos.rules.quality import clones as clones_mod

HASH_SEEDS = ("0", "1", "2", "3", "4", "5", "6", "7")

CLONE_SOURCE = '''\
DEFAULT_TIMEOUT_CONFIG = 5.0


def request(method, url, **kwargs):
    return (method, url, kwargs)


def get(
    url,
    *,
    params=None,
    headers=None,
    cookies=None,
    auth=None,
    proxy=None,
    follow_redirects=False,
    timeout=DEFAULT_TIMEOUT_CONFIG,
    verify=True,
    trust_env=True,
):
    """Send a GET request."""
    return request(
        "GET",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        trust_env=trust_env,
    )


def options(
    url,
    *,
    params=None,
    headers=None,
    cookies=None,
    auth=None,
    proxy=None,
    follow_redirects=False,
    timeout=DEFAULT_TIMEOUT_CONFIG,
    verify=True,
    trust_env=True,
):
    """Send an OPTIONS request."""
    return request(
        "OPTIONS",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        trust_env=trust_env,
    )


def head(
    url,
    *,
    params=None,
    headers=None,
    cookies=None,
    auth=None,
    proxy=None,
    follow_redirects=False,
    timeout=DEFAULT_TIMEOUT_CONFIG,
    verify=True,
    trust_env=True,
):
    """Send a HEAD request."""
    return request(
        "HEAD",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        trust_env=trust_env,
    )


def delete(
    url,
    *,
    params=None,
    headers=None,
    cookies=None,
    auth=None,
    proxy=None,
    timeout=DEFAULT_TIMEOUT_CONFIG,
    follow_redirects=False,
    verify=True,
    trust_env=True,
):
    """Send a DELETE request."""
    return request(
        "DELETE",
        url,
        params=params,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=proxy,
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        trust_env=trust_env,
    )
'''

# Mirrors the CloneConfig the analyzer builds for --quality.
CLONE_CONFIG_KWARGS = {
    "grouping_mode": clones_mod.GroupingMode.CONNECTED,
    "grouping_threshold": 0.80,
    "k_core_k": 2,
    "similarity_threshold": 0.90,
    "ignore_identifiers": True,
    "ignore_literals": True,
    "skip_docstrings": True,
}

# Runs the same pipeline in a fresh interpreter so PYTHONHASHSEED takes effect.
CHILD_SCRIPT = """\
import sys
from pathlib import Path

from skylos.rules.quality import clones as clones_mod

clones_mod._fast_similarity = None
path = Path(sys.argv[1])
cfg = clones_mod.CloneConfig(
    grouping_mode=clones_mod.GroupingMode.CONNECTED,
    grouping_threshold=0.80,
    k_core_k=2,
    similarity_threshold=0.90,
    ignore_identifiers=True,
    ignore_literals=True,
    skip_docstrings=True,
)
fragments = clones_mod.extract_fragments(path, path.read_text(), cfg)
groups = clones_mod.group_pairs(clones_mod.detect_pairs(fragments, cfg), cfg)
print(groups[0].clone_type.value)
"""


def _group_tied_clone_fixture(tmp_path):
    """Run the clone pipeline over the fixture and return its single group."""
    source_path = tmp_path / "api.py"
    source_path.write_text(CLONE_SOURCE)
    cfg = clones_mod.CloneConfig(**CLONE_CONFIG_KWARGS)
    fragments = clones_mod.extract_fragments(source_path, CLONE_SOURCE, cfg)
    groups = clones_mod.group_pairs(clones_mod.detect_pairs(fragments, cfg), cfg)
    assert len(groups) == 1
    return groups[0], fragments, cfg


def test_fixture_splits_pair_votes_evenly(tmp_path, monkeypatch):
    """The fixture must actually tie, or the determinism tests prove nothing."""
    monkeypatch.setattr(clones_mod, "_fast_similarity", None)
    group, fragments, cfg = _group_tied_clone_fixture(tmp_path)

    assert sorted(f.name for f in group.fragments) == [
        "delete",
        "get",
        "head",
        "options",
    ]

    votes = []
    for i in range(len(fragments)):
        for j in range(i + 1, len(fragments)):
            result = clones_mod.classify_clone(fragments[i], fragments[j], cfg)
            if result:
                votes.append(result[0])
    assert votes.count(clones_mod.CloneType.TYPE1) == 3
    assert votes.count(clones_mod.CloneType.TYPE2) == 3


def test_tied_vote_prefers_the_stricter_clone_type(tmp_path, monkeypatch):
    """A tie resolves to the lowest clone type, not to whatever `set` yields."""
    monkeypatch.setattr(clones_mod, "_fast_similarity", None)
    group, _, _ = _group_tied_clone_fixture(tmp_path)

    assert group.clone_type is clones_mod.CloneType.TYPE1


def test_tied_vote_is_stable_across_hash_seeds(tmp_path):
    """Identical input must yield one clone type for every PYTHONHASHSEED."""
    source_path = tmp_path / "api.py"
    source_path.write_text(CLONE_SOURCE)
    script_path = tmp_path / "vote.py"
    script_path.write_text(CHILD_SCRIPT)
    repo_root = Path(clones_mod.__file__).resolve().parents[3]

    observed = {}
    for seed in HASH_SEEDS:
        completed = subprocess.run(
            [sys.executable, str(script_path), str(source_path)],
            capture_output=True,
            check=False,
            cwd=tmp_path,
            env={"PATH": "", "PYTHONHASHSEED": seed, "PYTHONPATH": str(repo_root)},
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            pytest.fail(
                f"clone grouping failed at PYTHONHASHSEED={seed}: "
                f"{textwrap.shorten(completed.stderr.strip(), 500)}"
            )
        observed[seed] = completed.stdout.strip()

    assert set(observed.values()) == {"type1"}, (
        f"clone type varied with the hash seed: {observed}"
    )
