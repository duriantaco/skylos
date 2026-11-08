"""SKY-SCA-API001: your lines that use API a Python upgrade removed.

Expected results come from the feature's contract, not from scanner output.
Every package here is a small fixture; nothing reaches the network. Repository
tests go through the real ``ca9.artifacts`` digest check and unpacker with the
registry calls replaced.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from rich.console import Console

import skylos.cli as cli
import skylos.core.gatekeeper as gk
from skylos import api
from skylos.cicd.pr_summary import (
    SummaryInputs,
    _upgrade_api_lines,
    brief_lines,
    upgrade_api_receipt,
)
from skylos.cicd.workflow import generate_workflow
from skylos.commands.setup_cmd import write_ci
from skylos.config import load_config
from skylos.rules.sca import supply_chain_diff as diff
from skylos.rules.sca import upgrade_api_diff
from skylos.rules.sca.python_package_surface import build_surface
from skylos.rules.sca.supply_chain_diff import (
    open_sides,
    supply_chain_diff_findings,
)
from skylos.rules.sca.python_api_references import references_in_source
from skylos.rules.sca.upgrade_api_compare import compare_reference
from skylos.rules.sca.upgrade_api_diff import upgrade_api_findings

REAL_LOAD_CA9 = upgrade_api_diff._load_ca9
CLEAN = "No API-level impact found in {} call sites (behaviour changes not checked)"
REVIEW = "Review these {} call sites"


def _surface(tmp_path, tag, files, kind="wheel"):
    base = tmp_path / tag
    rows = []
    for relative, text in files.items():
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        rows.append(
            SimpleNamespace(
                relative_path=relative, path=path, size=path.stat().st_size
            )
        )
    return build_surface(rows, kind=kind)


def _outcome(tmp_path, old_files, new_files, source, *, root="pkg", kind="wheel"):
    old = _surface(tmp_path, "old", old_files, kind)
    new = _surface(tmp_path, "new", new_files, kind)
    removed = []
    unknown = []
    ok = 0
    for reference in references_in_source("user.py", source).get(root, set()):
        verdict = compare_reference(reference, old, new)
        if verdict.status == "removed" and not reference.guarded:
            removed.append((reference.line, verdict.symbol))
        elif verdict.status == "unknown":
            unknown.append(verdict.reason)
        elif verdict.status in {"ok", "removed"}:
            ok += 1
    return sorted(removed), unknown, ok


GONE = {"pkg/__init__.py": "def gone(): ...\ndef kept(): ...\n"}
KEPT = {"pkg/__init__.py": "def kept(): ...\n"}
POOL_OLD = {
    "pkg/__init__.py": "from .pool import Pool\n",
    "pkg/pool.py": (
        "class Conn:\n"
        "    def __init__(self, host, strict=False, retries=1): ...\n"
        "class Pool:\n"
        "    def __init__(self, host, strict=False, **conn_kw):\n"
        "        self.conn_kw = conn_kw\n"
        "    def connect(self):\n"
        "        return Conn(self.host, **self.conn_kw)\n"
    ),
}
POOL_NEW = {
    "pkg/__init__.py": "from .pool import Pool\n",
    "pkg/pool.py": (
        "class Conn:\n"
        "    def __init__(self, host, retries=1): ...\n"
        "class Pool:\n"
        "    ConnectionCls = Conn\n"
        "    def __init__(self, host, **conn_kw):\n"
        "        self.conn_kw = conn_kw\n"
        "    def connect(self):\n"
        "        return self.ConnectionCls(self.host, **self.conn_kw)\n"
    ),
}


@pytest.mark.parametrize(
    ("old_files", "new_files", "source", "expected"),
    [
        pytest.param(GONE, KEPT, "from pkg import gone\n", [(1, "pkg.gone")], id="from-import"),
        pytest.param(
            GONE,
            KEPT,
            "from pkg import gone as g\n\ng()\n",
            [(1, "pkg.gone"), (3, "pkg.gone")],
            id="from-import-alias-and-its-call",
        ),
        pytest.param(GONE, KEPT, "import pkg as p\n\np.gone()\n", [(3, "pkg.gone")], id="module-alias"),
        pytest.param(GONE, KEPT, 'import pkg\n\ngetattr(pkg, "gone")\n', [(3, "pkg.gone")], id="getattr"),
        pytest.param(
            GONE,
            KEPT,
            'import importlib\n\nm = importlib.import_module("pkg")\nm.gone()\n',
            [(4, "pkg.gone")],
            id="import-module-literal",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/sub.py": "def f(): ...\n"},
            {"pkg/__init__.py": ""},
            "from pkg.sub import f\n",
            [(1, "pkg.sub")],
            id="module-removed",
        ),
        pytest.param(
            {"pkg/__init__.py": "class C:\n    def m(self): ...\n    def n(self): ...\n"},
            {"pkg/__init__.py": "class C:\n    def n(self): ...\n"},
            "import pkg\n\nc = pkg.C()\nc.n()\nc.m()\n",
            [(5, "pkg.C.m")],
            id="method-on-instance",
        ),
        pytest.param(
            {"pkg/__init__.py": "class B:\n    def m(self): ...\nclass C(B): ...\n"},
            {"pkg/__init__.py": "class B: ...\nclass C(B): ...\n"},
            "import pkg\n\nwith pkg.C() as c:\n    c.m()\n",
            [(4, "pkg.C.m")],
            id="inherited-method-through-with",
        ),
        pytest.param(
            {"pkg/__init__.py": "def f(a, b=1): ...\n"},
            {"pkg/__init__.py": "def f(a): ...\n"},
            "import pkg\n\npkg.f(1, b=2)\npkg.f(1)\n",
            [(3, "pkg.f(b=)")],
            id="keyword-removed",
        ),
        pytest.param(
            POOL_OLD,
            POOL_NEW,
            'import pkg\n\npkg.Pool("h", strict=True)\npkg.Pool("h", retries=2)\n',
            [(3, "pkg.Pool(strict=)")],
            id="keyword-into-kwargs-forwarded-to-a-class-without-it",
        ),
        pytest.param(
            {"pkg/__init__.py": "from dataclasses import dataclass\n@dataclass\nclass D:\n    a: int\n    b: int\n"},
            {"pkg/__init__.py": "from dataclasses import dataclass\n@dataclass\nclass D:\n    a: int\n"},
            "import pkg\n\npkg.D(a=1, b=2)\n",
            [(3, "pkg.D(b=)")],
            id="dataclass-field-removed",
        ),
        pytest.param(
            {"pkg/__init__.py": "__all__ = ['a', 'b']\na = 1\nb = 2\n"},
            {"pkg/__init__.py": "__all__ = ['a']\na = 1\nb = 2\n"},
            "from pkg import *\n\nprint(a, b)\n",
            [(3, "pkg.b")],
            id="your-star-import-loses-a-name",
        ),
        pytest.param(
            {"pkg/__init__.py": "def gone(): ...\ndef __getattr__(name):\n    if name == '__version__':\n        return '1'\n    raise AttributeError(name)\n"},
            {"pkg/__init__.py": "def __getattr__(name):\n    if name == '__version__':\n        return '1'\n    raise AttributeError(name)\n"},
            "from pkg import gone\n",
            [(1, "pkg.gone")],
            id="getattr-that-handles-only-literals-proves-removal",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/fast.so": "", "pkg/fast.pyi": "def gone(): ...\ndef kept(): ...\n"},
            {"pkg/__init__.py": "", "pkg/fast.so": "", "pkg/fast.pyi": "def kept(): ...\n"},
            "from pkg.fast import gone, kept\n",
            [(1, "pkg.fast.gone")],
            id="compiled-module-read-from-its-stub",
        ),
    ],
)
def test_removed_api_is_reported_at_your_line(
    tmp_path, old_files, new_files, source, expected
):
    removed, unknown, _ok = _outcome(tmp_path, old_files, new_files, source)

    assert removed == expected
    assert unknown == []


@pytest.mark.parametrize(
    ("old_files", "new_files", "source"),
    [
        pytest.param(KEPT, KEPT, "import pkg\nfrom pkg import kept\n\npkg.kept()\nkept()\n", id="no-change"),
        pytest.param(GONE, KEPT, 'def gone(x):\n    return x\n\n\ngone("x")\n', id="local-function"),
        pytest.param(GONE, KEPT, "gone = print\ngone(1)\n", id="local-variable"),
        pytest.param(GONE, KEPT, "from .pkg import gone\n", id="relative-import-is-yours"),
        pytest.param(GONE, KEPT, "import pkg as p\n\n\ndef f(p):\n    return p.gone()\n", id="parameter-shadows-alias"),
        pytest.param(GONE, KEPT, "import pkg as p\n\n\ndef f():\n    p = object()\n    return p.gone()\n", id="local-shadows-alias"),
        pytest.param(GONE, KEPT, "import pkg as p\n\np = object()\np.gone()\n", id="alias-rebound-in-the-same-scope"),
        pytest.param(GONE, KEPT, "try:\n    from pkg import gone\nexcept ImportError:\n    gone = None\n\ngone()\n", id="guarded-import"),
        pytest.param(GONE, KEPT, 'import pkg\n\nif hasattr(pkg, "gone"):\n    pkg.gone()\n', id="hasattr-guard"),
        pytest.param(GONE, KEPT, 'import pkg\n\ngetattr(pkg, "gone", None)\n', id="getattr-default"),
        pytest.param(
            GONE,
            {"pkg/__init__.py": "from ._impl import gone\nfrom ._impl import kept\n", "pkg/_impl.py": "def gone(): ...\ndef kept(): ...\n"},
            "from pkg import gone\n",
            id="moved-behind-re-export",
        ),
        pytest.param(
            GONE,
            {"pkg/__init__.py": "from ._impl import *\n", "pkg/_impl.py": "def gone(): ...\ndef kept(): ...\n"},
            "from pkg import gone\n",
            id="moved-behind-star-import",
        ),
        pytest.param(
            GONE,
            {"pkg/__init__.py": "from ._impl import *\n", "pkg/_impl.py": "__all__ = ['gone', 'kept']\ndef gone(): ...\ndef kept(): ...\n"},
            "from pkg import gone\n",
            id="moved-behind-star-import-with-all",
        ),
        pytest.param(
            {"pkg/__init__.py": "__all__ = ['a', 'b']\na = 1\nb = 2\n"},
            {"pkg/__init__.py": "__all__ = ['a']\na = 1\nb = 2\n"},
            "from pkg import b\n",
            id="dropped-from-all-but-still-importable",
        ),
        pytest.param(
            {"pkg/__init__.py": "def _hidden(): ...\n", "pkg/_impl.py": "def x(): ...\n"},
            {"pkg/__init__.py": ""},
            "from pkg import _hidden\nimport pkg\n\npkg._hidden()\nfrom pkg._impl import x\n",
            id="underscore-private-is-not-public",
        ),
        pytest.param(KEPT, KEPT, "from pkg import never_existed\n", id="not-in-the-old-version"),
        pytest.param(
            {"pkg/__init__.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from other import Y\n"},
            {"pkg/__init__.py": ""},
            "from pkg import Y\n",
            id="type-checking-only-name-never-existed-at-runtime",
        ),
        pytest.param(
            {"pkg/__init__.py": "def f(a, b=1): ...\n"},
            {"pkg/__init__.py": "def f(a, **kw):\n    return kw.pop('b', None)\n"},
            "import pkg\n\npkg.f(1, b=2)\n",
            id="keyword-read-from-kwargs",
        ),
        pytest.param(
            {"pkg/__init__.py": "def f(a, b=1): ...\n"},
            {"pkg/__init__.py": "def f(a, **kw):\n    return g(a, **kw)\ndef g(a, b=1): ...\n"},
            "import pkg\n\npkg.f(1, b=2)\n",
            id="keyword-forwarded-to-a-function-naming-it",
        ),
        pytest.param(
            {"pkg/__init__.py": "class C:\n    def __init__(self, a, b=1): ...\n"},
            {"pkg/__init__.py": "class B:\n    def __init__(self, a, b=1): ...\nclass C(B):\n    def __init__(self, a, **kw):\n        super().__init__(a, **kw)\n"},
            "import pkg\n\npkg.C(1, b=2)\n",
            id="keyword-forwarded-through-super",
        ),
        pytest.param(
            {"pkg/__init__.py": "class C:\n    def m(self): ...\n"},
            {"pkg/__init__.py": "class B:\n    def m(self): ...\nclass C(B): ...\n"},
            "import pkg\n\npkg.C().m()\n",
            id="method-moved-to-a-base-class",
        ),
        pytest.param(
            {"pkg/__init__.py": "class C:\n    def __init__(self):\n        self.x = 1\n"},
            {"pkg/__init__.py": "class C:\n    x = 1\n"},
            "import pkg\n\npkg.C().x\n",
            id="instance-attribute-became-class-attribute",
        ),
        pytest.param(
            {"pkg/__init__.py": "import sys\nif sys.version_info >= (3, 12):\n    def f(): ...\nelse:\n    def f(): ...\n"},
            {"pkg/__init__.py": "try:\n    from ._fast import f\nexcept ImportError:\n    from ._slow import f\n", "pkg/_slow.py": "def f(): ...\n"},
            "import pkg\n\npkg.f()\n",
            id="conditional-definitions",
        ),
    ],
)
def test_lookalikes_and_unchanged_api_are_not_reported(
    tmp_path, old_files, new_files, source
):
    removed, unknown, _ok = _outcome(tmp_path, old_files, new_files, source)

    assert removed == []
    assert unknown == []


DYNAMIC_GETATTR = "_LAZY = {'thing': 1}\ndef __getattr__(name):\n    return _LAZY[name]\n"
DYNAMIC_ALL = "def thing(): ...\n__all__ = [n for n in dir() if not n.startswith('_')]\n"


@pytest.mark.parametrize(
    ("old_files", "new_files", "source", "reason"),
    [
        pytest.param(
            {"pkg/__init__.py": DYNAMIC_GETATTR},
            {"pkg/__init__.py": DYNAMIC_GETATTR},
            "from pkg import thing\n",
            "__getattr__",
            id="name-through-module-getattr",
        ),
        pytest.param(
            {"pkg/__init__.py": "def thing(): ...\n"},
            {"pkg/__init__.py": DYNAMIC_GETATTR},
            "from pkg import thing\n",
            "__getattr__",
            id="old-static-new-module-getattr",
        ),
        pytest.param(
            {"pkg/__init__.py": "def __getattr__(name):\n    if name == 'thing':\n        return 1\n    raise AttributeError(name)\n"},
            {"pkg/__init__.py": ""},
            "from pkg import thing\n",
            "__getattr__",
            id="literal-module-getattr-providing-the-name",
        ),
        pytest.param(
            {"pkg/__init__.py": DYNAMIC_ALL},
            {"pkg/__init__.py": DYNAMIC_ALL},
            "from pkg import thing\n",
            "__all__",
            id="dynamic-all-on-both-sides",
        ),
        pytest.param(
            {"pkg/__init__.py": "def thing(): ...\n"},
            {"pkg/__init__.py": "__all__ = list(load())\n"},
            "from pkg import thing\n",
            "__all__",
            id="dynamic-all-on-the-new-side",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/fast.so": ""},
            {"pkg/__init__.py": "", "pkg/fast.so": ""},
            "from pkg.fast import thing\n",
            "compiled",
            id="compiled-only-module",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/fast.py": "def thing(): ...\n"},
            {"pkg/__init__.py": "", "pkg/fast.cpython-311-x86_64-linux-gnu.so": ""},
            "from pkg.fast import thing\n",
            "compiled",
            id="python-module-became-compiled-only",
        ),
        pytest.param(
            {"pkg/__init__.py": "def thing(): ...\n"},
            {"pkg/__init__.py": "from elsewhere import *\n"},
            "from pkg import thing\n",
            "star import",
            id="star-import-from-outside-the-package",
        ),
        pytest.param(
            {"pkg/__init__.py": "def thing(): ...\n"},
            {"pkg/__init__.py": "globals().update(load())\n"},
            "from pkg import thing\n",
            "globals",
            id="names-written-through-globals",
        ),
        pytest.param(
            {"pkg/__init__.py": "def thing(): ...\n"},
            {"pkg/__init__.py": "import sys\nsys.modules[__name__] = make()\n"},
            "from pkg import thing\n",
            "sys.modules",
            id="module-replaces-itself",
        ),
        pytest.param(
            {"pkg/__init__.py": "def thing(): ...\n"},
            {"pkg/__init__.py": "def thing(:\n"},
            "from pkg import thing\n",
            "parsed",
            id="new-source-does-not-parse",
        ),
        pytest.param(
            {"pkg/__init__.py": "class C:\n    def m(self): ...\n"},
            {"pkg/__init__.py": "class C:\n    def __getattr__(self, name): ...\n"},
            "import pkg\n\npkg.C().m()\n",
            "__getattr__",
            id="class-getattr",
        ),
        pytest.param(
            {"pkg/__init__.py": "class C:\n    def m(self): ...\n"},
            {"pkg/__init__.py": "from other import Base\nclass C(Base): ...\n"},
            "import pkg\n\npkg.C().m()\n",
            "inherits",
            id="method-may-come-from-an-outside-base-class",
        ),
        pytest.param(
            {"pkg/__init__.py": "def f(a, b=1): ...\n"},
            {"pkg/__init__.py": "from other import g\ndef f(a, **kw):\n    return g(a, **kw)\n"},
            "import pkg\n\npkg.f(1, b=2)\n",
            "signature",
            id="keyword-forwarded-outside-the-package",
        ),
        pytest.param(
            {"pkg/__init__.py": "def f(a, b=1): ...\n"},
            {"pkg/__init__.py": "@wrap\ndef f(a): ...\n"},
            "import pkg\n\npkg.f(1, b=2)\n",
            "signature",
            id="unknown-decorator-may-accept-the-keyword",
        ),
    ],
)
def test_what_cannot_be_read_is_unknown_never_removed(
    tmp_path, old_files, new_files, source, reason
):
    removed, unknown, _ok = _outcome(tmp_path, old_files, new_files, source)

    assert removed == []
    assert len(unknown) == 1
    assert reason in unknown[0]


def test_keyword_through_kwargs_on_both_versions_is_counted_but_not_followed(tmp_path):
    files = {"pkg/__init__.py": "from other import g\ndef f(a, **kw):\n    return g(a, **kw)\n"}

    removed, unknown, ok = _outcome(tmp_path, files, files, "import pkg\n\npkg.f(1, b=2)\n")

    assert (removed, unknown, ok) == ([], [], 2)


def test_sdist_layout_is_read_from_its_source_folder(tmp_path):
    old = {
        "Pkg-1.0/setup.py": "raise SystemExit('never run')\n",
        "Pkg-1.0/tests/test_x.py": "def gone(): ...\n",
        "Pkg-1.0/src/pkg/__init__.py": "def gone(): ...\n",
    }
    new = {
        "Pkg-2.0/setup.py": "raise SystemExit('never run')\n",
        "Pkg-2.0/tests/test_x.py": "def gone(): ...\n",
        "Pkg-2.0/src/pkg/__init__.py": "def kept(): ...\n",
    }

    removed, unknown, _ok = _outcome(
        tmp_path, old, new, "from pkg import gone\nimport tests\n", kind="sdist"
    )

    assert removed == [(1, "pkg.gone")]
    assert unknown == []


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def _uv_lock(name: str, version: str) -> str:
    return (
        'version = 1\nrequires-python = ">=3.11"\n\n[[package]]\n'
        f'name = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )


def _repo(root: Path, code: dict[str, str], lock_name: str, old: str, new: str) -> Path:
    for name, text in {**code, lock_name: old}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "checkout", "-qb", "bump")
    (root / lock_name).write_text(new, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "bump")
    return root


def _wheel_bytes(name: str, version: str, files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for relative, text in files.items():
            archive.writestr(relative, text)
        archive.writestr(f"{name}-{version}.dist-info/METADATA", f"Name: {name}\n")
    return buffer.getvalue()


@pytest.fixture
def registry(monkeypatch):
    """A registry serving fixture wheels through the real digest check and unpack."""
    pytest.importorskip("ca9.artifacts")
    from ca9.artifacts import fetch, releases

    published: dict[tuple[str, str], bytes] = {}
    by_url: dict[str, bytes] = {}
    state = SimpleNamespace(lookups=[], publish=None)

    def publish(name: str, version: str, files: dict[str, str]) -> None:
        published[(name, version)] = _wheel_bytes(name, version, files)

    def entries(name, version, registry_url, config):
        state.lookups.append((name, version))
        raw = published[(name, version)]
        filename = f"{name}-{version}-py3-none-any.whl"
        url = f"https://files.pythonhosted.org/fixture/{filename}"
        by_url[url] = raw
        return [
            releases._entry(
                filename, url, hashlib.sha256(raw).hexdigest(), len(raw), "wheel"
            )
        ]

    def download(url, archive_path, max_bytes, policy=None):
        Path(archive_path).write_bytes(by_url[url])

    state.publish = publish
    monkeypatch.setattr(upgrade_api_diff, "_load_ca9", REAL_LOAD_CA9)
    monkeypatch.setattr(releases, "pypi_release_entries", entries)
    monkeypatch.setattr(fetch, "_download_artifact", download)
    return state


def _check(repo: Path) -> tuple[list[dict], dict, list]:
    sides = open_sides(repo, "main")
    receipt: dict = {}
    errors: list = []
    findings = upgrade_api_findings(sides, None, receipt, errors)
    return findings, receipt, errors


def _sites(findings: list[dict], repo: Path) -> list[tuple[str, int, str]]:
    return sorted(
        (
            str(Path(item["file"]).relative_to(repo)),
            item["line"],
            item["metadata"]["symbol"],
        )
        for item in findings
    )


BUMP = ("uv.lock", _uv_lock("pkg", "1.0"), _uv_lock("pkg", "2.0"))


def test_a_locked_upgrade_names_your_lines(tmp_path, registry):
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path,
        {
            "app/a.py": "from pkg import gone\n",
            "app/b.py": "import pkg as p\n\np.gone()\np.kept()\n",
            "app/c.py": "def gone():\n    return 1\n\n\ngone()\n",
            "vendor/pkg_copy.py": "from pkg import gone\n",
        },
        *BUMP,
    )

    findings, receipt, errors = _check(repo)

    assert _sites(findings, repo) == [
        ("app/a.py", 1, "pkg.gone"),
        ("app/b.py", 3, "pkg.gone"),
    ]
    finding = findings[0]
    assert finding["rule_id"] == "SKY-SCA-API001"
    assert finding["severity"] == "MEDIUM"
    assert finding["kind"] == diff.FINDING_KIND
    assert "2.0" in finding["message"] and "pkg.gone" in finding["message"]
    assert errors == []
    assert receipt["status"] == "complete"
    assert receipt["review_sites"] == 2
    assert _upgrade_api_lines(receipt)[0] == f"- {REVIEW.format(2)}"
    assert "- `app/a.py:1` · `pkg.gone` removed in pkg 2.0" in " ".join(
        _upgrade_api_lines(receipt)
    ).replace("  - ", "- ")


def test_a_skylos_ignore_comment_silences_that_line_only(tmp_path, registry):
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path,
        {
            "app/a.py": "from pkg import gone  # skylos: ignore[SKY-SCA-API001] tracked in JIRA\n",
            "app/b.py": "from pkg import gone  # skylos: ignore[SKY-D215] another rule\n",
            "app/c.py": "from pkg import gone  # noqa: F401\n",
        },
        *BUMP,
    )

    findings, receipt, _errors = _check(repo)

    assert _sites(findings, repo) == [
        ("app/b.py", 1, "pkg.gone"),
        ("app/c.py", 1, "pkg.gone"),
    ]
    assert receipt["call_sites"] == 3


def test_underscore_private_uses_are_counted_apart_and_dunders_are_not_mentioned(
    tmp_path, registry
):
    registry.publish("pkg", "1.0", {"pkg/__init__.py": "def _hidden(): ...\n__version__ = '1'\ndef kept(): ...\n"})
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path,
        {"app.py": "import pkg\nfrom pkg import _hidden\n\nprint(pkg.__version__)\npkg.kept()\n"},
        *BUMP,
    )

    findings, receipt, _errors = _check(repo)

    assert findings == []
    assert _upgrade_api_lines(receipt) == [
        f"- {CLEAN.format(2)}",
        "- 1 uses of underscore-private names were not compared",
    ]


def test_requirements_pins_are_compared_too(tmp_path, registry):
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path,
        {"app.py": "from pkg import gone\n"},
        "requirements.txt",
        "pkg==1.0\nother>=2\n",
        "pkg==2.0\nother>=2\n",
    )

    findings, receipt, _errors = _check(repo)

    assert _sites(findings, repo) == [("app.py", 1, "pkg.gone")]
    assert receipt["could_not_check"] == []


def test_a_requirements_file_with_a_custom_index_is_not_looked_up(tmp_path, registry):
    repo = _repo(
        tmp_path,
        {"app.py": "from pkg import gone\n"},
        "requirements.txt",
        "--index-url https://corp.example/simple\npkg==1.0\n",
        "--index-url https://corp.example/simple\npkg==2.0\n",
    )

    findings, receipt, _errors = _check(repo)

    assert findings == []
    assert registry.lookups == []
    assert "custom package index" in receipt["could_not_check"][0]["reason"]


def test_unchanged_api_says_no_impact_and_counts_the_sites(tmp_path, registry):
    registry.publish("pkg", "1.0", KEPT)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path, {"app.py": "from pkg import kept\n\nkept()\n"}, *BUMP
    )

    findings, receipt, _errors = _check(repo)

    assert findings == []
    assert _upgrade_api_lines(receipt) == [f"- {CLEAN.format(2)}"]


def test_a_locked_package_nothing_imports_is_not_used_with_zero_sites(
    tmp_path, registry
):
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path, {"app.py": "def gone():\n    return 1\n\n\ngone()\n"}, *BUMP
    )

    findings, receipt, _errors = _check(repo)

    assert findings == []
    assert receipt["packages"][0]["status"] == "not_used"
    assert receipt["call_sites"] == 0
    assert _upgrade_api_lines(receipt) == [
        f"- {CLEAN.format(0)}",
        "- `pkg` 1.0 to 2.0: not used, 0 call sites",
    ]


def test_your_own_module_with_the_same_name_is_not_the_package(tmp_path, registry):
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path,
        {"pkg/__init__.py": "def gone(): ...\n", "app.py": "from pkg import gone\n"},
        *BUMP,
    )

    findings, receipt, _errors = _check(repo)

    assert findings == []
    assert receipt["packages"][0]["status"] == "not_used"


def test_package_code_is_never_run(tmp_path, registry):
    sentinel = tmp_path / "ran.txt"
    hostile = (
        f"open({str(sentinel)!r}, 'w').write('ran')\n"
        "def kept(): ...\n"
    )
    registry.publish(
        "pkg", "1.0", {"pkg/__init__.py": hostile, "setup.py": hostile}
    )
    registry.publish("pkg", "2.0", {"pkg/__init__.py": hostile})
    repo = _repo(tmp_path / "repo", {"app.py": "from pkg import kept\n"}, *BUMP)

    _check(repo)

    assert not sentinel.exists()
    assert "pkg" not in sys.modules


def _assert_could_not_check(receipt: dict, errors: list, text: str) -> None:
    lines = _upgrade_api_lines(receipt)
    assert errors == []
    assert not any("No API-level impact" in line for line in lines)
    assert any(line.startswith("- Could not check") and text in line for line in lines)


def test_a_failed_download_says_could_not_check(tmp_path, registry, monkeypatch):
    from ca9.artifacts import fetch

    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)

    def refuse(*_args, **_kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(fetch, "_download_artifact", refuse)
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)

    findings, receipt, errors = _check(repo)

    assert findings == []
    assert receipt["status"] == "partial"
    _assert_could_not_check(receipt, errors, "connection refused")


def test_a_failed_release_lookup_says_could_not_check(tmp_path, registry, monkeypatch):
    from ca9.artifacts import releases

    def refuse(*_args, **_kwargs):
        raise ValueError("cannot reach pypi.org")

    monkeypatch.setattr(releases, "pypi_release_entries", refuse)
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)

    findings, receipt, errors = _check(repo)

    assert findings == []
    _assert_could_not_check(receipt, errors, "cannot reach pypi.org")


def test_a_release_with_no_comparable_file_says_could_not_check(
    tmp_path, registry, monkeypatch
):
    from ca9.artifacts import releases

    monkeypatch.setattr(releases, "select_pypi_pair", lambda *_args: None)
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)

    findings, receipt, errors = _check(repo)

    assert findings == []
    _assert_could_not_check(receipt, errors, "no wheel or sdist")


def test_an_archive_ca9_refuses_says_could_not_check(tmp_path, registry):
    registry.publish("pkg", "1.0", {"../escape.py": "x = 1\n", "pkg/__init__.py": ""})
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)

    findings, receipt, errors = _check(repo)

    assert findings == []
    _assert_could_not_check(receipt, errors, "traversal")


def test_without_ca9_every_change_says_could_not_check(tmp_path):
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)

    findings, receipt, errors = _check(repo)

    assert findings == []
    _assert_could_not_check(receipt, errors, "ca9.artifacts is not installed")


def test_a_dynamic_package_in_a_repository_is_never_clean(tmp_path, registry):
    registry.publish("pkg", "1.0", {"pkg/__init__.py": DYNAMIC_ALL})
    registry.publish("pkg", "2.0", {"pkg/__init__.py": DYNAMIC_ALL})
    repo = _repo(tmp_path, {"app.py": "from pkg import thing\n"}, *BUMP)

    findings, receipt, errors = _check(repo)

    assert findings == []
    assert receipt["call_sites"] == 0
    _assert_could_not_check(receipt, errors, "computes")


def test_a_locked_package_from_a_private_index_is_not_looked_up(tmp_path, registry):
    def lock(version):
        return (
            'version = 1\nrequires-python = ">=3.11"\n\n[[package]]\n'
            f'name = "corp"\nversion = "{version}"\n'
            'source = { registry = "https://corp.example/simple" }\n'
        )

    repo = _repo(
        tmp_path, {"app.py": "from corp import gone\n"}, "uv.lock", lock("1.0"), lock("2.0")
    )

    findings, receipt, errors = _check(repo)

    assert findings == []
    assert registry.lookups == []
    _assert_could_not_check(receipt, errors, "non-public")


def test_your_file_that_does_not_parse_blocks_the_clean_wording_only_if_it_names_the_package(
    tmp_path, registry
):
    registry.publish("pkg", "1.0", KEPT)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(
        tmp_path,
        {
            "app.py": "from pkg import kept\n",
            "legacy.py": "print 'no pkg here'\n",
            "other.py": "print 'unrelated'\n",
        },
        *BUMP,
    )

    _findings, receipt, errors = _check(repo)

    _assert_could_not_check(receipt, errors, "legacy.py")
    assert not any("other.py" in str(row) for row in receipt["could_not_check"])


def test_npm_and_unread_lockfiles_say_could_not_check(tmp_path, registry):
    lock = (
        '{"name": "x", "lockfileVersion": 3, "packages": '
        '{"node_modules/left-pad": {"version": "%s", '
        '"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-%s.tgz", '
        '"integrity": "sha512-aaaa"}}}'
    )
    repo = _repo(
        tmp_path,
        {"pdm.lock": "a\n"},
        "package-lock.json",
        lock % ("1.0.0", "1.0.0"),
        lock % ("1.1.0", "1.1.0"),
    )
    (repo / "pdm.lock").write_text("b\n", encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path fixture
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pdm")

    findings, receipt, errors = _check(repo)

    assert findings == []
    assert errors == []
    reasons = " ".join(row["reason"] for row in receipt["could_not_check"])
    assert "only Python package APIs" in reasons
    assert "pdm.lock" in reasons
    assert registry.lookups == []


def test_internal_packages_are_never_looked_up(tmp_path, registry):
    repo = _repo(
        tmp_path,
        {
            "app.py": "from pkg import gone\n",
            "pyproject.toml": '[tool.skylos.supply_chain]\ninternal_packages = ["pkg"]\n',
        },
        *BUMP,
    )

    findings, receipt, errors = _check(repo)

    assert findings == []
    assert registry.lookups == []
    _assert_could_not_check(receipt, errors, "internal package")


def test_it_runs_inside_review_upgrades_only_and_never_stops_the_gate(tmp_path):
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)
    engine = SimpleNamespace(
        review_upgrades=lambda pairs, options=None: {
            "results": [
                {**pair, "status": "reviewed", "complete": True} for pair in pairs
            ],
            "receipt": {"complete": True},
        }
    )

    _found, off, _errors = supply_chain_diff_findings(
        repo, "main", dependencies=True, security=False, review_upgrades=False, api=engine
    )
    _found, on, errors = supply_chain_diff_findings(
        repo, "main", dependencies=True, security=False, review_upgrades=True, api=engine
    )
    _found, ignored, _errors = supply_chain_diff_findings(
        repo,
        "main",
        dependencies=True,
        security=False,
        review_upgrades=True,
        ignore=["sky-sca-api001"],
        api=engine,
    )

    assert "upgrade_api" not in off["checks"]
    assert on["checks"]["upgrade_api"]["could_not_check"]
    assert not [item for item in errors if "API" in item["message"]]
    assert "upgrade_api" not in ignored["checks"]


@pytest.mark.parametrize(
    "scope",
    [["--diff", "main"], ["--diff-base", "main"], ["--diff-base", "main", "--diff", "main"]],
)
def test_a_diff_scoped_scan_keeps_findings_on_your_unchanged_lines(
    tmp_path, registry, monkeypatch, scope
):
    registry.publish("pkg", "1.0", GONE)
    registry.publish("pkg", "2.0", KEPT)
    repo = _repo(tmp_path / "repo", {"app.py": "from pkg import gone\n"}, *BUMP)
    output = tmp_path / "results.json"
    empty = {
        "analysis_summary": {"total_files": 1},
        "dependency_vulnerabilities": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }
    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            ".",
            "--sca",
            "--review-upgrades",
            *scope,
            "--json",
            "--no-provenance",
            "-o",
            str(output),
        ],
    )

    with (
        patch("skylos.cli.run_analyze", return_value=json.dumps(empty)),
        pytest.raises(SystemExit),
    ):
        cli.main()

    results = json.loads(output.read_text(encoding="utf-8"))
    assert [
        (finding["rule_id"], finding["line"])
        for finding in results["dependency_vulnerabilities"]
    ] == [("SKY-SCA-API001", 1)]
    assert upgrade_api_receipt(results)["review_sites"] == 1


def test_an_unexpected_failure_becomes_a_row_not_an_analysis_error(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"app.py": "from pkg import gone\n"}, *BUMP)

    def explode(_sides):
        raise RuntimeError("boom")

    monkeypatch.setattr(upgrade_api_diff, "api_pairs", explode)

    findings, receipt, errors = _check(repo)

    assert findings == []
    assert receipt["status"] == "failed"
    _assert_could_not_check(receipt, errors, "RuntimeError")


@pytest.mark.parametrize(
    "receipt",
    [
        {"status": "complete", "call_sites": 3, "packages": [{"name": "p"}], "could_not_check": []},
        {"status": "complete", "review_sites": 1, "packages": [{"name": "p"}], "sites": [{"file": "a.py", "line": 1, "symbol": "p.x", "package": "p", "new": "2"}], "could_not_check": []},
        {"status": "partial", "packages": [{"name": "p"}], "could_not_check": [{"subject": "p 1 to 2", "reason": "download failed"}]},
    ],
)
def test_the_comment_never_calls_an_upgrade_safe(receipt):
    text = " ".join(_upgrade_api_lines(receipt)).lower()

    assert text
    assert "safe" not in text


def test_a_could_not_check_row_says_how_many_sites_it_covers():
    lines = _upgrade_api_lines(
        {
            "status": "partial",
            "packages": [{"name": "a"}],
            "could_not_check": [
                {
                    "subject": "a 1 to 2",
                    "reason": "the module computes __all__ at import time",
                    "symbol": "a.b",
                    "file": "x.py",
                    "line": 3,
                    "count": 4,
                }
            ],
        }
    )

    assert lines == [
        "- Could not check `a 1 to 2` at `a.b` (`x.py:3`) and 3 more sites: "
        "the module computes `__all__` at import time"
    ]


def test_a_partial_result_never_shows_the_clean_sentence():
    receipt = {
        "status": "partial",
        "call_sites": 9,
        "packages": [{"name": "a", "status": "compared"}, {"name": "b"}],
        "could_not_check": [{"subject": "b 1 to 2", "reason": "no wheel"}],
    }

    lines = _upgrade_api_lines(receipt)

    assert lines == ["- Could not check `b 1 to 2`: no wheel"]


def test_the_section_degrades_on_its_own():
    assert upgrade_api_receipt({}) is None
    assert upgrade_api_receipt({"analysis_summary": "garbage"}) is None
    assert _upgrade_api_lines(None) == []
    assert _upgrade_api_lines({"packages": "garbage", "could_not_check": 3}) == []
    assert brief_lines(SummaryInputs(upgrade_api={"packages": "garbage"})) == []

    receipt = {"status": "complete", "call_sites": 1, "packages": [{"name": "p"}]}
    results = {
        "analysis_summary": {"supply_chain_diff": {"checks": {"upgrade_api": receipt}}}
    }
    assert upgrade_api_receipt(results) == receipt
    assert brief_lines(SummaryInputs(upgrade_api=receipt)) == [
        "**Dependency API changes**",
        "- No API-level impact found in 1 call site (behaviour changes not checked)",
    ]


def _api_finding():
    return {
        "rule_id": "SKY-SCA-API001",
        "severity": "MEDIUM",
        "kind": diff.FINDING_KIND,
        "category": "DEPENDENCY",
        "file": "app.py",
        "line": 1,
        "message": "removed",
    }


def _scan_results(findings):
    return {
        "dependency_vulnerabilities": findings,
        "analysis_summary": {"diff_scoped": True},
    }


def test_no_built_in_gate_counts_it(tmp_path):
    config = load_config(tmp_path)
    results = _scan_results([_api_finding()])

    passed, reasons = gk.check_gate(results, config)

    assert passed is True
    assert reasons == [] or not any("depend" in reason for reason in reasons)
    assert gk.blocking_gate_issues(results, config) == []


def test_a_real_vulnerability_next_to_it_still_fails_the_gate(tmp_path):
    config = load_config(tmp_path)
    vulnerability = {
        "rule_id": "SKY-SCA-CVE-2020-1",
        "severity": "HIGH",
        "file": "uv.lock",
        "line": 1,
    }

    passed, _reasons = gk.check_gate(
        _scan_results([_api_finding(), vulnerability]), config
    )

    assert passed is False


def test_a_synced_cloud_gate_does_not_count_it(tmp_path):
    (tmp_path / ".skylos").mkdir()
    (tmp_path / ".skylos" / "config.yaml").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        "gate:\n"
        "  by_category: {DEAD_CODE: 0, DEPENDENCY: 0, QUALITY: 0, SECRET: 0, SECURITY: 0}\n"
        "  by_severity: {CRITICAL: 0, HIGH: 0, LOW: 0, MEDIUM: 0}\n"
        "  enabled: true\n"
        "  mode: zero-new\n",
        encoding="utf-8",
    )
    config = load_config(tmp_path)

    passed, _reasons = gk.check_gate(_scan_results([_api_finding()]), config)

    assert passed is True
    assert gk.blocking_gate_issues(_scan_results([_api_finding()]), config) == []


def test_it_is_not_uploaded_to_cloud(monkeypatch):
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    advisory = {
        "rule_id": "SKY-SCA-CVE-2020-1",
        "severity": "HIGH",
        "file": "uv.lock",
        "line": 1,
        "message": "vulnerable",
    }

    receipt = {"checks": {"upgrades": {"status": "complete"}, "upgrade_api": {"sites": []}}}

    prepared = api._prepare_report_upload(
        {
            "analysis_summary": {"supply_chain_diff": receipt},
            "analysis_errors": [],
            "dependency_vulnerabilities": [_api_finding(), advisory],
        },
        analyzer_owned=True,
    )

    payload = prepared.compatibility_payload
    assert [finding["rule_id"] for finding in payload["findings"]] == [
        "SKY-SCA-CVE-2020-1"
    ]
    assert payload["summary"]["supply_chain_diff"]["checks"] == {
        "upgrades": {"status": "complete"}
    }


def test_the_generated_workflow_comments_on_bot_prs_without_pull_request_target():
    workflow = yaml.safe_load(generate_workflow(use_upload=False))
    jobs = workflow["jobs"]
    summary = jobs["summary"]
    scan_step = next(
        step for step in jobs["skylos"]["steps"] if step.get("name") == "Run Skylos Analysis"
    )
    post_step = next(
        step
        for step in summary["steps"]
        if step.get("name") == "Post the pull request summary"
    )

    assert "pull_request" in workflow["on"]
    assert "pull_request_target" not in workflow["on"]
    assert "--review-upgrades" in scan_step["run"]
    assert "pull_request_target" not in generate_workflow(use_upload=False)
    assert "github.event_name == 'pull_request'" in summary["if"]
    assert summary["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert post_step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "skylos cicd review" in post_step["run"]
    assert "--gate-result" in post_step["run"]


def test_skylos_setup_writes_a_workflow_with_the_upgrade_review_on(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")

    step = write_ci(
        tmp_path,
        SimpleNamespace(ci=None, yes=True),
        Console(file=io.StringIO()),
        False,
    )

    text = (tmp_path / ".github" / "workflows" / "skylos.yml").read_text(encoding="utf-8")
    assert step.ok
    assert "--sca --review-upgrades" in text
    assert "pull_request_target" not in text


def test_one_call_site_reads_as_one():
    receipt = {
        "status": "complete",
        "review_sites": 1,
        "sites": [],
        "packages": [{"name": "pkg", "status": "compared"}],
    }

    assert _upgrade_api_lines(receipt)[0] == "- Review this call site"
