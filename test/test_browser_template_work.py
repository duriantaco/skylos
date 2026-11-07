"""Absent string templates need no Python proof; real browser uses remain."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.deadcode import browser_refs, python_source_proofs


def _template_refs(tmp_path, monkeypatch, sources):
    constructed = []
    original = python_source_proofs._PythonReferenceProof

    def counted(*args, **kwargs):
        constructed.append(args[2])
        return original(*args, **kwargs)

    monkeypatch.setattr(python_source_proofs, "_PythonReferenceProof", counted)
    paths = []
    for index, source in enumerate(sources):
        path = tmp_path / f"module_{index}.py"
        path.write_text(source, encoding="utf-8")
        paths.append(path)
    refs = browser_refs._python_string_browser_names(tmp_path, paths, {})
    return refs, constructed


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\ndata = input()\n"
        + "".join(f"yaml.load(data, Loader=missing_{index})\n" for index in range(400)),
        "payload = b'<button onclick=\"browserOnly()\">go</button>'\n"
        "count = 7\nprint(count)\n",
        "# page = '<button onclick=\"browserOnly()\">go</button>'\nprint(None)\n",
    ],
    ids=["400-unknown-loaders", "bytes-and-numbers", "comment-only-markup"],
)
def test_string_free_modules_need_no_template_proof(tmp_path, monkeypatch, source):
    refs, constructed = _template_refs(tmp_path, monkeypatch, [source])

    assert refs == (set(), set())
    assert constructed == []


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "page = '\\x3cbutton onclick=\"browserOnly()\">go\\x3c/button>'\n",
            ({"browserOnly"}, set()),
        ),
        (
            "page = f'\\x3cbutton onclick=\"browserOnly()\">{caption}\\x3c/button>'\n",
            ({"browserOnly"}, set()),
        ),
        ('page = f"{value}"\n', (set(), set())),
    ],
    ids=["decoded-escape", "mixed-fstring", "formatted-only-fstring"],
)
def test_decoded_strings_and_fstrings_keep_template_proofs(
    tmp_path, monkeypatch, source, expected
):
    assert "<" not in source
    refs, constructed = _template_refs(tmp_path, monkeypatch, [source])

    assert refs == expected
    assert len(constructed) == 1


def test_absence_only_skips_the_current_file(tmp_path, monkeypatch):
    refs, constructed = _template_refs(
        tmp_path,
        monkeypatch,
        [
            "value = 1\n",
            "page = '<button onclick=\"browserOnly()\">go</button>'\n",
        ],
    )

    assert refs == ({"browserOnly"}, set())
    assert constructed == [tmp_path / "module_1.py"]


def test_string_free_consumer_keeps_cross_module_browser_effects(tmp_path):
    (tmp_path / "index.html").write_text(
        '<script src="app.js"></script>\n', encoding="utf-8"
    )
    (tmp_path / "app.js").write_text(
        "function browserOnly() { return 1; }\nfunction untouched() { return 2; }\n",
        encoding="utf-8",
    )
    (tmp_path / "config.py").write_text('code = "browserOnly()"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from config import code\nfrom nicegui import ui\nui.run_javascript(code)\n",
        encoding="utf-8",
    )

    refs = browser_refs.collect_browser_event_handler_refs(
        tmp_path, list(tmp_path.iterdir())
    )
    assert {name for name, _ in refs} == {"browserOnly"}
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {row["name"] for row in report.get("unused_functions", [])}
    assert "browserOnly" not in unused
    assert "untouched" in unused
