"""A native wrapper needs its delegated provider before it can prove safety.

Only the static scanner parses these fixtures; no open or wrapper executes.
"""

import pytest

from skylos.rules.danger.danger import scan_ctx

_DOCUMENT = (
    "import os\n"
    "from flask import Flask, request\n"
    "app=Flask(__name__)\n"
    "@app.get('/document')\n"
    "def document():\n"
    "    path=request.args['path']\n"
    "    descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
    "    with os.fdopen(descriptor, 'rb') as stream:\n"
    "        return stream.read(4096)\n"
)


def _scan(tmp_path, prelude="", *, modules=None, mode="rb"):
    source = prelude + _DOCUMENT.replace("'rb'", repr(mode))
    target = tmp_path / "app.py"
    target.write_text(source, encoding="utf-8")
    for name, text in (modules or {}).items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    sink_line = next(
        index
        for index, line in enumerate(source.splitlines(), 1)
        if "# checked_sink" in line
    )
    rules = {
        row["rule_id"]
        for row in scan_ctx(tmp_path, [target])
        if row["line"] == sink_line
    }
    return rules


@pytest.mark.parametrize(
    "prelude",
    ["", "from io import open as local_open\nlocal_open=opaque_wrapper\n"],
    ids=["native-providers", "unrelated-local-alias-rebound"],
)
def test_native_fdopen_read_can_use_its_unchanged_io_open_provider(tmp_path, prelude):
    rules = _scan(tmp_path, prelude)
    assert "SKY-D325" not in rules
    assert "SKY-D215" in rules


@pytest.mark.parametrize(
    "prelude,modules",
    [
        ("import io\nio.open=opaque_wrapper\n", {}),
        ("import io as streams\nstreams.open=opaque_wrapper\n", {}),
        ("import patch_io\n", {"patch_io.py": "import io\nio.open=opaque_wrapper\n"}),
    ],
    ids=[
        "direct-provider-replacement",
        "aliased-provider-replacement",
        "imported-provider-replacement",
    ],
)
def test_replaced_io_open_cannot_prove_fdopen_returns_a_native_bounded_handle(
    tmp_path, prelude, modules
):
    # os.fdopen is unchanged, but its delegated io.open can now return an
    # arbitrary object. A call spelled read(4096) is not a native-read proof.
    rules = _scan(tmp_path, prelude, modules=modules)
    assert "SKY-D325" in rules
    assert "SKY-D215" in rules


@pytest.mark.parametrize("mode", ["r", "rt"])
def test_text_fdopen_needs_its_called_encoding_provider(tmp_path, mode):
    # The native text wrapper calls this hook before io.open. An opaque hook
    # cannot establish that io.open remains the provider observed by the scan.
    rules = _scan(tmp_path, "import io\nio.text_encoding=opaque_wrapper\n", mode=mode)
    assert "SKY-D325" in rules
    assert "SKY-D215" in rules


def test_binary_fdopen_does_not_call_the_text_encoding_provider(tmp_path):
    rules = _scan(tmp_path, "import io\nio.text_encoding=opaque_wrapper\n", mode="rb")
    assert "SKY-D325" not in rules
    assert "SKY-D215" in rules
