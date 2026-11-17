"""A captured update descriptor is not evidence that no contents are read.

Fixtures are parsed by Skylos; their descriptor operations never execute.
"""

from textwrap import indent

import pytest

from skylos.rules.danger.danger import scan_ctx


def _rules(tmp_path, flags, body):
    source = (
        "import os\n"
        "from flask import Flask, request\n"
        "app=Flask(__name__)\n"
        "@app.get('/document')\n"
        "def document():\n"
        "    path=request.args['path']\n"
        f"    descriptor=os.open(path, {flags})  # checked_sink\n"
        + indent(body, "    ")
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    sink = next(
        line
        for line, text in enumerate(source.splitlines(), 1)
        if "# checked_sink" in text
    )
    return {row["rule_id"] for row in scan_ctx(tmp_path, [path]) if row["line"] == sink}


_UPDATE_FLAGS = [
    "os.O_RDWR | os.O_NOFOLLOW",
    "os.O_RDWR | os.O_CREAT | os.O_EXCL",
]


@pytest.mark.parametrize("flags", _UPDATE_FLAGS, ids=["nofollow", "exclusive"])
@pytest.mark.parametrize(
    "body",
    [
        (
            "def consume():\n"
            "    return os.read(descriptor, int(request.args['size']))\n"
            "return consume()\n"
        ),
        (
            "consume=lambda: os.read(descriptor, int(request.args['size']))\n"
            "return consume()\n"
        ),
    ],
    ids=["nested-function", "lambda"],
)
def test_captured_update_descriptor_keeps_its_unbounded_read_review(
    tmp_path, flags, body
):
    rules = _rules(tmp_path, flags, body)
    assert "SKY-D325" in rules
    assert "SKY-D215" in rules
    assert "SKY-D324" not in rules


@pytest.mark.parametrize("flags", _UPDATE_FLAGS, ids=["nofollow", "exclusive"])
def test_ordinary_write_only_update_descriptor_does_not_claim_a_read(tmp_path, flags):
    rules = _rules(
        tmp_path,
        flags,
        "os.write(descriptor, request.data)\nos.close(descriptor)\n",
    )
    assert "SKY-D325" not in rules
    assert "SKY-D324" not in rules
    assert "SKY-D215" in rules


@pytest.mark.parametrize("access", ["os.O_RDONLY", "os.O_RDWR"])
def test_private_native_nofollow_bounded_read_remains_a_specific_read_proof(
    tmp_path, access
):
    rules = _rules(
        tmp_path,
        f"{access} | os.O_NOFOLLOW",
        "with os.fdopen(descriptor, 'rb') as stream:\n    return stream.read(4096)\n",
    )
    assert "SKY-D325" not in rules
    assert "SKY-D215" in rules
