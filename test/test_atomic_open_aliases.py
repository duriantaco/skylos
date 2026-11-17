"""Native open import aliases must share detection and atomic proof behavior."""

import pytest

from skylos.rules.danger.danger import scan_ctx


@pytest.mark.parametrize(
    "declaration,callee",
    [("import os as fs", "fs.open"), ("from os import open as op", "op")],
)
@pytest.mark.parametrize(
    "flags,rule",
    [
        ("os.O_WRONLY", "SKY-D324"),
        ("os.O_RDONLY", "SKY-D325"),
        ("os.O_WRONLY|os.O_NOFOLLOW", None),
        ("os.O_WRONLY|os.O_CREAT|os.O_EXCL", None),
    ],
)
def test_native_aliases_share_path_detection(
    tmp_path, declaration, callee, flags, rule
):
    target = tmp_path / "app.py"
    target.write_text(
        "import os\nfrom flask import Flask, request\n"
        + declaration
        + "\napp=Flask(__name__)\n@app.get('/file')\ndef view():\n    return "
        + callee
        + "(request.args['path'], "
        + flags
        + ")\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D215" in rules
    if rule:
        assert rule in rules
    else:
        assert "SKY-D324" not in rules


def test_local_shadow_does_not_borrow_native_import_identity(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(
        "import os\nfrom os import open as op\nfrom flask import request\ndef view(op):\n    return op(request.args['path'], os.O_WRONLY)\n"
    )
    assert not {"SKY-D215", "SKY-D324", "SKY-D325"} & {
        row["rule_id"] for row in scan_ctx(tmp_path, [target])
    }


@pytest.mark.parametrize("opener", ["None", "opaque_opener"])
def test_custom_opener_cannot_borrow_builtin_exclusive_mode_proof(tmp_path, opener):
    target = tmp_path / "app.py"
    target.write_text(
        "from flask import request\ndef view():\n    return open(request.args['path'], 'x', opener="
        + opener
        + ")\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D215" in rules
    assert ("SKY-D324" in rules) is (opener != "None")


def test_path_exclusive_mode_requires_its_delegated_io_provider(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(
        "import io\nfrom pathlib import Path\nfrom flask import request\nio.open=opaque_open\ndef view():\n    return Path(request.args['path']).open('x')\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D324" in rules


@pytest.mark.parametrize(
    "declaration,callee",
    [
        ("import io as streams", "streams.open"),
        ("from io import open as op", "op"),
        ("import builtins as native", "native.open"),
        ("from builtins import open as op", "op"),
        ("import _io as streams", "streams.open"),
        ("from _io import open as op", "op"),
    ],
)
@pytest.mark.parametrize(
    "mode,rule", [("rb", "SKY-D325"), ("wb", "SKY-D324"), ("xb", None)]
)
def test_builtin_io_open_family_retains_detection_across_import_spelling(
    tmp_path, declaration, callee, mode, rule
):
    target = tmp_path / "app.py"
    target.write_text(
        "from flask import request\n"
        + declaration
        + "\ndef view():\n    return "
        + callee
        + "(request.args['path'], "
        + repr(mode)
        + ")\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D215" in rules
    if rule:
        assert rule in rules
    else:
        assert "SKY-D324" not in rules


@pytest.mark.parametrize("reads", [False, True])
def test_exclusive_update_mode_still_checks_an_observed_unbounded_read(tmp_path, reads):
    target = tmp_path / "app.py"
    target.write_text(
        "from flask import request\ndef view():\n"
        "    with open(request.args['path'], 'x+') as stream:\n"
        + (
            "        return stream.read()\n"
            if reads
            else "        stream.write('new')\n"
        )
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D215" in rules
    assert "SKY-D324" not in rules
    assert ("SKY-D325" in rules) is reads


@pytest.mark.parametrize(
    "declaration,operation",
    [
        ("", "open (request.args['path'], 'rb')"),
        ("import io as streams", "streams.open (request.args['path'], 'rb')"),
        (
            "from io import (\n    open as op,\n)",
            "op (request.args['path'], 'rb')",
        ),
        (
            "import os\nfrom os import (\n    open as op,\n)",
            "op (request.args['path'], os.O_RDONLY)",
        ),
    ],
)
def test_open_dispatch_uses_syntax_instead_of_exact_source_tokens(
    tmp_path, declaration, operation
):
    target = tmp_path / "app.py"
    target.write_text(
        "from flask import request\n"
        + declaration
        + "\ndef view():\n    return "
        + operation
        + "\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert {"SKY-D215", "SKY-D325"} <= rules


@pytest.mark.parametrize(
    "read_source, extra_flags, read_warning",
    [
        ("os.close(descriptor)", "", False),
        ("return os.fdopen(descriptor, 'rb').read()", "", True),
        (
            "with os.fdopen(descriptor, 'rb') as stream:\n        return stream.read()",
            "",
            True,
        ),
        ("return os.read(descriptor, request.args['size'])", "", True),
        ("return os.read(descriptor, 4096)", " | os.O_NOFOLLOW", False),
    ],
    ids=[
        "write-only",
        "direct-unbounded",
        "with-unbounded",
        "dynamic-size",
        "bounded-nofollow",
    ],
)
def test_exclusive_readwrite_descriptor_keeps_its_observed_read_check(
    tmp_path, read_source, extra_flags, read_warning
):
    target = tmp_path / "app.py"
    target.write_text(
        "import os\nfrom flask import request\ndef view():\n"
        "    descriptor=os.open(request.args['path'], os.O_RDWR | os.O_CREAT | os.O_EXCL"
        + extra_flags
        + ")\n    "
        + read_source
        + "\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D215" in rules
    assert "SKY-D324" not in rules
    assert ("SKY-D325" in rules) is read_warning


@pytest.mark.parametrize("protected", [False, True])
def test_native_flag_aliases_preserve_write_direction(tmp_path, protected):
    target = tmp_path / "app.py"
    target.write_text(
        "from os import open as op, O_WRONLY as W, O_NOFOLLOW as N\n"
        "from flask import request\ndef view():\n"
        "    return op(request.args['path'], W" + (" | N" if protected else "") + ")\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert "SKY-D215" in rules
    assert ("SKY-D324" in rules) is not protected
    assert "SKY-D325" not in rules


@pytest.mark.parametrize(
    "prelude,flags",
    [
        ("os.O_RDONLY=os.O_WRONLY", "os.O_RDONLY"),
        ("os.O_WRONLY=os.O_RDONLY", "os.O_WRONLY"),
        ("class Forged:\n    O_WRONLY=0", "Forged.O_WRONLY"),
        ("from os import O_RDONLY as R\nR=os.O_WRONLY", "R"),
    ],
)
def test_uncertain_flag_direction_cannot_hide_either_operation(
    tmp_path, prelude, flags
):
    target = tmp_path / "app.py"
    target.write_text(
        "import os\nfrom flask import request\n"
        + prelude
        + "\ndef view():\n    return os.open(request.args['path'], "
        + flags
        + ")\n"
    )
    rules = {row["rule_id"] for row in scan_ctx(tmp_path, [target])}
    assert {"SKY-D215", "SKY-D324", "SKY-D325"} <= rules
