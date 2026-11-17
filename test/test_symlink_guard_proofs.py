"""Symlink suppression requires an effective guard on the actual operation.

Only Skylos parses these fixtures. Their filesystem operations never execute.
"""

from textwrap import indent

import pytest

from skylos.rules.danger.danger import scan_ctx

HEADER = (
    "import os, stat\nfrom pathlib import Path\n"
    "from flask import Flask, request\napp=Flask(__name__)\n"
    "@app.get('/document')\ndef document():\n"
    "    path=request.args['path']\n"
)


def _scan(tmp_path, body, *, extra=""):
    source = extra + HEADER + indent(body, "    ")
    target = tmp_path / "app.py"
    target.write_text(source)
    return source, scan_ctx(tmp_path, [target])


def _sink_line(source):
    return next(
        number
        for number, line in enumerate(source.splitlines(), 1)
        if "# checked_sink" in line
    )


def _assert_rule_at_sink(source, findings, rule):
    assert any(
        row["rule_id"] == rule and row["line"] == _sink_line(source) for row in findings
    ), (source, findings)


def _operation(operation, operand="path"):
    if operation == "write":
        return (
            f"with open({operand}, 'wb') as stream:  # checked_sink\n"
            "    stream.write(b'data')\n"
        )
    return (
        f"with open({operand}, 'rb') as stream:  # checked_sink\n"
        "    data=stream.read(4096)\n"
    )


@pytest.mark.parametrize(
    "operation,rule", [("write", "SKY-D324"), ("read", "SKY-D325")]
)
@pytest.mark.parametrize(
    "check",
    [
        "Path(path).is_symlink()\n",
        "Path('/srv/unrelated').is_symlink()\n",
        "Path(path).is_file()\n",
        "os.fstat(0)\n",
        "Path('/srv/unrelated').resolve()\n",
        "unused_flag=os.O_NOFOLLOW\n",
        "if Path(path).is_symlink():\n    pass\n",
        "if Path('/srv/unrelated').is_symlink():\n    raise ValueError('link')\n",
    ],
    ids=[
        "ignored-result",
        "different-path",
        "ignored-is-file",
        "different-fd",
        "different-resolve",
        "unused-flag",
        "non-rejecting-branch",
        "different-rejected-path",
    ],
)
def test_mentioned_guard_does_not_protect_a_different_or_unchecked_operation(
    tmp_path, operation, rule, check
):
    source, findings = _scan(tmp_path, check + _operation(operation))
    _assert_rule_at_sink(source, findings, rule)


@pytest.mark.parametrize(
    "operation,rule", [("write", "SKY-D324"), ("read", "SKY-D325")]
)
def test_check_after_the_operation_cannot_guard_the_operation(
    tmp_path, operation, rule
):
    source, findings = _scan(
        tmp_path, _operation(operation) + "Path(path).is_symlink()\n"
    )
    _assert_rule_at_sink(source, findings, rule)


@pytest.mark.parametrize(
    "operation,rule", [("write", "SKY-D324"), ("read", "SKY-D325")]
)
def test_guarded_name_rebinding_discards_the_old_path_check(tmp_path, operation, rule):
    body = (
        "checked=Path('/srv/fixed')\n"
        "if checked.is_symlink():\n    raise ValueError('link')\n"
        "checked=Path(path)\n" + _operation(operation, "checked")
    )
    source, findings = _scan(tmp_path, body)
    _assert_rule_at_sink(source, findings, rule)


@pytest.mark.parametrize(
    "operation,rule", [("write", "SKY-D324"), ("read", "SKY-D325")]
)
def test_nonatomic_symlink_rejection_is_not_a_race_free_open(tmp_path, operation, rule):
    body = "if Path(path).is_symlink():\n    raise ValueError('link')\n" + _operation(
        operation
    )
    source, findings = _scan(tmp_path, body)
    _assert_rule_at_sink(source, findings, rule)


@pytest.mark.parametrize(
    "operation,rule", [("write", "SKY-D324"), ("read", "SKY-D325")]
)
def test_native_nofollow_on_another_open_does_not_guard_this_sink(
    tmp_path, operation, rule
):
    body = (
        "descriptor=os.open('/srv/fixed', os.O_WRONLY | os.O_NOFOLLOW)\n"
        "os.close(descriptor)\n" + _operation(operation)
    )
    source, findings = _scan(tmp_path, body)
    _assert_rule_at_sink(source, findings, rule)


@pytest.mark.parametrize(
    "flags,prelude",
    [
        ("os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)", ""),
        ("os.O_WRONLY | (os.O_NOFOLLOW if request.args.get('strict') else 0)", ""),
        ("os.O_WRONLY | os.O_NOFOLLOW", "os.O_NOFOLLOW=0\n"),
        ("flags", "flags=os.O_WRONLY | os.O_NOFOLLOW\nflags=os.O_WRONLY\n"),
        ("os.O_WRONLY | os.O_NOFOLLOW", "os.open=unknown_open\n"),
    ],
    ids=[
        "fallback-zero",
        "conditional-flag",
        "mutated-flag",
        "rebound-flags",
        "replaced-open",
    ],
)
def test_flag_spelling_without_a_native_atomic_guarantee_stays_visible(
    tmp_path, flags, prelude
):
    source, findings = _scan(
        tmp_path,
        prelude + f"descriptor=os.open(path, {flags})  # checked_sink\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D324")


@pytest.mark.parametrize(
    "statement",
    [
        "descriptor=os.open(path, os.O_WRONLY | os.O_NOFOLLOW)",
        "descriptor=os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)",
        "stream=open(path, 'xb')",
    ],
    ids=["atomic-nofollow", "atomic-exclusive", "exclusive-mode"],
)
def test_native_atomic_write_proofs_keep_traversal_checks(tmp_path, statement):
    source, findings = _scan(tmp_path, statement + "  # checked_sink\n")
    assert not any(row["rule_id"] == "SKY-D324" for row in findings)
    _assert_rule_at_sink(source, findings, "SKY-D215")


def test_exclusive_flags_do_not_prove_a_replaced_open_honors_them(tmp_path):
    source, findings = _scan(
        tmp_path,
        "os.open=unknown_open\n"
        "descriptor=os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)  # checked_sink\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D324")


def test_imported_mutation_invalidates_the_exclusive_flag_provider(tmp_path):
    (tmp_path / "patcher.py").write_text("import os\nos.O_EXCL=0\n")
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)  # checked_sink\n",
        extra="import patcher\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D324")


def test_nofollow_does_not_bound_the_contents_read_from_the_descriptor(tmp_path):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n    return stream.read()\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_bounded_read_of_another_descriptor_does_not_protect_this_one(tmp_path):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(0, 'rb') as other:\n    sample=other.read(4096)\n"
        "return os.read(descriptor, int(request.args['size']))\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_repeated_chunk_reads_accumulated_without_a_cap_are_not_a_bounded_read(
    tmp_path,
):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n"
        "    chunks=[]\n"
        "    while True:\n"
        "        chunk=stream.read(4096)\n"
        "        if not chunk:\n            break\n"
        "        chunks.append(chunk)\n"
        "    return b''.join(chunks)\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_native_nofollow_and_bounded_read_of_its_own_descriptor_are_distinct_proofs(
    tmp_path,
):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "info=os.fstat(descriptor)\n"
        "if not stat.S_ISREG(info.st_mode):\n    raise ValueError('not regular')\n"
        "if info.st_size > 4096:\n    raise ValueError('too large')\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n    return stream.read(4096)\n",
    )
    assert not any(row["rule_id"] == "SKY-D325" for row in findings)
    _assert_rule_at_sink(source, findings, "SKY-D215")


@pytest.mark.parametrize(
    "change",
    [
        "descriptor=os.open(request.args['other'], os.O_RDONLY)\n",
        "alias=descriptor\nopaque_consume(alias)\n",
        "os.close(descriptor)\n",
        "os.dup2(int(request.args['descriptor']), descriptor)\n",
    ],
    ids=[
        "rebound-descriptor",
        "escaped-alias",
        "closed-before-read",
        "replaced-description",
    ],
)
def test_changed_or_escaped_descriptor_is_not_the_proven_bounded_read(tmp_path, change):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        + change
        + "with os.fdopen(descriptor, 'rb') as stream:\n    return stream.read(4096)\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


@pytest.mark.parametrize(
    "size,prelude",
    [
        ("int(request.args['size'])", ""),
        ("limit", "limit=4096\nlimit=int(request.args['size'])\n"),
        ("-1", ""),
    ],
    ids=["runtime-bound", "reassigned-bound", "unlimited-sentinel"],
)
def test_dynamic_or_replaced_read_bound_is_not_a_size_cap(tmp_path, size, prelude):
    source, findings = _scan(
        tmp_path,
        prelude
        + "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n"
        f"    return stream.read({size})\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_a_bounded_read_does_not_justify_a_later_unbounded_read(tmp_path):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n"
        "    prefix=stream.read(4096)\n"
        "    return prefix+stream.read()\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_fileno_escape_does_not_preserve_private_descriptor_consumption(tmp_path):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n"
        "    opaque_consume(stream.fileno())\n"
        "    return stream.read(4096)\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_consumption_after_fdopen_closed_the_descriptor_has_no_identity_proof(tmp_path):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "with os.fdopen(descriptor, 'rb') as stream:\n"
        "    prefix=stream.read(4096)\n"
        "replacement=os.open(request.args['other'], os.O_RDONLY)\n"
        "return os.read(descriptor, 4096)\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


@pytest.mark.parametrize(
    "mutation, consumption",
    [
        ("os.read=opaque_read\n", "return os.read(descriptor, 4096)\n"),
        (
            "os.fdopen=opaque_wrapper\n",
            "with os.fdopen(descriptor, 'rb') as stream:\n    return stream.read(4096)\n",
        ),
    ],
    ids=["changed-native-read", "changed-native-wrapper"],
)
def test_replaced_read_provider_cannot_prove_bounded_consumption(
    tmp_path, mutation, consumption
):
    source, findings = _scan(
        tmp_path,
        mutation
        + "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        + consumption,
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")


def test_native_bounded_descriptor_read_with_finally_close_stays_quiet(tmp_path):
    source, findings = _scan(
        tmp_path,
        "descriptor=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # checked_sink\n"
        "try:\n    return os.read(descriptor, 4096)\n"
        "finally:\n    os.close(descriptor)\n",
    )
    assert not any(row["rule_id"] == "SKY-D325" for row in findings)
    _assert_rule_at_sink(source, findings, "SKY-D215")


def test_exclusive_update_handle_does_not_certify_later_unbounded_contents(tmp_path):
    source, findings = _scan(
        tmp_path,
        "with open(path, 'x+') as stream:  # checked_sink\n"
        "    stream.write(request.get_data(as_text=True))\n"
        "    stream.seek(0)\n"
        "    return stream.read()\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")
    _assert_rule_at_sink(source, findings, "SKY-D215")
    assert not any(row["rule_id"] == "SKY-D324" for row in findings)


@pytest.mark.parametrize(
    "flags",
    ["os.O_RDWR | os.O_CREAT | os.O_EXCL", "os.O_RDWR | os.O_NOFOLLOW"],
    ids=["exclusive-update-descriptor", "nofollow-update-descriptor"],
)
def test_native_update_descriptor_keeps_its_observed_unbounded_read(tmp_path, flags):
    source, findings = _scan(
        tmp_path,
        f"descriptor=os.open(path, {flags})  # checked_sink\n"
        "os.write(descriptor, request.data)\n"
        "os.lseek(descriptor, 0, os.SEEK_SET)\n"
        "return os.read(descriptor, int(request.args['size']))\n",
    )
    _assert_rule_at_sink(source, findings, "SKY-D325")
    _assert_rule_at_sink(source, findings, "SKY-D215")
    assert not any(row["rule_id"] == "SKY-D324" for row in findings)
