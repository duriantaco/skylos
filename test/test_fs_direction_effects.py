"""Static operation directions are distinct from final-symlink guarantees."""

from textwrap import indent

import pytest

from skylos.rules.danger.danger import scan_ctx


def _rules(tmp_path, setup, body, *, prelude="", modules=None):
    source = (
        "import os\nimport fcntl\nfrom flask import request\n"
        + prelude
        + "\ndef view():\n"
        + indent(setup, "    ")
        + "    descriptor=os.open(request.args['path'], flags)  # sink\n"
        + indent(body, "    ")
    )
    target = tmp_path / "app.py"
    target.write_text(source)
    for name, text in (modules or {}).items():
        (tmp_path / name).write_text(text)
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "# sink" in text)
    return {
        row["rule_id"] for row in scan_ctx(tmp_path, [target]) if row["line"] == line
    }


@pytest.mark.parametrize(
    "flag", ["O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"]
)
@pytest.mark.parametrize("augmented", [False, True])
def test_optional_native_modifiers_do_not_turn_readonly_into_write(
    tmp_path, flag, augmented
):
    modifier = f"getattr(os, {flag!r}, 0)"
    setup = (
        f"flags=os.O_RDONLY\nflags |= {modifier}\n"
        if augmented
        else f"flags=os.O_RDONLY | {modifier}\n"
    )
    rules = _rules(tmp_path, setup, "return os.read(descriptor, 4097)\n")
    assert "SKY-D215" in rules
    assert "SKY-D324" not in rules
    assert "SKY-D325" in rules


@pytest.mark.parametrize(
    "prelude,setup",
    [
        (
            "os.O_NOFOLLOW=os.O_WRONLY\n",
            "flags=os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)\n",
        ),
        (
            "def getattr(*args):\n    return os.O_WRONLY\n",
            "flags=os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)\n",
        ),
        ("", "flags=os.O_RDONLY | getattr(os, request.args['flag'], 0)\n"),
        ("", "flags=os.O_RDONLY\nflags |= request.args['flags']\n"),
        ("", "flags=os.O_RDONLY\nflags=os.O_WRONLY\n"),
    ],
)
def test_opaque_or_rebound_optional_flags_keep_both_directions(
    tmp_path, prelude, setup
):
    rules = _rules(
        tmp_path, setup, "return os.read(descriptor, 4097)\n", prelude=prelude
    )
    assert {"SKY-D215", "SKY-D324", "SKY-D325"} <= rules


@pytest.mark.parametrize("access", ["os.O_RDONLY", "os.O_RDWR | os.O_CREAT"])
@pytest.mark.parametrize(
    "body",
    [
        "os.fstat(descriptor)\nos.fsync(descriptor)\nos.close(descriptor)\n",
        "fcntl.flock(descriptor, fcntl.LOCK_SH)\nfcntl.flock(descriptor, fcntl.LOCK_UN)\nos.close(descriptor)\n",
    ],
)
def test_owned_descriptor_metadata_lock_sync_uses_do_not_consume_contents(
    tmp_path, access, body
):
    rules = _rules(
        tmp_path, f"flags={access}\nflags |= getattr(os, 'O_CLOEXEC', 0)\n", body
    )
    assert "SKY-D215" in rules
    assert "SKY-D325" not in rules


@pytest.mark.parametrize(
    "body",
    [
        "opaque_consume(descriptor)\n",
        "return descriptor\n",
        "alias=descriptor\nopaque_consume(alias)\n",
        "descriptor=opaque_descriptor()\nreturn os.read(descriptor, 4097)\n",
        "return (os.fstat(descriptor) for _ in (0,))\n",
        "return os.read(descriptor, 4097)\n",
        "with os.fdopen(descriptor, 'rb') as stream:\n    return stream.read()\n",
    ],
)
def test_descriptor_escape_rebinding_or_contents_keeps_read_review(tmp_path, body):
    rules = _rules(tmp_path, "flags=os.O_RDWR | os.O_CREAT | os.O_EXCL\n", body)
    assert "SKY-D215" in rules
    assert "SKY-D325" in rules


@pytest.mark.parametrize("provider", ["os.open", "os.fsync", "os.fstat", "fcntl.flock"])
def test_mutated_native_descriptor_provider_cannot_prove_no_content_use(
    tmp_path, provider
):
    rules = _rules(
        tmp_path,
        "flags=os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)\n",
        "os.fstat(descriptor)\nfcntl.flock(descriptor, fcntl.LOCK_SH)\nos.fsync(descriptor)\nos.close(descriptor)\n",
        prelude=f"{provider}=opaque_operation\n",
    )
    assert "SKY-D325" in rules


def test_native_exclusive_create_with_optional_modifier_stays_write_only(tmp_path):
    rules = _rules(
        tmp_path,
        "flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL\nflags |= getattr(os, 'O_CLOEXEC', 0)\n",
        "with os.fdopen(descriptor, 'w') as output:\n    output.write('new')\n",
    )
    assert "SKY-D215" in rules
    assert not {"SKY-D324", "SKY-D325"} & rules


@pytest.mark.parametrize(
    "setup,write_expected,read_expected",
    [
        ("flags=os.O_RDONLY | getattr(os, 'O_WRONLY', 0)\n", True, True),
        ("flags=os.O_RDONLY | getattr(os, 'O_CREAT', 0)\n", True, True),
        ("flags=os.O_WRONLY | os.O_CREAT | getattr(os, 'O_EXCL', 0)\n", True, False),
        (
            "flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)\n",
            False,
            False,
        ),
    ],
)
def test_optional_bits_never_become_required_atomic_bits(
    tmp_path, setup, write_expected, read_expected
):
    rules = _rules(
        tmp_path,
        setup,
        "os.close(descriptor)\n"
        if not read_expected
        else "return os.read(descriptor, 4097)\n",
    )
    assert "SKY-D215" in rules
    assert ("SKY-D324" in rules) is write_expected
    assert ("SKY-D325" in rules) is read_expected


def test_native_getter_and_module_aliases_preserve_direction(tmp_path):
    rules = _rules(
        tmp_path,
        "flags=READ_ONLY | optional(native, 'O_CLOEXEC', 0)\nflags |= optional(native, 'O_NOFOLLOW', 0)\n",
        "return os.read(descriptor, 4097)\n",
        prelude="import os as native\nfrom os import O_RDONLY as READ_ONLY\nfrom builtins import getattr as optional\n",
    )
    assert "SKY-D324" not in rules
    assert {"SKY-D215", "SKY-D325"} <= rules


def test_operation_flag_cache_is_discarded_before_next_operation():
    import ast

    from skylos.rules.danger.danger_fs.atomic_open_proof import AtomicOpenProofs

    tree = ast.parse(
        "def f(path):\n    return os.open(path, os.O_WRONLY | os.O_NOFOLLOW)\n"
    )
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    proof = AtomicOpenProofs(tree)
    state = {"stable": True, "open_checks": 0}

    def native(expression, qualified):
        if ast.unparse(expression) != qualified:
            return False
        if qualified == "os.open":
            state["open_checks"] += 1
        return state["stable"]

    with proof.operation(call):
        assert proof.nofollow(call, native)
        assert not proof.exclusive(call, native)
        assert proof.facts(call, native).directions() == (True, False)
    assert state["open_checks"] == 1
    state["stable"] = False
    with proof.operation(call):
        assert not proof.nofollow(call, native)
    assert state["open_checks"] == 2


@pytest.mark.parametrize("replacement", ["None", "opaque_descriptor()"])
def test_nullable_descriptor_cleanup_is_distinct_from_opaque_rebinding(
    tmp_path, replacement
):
    rules = _rules(
        tmp_path,
        "descriptor=None\nflags=os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)\n",
        "try:\n    os.fstat(descriptor)\n    fcntl.flock(descriptor, fcntl.LOCK_SH)\n"
        "finally:\n    if descriptor is not None:\n        os.close(descriptor)\n"
        f"    descriptor={replacement}\n    if descriptor is not None:\n        os.fsync(descriptor)\n",
    )
    assert "SKY-D215" in rules
    assert ("SKY-D325" in rules) is (replacement != "None")
