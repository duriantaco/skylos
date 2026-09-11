"""Frozen closure acceptance cases; fixture modules are parsed, never executed."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())
    return path


def _unused(root, source, *, grep_verify=True):
    _write(root, "worker.py", source)
    result = json.loads(
        analyze(str(root.resolve()), trace_file=False, grep_verify=grep_verify)
    )
    assert not result.get("analysis_errors")
    return {item["full_name"] for item in result.get("unused_functions", [])}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("activation", ["none", "outer", "inner"])
def test_creating_a_nested_function_does_not_execute_its_body(
    tmp_path, grep_verify, activation
):
    source = """
        def finish_packet():
            return 17

        def arrange_packet():
            def process_packet():
                return finish_packet()
            PLACEHOLDER
    """
    source = source.replace(
        "PLACEHOLDER",
        "return process_packet()" if activation == "inner" else "return 0",
    )
    if activation != "none":
        source = textwrap.dedent(source) + "\narrange_packet()\n"

    unused = _unused(tmp_path, source, grep_verify=grep_verify)
    targets = {
        "worker.finish_packet",
        "worker.arrange_packet",
        "worker.arrange_packet.process_packet",
    }
    expected = targets if activation == "none" else targets - {"worker.arrange_packet"}
    if activation == "inner":
        expected = set()
    assert unused & targets == expected


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("live", [False, True])
def test_returned_callback_only_protects_its_body_when_factory_is_live(
    tmp_path, grep_verify, live
):
    source = textwrap.dedent("""
        def finish_packet():
            return 17

        def arrange_packet():
            def process_packet():
                return finish_packet()
            return process_packet
    """)
    if live:
        source += "callback = arrange_packet()\ncallback()\n"

    unused = _unused(tmp_path, source, grep_verify=grep_verify)
    targets = {
        "worker.finish_packet",
        "worker.arrange_packet",
        "worker.arrange_packet.process_packet",
    }
    assert unused & targets == (set() if live else targets)


@pytest.mark.parametrize(
    "use",
    [
        "return process_packet",
        "register(process_packet)",
        "registry.append(process_packet)",
        "registry['process'] = process_packet",
        "return {'callbacks': [process_packet]}",
    ],
    ids=["returned", "passed", "appended", "stored", "nested-container"],
)
def test_live_owner_keeps_callbacks_that_may_be_invoked_elsewhere(tmp_path, use):
    source = """
        from external import register, registry

        def finish_packet():
            return 17

        def arrange_packet():
            def process_packet():
                return finish_packet()
            PLACEHOLDER

        arrange_packet()
    """.replace("PLACEHOLDER", use)

    unused = _unused(tmp_path, source)

    assert not {"worker.finish_packet", "worker.arrange_packet.process_packet"} & unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("activation", ["none", "outer", "inner"])
def test_sibling_recursive_callbacks_need_a_reachable_call(
    tmp_path, grep_verify, activation
):
    source = """
        def arrange_packet():
            def first_phase(count):
                return second_phase(count - 1) if count else 1
            def second_phase(count):
                return first_phase(count - 1) if count else 2
            PLACEHOLDER
    """.replace(
        "PLACEHOLDER", "return first_phase(3)" if activation == "inner" else "return 0"
    )
    if activation != "none":
        source = textwrap.dedent(source) + "\narrange_packet()\n"

    unused = _unused(tmp_path, source, grep_verify=grep_verify)
    targets = {
        "worker.arrange_packet.first_phase",
        "worker.arrange_packet.second_phase",
    }
    assert unused & targets == (set() if activation == "inner" else targets)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_same_named_callbacks_in_separate_owners_keep_distinct_identities(
    tmp_path, grep_verify
):
    unused = _unused(
        tmp_path,
        """
        def north_finish():
            return 1
        def south_finish():
            return 2

        def north_factory():
            def process_packet():
                return north_finish()
            return process_packet()

        def south_factory():
            def process_packet():
                return south_finish()
            return process_packet()

        north_factory()
        """,
        grep_verify=grep_verify,
    )

    assert {
        "worker.south_finish",
        "worker.south_factory",
        "worker.south_factory.process_packet",
    } <= unused
    assert not {"worker.north_finish", "worker.north_factory.process_packet"} & unused


@pytest.mark.parametrize("grep_verify", [False, True])
def test_nested_name_shadows_module_function(tmp_path, grep_verify):
    unused = _unused(
        tmp_path,
        """
        def process_packet():
            return 99

        def arrange_packet():
            def process_packet():
                return 17
            return process_packet()

        arrange_packet()
        """,
        grep_verify=grep_verify,
    )

    assert "worker.process_packet" in unused
    assert "worker.arrange_packet.process_packet" not in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("live", [False, True])
def test_nested_body_resolves_import_captured_from_enclosing_function(
    tmp_path, grep_verify, live
):
    _write(
        tmp_path,
        "packet_ops.py",
        """
        def finish_packet():
            return 17
        """,
    )
    source = """
        def arrange_packet():
            import packet_ops as operations
            def process_packet():
                return operations.finish_packet()
            PLACEHOLDER

        arrange_packet()
    """.replace("PLACEHOLDER", "return process_packet()" if live else "return 0")

    unused = _unused(tmp_path, source, grep_verify=grep_verify)
    targets = {"packet_ops.finish_packet", "worker.arrange_packet.process_packet"}
    assert unused & targets == (set() if live else targets)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("live", [False, True])
def test_nested_body_resolves_stable_captured_receiver(tmp_path, grep_verify, live):
    source = """
        class PacketCodec:
            def encode_packet(self):
                return 17

        def arrange_packet():
            codec = PacketCodec()
            def process_packet():
                return codec.encode_packet()
            PLACEHOLDER

        arrange_packet()
    """.replace("PLACEHOLDER", "return process_packet()" if live else "return 0")

    unused = _unused(tmp_path, source, grep_verify=grep_verify)
    targets = {
        "worker.PacketCodec.encode_packet",
        "worker.arrange_packet.process_packet",
    }
    assert unused & targets == (set() if live else targets)


@pytest.mark.parametrize("activation", ["none", "outer", "inner"])
def test_nested_defaults_execute_with_owner_and_body_requires_callback_call(
    tmp_path, activation
):
    source = """
        def prepare_option():
            return 17
        def finish_packet():
            return 19

        def arrange_packet():
            def process_packet(option=prepare_option()):
                return finish_packet() + option
            PLACEHOLDER
    """.replace(
        "PLACEHOLDER",
        "return process_packet()" if activation == "inner" else "return 0",
    )
    if activation != "none":
        source = textwrap.dedent(source) + "\narrange_packet()\n"

    unused = _unused(tmp_path, source)

    assert ("worker.prepare_option" in unused) == (activation == "none")
    assert ("worker.finish_packet" in unused) == (activation != "inner")


@pytest.mark.parametrize("live", [False, True])
def test_decorating_callback_is_an_owner_time_use_and_can_execute_body(tmp_path, live):
    source = textwrap.dedent("""
        def finish_packet():
            return 17

        def arrange_packet():
            from external import register
            @register
            def process_packet():
                return finish_packet()
            return 0
    """)
    if live:
        source += "arrange_packet()\n"

    unused = _unused(tmp_path, source)

    # A decorator can invoke or retain the callback, but cannot run when its
    # enclosing function is unreachable.
    assert ("worker.finish_packet" in unused) == (not live)


@pytest.mark.parametrize("live", [False, True])
def test_nested_async_body_keeps_its_own_owner(tmp_path, live):
    source = """
        def finish_packet():
            return 17

        async def arrange_packet():
            async def process_packet():
                return finish_packet()
            PLACEHOLDER

        from external import run
        run(arrange_packet())
    """.replace("PLACEHOLDER", "return await process_packet()" if live else "return 0")

    unused = _unused(tmp_path, source)
    targets = {"worker.finish_packet", "worker.arrange_packet.process_packet"}
    assert unused & targets == (set() if live else targets)


@pytest.mark.parametrize("live", [False, True])
def test_method_nested_body_can_capture_its_enclosing_receiver(tmp_path, live):
    source = """
        class PacketCodec:
            def encode_packet(codec):
                return 17
            def arrange_packet(codec):
                def process_packet():
                    return codec.encode_packet()
                PLACEHOLDER

        PacketCodec().arrange_packet()
    """.replace("PLACEHOLDER", "return process_packet()" if live else "return 0")

    unused = _unused(tmp_path, source)
    targets = {
        "worker.PacketCodec.encode_packet",
        "worker.PacketCodec.arrange_packet.process_packet",
    }
    assert unused & targets == (set() if live else targets)


@pytest.mark.parametrize(
    "source,protected",
    [
        (
            """
            def first_finish(): return 1
            def second_finish(): return 2
            def arrange_packet():
                finish = first_finish
                def process_packet():
                    return finish()
                finish = second_finish
                return process_packet()
            arrange_packet()
            """,
            {"second_finish", "arrange_packet.process_packet"},
        ),
        (
            """
            def first_finish(): return 1
            def second_finish(): return 2
            def arrange_packet():
                finish = first_finish
                def replace_finish():
                    nonlocal finish
                    finish = second_finish
                def process_packet():
                    return finish()
                replace_finish()
                return process_packet()
            arrange_packet()
            """,
            {
                "second_finish",
                "arrange_packet.process_packet",
                "arrange_packet.replace_finish",
            },
        ),
        (
            """
            def finish_packet(): return 1
            def arrange_packet():
                finish_packet = None
                def process_packet():
                    global finish_packet
                    return finish_packet()
                return process_packet()
            arrange_packet()
            """,
            {"finish_packet", "arrange_packet.process_packet"},
        ),
        (
            """
            from external import choose
            def first_finish(): return 1
            def second_finish(): return 2
            def arrange_packet():
                if choose():
                    def process_packet(): return first_finish()
                else:
                    def process_packet(): return second_finish()
                return process_packet()
            arrange_packet()
            """,
            {"first_finish", "second_finish"},
        ),
        (
            """
            class NorthCodec:
                def encode_packet(self): return 1
            class SouthCodec:
                def encode_packet(self): return 2
            def arrange_packet():
                codec = NorthCodec()
                def process_packet():
                    return codec.encode_packet()
                codec = SouthCodec()
                return process_packet()
            arrange_packet()
            """,
            {"SouthCodec.encode_packet", "arrange_packet.process_packet"},
        ),
        (
            """
            def finish_packet(): return 1
            def arrange_packet():
                def process_packet():
                    return finish_packet()
                saved = process_packet
                process_packet = None
                return saved()
            arrange_packet()
            """,
            {"finish_packet", "arrange_packet.process_packet"},
        ),
        (
            """
            from external import choose
            def first_finish(): return 1
            def second_finish(): return 2
            def arrange_packet():
                def process_packet():
                    return finish()
                finish = first_finish if choose() else second_finish
                return process_packet()
            arrange_packet()
            """,
            {"first_finish", "second_finish", "arrange_packet.process_packet"},
        ),
        (
            """
            class NorthCodec:
                def encode_packet(self): return 1
            class SouthCodec:
                def encode_packet(self): return 2
            def arrange_packet():
                codec = NorthCodec()
                def process_packet(value=(codec := SouthCodec())):
                    return codec.encode_packet()
                return process_packet()
            arrange_packet()
            """,
            {"SouthCodec.encode_packet", "arrange_packet.process_packet"},
        ),
    ],
    ids=[
        "captured-callable-reassigned",
        "nonlocal-cell-reassigned",
        "explicit-global-skips-enclosing-local",
        "conditional-definitions",
        "captured-receiver-reassigned",
        "callback-saved-before-reassignment",
        "late-bound-conditional-capture",
        "default-walrus-rebinds-captured-receiver",
    ],
)
def test_mutable_or_conditional_bindings_keep_possible_live_targets(
    tmp_path, source, protected
):
    unused = _unused(tmp_path, source)

    assert not {f"worker.{name}" for name in protected} & unused


def test_closure_inside_closure_uses_nearest_lexical_binding(tmp_path):
    unused = _unused(
        tmp_path,
        """
        def finish_packet(): return 99
        def arrange_packet():
            def finish_packet(): return 17
            def middle_phase():
                def process_packet():
                    return finish_packet()
                return process_packet()
            return middle_phase()
        arrange_packet()
        """,
    )

    assert "worker.finish_packet" in unused
    assert (
        not {
            "worker.arrange_packet.finish_packet",
            "worker.arrange_packet.middle_phase",
            "worker.arrange_packet.middle_phase.process_packet",
        }
        & unused
    )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "source,protected",
    [
        (
            """
            def finish_packet(): return 17
            class PacketCodec:
                def arrange_packet(codec):
                    def __process_packet():
                        return finish_packet()
                    return _PacketCodec__process_packet()
            PacketCodec().arrange_packet()
            """,
            {"finish_packet", "PacketCodec.arrange_packet.__process_packet"},
        ),
        (
            """
            def first_finish(): return 1
            def second_finish(): return 2
            class PacketCodec:
                def arrange_packet(codec):
                    def __process_packet():
                        return first_finish()
                    def _PacketCodec__process_packet():
                        return second_finish()
                    return __process_packet()
            PacketCodec().arrange_packet()
            """,
            {
                "second_finish",
                "PacketCodec.arrange_packet._PacketCodec__process_packet",
            },
        ),
        (
            """
            class NorthCodec:
                def encode_packet(self): return 1
            class SouthCodec:
                def encode_packet(self): return 2
            class PacketCodec:
                def arrange_packet(codec):
                    __receiver = NorthCodec()
                    def process_packet(__receiver):
                        return _PacketCodec__receiver.encode_packet()
                    return process_packet(SouthCodec())
            PacketCodec().arrange_packet()
            """,
            {"SouthCodec.encode_packet", "PacketCodec.arrange_packet.process_packet"},
        ),
    ],
    ids=[
        "private-local-callback",
        "mangled-local-collision",
        "mangled-parameter-shadow",
    ],
)
def test_method_local_name_mangling_preserves_live_callbacks_and_receivers(
    tmp_path, source, protected, grep_verify
):
    unused = _unused(tmp_path, source, grep_verify=grep_verify)

    assert not {f"worker.{name}" for name in protected} & unused
