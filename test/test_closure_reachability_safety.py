"""Independent closure safety controls; fixture source is parsed, never executed."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


_PRELUDE = """
def leaf_north():
    return 1

def leaf_south():
    return 2

class NorthernCodec:
    def encode_packet(codec):
        return leaf_north()

class SouthernCodec:
    def encode_packet(codec):
        return leaf_south()

def identity(value):
    return value
"""


_CASES = [
    (
        "called-nonlocal-receiver-mutator",
        """
        def launch():
            receiver = NorthernCodec()
            def mutate():
                nonlocal receiver
                receiver = SouthernCodec()
            def invoke():
                return receiver.encode_packet()
            mutate()
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "escaped-nonlocal-receiver-mutator",
        """
        from external import dispatch
        def launch():
            receiver = NorthernCodec()
            def mutate():
                nonlocal receiver
                receiver = SouthernCodec()
            def invoke():
                return receiver.encode_packet()
            dispatch(mutate)
            return invoke()
        launch()
        """,
        {"NorthernCodec.encode_packet", "SouthernCodec.encode_packet"},
    ),
    (
        "global-capture-rebinding",
        """
        receiver = NorthernCodec()
        def launch():
            def mutate():
                global receiver
                receiver = SouthernCodec()
            def invoke():
                return receiver.encode_packet()
            mutate()
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "grandchild-nonlocal-rebinding",
        """
        def launch():
            receiver = NorthernCodec()
            def prepare():
                def mutate():
                    nonlocal receiver
                    receiver = SouthernCodec()
                mutate()
            def invoke():
                return receiver.encode_packet()
            prepare()
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "nonlocal-function-rebinding",
        """
        def launch():
            def callback():
                return leaf_north()
            def mutate():
                nonlocal callback
                callback = leaf_south
            mutate()
            return callback()
        launch()
        """,
        {"leaf_south"},
    ),
    (
        "receiver-bound-after-closure-creation",
        """
        def launch():
            def invoke():
                return receiver.encode_packet()
            receiver = SouthernCodec()
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "receiver-alias-within-descendant",
        """
        def launch():
            receiver = SouthernCodec()
            def prepare():
                alias = receiver
                def invoke():
                    return alias.encode_packet()
                return invoke()
            return prepare()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "receiver-reassigned-after-closure-creation",
        """
        def launch():
            receiver = NorthernCodec()
            def invoke():
                return receiver.encode_packet()
            receiver = SouthernCodec()
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "conditional-captured-receiver",
        """
        from external import choose
        def launch():
            if choose():
                receiver = NorthernCodec()
            else:
                receiver = SouthernCodec()
            def invoke():
                return receiver.encode_packet()
            return invoke()
        launch()
        """,
        {"NorthernCodec.encode_packet", "SouthernCodec.encode_packet"},
    ),
    (
        "conditional-nested-definition",
        """
        def launch():
            if True:
                def callback():
                    return leaf_south()
            return callback()
        launch()
        """,
        {"leaf_south"},
    ),
    (
        "repeated-nested-definition",
        """
        def launch():
            def callback():
                return leaf_north()
            callback()
            def callback():
                return leaf_south()
            return callback()
        launch()
        """,
        {"leaf_north", "leaf_south"},
    ),
    (
        "finally-nested-definition",
        """
        def launch():
            try:
                value = 1
            finally:
                def callback():
                    return leaf_south() + value
            return callback()
        launch()
        """,
        {"leaf_south"},
    ),
    (
        "local-class-namespace-is-not-method-closure",
        """
        def launch():
            def callback():
                return leaf_south()
            class Local:
                callback = None
                def invoke(instance):
                    return callback()
            return Local().invoke()
        launch()
        """,
        {"leaf_south"},
    ),
    (
        "unsupported-static-method-owner",
        """
        class Runner:
            @staticmethod
            def launch():
                def callback():
                    return leaf_south()
                return callback()
        Runner.launch()
        """,
        {"leaf_south"},
    ),
    (
        "inherited-method-with-closure",
        """
        class Runner:
            def launch(instance):
                def callback():
                    return leaf_south()
                return callback()
        class Child(Runner):
            pass
        Child().launch()
        """,
        {"leaf_south"},
    ),
    (
        "lambda-default-mutates-captured-receiver",
        """
        def launch():
            receiver = NorthernCodec()
            def invoke():
                return receiver.encode_packet()
            initialize = lambda value=(receiver := SouthernCodec()): value
            return invoke(), initialize
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "decorator-expression-mutates-captured-receiver",
        """
        def launch():
            receiver = NorthernCodec()
            @((receiver := SouthernCodec()) and identity)
            def invoke():
                return receiver.encode_packet()
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "class-header-mutates-captured-receiver",
        """
        def launch():
            receiver = NorthernCodec()
            @((receiver := SouthernCodec()) and identity)
            class Local:
                pass
            def invoke():
                return receiver.encode_packet()
            return invoke(), Local
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "comprehension-target-shadows-nested-function",
        """
        def launch():
            def callback():
                return leaf_north()
            return [callback() for callback in [leaf_south]]
        launch()
        """,
        {"leaf_south"},
    ),
    (
        "escaped-generator-target-shadows-nested-function",
        """
        def launch():
            def callback():
                return leaf_north()
            return (callback() for callback in [leaf_south])
        consume = launch()
        list(consume)
        """,
        {"leaf_south"},
    ),
]


@pytest.mark.parametrize(
    "source,protected", [(c[1], c[2]) for c in _CASES], ids=[c[0] for c in _CASES]
)
def test_dynamic_closure_boundaries_preserve_live_code(tmp_path, source, protected):
    path = tmp_path / "worker.py"
    contents = textwrap.dedent(_PRELUDE).lstrip() + "\n" + textwrap.dedent(source)
    assert write_text_no_symlink(path, contents)

    result = json.loads(analyze(str(tmp_path.resolve()), trace_file=False))
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result.get("unused_functions", [])}

    assert not {f"worker.{name}" for name in protected} & unused


# Additional controls identified during implementation review, separate from
# the original frozen 20-case safety baseline.
_FOLLOWUP_CASES = [
    (
        "class-private-name-module-fallback",
        """
        def __dispatch():
            return leaf_north()
        def _Envelope__dispatch():
            return leaf_south()
        class Envelope:
            def launch(envelope):
                def invoke():
                    return __dispatch()
                return invoke()
        Envelope().launch()
        """,
        {"_Envelope__dispatch", "leaf_south"},
    ),
    (
        "private-attribute-uses-lexical-class",
        """
        class Envelope:
            def launch(envelope):
                receiver = Receiver()
                def invoke():
                    return receiver.__dispatch()
                return invoke()
        class Receiver:
            def __dispatch(receiver):
                return leaf_north()
            def _Envelope__dispatch(receiver):
                return leaf_south()
        Envelope().launch()
        """,
        {"Receiver._Envelope__dispatch", "leaf_south"},
    ),
    (
        "argument-annotation-mutates-captured-receiver",
        """
        def launch():
            receiver = NorthernCodec()
            def annotation():
                nonlocal receiver
                receiver = SouthernCodec()
                return int
            def invoke(value: annotation() = None):
                return receiver.encode_packet(), value
            invoke.__annotations__
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "return-annotation-mutates-captured-receiver",
        """
        def launch():
            receiver = NorthernCodec()
            def annotation():
                nonlocal receiver
                receiver = SouthernCodec()
                return int
            def invoke() -> annotation():
                return receiver.encode_packet()
            invoke.__annotations__
            return invoke()
        launch()
        """,
        {"SouthernCodec.encode_packet", "leaf_south"},
    ),
    (
        "lambda-captures-private-local-function",
        """
        class Envelope:
            def launch(envelope):
                def __dispatch():
                    return leaf_south()
                callback = lambda: _Envelope__dispatch()
                return callback()
        Envelope().launch()
        """,
        {"Envelope.launch.__dispatch", "leaf_south"},
    ),
    (
        "lambda-private-parameter-shadows-local-function",
        """
        class Envelope:
            def launch(envelope):
                def __dispatch():
                    return leaf_north()
                callback = lambda __dispatch: _Envelope__dispatch()
                return callback(leaf_south)
        Envelope().launch()
        """,
        {"leaf_south"},
    ),
]


@pytest.mark.parametrize(
    "source,protected",
    [(c[1], c[2]) for c in _FOLLOWUP_CASES],
    ids=[c[0] for c in _FOLLOWUP_CASES],
)
def test_reviewed_header_and_private_scope_boundaries(tmp_path, source, protected):
    path = tmp_path / "worker.py"
    contents = textwrap.dedent(_PRELUDE).lstrip() + "\n" + textwrap.dedent(source)
    assert write_text_no_symlink(path, contents)

    result = json.loads(analyze(str(tmp_path.resolve()), trace_file=False))
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result.get("unused_functions", [])}

    assert not {f"worker.{name}" for name in protected} & unused
