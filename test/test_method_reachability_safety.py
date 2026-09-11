"""Live method controls, derived from Python semantics; fixture code never runs."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _assert_live(tmp_path, source, *targets, grep_verify=False):
    path = tmp_path / "worker.py"
    assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())
    result = json.loads(
        analyze(str(tmp_path.resolve()), trace_file=False, grep_verify=grep_verify)
    )
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    assert not {f"worker.{target}" for target in targets} & unused


@pytest.mark.parametrize("grep_verify", [False, True])
def test_custom_new_can_return_an_unrelated_receiver(tmp_path, grep_verify):
    _assert_live(
        tmp_path,
        """
        class Requested:
            def __new__(cls):
                return Actual()
            def deliver(self):
                return 0

        class Actual:
            def deliver(self):
                return 1

        Requested().deliver()
        """,
        "Actual.deliver",
        grep_verify=grep_verify,
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_inherited_method_dispatches_to_child_override(tmp_path, grep_verify):
    _assert_live(
        tmp_path,
        """
        def finish_child_work():
            return 1

        class Parent:
            def run(self):
                return self.step()
            def step(self):
                return 0

        class Child(Parent):
            def step(self):
                return finish_child_work()

        Child().run()
        """,
        "Parent.run",
        "Child.step",
        "finish_child_work",
        grep_verify=grep_verify,
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_constructor_reaches_helpers_with_arbitrary_receiver_name(
    tmp_path, grep_verify
):
    _assert_live(
        tmp_path,
        """
        def finish_setup():
            return 1

        class Service:
            def __init__(instance):
                instance.prepare()
            def prepare(instance):
                return instance.finish()
            def finish(instance):
                return finish_setup()

        Service()
        """,
        "Service.prepare",
        "Service.finish",
        "finish_setup",
        grep_verify=grep_verify,
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_constructor_can_replace_method_through_receiver_alias(tmp_path, grep_verify):
    _assert_live(
        tmp_path,
        """
        class Replacement:
            def perform(self):
                return 1

        class Service:
            def __init__(self):
                alias = self
                alias.perform = Replacement().perform
            def perform(self):
                return 0

        Service().perform()
        """,
        "Replacement.perform",
        grep_verify=grep_verify,
    )


def test_method_global_lookup_does_not_use_the_class_namespace(tmp_path):
    _assert_live(
        tmp_path,
        """
        def operation():
            return 1

        class Service:
            operation = None
            def run(self):
                return operation()

        Service().run()
        """,
        "operation",
        "Service.run",
    )


def test_method_default_is_evaluated_in_class_namespace(tmp_path):
    _assert_live(
        tmp_path,
        """
        def initialize_option():
            return 1

        class Service:
            provider = initialize_option
            def run(self, value=provider()):
                return value
        """,
        "initialize_option",
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_exported_factory_keeps_returned_instance_methods_possible(
    tmp_path, grep_verify
):
    _assert_live(
        tmp_path,
        """
        __all__ = ["make_service"]

        class Service:
            def run(self):
                return self.finish()
            def finish(self):
                return 1

        def make_service():
            return Service()
        """,
        "Service.run",
        "Service.finish",
        grep_verify=grep_verify,
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_callback_escape_does_not_close_its_argument_types(tmp_path, grep_verify):
    _assert_live(
        tmp_path,
        """
        from external import register

        class Local:
            def accept(self):
                return 0

        class Remote:
            def accept(self):
                return 1

        def dispatch(receiver):
            return receiver.accept()

        dispatch(Local())
        register(dispatch, Remote())
        """,
        "Remote.accept",
        grep_verify=grep_verify,
    )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "unpacked_call", ["dispatch(*(Remote(),))", "dispatch(**{'receiver': Remote()})"]
)
def test_unpacked_argument_is_not_removed_from_receiver_candidates(
    tmp_path, grep_verify, unpacked_call
):
    source = """
        class Local:
            def accept(self):
                return 0

        class Remote:
            def accept(self):
                return 1

        def dispatch(receiver):
            return receiver.accept()

        dispatch(Local())
    """
    _assert_live(
        tmp_path,
        textwrap.dedent(source) + unpacked_call + "\n",
        "Local.accept",
        "Remote.accept",
        grep_verify=grep_verify,
    )


def test_bound_method_alias_keeps_transitive_helpers(tmp_path):
    _assert_live(
        tmp_path,
        """
        class Service:
            def run(self):
                return self.finish()
            def finish(self):
                return 1

        callback = Service().run
        callback()
        """,
        "Service.run",
        "Service.finish",
    )


def test_property_result_is_not_an_instance_of_its_owner(tmp_path):
    _assert_live(
        tmp_path,
        """
        class Payload:
            def deliver(self):
                return 1

        class Envelope:
            @property
            def payload(self):
                return Payload()
            def deliver(self):
                return 0

        Envelope().payload.deliver()
        """,
        "Payload.deliver",
    )


def test_receiver_reassignment_does_not_change_an_earlier_alias(tmp_path):
    _assert_live(
        tmp_path,
        """
        class First:
            def run(self):
                return 1

        class Second:
            def run(self):
                return 2

        receiver = First()
        original = receiver
        receiver = Second()
        original.run()
        receiver.run()
        """,
        "First.run",
        "Second.run",
    )


def test_loop_receiver_keeps_each_possible_method(tmp_path):
    _assert_live(
        tmp_path,
        """
        class First:
            def run(self):
                return 1

        class Second:
            def run(self):
                return 2

        for receiver in (First(), Second()):
            receiver.run()
        """,
        "First.run",
        "Second.run",
    )


def test_explicit_unbound_call_uses_the_passed_receiver(tmp_path):
    _assert_live(
        tmp_path,
        """
        class First:
            def run(instance):
                return instance.finish()
            def finish(instance):
                return 1

        class Second:
            def finish(instance):
                return 2

        First.run(Second())
        """,
        "First.run",
        "Second.finish",
    )


@pytest.mark.parametrize(
    "escape",
    [
        "from external import accept\naccept([Worker() for item in (1,)])\n",
        "from external import accept\naccept(Worker() for item in (1,))\n",
        "__all__ = ['factory']\ndef factory(flag):\n"
        "    return Worker() if flag else None\n",
        "from external import accept, choose\naccept(Worker() if choose() else None)\n",
        "from external import accept\naccept(Worker() or None)\n",
        "__all__ = ['factory']\ndef factory():\n"
        "    return [Worker() for item in (1,)]\n",
    ],
    ids=[
        "list-comprehension",
        "generator-expression",
        "conditional-return",
        "conditional-argument",
        "boolean-argument",
        "comprehension-return",
    ],
)
def test_receiver_escapes_through_compound_expressions(tmp_path, escape):
    source = """
        class Worker:
            def start(self):
                return self.finish()
            def finish(self):
                return self.start()

    """
    _assert_live(
        tmp_path,
        textwrap.dedent(source) + escape,
        "Worker.start",
        "Worker.finish",
        grep_verify=True,
    )


@pytest.mark.parametrize(
    "extension",
    [
        "from external import invoke\nAlias.invoke = invoke\nWorker().invoke()\n",
        "from external import Descriptor\n"
        "Alias.action = Descriptor()\nWorker().action()\n",
    ],
    ids=["foreign-method", "foreign-descriptor"],
)
def test_new_class_member_can_pass_receiver_to_external_code(tmp_path, extension):
    source = """
        class Worker:
            def start(self):
                return self.finish()
            def finish(self):
                return self.start()

        Alias = Worker
    """
    _assert_live(
        tmp_path,
        textwrap.dedent(source) + extension,
        "Worker.start",
        "Worker.finish",
        grep_verify=True,
    )


def test_explicit_mangled_method_name_reaches_private_group(tmp_path):
    _assert_live(
        tmp_path,
        """
        class Worker:
            def __start(self):
                return self.__finish()
            def __finish(self):
                return self.__start()

        Worker()._Worker__start()
        """,
        "Worker.__start",
        "Worker.__finish",
        grep_verify=True,
    )


@pytest.mark.parametrize(
    "source,method",
    [
        (
            """
            class Worker:
                def __start(self):
                    return 0
                def _Worker__start(self):
                    return self.finish()
                def finish(self):
                    return self._Worker__start()
                def run(self):
                    return self.__start()

            Worker().run()
            """,
            "Worker._Worker__start",
        ),
        (
            """
            class Worker:
                _Worker__start = None
                def __start(self):
                    return self.finish()
                def finish(self):
                    return self.__start()
                def run(self):
                    return self._Worker__start()

            Worker().run()
            """,
            "Worker.__start",
        ),
    ],
    ids=["method-replaces-private-method", "private-method-replaces-assignment"],
)
def test_mangled_namespace_collision_keeps_actual_method_live(tmp_path, source, method):
    _assert_live(tmp_path, source, method, "Worker.finish", grep_verify=True)


def test_instance_class_attribute_exposes_its_class(tmp_path):
    _assert_live(
        tmp_path,
        """
        from external import register

        class Worker:
            def start(self):
                return self.finish()
            def finish(self):
                return self.start()

        register(Worker().__class__)
        """,
        "Worker.start",
        "Worker.finish",
        grep_verify=True,
    )
