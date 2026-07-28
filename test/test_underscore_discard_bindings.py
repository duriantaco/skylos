import json

from skylos.analyzer import analyze


def test_issue_647_uses_scope_aware_underscore_discard_policy(tmp_path):
    source = tmp_path / "issue_647.py"
    source.write_text(
        """
from collections.abc import AsyncIterator, Callable

_module_assignment: object = object()


def make_recursive(values: list[str]) -> Callable[[str], list[str]]:
    if not values:
        def dispatch_leaf(_unused_argument: str) -> list[str]:
            return []

        return dispatch_leaf

    rest = make_recursive(values[1:])

    def dispatch_branch(used_argument: str) -> list[str]:
        return rest(used_argument)

    return dispatch_branch


def parameters(
    _positional_only: object,
    /,
    _ordinary: object,
    *,
    _keyword_only: object,
    regular_unused: object,
    __private: object,
) -> None:
    pass


def changing_type(_input2: str) -> None:
    for _itr in range(5):
        pass


async def consume_async(stream: AsyncIterator[object]) -> None:
    async for _async_item in stream:
        pass


def direct_assignment() -> None:
    _local_assignment = object()


def other_bindings(context: object, value: object) -> None:
    with context as _with_binding:
        pass
    try:
        raise ValueError
    except ValueError as _error_binding:
        pass
    match value:
        case {"key": _match_binding}:
            pass


for _loop_target in range(5):
    pass

for used_loop_target, _tuple_loop_target, *_starred_loop_target in (
    (object(), object(), object()),
):
    print(used_loop_target)

for __private_loop in range(1):
    pass


make_recursive([])
parameters(
    object(),
    object(),
    _keyword_only=object(),
    regular_unused=object(),
    __private=object(),
)
changing_type("test")
direct_assignment()
other_bindings(object(), {"key": object()})
""",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), grep_verify=False))
    unused_parameters = {
        item["simple_name"] for item in result.get("unused_parameters", [])
    }
    unused_variables = {
        item["simple_name"] for item in result.get("unused_variables", [])
    }

    assert {
        "_unused_argument",
        "_positional_only",
        "_ordinary",
        "_keyword_only",
        "_input2",
    }.isdisjoint(unused_parameters)
    assert {"regular_unused", "__private"} <= unused_parameters

    assert {
        "_loop_target",
        "_tuple_loop_target",
        "_starred_loop_target",
        "_itr",
        "_async_item",
    }.isdisjoint(unused_variables)
    assert {
        "_module_assignment",
        "_local_assignment",
        "__private_loop",
        "_with_binding",
        "_error_binding",
        "_match_binding",
    } <= unused_variables
