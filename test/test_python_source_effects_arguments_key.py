"""The literal-argument key for evaluated calls must never raise.

A real project (pyload) made the source-effects pass crash with
``TypeError: '<' not supported between instances of 'NoneType' and 'str'``
because an environment held a ``None`` key beside parameter names.
"""

from pathlib import Path

from skylos.deadcode.python_source_effects import _arguments_key


def test_mixed_none_and_string_keys_do_not_raise():
    key = _arguments_key({"name": "x", None: "y", "count": 3})
    assert key == (("count", "3"), ("name", "x"), (None, "y"))


def test_string_keys_keep_name_order_and_literal_values_only():
    env = {"b": Path("/tmp/b"), "a": True, "c": object(), "d": None}
    assert _arguments_key(env) == (("a", "True"), ("b", "/tmp/b"))
