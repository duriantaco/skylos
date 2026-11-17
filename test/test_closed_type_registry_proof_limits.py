"""Native-value budgets apply before expensive abstract operations.

The old interpreter's work in these tests stays modest; the cases show growth
that would become dangerous if simply repeated to the AST step limit.
"""

from test.test_closed_type_registry_independent_review import negative_names


def test_repeated_integer_squaring_abstains_before_unbounded_growth(tmp_path):
    iterations = ",".join("0" for _ in range(16))
    body = (
        "growth = 2\n"
        f"for iteration in ({iterations},):\n"
        "    growth = growth * growth\n"
        "print(router.deliver(1))"
    )
    assert negative_names(tmp_path, body) == set()


def test_large_literal_scalar_abstains_before_native_string_method(tmp_path):
    body = (
        "payload = " + repr("a" * 9000) + "\npayload.upper()\nprint(router.deliver(1))"
    )
    assert negative_names(tmp_path, body) == set()


def test_repeated_repr_is_bounded_even_when_each_call_is_pure(tmp_path):
    iterations = ",".join("0" for _ in range(13))
    body = (
        'text = "x"\n'
        f"for iteration in ({iterations},):\n"
        "    text = repr(text)\n"
        "print(router.deliver(1))"
    )
    assert negative_names(tmp_path, body) == set()


def test_table_updates_cannot_accumulate_past_literal_item_bound(tmp_path):
    first = repr({n: None for n in range(200)})
    second = repr({n: None for n in range(200, 400)})
    body = (
        f"router.handlers.update({first})\n"
        f"router.handlers.update({second})\n"
        "print(router.deliver(1))"
    )
    assert negative_names(tmp_path, body) == set()


def test_table_assignments_cannot_accumulate_past_literal_item_bound(tmp_path):
    first = ",".join(str(n) for n in range(200))
    second = ",".join(str(n) for n in range(200, 400))
    body = (
        f"for key in ({first},):\n"
        "    router.handlers[key] = None\n"
        f"for key in ({second},):\n"
        "    router.handlers[key] = None\n"
        "print(router.deliver(1))"
    )
    assert negative_names(tmp_path, body) == set()


def test_shared_tuple_key_graph_cannot_expand_outside_proof_budget(tmp_path):
    iterations = ",".join("0" for _ in range(15))
    body = (
        "key = (int,)\n"
        f"for iteration in ({iterations},):\n"
        "    key = (key, key)\n"
        "router.handlers.get(key)\n"
        "print(router.deliver(1))"
    )
    assert negative_names(tmp_path, body) == set()
