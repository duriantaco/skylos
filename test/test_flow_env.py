"""Branch joins of ``flow_env.ValueFlow``: a value that any path can produce
reaches the join; a path that cannot continue does not."""

import ast
import textwrap

from skylos.rules.danger import flow_env

TAINT = frozenset({"tainted"})
UNKNOWN = frozenset({"unknown"})


def _evaluate(node, value):
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "source"
    ):
        return TAINT
    labels = frozenset()
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.expr):
            labels |= value(child)
    return labels


def _sink_labels(code, *, max_steps=flow_env.MAX_STEPS):
    tree = ast.parse(textwrap.dedent(code))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    sinks = [
        node.args[0]
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "sink"
    ]
    flow = flow_env.ValueFlow(
        function,
        _evaluate,
        outer=lambda name: frozenset(),
        top=UNKNOWN,
        max_steps=max_steps,
    )
    results = flow.run(sinks)
    if results is None:
        return None
    return [results.get(id(node)) for node in sinks]


def test_if_elif_else_joins_every_branch():
    assert _sink_labels(
        """
        def f(c, d):
            x = 'a'
            if c:
                x = source()
            elif d:
                x = 'b'
            else:
                pass
            sink(x)
        """
    ) == [TAINT]


def test_strong_updates_on_every_branch_remove_the_old_value():
    assert _sink_labels(
        """
        def f(c):
            x = source()
            if c:
                x = 'a'
            else:
                x = 'b'
            sink(x)
        """
    ) == [frozenset()]


def test_returning_or_raising_branch_does_not_reach_the_join():
    assert _sink_labels(
        """
        def f(c, d):
            x = 'a'
            if c:
                x = source()
                return
            if d:
                x = source()
                raise ValueError(x)
            sink(x)
        """
    ) == [frozenset()]


def test_loop_keeps_zero_iteration_path():
    assert _sink_labels(
        """
        def f(items):
            x = source()
            for item in items:
                x = 'a'
            sink(x)
        """
    ) == [TAINT]


def test_loop_carries_values_into_the_next_iteration():
    assert _sink_labels(
        """
        def f(items):
            x = 'a'
            for item in items:
                sink(x)
                x = source()
        """
    ) == [TAINT]


def test_break_and_continue_states_reach_the_loop_exit():
    assert _sink_labels(
        """
        def f(cond, items, c):
            x = 'a'
            while cond():
                if c:
                    x = source()
                    break
                x = 'b'
            sink(x)
            y = 'a'
            for item in items:
                if c:
                    y = source()
                    continue
                y = 'b'
            sink(y)
        """
    ) == [TAINT, TAINT]


def test_loop_else_and_break_paths_join():
    assert _sink_labels(
        """
        def f(items):
            for item in items:
                x = source()
                break
            else:
                x = 'a'
            sink(x)
        """
    ) == [TAINT]


def test_handler_starts_from_any_state_the_body_can_raise_in():
    assert _sink_labels(
        """
        def f():
            x = 'a'
            try:
                x = source()
                risky()
                x = 'b'
            except ValueError:
                sink(x)
            y = 'a'
            try:
                y = source()
            except ValueError:
                y = 'b'
            sink(y)
        """
    ) == [TAINT, TAINT]


def test_finally_sees_returning_paths_and_break_sees_finally_effects():
    assert _sink_labels(
        """
        def f(items):
            try:
                x = source()
                return x
            finally:
                sink(x)
        """
    ) == [TAINT]
    assert _sink_labels(
        """
        def f(items):
            x = 'a'
            for item in items:
                try:
                    break
                finally:
                    x = source()
            sink(x)
        """
    ) == [TAINT]


def test_with_body_can_be_cut_short_by_a_suppressed_exception():
    assert _sink_labels(
        """
        def f(ctx):
            x = 'a'
            with ctx():
                x = source()
                fail()
                x = 'b'
            sink(x)
        """
    ) == [TAINT]


def test_match_joins_cases_and_falls_through_without_a_wildcard():
    assert _sink_labels(
        """
        def f(command):
            match command:
                case 'a':
                    x = source()
                case _:
                    x = 'b'
            sink(x)
            y = source()
            match command:
                case 'a':
                    y = 'b'
            sink(y)
            z = source()
            match command:
                case 'a':
                    z = 'b'
                case other:
                    z = 'c'
            sink(z)
        """
    ) == [TAINT, TAINT, frozenset()]


def test_walrus_binds_in_conditions_short_circuits_and_comprehensions():
    assert _sink_labels(
        """
        def f(c, items):
            if (x := source()):
                pass
            sink(x)
            y = 'a'
            ok = c and (y := source())
            sink(y)
            [(z := source()) for item in items]
            sink(z)
        """
    ) == [TAINT, TAINT, TAINT]


def test_augmented_assignment_keeps_the_old_value():
    assert _sink_labels(
        """
        def f():
            x = 'a'
            x += source()
            sink(x)
        """
    ) == [TAINT]


def test_container_stores_taint_the_container_but_literal_keys_stay_precise():
    assert _sink_labels(
        """
        def f(key):
            d = {'a': 'x'}
            d['b'] = source()
            sink(d)
            sink(d['a'])
            sink(d['b'])
            e = {'a': 'x'}
            e[key] = source()
            sink(e['a'])
            g = {'a': 'x'}
            g.update(source())
            sink(g['a'])
            items = []
            items.append(source())
            sink(items)
        """
    ) == [TAINT, frozenset(), TAINT, TAINT, TAINT, TAINT]


def test_parameters_are_unknown_and_unreachable_or_nested_sinks_are_absent():
    assert _sink_labels(
        """
        def f(p):
            sink(p)
            def inner():
                sink('a')
            return
            sink('b')
        """
    ) == [UNKNOWN, None, None]


def test_budget_exceeded_returns_none():
    body = "\n".join(f"    x{index} = source()" for index in range(200))
    assert _sink_labels(f"def f():\n{body}\n    sink(x1)\n", max_steps=50) is None
