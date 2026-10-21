"""Finite abstract values for project-owned Python path and listing effects."""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode.python_project_sources import (
    Choice,
    BrowserMethod,
    Class,
    Function,
    Environment,
    NULL,
    NullValue,
    Record,
    SourceSuper,
    Symbol,
    alternatives,
    merge,
)
from skylos.deadcode.python_source_proofs import _scope_nodes


def _items(value):
    result = []
    for candidate in alternatives(value):
        if isinstance(candidate, dict):
            result.extend(candidate)
        elif isinstance(candidate, (list, tuple)):
            result.extend(candidate)
    return result[:512]


def _truth_states(value):
    states = set()
    for item in alternatives(value):
        if isinstance(item, NullValue):
            states.add(False)
        elif isinstance(item, (str, int, float, bool, list, tuple, dict, Path)):
            states.add(bool(item))
        else:
            states.update({False, True})
    return states or {False, True}


def _safe_fields(index, owner, seen=frozenset()):
    if owner is None or owner.node is None:
        return True
    if id(owner.node) in seen:
        return False
    node = owner.node
    methods = {child.name for child in node.body if isinstance(child, ast.FunctionDef)}
    if node.keywords or methods & {"__getattribute__", "__getattr__", "__new__"}:
        return False
    for base in node.bases:
        parent = index.evaluate(base, owner.path, {})
        if isinstance(parent, Class):
            if not _safe_fields(index, parent, seen | {id(node)}):
                return False
        elif not isinstance(parent, Symbol) or not parent.name.startswith("gradio."):
            return False
    return True


def gradio_class_provider(index, owner, seen=frozenset()):
    if (
        owner is None
        or owner.node is None
        or id(owner.node) in seen
        or not _safe_fields(index, owner)
    ):
        return None
    for base in owner.node.bases:
        value = index.evaluate(base, owner.path, {})
        if isinstance(value, Symbol) and value.name.startswith("gradio."):
            return value.name
        if isinstance(value, Class):
            provider = gradio_class_provider(index, value, seen | {id(owner.node)})
            if provider:
                return provider
    return None


def _attribute(index, value, name):
    from skylos.deadcode.python_module_effects import SourceNamespace

    if isinstance(value, SourceNamespace):
        return value.attribute(index, name)
    if isinstance(value, SourceSuper):
        lineage = index.source_lineage(value.receiver.owner)
        if lineage is None:
            return None
        after_owner = False
        for parent in lineage:
            if parent is value.owner:
                after_owner = True
                continue
            if not after_owner:
                continue
            for child in parent.node.body:
                if isinstance(child, ast.FunctionDef) and child.name == name:
                    return index.instance_method(value.receiver, name, parent)
        return None
    if isinstance(value, Symbol):
        resolved = index.symbol(value)
        if resolved is None:
            return None
        if not isinstance(resolved, Symbol):
            return _attribute(index, resolved, name)
        return index.symbol(
            Symbol(value.name + "." + name, bound=value.bound, invalid=value.invalid)
        )
    if isinstance(value, Record):
        if not _safe_fields(index, value.owner):
            return None
        if value.owner is not None and value.owner.node is not None:
            node = value.owner.node
            methods = {
                child.name for child in node.body if isinstance(child, ast.FunctionDef)
            }
            if node.keywords or methods & {
                "__getattribute__",
                "__getattr__",
                "__new__",
            }:
                return None
            if name in methods:
                for child in node.body:
                    if (
                        isinstance(child, ast.FunctionDef)
                        and child.name == name
                        and child.decorator_list
                    ):
                        return None
        if name in value.fields:
            return value.fields[name]
        method = index.instance_method(value, name)
        if method is not None:
            return method
        if value.provider is not None and name in {
            "click",
            "change",
            "input",
            "submit",
            "select",
            "load",
            "then",
            "success",
            "release",
            "upload",
            "clear",
            "play",
            "pause",
            "stop",
            "end",
            "blur",
            "focus",
            "execute_script",
        }:
            return BrowserMethod(value, name)
    if isinstance(value, Path) and name == "parent":
        return value.parent
    if isinstance(value, Path) and name == "name":
        return value.name
    if isinstance(value, Path) and name == "suffix":
        return value.suffix
    return None


def evaluate(index, node, path, env):
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        if node.value is None:
            return NULL
        if isinstance(node.value, (str, int, float, bool)):
            return node.value
        return None
    if isinstance(node, ast.Name):
        return index.name(path, node.id, env)
    if isinstance(node, ast.Yield):
        value = index.evaluate(node.value, path, env)
        if isinstance(env, Environment):
            env.yielded.append(value)
        return None
    if isinstance(node, ast.YieldFrom):
        value = index.evaluate(node.value, path, env)
        if isinstance(env, Environment):
            env.yielded.extend(_items(value))
        return None
    if isinstance(node, ast.Attribute):
        return merge(
            _attribute(index, value, node.attr)
            for value in alternatives(index.evaluate(node.value, path, env))
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = []
        for child in node.elts:
            values.append(index.evaluate(child, path, env))
        return values
    if isinstance(node, ast.Dict):
        values = {}
        for key, value in zip(node.keys, node.values):
            if key is None:
                continue
            resolved = index.evaluate(key, path, env)
            if isinstance(resolved, (str, int, type(None))):
                values[resolved] = index.evaluate(value, path, env)
        return values
    if isinstance(node, ast.Subscript):
        value = index.evaluate(node.value, path, env)
        key = index.evaluate(node.slice, path, env)
        result = []
        for container in alternatives(value):
            if isinstance(container, dict):
                if key is None:
                    result.extend(container.values())
                elif isinstance(key, (str, int)):
                    result.append(container.get(key))
            elif isinstance(container, (list, tuple, str)) and isinstance(key, int):
                if -len(container) <= key < len(container):
                    result.append(container[key])
        return merge(result)
    if isinstance(node, ast.BinOp):
        left, right = (
            index.evaluate(node.left, path, env),
            index.evaluate(node.right, path, env),
        )
        result = []
        for first in alternatives(left):
            for second in alternatives(right):
                if (
                    isinstance(node.op, ast.Add)
                    and isinstance(first, str)
                    and isinstance(second, str)
                ):
                    result.append(first + second)
                elif (
                    isinstance(node.op, ast.Add)
                    and isinstance(first, list)
                    and isinstance(second, list)
                ):
                    result.append(first + second)
                elif (
                    isinstance(node.op, ast.Div)
                    and isinstance(first, Path)
                    and isinstance(second, str)
                ):
                    result.append(first / second)
        return merge(result)
    if isinstance(node, ast.JoinedStr):
        values = [""]
        for child in node.values:
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                choices = [child.value]
            elif (
                isinstance(child, ast.FormattedValue)
                and child.conversion == -1
                and child.format_spec is None
            ):
                choices = [
                    str(value)
                    for value in alternatives(index.evaluate(child.value, path, env))
                    if isinstance(value, (str, int, Path))
                ]
            else:
                return None
            if not choices:
                choices = ["\x00"]
            values = [prefix + suffix for prefix in values for suffix in choices][:256]
        return merge(values)
    if isinstance(node, ast.IfExp):
        condition = index.evaluate(node.test, path, env)
        states = _truth_states(condition)
        if len(states) == 1:
            return index.evaluate(
                node.body if True in states else node.orelse, path, env
            )
        return merge(
            [
                index.evaluate(node.body, path, env),
                index.evaluate(node.orelse, path, env),
            ]
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = index.evaluate(node.operand, path, env)
        return merge(not state for state in _truth_states(value))
    if isinstance(node, ast.BoolOp):
        possible = []
        for position, expression in enumerate(node.values):
            value = index.evaluate(expression, path, env)
            final = position == len(node.values) - 1
            continue_possible = False
            for item in alternatives(value):
                states = _truth_states(item)
                short_state = True if isinstance(node.op, ast.Or) else False
                if final or short_state in states:
                    possible.append(item)
                if not final and short_state not in states:
                    continue_possible = True
                elif not final and len(states) > 1:
                    continue_possible = True
            if final or not continue_possible:
                return merge(possible)
        return merge(possible)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = (
            index.evaluate(node.left, path, env),
            index.evaluate(node.comparators[0], path, env),
        )
        if (
            left is None
            or right is None
            or isinstance(left, Choice)
            or isinstance(right, Choice)
        ):
            return None
        operator = node.ops[0]
        if isinstance(operator, (ast.Is, ast.IsNot)):
            if isinstance(left, NullValue) and isinstance(right, NullValue):
                same = True
            elif isinstance(left, NullValue) and isinstance(
                right, (str, int, float, bool, Path, list, tuple, dict, Record)
            ):
                same = False
            elif isinstance(right, NullValue) and isinstance(
                left, (str, int, float, bool, Path, list, tuple, dict, Record)
            ):
                same = False
            else:
                return None
            if isinstance(operator, ast.Is):
                return same
            return not same
        if not isinstance(left, (str, int, float, bool, Path)):
            return None
        if isinstance(operator, (ast.Eq, ast.NotEq)):
            same = left == right
            if isinstance(operator, ast.Eq):
                return same
            return not same
        if isinstance(operator, (ast.In, ast.NotIn)) and isinstance(
            right, (str, list, tuple, dict)
        ):
            same = left in right
            if isinstance(operator, ast.In):
                return same
            return not same
        return None
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        return _comprehension(index, node, path, env)
    if isinstance(node, ast.Call):
        from skylos.deadcode.python_source_intrinsics import _invoke, _method

        arguments = []
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                values = index.evaluate(argument.value, path, env)
                if not isinstance(values, (list, tuple)):
                    return None
                arguments.extend(values)
            else:
                arguments.append(index.evaluate(argument, path, env))
            if len(arguments) > 512:
                return None
        keywords = {}
        for keyword in node.keywords:
            value = index.evaluate(keyword.value, path, env)
            if keyword.arg in {"_js", "js"} and value is None:
                from skylos.deadcode.browser_refs import _string_parts

                parts = _string_parts(keyword.value)
                if parts is not None:
                    value = "".join(parts)
            if keyword.arg is None:
                if isinstance(value, dict):
                    if set(value) & set(keywords):
                        return None
                    keywords.update(value)
                else:
                    return None
            else:
                if keyword.arg in keywords:
                    return None
                keywords[keyword.arg] = value
        if isinstance(node.func, ast.Attribute):
            receiver = index.evaluate(node.func.value, path, env)
            results = []
            for value in alternatives(receiver):
                function = _attribute(index, value, node.func.attr)
                if (
                    isinstance(value, Record)
                    and value.provider is not None
                    and node.func.attr not in value.fields
                    and function is None
                    and _safe_fields(index, value.owner)
                    and index.symbol(
                        Symbol(value.provider + "." + node.func.attr, bound=True)
                    )
                    is not None
                ):
                    if len(index.browser_calls) < 20_000:
                        browser_keywords = dict(keywords)
                        if node.func.attr == "execute_script" and arguments:
                            browser_keywords["js"] = arguments[0]
                        index.browser_calls.append(
                            (
                                value.provider,
                                node.func.attr,
                                browser_keywords,
                            )
                        )
                if index.observer is not None:
                    replacement = index.observer(
                        node, path, env, function, arguments, keywords
                    )
                    if replacement is not None:
                        results.append(replacement)
                        continue
                if function is not None:
                    results.append(_invoke(index, function, arguments, keywords, path))
                elif isinstance(value, Record) and node.func.attr in value.fields:
                    results.append(
                        _invoke(
                            index,
                            value.fields[node.func.attr],
                            arguments,
                            keywords,
                            path,
                        )
                    )
                else:
                    results.append(
                        _method(index, value, node.func.attr, arguments, keywords, path)
                    )
            return merge(results)
        function = index.evaluate(node.func, path, env)
        if (
            isinstance(function, Symbol)
            and function.name == "builtins.super"
            and isinstance(node.func, ast.Name)
            and node.func.id == "super"
            and not arguments
            and not keywords
        ):
            owner = getattr(env, "class_owner", None)
            receiver = env.get("self")
            if isinstance(owner, Class) and isinstance(receiver, Record):
                return SourceSuper(receiver, owner)
            return None
        if index.observer is not None:
            replacement = index.observer(node, path, env, function, arguments, keywords)
            if replacement is not None:
                return replacement
        return merge(
            _invoke(index, value, arguments, keywords, path)
            for value in alternatives(function)
        )
    return None


def _assign(index, target, value, path, env):
    for text in alternatives(value):
        if isinstance(text, str) and "<" in text and len(index.rendered_html) < 4096:
            index.rendered_html.append(text)
    if isinstance(target, ast.Name):
        env[target.id] = value
        if getattr(env, "module_scope", False) or target.id in getattr(
            env, "global_names", ()
        ):
            index.globals[(path, target.id)] = value
    elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (list, tuple)):
        for child, item in zip(target.elts, value):
            _assign(index, child, item, path, env)
    elif isinstance(target, ast.Attribute):
        receiver = index.evaluate(target.value, path, env)
        from skylos.deadcode.python_module_effects import invalidate_namespace

        if invalidate_namespace(receiver):
            return
        if isinstance(receiver, Record):
            receiver.fields[target.attr] = value
        elif isinstance(receiver, Symbol):
            index.mutations.add(receiver.name + "." + target.attr)
        else:
            from skylos.deadcode.python_template_effects import TemplateStream

            if isinstance(receiver, TemplateStream):
                receiver.valid = False
    elif isinstance(target, ast.Subscript):
        receiver = index.evaluate(target.value, path, env)
        key = index.evaluate(target.slice, path, env)
        from skylos.deadcode.python_module_effects import invalidate_namespace

        if invalidate_namespace(receiver):
            return
        if isinstance(receiver, Symbol) and receiver.name == "sys.modules":
            if isinstance(key, str):
                index.registry_changes.add(key)
            else:
                index.registry_unknown = True
        if isinstance(receiver, dict) and isinstance(key, (str, int, type(None))):
            receiver[key] = value


def _comprehension(index, node, path, env):
    result = {} if isinstance(node, ast.DictComp) else []
    pending = [(0, dict(env))]
    steps = 0
    while pending and steps < 2048:
        steps += 1
        position, local = pending.pop()
        if position == len(node.generators):
            if isinstance(node, ast.DictComp):
                key = index.evaluate(node.key, path, local)
                if isinstance(key, (str, int, type(None))):
                    result[key] = index.evaluate(node.value, path, local)
            else:
                result.append(index.evaluate(node.elt, path, local))
            continue
        generator = node.generators[position]
        iterable = index.evaluate(generator.iter, path, local)
        items = _items(iterable)
        if iterable is None:
            items = [None]
        for item in items:
            bound = dict(local)
            _assign(index, generator.target, item, path, bound)
            if any(
                index.evaluate(condition, path, bound) is False
                for condition in generator.ifs
            ):
                continue
            pending.append((position + 1, bound))
    return result


def block(index, statements, path, env):
    returns = []
    for node in statements:
        index.budget += 1
        index.total_steps += 1
        index.owner_steps += 1
        if index.budget > 150_000 or index.owner_steps > 1_000_000:
            break
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = index.evaluate(node.value, path, env)
            for text in alternatives(value):
                if (
                    isinstance(text, str)
                    and "<" in text
                    and len(index.rendered_html) < 4096
                ):
                    index.rendered_html.append(text)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                _assign(index, target, value, path, env)
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            left = index.evaluate(node.target, path, env)
            right = index.evaluate(node.value, path, env)
            if isinstance(left, list) and isinstance(right, list):
                left.extend(right[: 512 - len(left)])
            elif isinstance(left, (str, Choice)):
                joined = []
                for first in alternatives(left):
                    for second in alternatives(right):
                        if isinstance(first, str) and isinstance(second, str):
                            joined.append(first + second)
                            if len(joined) >= 256:
                                break
                    if len(joined) >= 256:
                        break
                _assign(index, node.target, merge(joined), path, env)
        elif isinstance(node, ast.Return):
            value = index.evaluate(node.value, path, env)
            returns.append(value)
            for text in alternatives(value):
                if (
                    isinstance(text, str)
                    and "<" in text
                    and len(index.rendered_html) < 4096
                ):
                    index.rendered_html.append(text)
            return returns, "return"
        elif isinstance(node, ast.Continue):
            return returns, "continue"
        elif isinstance(node, ast.Break):
            return returns, "break"
        elif isinstance(node, ast.Raise):
            index.evaluate(node.exc, path, env)
            index.evaluate(node.cause, path, env)
            return returns, "raise"
        elif isinstance(node, ast.Expr):
            index.evaluate(node.value, path, env)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            env.update(index.import_bindings(node, path))
        elif isinstance(node, ast.FunctionDef):
            if getattr(env, "module_scope", False):
                env[node.name] = index.global_value(path, node.name)
            else:
                env[node.name] = Function(path, node, env)
            if index.registered_route(node, path, env):
                function = Function(path, node, env, registered=True)
                parameters = node.args.posonlyargs + node.args.args
                index.call(
                    function,
                    [None] * len(parameters),
                    {item.arg: None for item in node.args.kwonlyargs},
                )
        elif isinstance(node, ast.Global):
            if isinstance(env, Environment):
                env.global_names.update(node.names)
        elif isinstance(node, ast.If):
            condition = index.evaluate(node.test, path, env)
            states = _truth_states(condition)
            if len(states) > 1:
                left = Environment(
                    env, module_scope=getattr(env, "module_scope", False)
                )
                right = Environment(
                    env, module_scope=getattr(env, "module_scope", False)
                )
                first, first_flow = block(index, node.body, path, left)
                second, second_flow = block(index, node.orelse, path, right)
                returns.extend(first + second)
                env.yielded.extend(left.yielded)
                env.yielded.extend(right.yielded)
                for name in set(left) | set(right):
                    env[name] = merge([left.get(name), right.get(name)])
                if first_flow == second_flow and first_flow:
                    return returns, first_flow
            else:
                branch = node.body if True in states else node.orelse
                found, flow = block(index, branch, path, env)
                returns.extend(found)
                if flow:
                    return returns, flow
        elif isinstance(node, ast.For):
            iterable = index.evaluate(node.iter, path, env)
            items = _items(iterable)
            if iterable is None:
                items = [None]
            for item in items:
                _assign(index, node.target, item, path, env)
                found, flow = block(index, node.body, path, env)
                returns.extend(found)
                if flow == "break":
                    break
                if flow in {"return", "raise"}:
                    return returns, flow
        elif isinstance(node, ast.With):
            streams = []
            from skylos.deadcode.python_template_effects import TemplateStream

            for item in node.items:
                value = index.evaluate(item.context_expr, path, env)
                if isinstance(value, TemplateStream):
                    streams.append(value)
                if item.optional_vars is not None:
                    _assign(index, item.optional_vars, value, path, env)
            found, flow = block(index, node.body, path, env)
            returns.extend(found)
            for stream in streams:
                stream.valid = False
            if flow:
                return returns, flow
        elif isinstance(node, ast.Try):
            branches = []
            normal = Environment(env, module_scope=getattr(env, "module_scope", False))
            found, flow = block(index, node.body, path, normal)
            if flow != "raise":
                if not flow:
                    extra, flow = block(index, node.orelse, path, normal)
                    found.extend(extra)
                branches.append((normal, found, flow))
            for handler in node.handlers:
                caught = Environment(
                    env, module_scope=getattr(env, "module_scope", False)
                )
                if handler.name:
                    caught[handler.name] = None
                found, flow = block(index, handler.body, path, caught)
                branches.append((caught, found, flow))
            continuing = []
            flows = set()
            for branch, found, flow in branches:
                final_returns, final_flow = block(index, node.finalbody, path, branch)
                if final_flow:
                    found = final_returns
                    flow = final_flow
                else:
                    found.extend(final_returns)
                returns.extend(found)
                env.yielded.extend(branch.yielded)
                flows.add(flow)
                if not flow:
                    continuing.append(branch)
            names = set()
            for branch in continuing:
                names.update(branch)
            for name in names:
                values = []
                for branch in continuing:
                    values.append(branch.get(name))
                env[name] = merge(values)
            if not branches:
                found, final_flow = block(index, node.finalbody, path, env)
                returns.extend(found)
                return returns, final_flow or "raise"
            if not continuing and len(flows) == 1:
                flow = flows.pop()
                if flow:
                    return returns, flow
            elif not continuing:
                if "continue" in flows:
                    return returns, "continue"
                if "break" in flows:
                    return returns, "break"
                return returns, "return"
    return returns, ""


def call_function(index, function, arguments, keywords):
    active = getattr(index, "active_calls", set())
    index.active_calls = active
    if (
        len(active) > 16
        or id(function.node) in active
        or (function.node.decorator_list and not function.registered)
    ):
        return None
    args = function.node.args
    parameters = args.posonlyargs + args.args
    supplied = list(arguments)
    if parameters and parameters[0].arg == "self" and "self" in function.closure:
        supplied.insert(0, function.closure["self"])
    if len(supplied) > len(parameters) and args.vararg is None:
        return None
    declared = {parameter.arg for parameter in parameters + args.kwonlyargs}
    if args.kwarg is None and set(keywords) - declared:
        return None
    if {parameter.arg for parameter in args.posonlyargs} & set(keywords):
        return None
    positional_names = {parameter.arg for parameter in parameters[: len(supplied)]}
    if positional_names & set(keywords):
        return None
    env = Environment(function.closure)
    env.class_owner = function.owner
    for parameter, value in zip(parameters, supplied):
        env[parameter.arg] = value
    env.update(keywords)
    if args.vararg is not None:
        env[args.vararg.arg] = supplied[len(parameters) :]
    if args.kwarg is not None:
        env[args.kwarg.arg] = {
            key: value for key, value in keywords.items() if key not in declared
        }
    defaults = (
        dict(
            zip(
                [value.arg for value in parameters[-len(args.defaults) :]],
                args.defaults,
            )
        )
        if args.defaults
        else {}
    )
    defaults.update(zip([value.arg for value in args.kwonlyargs], args.kw_defaults))
    for parameter in parameters + args.kwonlyargs:
        if parameter.arg not in env:
            if parameter.arg not in defaults or defaults[parameter.arg] is None:
                return None
            env[parameter.arg] = index.evaluate(
                defaults.get(parameter.arg), function.path, env
            )
    caller_budget = index.budget
    caller_owner_steps = index.owner_steps
    index.budget = 0
    index.owner_steps = 0
    active.add(id(function.node))
    index.reachable.add((function.path, id(function.node)))
    arguments_key = []
    for name, value in sorted(env.items()):
        if isinstance(value, (str, int, bool, Path)):
            arguments_key.append((name, str(value)))
    context_key = (function.path, id(function.node), tuple(arguments_key))
    if context_key not in index.context_keys and len(index.executed_contexts) < 4096:
        index.context_keys.add(context_key)
        index.executed_contexts.append((function.node, function.path, env))
    try:
        values, flow = block(index, function.node.body, function.path, env)
        if index.budget > 150_000 or index.owner_steps > 1_000_000:
            return None
        index.completed.add((function.path, id(function.node)))
        if flow == "raise":
            return None
        if any(
            isinstance(node, (ast.Yield, ast.YieldFrom))
            for node in _scope_nodes(function.node)
        ):
            return env.yielded
        if not values:
            return NULL
        return merge(values)
    finally:
        active.remove(id(function.node))
        index.budget = caller_budget
        index.owner_steps = caller_owner_steps
