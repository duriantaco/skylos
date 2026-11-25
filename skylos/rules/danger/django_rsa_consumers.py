"""Follow a registered setting's fallback path to an OpenSSL RSA size argument."""

from __future__ import annotations

import ast
import re
from string import Formatter

from .danger_sql.sql_syntax import _first, _load, _prior, _reachable, _valid_call
from .django_field_providers import django_field_is_available
from .import_proof import provider_binding_is_stable
from .oslo_config_options import _body
from .rsa_config_defaults import _parameter, _single_local
from .rsa_key_sizes import _VECTOR_RUNNERS, openssl_size_operand


def _formatted_size(expr):
    """Substitute AST arguments for whole shell words, without evaluating the string."""
    if isinstance(expr, ast.JoinedStr):
        parts = []
        args = []
        for item in expr.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                if any(char in item.value for char in "{}"):
                    return None
                parts.append(item.value)
            elif (
                isinstance(item, ast.FormattedValue)
                and item.format_spec is None
                and item.conversion == -1
            ):
                parts.append("{}")
                args.append(item.value)
            else:
                return None
        template = "".join(parts)
    elif (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "format"
        and isinstance(expr.func.value, ast.Constant)
        and isinstance(expr.func.value.value, str)
        and not expr.keywords
    ):
        template, args = expr.func.value.value, expr.args
    else:
        return None
    if (
        "genrsa" not in template
        or len(template) > 512
        or len(args) > 16
        or any(isinstance(arg, ast.Starred) for arg in args)
    ):
        return None
    # Restrict the shell command to plain words. In particular, a semicolon,
    # quote, pipe or redirection changes how the shell parses the operands.
    if not re.fullmatch(r"[a-zA-Z0-9_ ./{}-]+", template):
        return None
    vector = []
    auto = 0
    numbered = False
    try:
        for word in template.split():
            (field,) = Formatter().parse(word)
            literal, index, spec, conversion = field
            if index is None:
                vector.append(ast.Constant(literal))
                continue
            if literal or spec or conversion or index and not index.isdecimal():
                return None
            if (auto and index) or (numbered and not index):
                return None
            numbered |= bool(index)
            vector.append(args[int(index) if index else auto])
            auto += not index
    except (ValueError, IndexError):
        return None
    call = ast.Call(func=ast.Name(id="run"), args=[ast.List(elts=vector)], keywords=[])
    return openssl_size_operand(call, "subprocess.run")


def _condition(test, defaults):
    if isinstance(test, ast.Name):
        return bool(defaults[test.id]) if test.id in defaults else None
    if (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id in defaults
        and len(test.ops) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    ):
        if isinstance(test.ops[0], ast.IsNot):
            return defaults[test.left.id] is not None
        if isinstance(test.ops[0], ast.Is):
            return defaults[test.left.id] is None
    return None


def _wrapper_executes(project, unit, fn):
    """Prove the first argument is executed with shell=True for a one-argument call."""
    if fn.decorator_list or not _first(fn):
        return False
    positional = [*fn.args.posonlyargs, *fn.args.args]
    defaults = {
        arg.arg: val.value
        for arg, val in zip(reversed(positional), reversed(fn.args.defaults))
        if isinstance(val, ast.Constant) and arg.arg != _first(fn)
    }
    kwargs = fn.args.kwarg.arg if fn.args.kwarg else None
    shell = False
    pending = list(reversed(fn.body))
    while pending:
        project.charge()
        stmt = pending.pop()
        if isinstance(stmt, ast.If):
            take = _condition(stmt.test, defaults)
            if take is None:
                return False
            pending.extend(reversed(stmt.body if take else stmt.orelse))
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        value = getattr(stmt, "value", None)
        if isinstance(value, ast.Call):
            name = project.external(unit, value.func)
            if (
                name in _VECTOR_RUNNERS
                and len(value.args) == 1
                and _load(value.args[0], _first(fn))
            ):
                options = {kw.arg: kw.value for kw in value.keywords}
                if set(options) == {None} and _load(options[None], kwargs):
                    verified_shell = shell
                else:
                    verified_shell = (
                        set(options) == {"shell"}
                        and isinstance(options["shell"], ast.Constant)
                        and options["shell"].value is True
                    )
                return verified_shell and provider_binding_is_stable(
                    name, unit.tree, unit.path, project.root
                )
        # A wrapper can add subprocess I/O options without changing the command.
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if (
                isinstance(target, ast.Subscript)
                and _load(target.value, kwargs)
                and isinstance(target.slice, ast.Constant)
            ):
                key = target.slice.value
                if (
                    key == "shell"
                    and isinstance(value, ast.Constant)
                    and value.value is True
                ):
                    shell = True
                    continue
                if key in {"stdin", "stdout", "stderr"} and project.external(
                    unit, value
                ) in {"subprocess.PIPE", "subprocess.STDOUT", "subprocess.DEVNULL"}:
                    continue
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and _load(value.func.value, kwargs)
            and value.func.attr == "update"
            and not value.args
            and all(
                kw.arg in {"stdin", "stdout", "stderr"}
                and project.external(unit, kw.value)
                in {"subprocess.PIPE", "subprocess.STDOUT", "subprocess.DEVNULL"}
                for kw in value.keywords
            )
        ):
            continue
        return False
    return False


def _size_at(project, unit, scope, call):
    vector = (
        call.args[0]
        if call.args
        else next((kw.value for kw in call.keywords if kw.arg == "args"), None)
    )
    if vector is None:
        return None
    formatted = _formatted_size(vector)
    if formatted is None and not isinstance(vector, (ast.List, ast.Tuple)):
        return None
    name = project.external(unit, call.func)
    if name in _VECTOR_RUNNERS:
        if not provider_binding_is_stable(name, unit.tree, unit.path, project.root):
            return None
        if formatted is None:
            value = openssl_size_operand(call, name)
            if (
                isinstance(value, ast.Call)
                and _load(value.func, "str")
                and unit.lookup(scope, "str") is None
                and len(value.args) == 1
                and not value.keywords
            ):
                return value.args[0]
            return value
        options = {kw.arg: kw.value for kw in call.keywords}
        shell = options.get("shell")
        if (
            len(call.args) == 1
            and set(options) <= {"shell", "check", "capture_output", "text"}
            and isinstance(shell, ast.Constant)
            and shell.value is True
        ):
            return formatted
    elif formatted is not None and len(call.args) == 1 and not call.keywords:
        receiver = project.target(unit, call.func)
        if (
            receiver
            and receiver.kind == "fn"
            and not receiver.bound
            and _valid_call(receiver.node, call)
            and _wrapper_executes(project, receiver.unit, receiver.node)
        ):
            return formatted
    return None


def _lookup(node):
    return isinstance(node, ast.Call) and any(
        isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        for arg in node.args
    )


def _override_choice(expr):
    if isinstance(expr, ast.IfExp) and ast.dump(expr.test) == ast.dump(expr.body):
        return expr.test, expr.orelse
    if (
        isinstance(expr, ast.BoolOp)
        and isinstance(expr.op, ast.Or)
        and len(expr.values) == 2
    ):
        return tuple(expr.values)
    return None, expr


def _default_queryset(project, model, method):
    # A custom manager may exclude rows with an unset override, or return a
    # different model. Accept inherited Django behavior only.
    order, bases = project.mro(model)
    if set(bases) != {"django.db.models.Model"}:
        return False
    for unit, cls in order:
        declarations = unit.class_scopes[id(cls)].binds.get("objects", ())
        if not declarations:
            continue
        if len(declarations) != 1 or not isinstance(declarations[0].value, ast.Call):
            return False
        declaration = declarations[0].value
        if declaration.args or declaration.keywords:
            return False
        manager = project.target(unit, declaration.func)
        if not manager:
            return False
        if manager.kind == "ext":
            return manager.name == "django.db.models.Manager"
        if manager.kind != "cls":
            return False
        managers, bases = project.mro(manager.node)
        return set(bases) == {"django.db.models.Manager"} and all(
            not {"__init__", "__getattr__", "get_queryset", method}.intersection(
                source.class_scopes[id(base)].binds
            )
            for source, base in managers
        )
    return True


def _model_allows_blank(project, unit, query, field):
    if not isinstance(query, ast.Call) or not isinstance(query.func, ast.Attribute):
        return False
    mgr = query.func.value
    if (
        not isinstance(mgr, ast.Attribute)
        or mgr.attr != "objects"
        or query.func.attr not in {"all", "filter"}
    ):
        return False
    model = project.target(unit, mgr.value)
    if (
        not model
        or model.kind != "cls"
        or not _default_queryset(project, model.node, query.func.attr)
    ):
        return False
    if query.args or any(
        kw.arg is None or kw.arg.split("__")[0] == field for kw in query.keywords
    ):
        return False
    return _nullable_integer_field(project, model, field)


def _nullable_integer_field(project, model, field):
    values = model.unit.class_scopes[id(model.node)].binds.get(field, ())
    if (
        len(values) != 1
        or values[0].kind != "assign"
        or not isinstance(values[0].value, ast.Call)
    ):
        return False
    declaration = values[0].value
    name = project.external(model.unit, declaration.func)
    if name not in {
        "django.db.models.PositiveSmallIntegerField",
        "django.db.models.PositiveIntegerField",
        "django.db.models.IntegerField",
        "django.db.models.BigIntegerField",
        "django.db.models.SmallIntegerField",
        "django.db.models.PositiveBigIntegerField",
    } or not django_field_is_available(project, model.unit, name):
        return False
    return any(
        kw.arg == "null"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in declaration.keywords
    )


def _size_path(statements, operand, *, missing):
    """Follow copies and identity tests on one nullable field to an RSA operand or return."""
    locals_ = {}
    field = None

    def resolve(expr):
        return locals_.get(expr.id, expr) if isinstance(expr, ast.Name) else expr

    def choose(test):
        nonlocal field
        match test:
            case ast.Compare(
                left=left,
                ops=[ast.Is() | ast.IsNot() as op],
                comparators=[ast.Constant(value=None)],
            ):
                checked = resolve(left)
                if (
                    isinstance(checked, ast.Attribute)
                    and isinstance(checked.value, ast.Name)
                    and (field is None or ast.dump(checked) == ast.dump(field))
                ):
                    field = checked
                    return missing if isinstance(op, ast.Is) else not missing
        return None

    pending = list(reversed(statements))
    calls = set()
    reads = set()
    while True:
        target = None
        if not pending:
            expr = operand
        else:
            stmt = pending.pop()
            if isinstance(stmt, ast.If):
                take = choose(stmt.test)
                if take is None:
                    return None
                pending.extend(reversed(stmt.body if take else stmt.orelse))
                continue
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                target, expr = stmt.targets[0].id, stmt.value
            elif isinstance(stmt, ast.Return) and operand is None:
                expr = stmt.value
            else:
                return None
        if isinstance(expr, ast.IfExp):
            take = choose(expr.test)
            if take is None:
                return None
            expr = expr.body if take else expr.orelse
        expr = resolve(expr)
        if isinstance(expr, ast.Call):
            calls.add(expr)
        elif isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            reads.add(ast.dump(expr))
        elif not isinstance(expr, (ast.Name, ast.Constant)):
            return None
        if target is not None:
            locals_[target] = expr
            continue
        # An unused call or property read can change the receiver before selection.
        if calls - {expr} or reads - ({ast.dump(field)} if field else set()):
            return None
        return field, expr


def _selection(statements, operand):
    absent = _size_path(statements, operand, missing=True)
    if not absent:
        return None
    field, lookup = absent
    if field is None:
        return (None, lookup) if isinstance(lookup, ast.Call) else None
    present = _size_path(statements, operand, missing=False)
    if present and _lookup(lookup) and ast.dump(present[1]) == ast.dump(field):
        return field, lookup
    return None


def _annotated_model(project, unit, fn, receiver):
    param = _parameter(unit, fn, receiver)
    if not param:
        return None
    scope = unit.function_scopes[id(fn)]
    model = project.target(unit, scope.binds[param][0].node.annotation)
    if not model or model.kind != "cls":
        return None
    order, bases = project.mro(model.node)
    if set(bases) != {"django.db.models.Model"} or any(
        cls.keywords
        or cls.decorator_list
        or {"__getattribute__", "__getattr__", "__setattr__"}.intersection(
            source.class_scopes[id(cls)].binds
        )
        for source, cls in order
    ):
        return None
    return model


def _model_method_replaced(project, model, name):
    lineage = {cls for _, cls in project.mro(model.node)[0]}
    for unit in project.units:
        if unit.is_test:
            continue
        project.charge(len(unit.parents))
        receivers = [
            node.value
            for node in ast.walk(unit.tree)
            if isinstance(node, ast.Attribute)
            and node.attr == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        for call, _ in unit.calls:
            if (
                isinstance(call.func, ast.Name)
                and call.func.id in {"setattr", "delattr"}
                and len(call.args) >= 2
            ):
                key = call.args[1]
                if not isinstance(key, ast.Constant) or key.value == name:
                    receivers.append(call.args[0])
        for receiver in receivers:
            bound = project.target(unit, receiver)
            if bound and bound.kind in {"cls", "inst"} and bound.node in lineage:
                return True
    return False


def _typed_lookup(project, unit, fn, statement, size):
    """Prove the selection under the caller's Django model type contract."""
    if fn.decorator_list or fn not in unit.tree.body:
        return None
    body = _body(fn)
    selection = _selection(body[: body.index(statement)], size)
    if not selection:
        return None
    field, value = selection
    if field is not None:
        model = _annotated_model(project, unit, fn, field.value)
        if model and _nullable_integer_field(project, model, field.attr):
            return unit, value, None
        return None

    if not isinstance(value.func, ast.Attribute) or not all(
        isinstance(arg, (ast.Name, ast.Constant))
        or isinstance(arg, ast.Dict)
        and all(isinstance(x, ast.Constant) for x in [*arg.keys, *arg.values])
        for arg in [*value.args, *(kw.value for kw in value.keywords)]
    ):
        return None
    model = _annotated_model(project, unit, fn, value.func.value)
    if not model or _model_method_replaced(project, model, value.func.attr):
        return None
    members = project.class_member(model.node, value.func.attr, True, 0)
    if not members or len(members) != 1:
        return None
    member = next(iter(members))
    method = member.node
    if (
        member.kind != "fn"
        or not member.bound
        or not isinstance(method, ast.FunctionDef)
        or method.decorator_list
        or not _valid_call(method, value, bound=True)
        or method.args.vararg
        or method.args.kwarg
    ):
        return None
    selection = _selection(_body(method), None)
    if not selection:
        return None
    override, lookup = selection
    if (
        override is None
        or _parameter(member.unit, method, override.value) != _first(method)
        or not _nullable_integer_field(project, model, override.attr)
    ):
        return None
    positional = [*method.args.posonlyargs, *method.args.args][1:]
    actuals = {param.arg: arg for param, arg in zip(positional, value.args)}
    actuals.update({kw.arg: kw.value for kw in value.keywords})
    return member.unit, lookup, (unit, value, actuals)


def _optional_from_loop(project, unit, fn, call, source_scope, override):
    if not isinstance(override, ast.Attribute) or not isinstance(
        override.value, ast.Name
    ):
        return False
    params = [*fn.args.posonlyargs, *fn.args.args]
    try:
        i = [p.arg for p in params[1:]].index(_parameter(unit, fn, override.value))
    except ValueError:
        return False
    if i >= len(call.args) or not isinstance(call.args[i], ast.Name):
        return False
    loop = next(
        (n for n in unit.ancestors(call) if isinstance(n, (ast.For, ast.FunctionDef))),
        None,
    )
    if (
        not isinstance(loop, ast.For)
        or not _load(loop.target, call.args[i].id)
        or loop not in source_scope.node.body
        or not loop.body
        or not isinstance(loop.body[0], ast.Expr)
        or call is not loop.body[0].value
    ):
        return False
    if len(source_scope.binds.get(call.args[i].id, ())) != 1:
        return False
    query = _single_local(unit, loop.iter, source_scope)
    return _model_allows_blank(project, unit, query, override.attr)


def _direct_statement(unit, call, block, *, allow_stdout=False):
    parent = unit.parents.get(id(call))
    if (
        allow_stdout
        and isinstance(parent, ast.Attribute)
        and parent.attr == "stdout"
        and isinstance(parent.ctx, ast.Load)
    ):
        # Reading stdout evaluates the call before accessing its result.
        parent = unit.parents.get(id(parent))
    if isinstance(parent, (ast.Assign, ast.Return, ast.Expr)) and parent in block.body:
        return parent
    return None


def _unguarded(unit, call, fn):
    return _reachable(unit, call, fn) and not any(
        isinstance(stmt, (ast.If, ast.Try, ast.Match, ast.Assert, ast.For, ast.While))
        for stmt in _prior(unit, call, fn)
    )


def _objects_escape(unit, fn, call, names):
    """An earlier call receiving the object or invoking its method can change the field."""
    for prior in _prior(unit, call, fn):
        for node in ast.walk(prior):
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in names
            ):
                return True
            if any(
                isinstance(value, ast.Name) and value.id in names
                for value in [*node.args, *(kw.value for kw in node.keywords)]
            ):
                return True
    return False


def _sources(project, unit, fn, sink, value):
    scope = unit.function_scopes[id(fn)]
    override, fallback = _override_choice(_single_local(unit, value, scope))
    if override is None and _lookup(fallback):
        yield fallback
        return
    owner = scope.parent
    if owner is None or owner.kind != "class" or fn.decorator_list:
        return
    if override is not None and (
        not isinstance(override, ast.Attribute)
        or any(
            n.attr == override.attr and site is scope and stmt.lineno <= sink.lineno
            for n, _value, stmt, site in unit.attribute_stores
        )
    ):
        return
    if not isinstance(fallback, ast.Attribute) or _parameter(
        unit, fn, fallback.value
    ) != _first(fn):
        return
    names = {_first(fn)}
    if isinstance(override, ast.Attribute) and isinstance(override.value, ast.Name):
        names.add(override.value.id)
    if _objects_escape(unit, fn, sink, names):
        return
    writes = [
        (n, v, stmt, s)
        for n, v, stmt, s in unit.attribute_stores
        if n.attr == fallback.attr and s.parent is owner
    ]
    if len(writes) != 1:
        return
    node, source, stmt, caller = writes[0]
    if (
        not _lookup(source)
        or _parameter(unit, caller.node, node.value) != _first(caller.node)
        or stmt not in caller.node.body
    ):
        return
    for caller_unit, call, site in project.calls_by_name.get(fn.name, ()):
        project.charge()
        if (
            caller_unit is not unit
            or site is not caller
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != fn.name
        ):
            continue
        if (
            not _load(call.func.value, _first(caller.node))
            or project.function(unit, call.func) is not fn
            or not _valid_call(fn, call, bound=True)
        ):
            continue
        if (
            stmt not in _prior(unit, call, caller.node)
            or not _unguarded(unit, call, caller.node)
            or _objects_escape(unit, caller.node, call, {_first(caller.node)})
        ):
            continue
        if override is None and _direct_statement(unit, call, caller.node) is None:
            continue
        if override is not None and not _optional_from_loop(
            project, unit, fn, call, caller, override
        ):
            continue
        yield source
        return


def rsa_setting_lookups(project, unit):
    """Yield the lookup owner and AST, generation site and optional method arguments."""
    for call, scope in unit.calls:
        project.charge()
        fn = scope.node
        if not isinstance(fn, ast.FunctionDef):
            continue
        statement = _direct_statement(unit, call, fn, allow_stdout=True)
        if statement is None:
            continue
        size = _size_at(project, unit, scope, call)
        if size is None:
            continue
        # First follow branches whose nullable model field can be resolved.
        # Other guards may reject or replace the default before generation.
        fallback = _typed_lookup(project, unit, fn, statement, size)
        if fallback is not None:
            owner, lookup, forwarded = fallback
            yield owner, lookup, call, forwarded
            continue
        if not _unguarded(unit, call, fn):
            continue
        for lookup in _sources(project, unit, fn, call, size):
            yield unit, lookup, call, None
