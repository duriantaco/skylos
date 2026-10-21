"""Documented, bounded intrinsic effects for static project-source proofs."""

from __future__ import annotations

import ast
import os
from itertools import islice
from pathlib import Path

from skylos.deadcode.python_project_sources import (
    NULL,
    BrowserMethod,
    Class,
    Function,
    Record,
    Symbol,
)
from skylos.deadcode.python_source_effects import (
    _attribute,
    _items,
    gradio_class_provider,
)

from skylos.deadcode.python_template_effects import (
    TemplateStream,
    escape_text,
    format_text,
    join_text,
    json_text,
    open_template,
    stream_method,
)


# tqdm's documented iterator contract yields the original iterable's items:
# https://tqdm.github.io/docs/tqdm/#tqdm-objects
_ITERABLE_DECORATORS = {
    "tqdm.tqdm",
    "tqdm.std.tqdm",
    "tqdm.auto.tqdm",
    "tqdm.autonotebook.tqdm",
}
_ITERABLE_DECORATOR_OPTIONS = {
    "iterable",
    "desc",
    "total",
    "leave",
    "ncols",
    "mininterval",
    "maxinterval",
    "miniters",
    "ascii",
    "disable",
    "unit",
    "unit_scale",
    "dynamic_ncols",
    "smoothing",
    "bar_format",
    "initial",
    "position",
    "unit_divisor",
    "write_bytes",
    "nrows",
    "colour",
    "delay",
    "gui",
}


def _inside(index, value):
    if not isinstance(value, (str, Path)):
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = index.root / candidate
    try:
        if any(
            part.is_symlink()
            for part in [candidate, *candidate.parents]
            if part != index.root
        ):
            return None
        candidate = candidate.resolve()
        candidate.relative_to(index.root)
    except (ValueError, OSError):
        return None
    return candidate


def _invalidate(index, values):
    from skylos.deadcode.python_module_effects import invalidate_namespace

    pending = list(values)
    seen = set()
    while pending and len(seen) < 1024:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if invalidate_namespace(value):
            continue
        if isinstance(value, Symbol):
            if not value.name.startswith("builtins."):
                index.mutations.add(value.name)
        elif isinstance(value, TemplateStream):
            value.valid = False
        elif isinstance(value, Record):
            value.fields.clear()
            value.provider = None
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
        elif isinstance(value, dict):
            pending.extend(value.values())


def _invoke(index, function, args, kwargs, path):
    function = index.symbol(function)
    if isinstance(function, BrowserMethod):
        receiver = function.receiver
        if receiver.provider is None or function.name in receiver.fields:
            return None
        if (
            index.symbol(Symbol(receiver.provider + "." + function.name, bound=True))
            is None
        ):
            return None
        browser_keywords = dict(kwargs)
        if function.name == "execute_script" and args:
            browser_keywords["js"] = args[0]
        if len(index.browser_calls) < 20_000:
            index.browser_calls.append(
                (receiver.provider, function.name, browser_keywords)
            )
        return _method(index, receiver, function.name, args, kwargs, path)
    if isinstance(function, Function):
        index.initialize_module(function.path)
        from skylos.deadcode.python_module_effects import source_loader_result

        namespace = source_loader_result(index, function, args, kwargs)
        if namespace is not None:
            return namespace
        return index.call(function, args, kwargs)
    if isinstance(function, Class):
        index.initialize_module(function.path)
        if function.node is not None:
            node = function.node
            if node.keywords or (node.decorator_list and not function.generated_init):
                return None
        record = Record(function, {})
        if function.fields or function.generated_init:
            if len(args) > len(function.fields):
                return None
            supplied_names = set(function.fields[: len(args)])
            if supplied_names & set(kwargs) or set(kwargs) - set(function.fields):
                return None
            record.fields.update(function.defaults)
            record.fields.update(zip(function.fields, args))
            record.fields.update(kwargs)
            if set(function.fields) - set(record.fields):
                return None
        provider = gradio_class_provider(index, function)
        if provider:
            record.provider = provider
        initializer = index.source_initializer(record)
        if initializer is not None:
            initialized = index.call(initializer, args, kwargs)
            if initialized is None:
                return None
        elif function.node is not None:
            for child in function.node.body:
                if isinstance(child, ast.FunctionDef) and child.name == "__init__":
                    return None
        return record
    if not isinstance(function, Symbol):
        _invalidate(index, [*args, *kwargs.values()])
        return None
    name = function.name
    if name in {"inspect.isclass", "builtins.issubclass"}:
        from skylos.deadcode.python_module_effects import (
            inspect_provider_available,
            source_isclass,
            source_issubclass,
        )

        if (
            name == "inspect.isclass"
            and len(args) == 1
            and not kwargs
            and inspect_provider_available(index, path)
        ):
            return source_isclass(args[0])
        if name == "builtins.issubclass" and len(args) == 2 and not kwargs:
            return source_issubclass(index, args[0], args[1])
    if name == "inspect.getmembers" and len(args) == 2 and not kwargs:
        from skylos.deadcode.python_module_effects import inspect_provider_available

        predicate = index.symbol(args[1])
        if (
            isinstance(predicate, Symbol)
            and predicate.name == "inspect.isclass"
            and inspect_provider_available(index, path)
        ):
            # The stdlib calls this known pure predicate; it does not receive
            # ownership of the predicate. Member values themselves stay unknown.
            _invalidate(index, [args[0]])
            return None
    if name in {"builtins.open", "io.open"}:
        return open_template(index, args, kwargs)
    if name == "html.escape":
        return escape_text(args, kwargs)
    if name == "json.dumps":
        return json_text(args, kwargs)
    if name == "builtins.type" and len(args) == 1 and not kwargs:
        return None
    if name == "builtins.isinstance" and len(args) == 2 and not kwargs:
        if isinstance(args[1], Symbol) and args[1].name.startswith(
            ("builtins.", "gradio.")
        ):
            return None
    if (
        name == "builtins.enumerate"
        and args
        and isinstance(args[0], (list, tuple, dict))
    ):
        start = 0
        if len(args) > 1:
            start = args[1]
        if not isinstance(start, int):
            return None
        result = []
        for position, value in enumerate(_items(args[0]), start):
            result.append([position, value])
        return result
    if (
        name == "builtins.zip"
        and args
        and all(isinstance(value, (list, tuple, dict)) for value in args)
    ):
        result = []
        for values in zip(*[_items(value) for value in args]):
            result.append(list(values))
        return result
    if name in {"builtins.setattr", "builtins.delattr"} and len(args) >= 2:
        if isinstance(args[0], Symbol):
            if isinstance(args[1], str):
                index.mutations.add(args[0].name + "." + args[1])
            else:
                index.mutations.add(args[0].name)
        elif isinstance(args[0], Record) and isinstance(args[1], str):
            if len(args) > 2:
                args[0].fields[args[1]] = args[2]
            else:
                args[0].fields[args[1]] = None
        return None
    if name in {
        "builtins.sorted",
        "builtins.reversed",
        "builtins.list",
        "builtins.tuple",
    }:
        if args:
            if not isinstance(args[0], (list, tuple, dict)):
                return None
            return _items(args[0])
        return []
    if name in _ITERABLE_DECORATORS and len(args) <= 1:
        if not (args and "iterable" in kwargs):
            safe_options = not (set(kwargs) - _ITERABLE_DECORATOR_OPTIONS)
            for key, value in kwargs.items():
                if (
                    key != "iterable"
                    and value is not NULL
                    and not isinstance(value, (str, int, float, bool))
                ):
                    safe_options = False
            if safe_options:
                iterable = kwargs.get("iterable")
                if args:
                    iterable = args[0]
                return _items(iterable)
    if name == "builtins.dict":
        return dict(kwargs)
    if (
        name == "builtins.str"
        and len(args) == 1
        and isinstance(args[0], (str, int, Path))
    ):
        return str(args[0])
    if (
        name == "builtins.len"
        and len(args) == 1
        and isinstance(args[0], (str, list, tuple, dict))
    ):
        return len(args[0])
    if name in {"builtins.getattr", "builtins.hasattr"}:
        if len(args) >= 2 and isinstance(args[1], str):
            if name == "builtins.getattr":
                return _attribute(index, args[0], args[1])
            return None
        return None
    if name == "collections.namedtuple" and len(args) >= 2:
        fields = args[1]
        if isinstance(fields, str):
            fields = fields.replace(",", " ").split()
        if isinstance(fields, list) and all(isinstance(value, str) for value in fields):
            return Class(path, None, tuple(fields))
    if (
        name == "pathlib.Path"
        and args
        and all(isinstance(value, (str, Path)) for value in args)
    ):
        return Path(*args)
    if (
        name == "os.path.join"
        and args
        and all(isinstance(value, (str, Path)) for value in args)
    ):
        return os.path.join(*map(str, args))
    if (
        name in {"os.path.dirname", "os.path.basename", "os.path.splitext"}
        and len(args) == 1
        and isinstance(args[0], (str, Path))
    ):
        return getattr(os.path, name.rpartition(".")[2])(str(args[0]))
    if name in {"os.path.realpath", "os.path.abspath"} and len(args) == 1:
        return _inside(index, args[0])
    if (
        name == "os.path.relpath"
        and args
        and all(isinstance(value, (str, Path)) for value in args)
    ):
        first = _inside(index, args[0])
        base = _inside(index, args[1]) if len(args) > 1 else index.root
        if first is not None and base is not None:
            return os.path.relpath(first, base)
    if (
        name == "os.path.commonpath"
        and len(args) == 1
        and isinstance(args[0], list)
        and all(isinstance(value, (str, Path)) for value in args[0])
    ):
        try:
            return os.path.commonpath(args[0])
        except ValueError:
            return None
    if name in {"os.path.isfile", "os.path.isdir", "os.path.exists"} and len(args) == 1:
        candidate = _inside(index, args[0])
        if candidate is not None:
            if name == "os.path.isfile":
                return candidate.is_file()
            if name == "os.path.isdir":
                return candidate.is_dir()
            return candidate.exists()
    if name in {"os.listdir", "os.scandir"} and len(args) == 1:
        folder = _inside(index, args[0])
        if folder is not None and folder.is_dir():
            try:
                files = list(islice(folder.iterdir(), 513))
                if len(files) > 512:
                    return None
                files.sort()
            except OSError:
                return None
            if name == "os.listdir":
                return [value.name for value in files]
            return [
                Record(None, {"name": value.name, "path": value}) for value in files
            ]
    if name == "os.walk" and len(args) == 1:
        folder = _inside(index, args[0])
        if folder is None or not folder.is_dir() or kwargs.get("followlinks"):
            return None
        pending = [folder]
        result = []
        count = 0
        while pending:
            current = pending.pop()
            try:
                entries = list(islice(current.iterdir(), 513 - count))
            except OSError:
                return None
            count += len(entries)
            if count > 512:
                return None
            folders = []
            files = []
            for entry in entries:
                if _inside(index, entry) is None:
                    continue
                if entry.is_dir():
                    folders.append(entry.name)
                    pending.append(entry)
                else:
                    files.append(entry.name)
            result.append([str(current), folders, files])
        return result
    if (
        name in {"glob.glob", "glob.iglob"}
        and len(args) == 1
        and isinstance(args[0], str)
    ):
        pattern = Path(args[0])
        if pattern.is_absolute() or ".." in pattern.parts or "\\" in args[0]:
            return None
        values = _method(index, index.root, "glob", args, {}, path)
        if values is not None:
            return [str(value.relative_to(index.root)) for value in values]
        return None
    if name.startswith("gradio."):
        return Record(None, {}, provider=name)
    if name in {
        "flask.Flask",
        "flask.Blueprint",
        "fastapi.FastAPI",
        "fastapi.APIRouter",
    }:
        return Record(None, {}, provider=name)
    if name in {
        "selenium.webdriver.Chrome",
        "selenium.webdriver.Firefox",
        "selenium.webdriver.Remote",
        "selenium.webdriver.Edge",
        "selenium.webdriver.Safari",
    }:
        return Record(None, {}, provider=name)
    if name == "nicegui.ui.run_javascript" and args:
        if len(index.browser_calls) < 20_000:
            index.browser_calls.append((name, "run_javascript", {"js": args[0]}))
        return None
    _invalidate(index, [*args, *kwargs.values()])
    return None


def _method(index, receiver, name, args, kwargs, path):
    from skylos.deadcode.python_module_effects import NamespaceValues

    if isinstance(receiver, NamespaceValues) and not receiver.owner.valid:
        return None
    if isinstance(receiver, TemplateStream):
        return stream_method(receiver, name, args, kwargs)
    if isinstance(receiver, str):
        if name == "join" and len(args) == 1 and not kwargs:
            return join_text(receiver, args[0])
        if name == "format":
            return format_text(receiver, args, kwargs)
        if (
            name == "format_map"
            and len(args) == 1
            and isinstance(args[0], dict)
            and not kwargs
        ):
            return format_text(receiver, [], args[0])
        allowed = {
            "lower",
            "upper",
            "replace",
            "startswith",
            "endswith",
            "split",
            "rsplit",
            "partition",
            "rpartition",
            "strip",
            "lstrip",
            "rstrip",
        }
        if name in allowed and all(
            isinstance(value, (str, int, tuple)) for value in args
        ):
            try:
                return getattr(receiver, name)(*args)
            except (ValueError, TypeError):
                return None
    if isinstance(receiver, list):
        if name == "copy" and not args and not kwargs:
            return list(receiver)
        if name == "append" and len(args) == 1 and len(receiver) < 512:
            receiver.append(args[0])
        elif name == "extend" and args:
            receiver.extend(_items(args[0])[: 512 - len(receiver)])
        elif name == "clear":
            receiver.clear()
        return None
    if isinstance(receiver, dict):
        if name == "copy" and not args and not kwargs:
            return dict(receiver)
        if name == "values":
            return list(receiver.values())
        if name == "keys":
            return list(receiver)
        if name == "items":
            return [list(item) for item in receiver.items()]
        if name == "get" and args and isinstance(args[0], (str, int, type(None))):
            return receiver.get(args[0], args[1] if len(args) > 1 else None)
    if isinstance(receiver, Path):
        if index.symbol(Symbol("pathlib.Path." + name, bound=True)) is None:
            return None
        candidate = _inside(index, receiver)
        if candidate is None:
            return None
        if name in {"absolute", "resolve"} and not args:
            return candidate
        if name in {"iterdir", "glob", "rglob"}:
            if name == "iterdir" and not args:
                pattern = "*"
            elif len(args) == 1 and isinstance(args[0], str):
                pattern = args[0]
            else:
                return None
            if (
                Path(pattern).is_absolute()
                or ".." in Path(pattern).parts
                or "\\" in pattern
            ):
                return None
            try:
                iterator = (
                    candidate.rglob(pattern)
                    if name == "rglob"
                    else candidate.glob(pattern)
                )
                values = list(islice(iterator, 513))
                if len(values) > 512:
                    return None
                return [value for value in values if _inside(index, value) is not None]
            except (OSError, ValueError, NotImplementedError):
                return None
    if (
        isinstance(receiver, Record)
        and receiver.provider is not None
        and name
        in {
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
            "style",
        }
    ):
        return receiver
    if isinstance(receiver, Symbol):
        _invalidate(index, [*args, *kwargs.values()])
    else:
        _invalidate(index, [receiver, *args, *kwargs.values()])
    return None
