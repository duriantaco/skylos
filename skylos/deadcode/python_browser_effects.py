"""Consume source-owned path and browser API effects at their actual positions."""

from __future__ import annotations

from pathlib import Path

from skylos.deadcode.python_project_sources import Function, Record, alternatives


def _script_path(index, value):
    if not isinstance(value, (str, Path)):
        return None
    value = str(value).split("?", 1)[0].split("#", 1)[0]
    file_url = value.startswith("file=")
    if file_url:
        value = value[len("file=") :]
    if "\x00" in value or "://" in value or value.startswith("//"):
        return None
    candidate = Path(value)
    if candidate.is_absolute() and not file_url:
        try:
            candidate.relative_to(index.root)
        except ValueError:
            candidate = index.root / value.lstrip("/")
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
    except (OSError, ValueError):
        return None
    if candidate.is_file():
        return candidate
    return None


def project_script_entry_files(index, *, classic_only=False):
    from skylos.visitors.languages.typescript.file_references import (
        _ScriptSources,
    )
    from skylos.deadcode.browser_refs import _CLASSIC_SCRIPT_TYPES

    found = set()
    list(index.contexts())
    for text in index.rendered_html:
        parser = _ScriptSources()
        try:
            parser.feed(text)
            parser.close()
        except (ValueError, RecursionError):
            continue
        for value, attrs in parser.sources:
            kind = dict(attrs).get("type", "") or ""
            if classic_only and kind.strip().lower() not in _CLASSIC_SCRIPT_TYPES:
                continue
            candidate = _script_path(index, value)
            if candidate is not None:
                found.add(candidate)
    return found


def _consume_html(text, names, patterns):
    from skylos.deadcode.browser_refs import (
        _PythonBrowserCode,
        _template_browser_names,
    )

    if not isinstance(text, str):
        return
    parser = _PythonBrowserCode()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, RecursionError):
        return
    for code in parser.code:
        _template_browser_names(code, names, patterns, allow_bare=False)


def _consume_callback_html(result, outputs, names, patterns):
    for value in alternatives(result):
        if isinstance(value, str) and len(outputs) == 1:
            values = [value]
        elif isinstance(value, (list, tuple)) and len(value) == len(outputs):
            values = value
        else:
            continue
        for output, returned in zip(outputs, values):
            if isinstance(output, Record) and output.provider == "gradio.HTML":
                for text in alternatives(returned):
                    _consume_html(text, names, patterns)


def project_browser_names(index):
    from skylos.deadcode.browser_refs import (
        _GRADIO_COMPONENTS,
        _GRADIO_EVENTS,
        _PythonBrowserCode,
        _python_string_templates,
        _template_browser_names,
    )

    names, patterns = set(), set()
    list(index.contexts())
    callback_start = index.total_steps
    queried_callbacks = set()
    for provider, method, keywords in list(index.browser_calls)[:4096]:
        if not provider.startswith("gradio.") or method not in _GRADIO_EVENTS:
            continue
        callback = keywords.get("fn")
        inputs = keywords.get("inputs", [])
        outputs = keywords.get("outputs", [])
        if not isinstance(callback, Function) or not isinstance(inputs, list):
            continue
        if not isinstance(outputs, list) or not any(
            isinstance(value, Record) and value.provider == "gradio.HTML"
            for value in outputs
        ):
            continue
        key = (id(callback), len(inputs))
        if key in queried_callbacks:
            continue
        queried_callbacks.add(key)
        # Callback analysis has its own bounded phase, as source-owner loader
        # queries do. Startup traversal must not exhaust every callback's work.
        if index.total_steps - callback_start >= 1_000_000:
            break
        index.budget = 0
        index.owner_steps = 0
        index.initialize_module(callback.path)
        result = index.call(callback, [None] * len(inputs), {})
        _consume_callback_html(result, outputs, names, patterns)
    for text in index.rendered_html:
        _consume_html(text, names, patterns)
    for provider, method, keywords in index.browser_calls:
        package, _, component = provider.rpartition(".")
        valid = (
            package in {"gradio", "gradio.components", "gradio.layouts"}
            and component in _GRADIO_COMPONENTS
            and method in _GRADIO_EVENTS
        )
        if provider == "nicegui.ui.run_javascript":
            valid = True
        if (
            provider
            in {
                "selenium.webdriver.Chrome",
                "selenium.webdriver.Firefox",
                "selenium.webdriver.Remote",
                "selenium.webdriver.Edge",
                "selenium.webdriver.Safari",
            }
            and method == "execute_script"
        ):
            valid = True
        if not valid:
            continue
        for key in ("_js", "js"):
            for value in alternatives(keywords.get(key)):
                if isinstance(value, str):
                    _template_browser_names(value, names, patterns)
    seen_owners = set()
    # HTML callbacks above can reach owners after contexts() cached its result.
    # Include those owners even when the bounded HTML buffer is already full.
    for owner, path, bindings in list(index.executed_contexts):
        if id(owner) in seen_owners:
            continue
        seen_owners.add(id(owner))
        for template in _python_string_templates(owner):
            parser = _PythonBrowserCode()
            try:
                parser.feed(template)
                parser.close()
            except (ValueError, RecursionError):
                continue
            for code in parser.code:
                _template_browser_names(code, names, patterns, allow_bare=False)
    return names, patterns
