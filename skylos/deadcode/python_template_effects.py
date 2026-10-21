"""Bounded text-template effects; target readers and renderers are never run."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path
from string import Formatter

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.deadcode.python_project_sources import NULL, alternatives, merge

_MAX_TEXT = 128_000


@dataclass
class TemplateStream:
    text: str
    position: int = 0
    valid: bool = True


def open_template(index, args, kwargs):
    if not args or len(args) > 2 or not isinstance(args[0], (str, Path)):
        return None
    if "\x00" in str(args[0]):
        return None
    if set(kwargs) - {"mode", "encoding", "errors", "newline"}:
        return None
    if len(args) == 2 and "mode" in kwargs:
        return None
    mode = kwargs.get("mode", "r")
    if len(args) == 2:
        mode = args[1]
    if not isinstance(mode, str) or mode not in {"r", "rt"}:
        return None
    encoding = kwargs.get("encoding", "utf-8")
    if not isinstance(encoding, str) or encoding not in {"utf-8", "utf8", "ascii"}:
        return None
    errors = kwargs.get("errors")
    if errors is not None and errors != "strict":
        return None
    if kwargs.get("newline") is not None:
        return None
    text = read_project_text_no_symlink(
        index.root, args[0], max_bytes=_MAX_TEXT, encoding=encoding
    )
    if text is None:
        return None
    return TemplateStream(text)


def stream_method(stream, name, args, kwargs):
    if name == "close" and not args and not kwargs:
        stream.valid = False
        return NULL
    if not stream.valid or name != "read" or kwargs or len(args) > 1:
        stream.valid = False
        return None
    size = len(stream.text)
    if args:
        size = args[0]
        if not isinstance(size, int) or size < -1:
            stream.valid = False
            return None
        if size == -1:
            size = len(stream.text)
    result = stream.text[stream.position : stream.position + size]
    stream.position += len(result)
    return result


def escape_text(args, kwargs):
    if len(args) != 1 or set(kwargs) - {"quote"}:
        return None
    quote = kwargs.get("quote", True)
    if not isinstance(quote, bool):
        return None
    result = []
    for value in alternatives(args[0]):
        if not isinstance(value, str) or len(value) > _MAX_TEXT:
            return None
        result.append(html.escape(value, quote=quote))
    return merge(result)


def json_text(args, kwargs):
    if len(args) != 1 or kwargs or not isinstance(args[0], (str, int, float, bool)):
        return None
    result = json.dumps(args[0])
    if len(result) > _MAX_TEXT:
        return None
    return result


def join_text(separator, values):
    if not isinstance(values, (list, tuple)):
        return None
    result = [""]
    for position, value in enumerate(values):
        combined = []
        for candidate in alternatives(value):
            if candidate is None:
                candidate = "\x00"
            if not isinstance(candidate, str):
                continue
            for prefix in result:
                text = prefix
                if position:
                    text += separator
                text += candidate
                if len(text) > _MAX_TEXT:
                    continue
                combined.append(text)
                if len(combined) >= 256:
                    break
            if len(combined) >= 256:
                break
        result = combined
    return merge(result)


def format_text(template, args, kwargs):
    if len(template) > _MAX_TEXT:
        return None
    try:
        parts = list(Formatter().parse(template))
    except ValueError:
        return None
    outputs = [""]
    automatic = 0
    numbering = None
    for literal, key, specification, conversion in parts:
        values = [literal]
        if key is not None:
            if specification or conversion not in {None, "s"}:
                return None
            automatic_field = key == ""
            if automatic_field:
                if numbering == "manual":
                    return None
                numbering = "automatic"
                key = str(automatic)
                automatic += 1
            if key.isdecimal():
                if not automatic_field:
                    if numbering == "automatic":
                        return None
                    numbering = "manual"
                if len(key) > 6:
                    return None
                position = int(key)
                if position >= len(args):
                    return None
                value = args[position]
            elif key.isidentifier() and key in kwargs:
                value = kwargs[key]
            else:
                return None
            values = []
            for candidate in alternatives(value):
                if candidate is None:
                    rendered = "\x00"
                elif candidate is NULL:
                    rendered = "None"
                elif isinstance(candidate, (str, int, float, bool, Path)):
                    rendered = str(candidate)
                else:
                    rendered = "\x00"
                values.append(literal + rendered)
        combined = []
        for prefix in outputs:
            for suffix in values:
                if len(prefix) + len(suffix) > _MAX_TEXT:
                    continue
                combined.append(prefix + suffix)
                if len(combined) >= 256:
                    break
            if len(combined) >= 256:
                break
        outputs = combined
    return merge(outputs)
