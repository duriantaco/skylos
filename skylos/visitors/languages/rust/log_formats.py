"""Identify arguments actually displayed by a log or tracing macro."""

from string import Formatter

from ._security_bindings import REQUEST_TEXT
from .web_model import REQUEST_EXTRACTORS, request_label

_DECODED = {
    request_label(f"extractor {api}")
    for api in REQUEST_EXTRACTORS
    if api.rsplit("::", 1)[-1] in {"Path", "Query", "Json", "Form"}
}


def displayed_arguments(tree, *, structured=False):
    """Yield the original argument tokens or implicit name and its format spec."""
    groups = [[]]
    for token in tree.children[1:-1]:
        if token.type == ",":
            groups.append([])
        elif token.type not in {"line_comment", "block_comment"}:
            groups[-1].append(token)
    positional = []
    named = {}
    template = None
    for group in groups:
        if not group:
            continue
        if template is None:
            if len(group) == 1 and group[0].type in {
                "string_literal",
                "raw_string_literal",
            }:
                raw = group[0].text.decode("utf-8", "replace")
                template = raw[raw.index('"') + 1 : raw.rindex('"')]
            elif structured:
                field = group[2:] if len(group) > 2 and group[1].type == "=" else group
                if field and field[0].type in {"%", "?"}:
                    field = field[1:]
                yield field, ""
        elif len(group) > 2 and group[0].type == "identifier" and group[1].type == "=":
            named[group[0].text.decode("utf-8", "replace")] = group[2:]
        else:
            positional.append(group)
    if template is None:
        return
    try:
        position = 0
        for _, field, spec, conversion in Formatter().parse(template):
            if field is None:
                continue
            if conversion or "*" in spec or "$" in spec:
                return
            if field == "":
                if position < len(positional):
                    yield positional[position], spec
                position += 1
            elif field.isascii() and field.isdecimal() and len(field) < 7:
                index = int(field)
                if index < len(positional):
                    yield positional[index], spec
            elif field.isidentifier():
                yield named.get(field, field), spec
    except ValueError:
        return


def logs_request_text(tree, state):
    """Only Display of a decoded request string can introduce a record delimiter."""
    for argument, spec in displayed_arguments(tree):
        if spec:
            continue
        if isinstance(argument, str):
            name = argument
        elif len(argument) == 1 and argument[0].type == "identifier":
            name = argument[0].text.decode("utf-8", "replace")
        else:
            continue
        value = state.get(name)
        if (
            value.kind == REQUEST_TEXT
            and not value.items
            and value.request_sources & _DECODED
        ):
            return True
    return False
