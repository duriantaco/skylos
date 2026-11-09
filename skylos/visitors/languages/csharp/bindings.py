"""Source-local C# binding context for value and attribute references.

These are references, not roots. The project resolver must prove the referenced
declaration before keeping its type or member alive.
"""

from __future__ import annotations

import re

from ._lex import matching_brace

_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_SPACE = re.compile(r"\s*")
_INTERPOLATED_START = re.compile(r'(?:\$@|@\$|\$)"')
_LOCAL_DECLARATION = re.compile(
    r"(?m)(?:^|(?<=[;{}]))\s*(?:const\s+)?"
    r"(?P<type>[A-Za-z_][\w.<>\[\],?\s]*)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?=[=;,])"
)
_USING = re.compile(
    r"(?m)(?:^|(?<=[;{}]))\s*(?:global\s+)?using\s+"
    r"(?:(?P<alias>[A-Za-z_]\w*)\s*=\s*|(?P<static>static)\s+)?"
    r"(?P<name>(?:global::)?[A-Za-z_]\w*(?:(?:\.|::)[A-Za-z_]\w*)*)\s*;"
)


def reference_expression_mask(source: str, masked: str, nesting: int = 0) -> str:
    """Recover interpolation expressions only, keeping literal code as data.

    This mask is used for dead-code references; declaration and security lexing
    retain their original whole-literal masking policy.
    """
    from ._lex import (
        _RAW_START_RE,
        _TOKEN_RE,
        _interpolation_end,
        mask_comments_and_strings,
    )

    if nesting >= 32:
        return masked
    chars = list(masked)
    consumed = 0
    for token in _TOKEN_RE.finditer(source):
        start = token.start()
        if start < consumed:
            continue
        raw = _RAW_START_RE.match(source, start)
        ordinary = _INTERPOLATED_START.match(source, start)
        if raw is not None:
            count = len(raw.group("dollars"))
            if not count:
                continue
            index = raw.end()
            end = token.end()
            content_end = end - len(raw.group("quotes"))
            verbatim = False
        elif ordinary is not None:
            count = 1
            index = ordinary.end()
            end = len(source)
            content_end = end
            verbatim = "@" in ordinary.group()
        else:
            continue
        holes = []
        while index < content_end:
            char = source[index]
            if raw is None:
                if char == '"':
                    if verbatim and source.startswith('""', index):
                        index += 2
                        continue
                    end = index + 1
                    break
                if not verbatim and char == "\\":
                    index += 2
                    continue
                if source.startswith("{{", index) or source.startswith("}}", index):
                    index += 2
                    continue
            if char == "{":
                run_end = index + 1
                while run_end < content_end and source[run_end] == "{":
                    run_end += 1
                if run_end - index >= count:
                    hole_end = _interpolation_end(source, run_end, count, nesting + 1)
                    if hole_end > content_end or not source.startswith(
                        "}" * count, hole_end - count
                    ):
                        break
                    holes.append((run_end, hole_end - count))
                    index = hole_end
                    continue
            index += 1
        chars[start:end] = ["\n" if c == "\n" else " " for c in source[start:end]]
        for lo, hi in holes:
            expression = source[lo:hi]
            recovered = reference_expression_mask(
                expression, mask_comments_and_strings(expression), nesting + 1
            )
            expression_end = _interpolation_expression_end(recovered)
            chars[lo : lo + expression_end] = recovered[:expression_end]
        consumed = end
    return "".join(chars)


def _interpolation_expression_end(expression: str) -> int:
    depth = 0
    conditional = 0
    for offset, char in enumerate(expression):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0:
            if (
                char == "?"
                and expression[offset : offset + 2]
                not in (
                    "?.",
                    "?[",
                    "??",
                )
                and (offset == 0 or expression[offset - 1] != "?")
            ):
                conditional += 1
            elif char == ":" and not (
                expression.startswith("::", offset)
                or (offset and expression[offset - 1] == ":")
            ):
                if conditional:
                    conditional -= 1
                else:
                    return offset
    return len(expression)


def _paired_ranges(text: str, opener: str, closer: str) -> list[tuple[int, int]]:
    stack = []
    ranges = []
    for offset, char in enumerate(text):
        if char == opener:
            stack.append(offset)
        elif char == closer and stack:
            ranges.append((stack.pop(), offset + 1))
    return ranges


def non_field_ranges(masked: str) -> list[tuple[int, int]]:
    # All signatures, argument lists and attributes with arguments are outside
    # the field grammar. Brace-depth alone cannot distinguish a parameter from
    # a field, because its method body has not opened yet.
    from .core import _TYPE_RE, _TYPE_BODY_START_RE

    ranges = _paired_ranges(masked, "(", ")")
    for match in _TYPE_RE.finditer(masked):
        if match.group("kind") != "enum":
            continue
        opening = _TYPE_BODY_START_RE.search(masked, match.end())
        if opening is not None and opening.group() == "{":
            closing = matching_brace(masked, opening.start())
            if closing >= 0:
                ranges.append((opening.start(), closing + 1))
    return ranges


class ReferenceContext:
    def __init__(self, masked, type_ranges, namespace_ranges, destination=None):
        self.masked = masked
        self.type_ranges = type_ranges
        self.namespace_ranges = namespace_ranges
        self.destination = destination if destination is not None else {}
        self.usings = list(_USING.finditer(masked))
        self.receiver_types = []
        self.shadows = _shadows(masked, type_ranges, self.receiver_types)
        for name, type_name, lo, hi in _member_shadows(masked, type_ranges):
            self.shadows.append((name, lo, hi))
            if type_name:
                self.receiver_types.append((name, type_name, lo, hi))

    def record(self, reference: str, offset: int, *, spelling=None) -> None:
        from .core import _containing_type_range, _namespace_at

        owner = _containing_type_range(self.type_ranges, offset)
        namespace = _namespace_at(self.namespace_ranges, offset)
        aliases = {}
        usings = []
        static_usings = []
        for directive in self.usings:
            scope = _namespace_at(self.namespace_ranges, directive.start("name"))
            if scope and namespace != scope and not namespace.startswith(scope + "."):
                continue
            name = directive.group("name").replace("global::", "")
            alias = directive.group("alias")
            if alias:
                aliases[alias] = name
            elif directive.group("static"):
                static_usings.append(name)
            elif name not in usings:
                usings.append(name)
        record = {
            "spelling": spelling
            if spelling is not None
            else reference.split(":", 1)[-1],
            "owner": owner[2] if owner else None,
            "namespace": namespace,
            "usings": usings,
            "aliases": aliases,
            "static_usings": static_usings,
            "offset": offset,
        }
        shadowed = sorted({name for name, lo, hi in self.shadows if lo <= offset < hi})
        record["shadowed_names"] = shadowed
        receiver = record["spelling"].split(".", 1)[0]
        record["receiver_shadowed"] = receiver in shadowed
        if record["receiver_shadowed"]:
            # Use the innermost declaration even when its type is unknown: an
            # untyped lambda parameter must not inherit an outer local's type.
            scope = max(
                (lo, hi)
                for name, lo, hi in self.shadows
                if name == receiver and lo <= offset < hi
            )
            types = {
                type_name
                for name, type_name, lo, hi in self.receiver_types
                if name == receiver and (lo, hi) == scope
            }
            if len(types) == 1:
                record["receiver_type"] = types.pop()
        self.destination.setdefault(reference, []).append(record)


def _type_spelling(value: str) -> str | None:
    """Keep a qualified declared type, without generic argument identities."""
    value = value.strip().removeprefix("global::").removesuffix("?").strip()
    position = 0
    names = []
    while position < len(value):
        name = _IDENTIFIER.match(value, position)
        if name is None:
            return None
        names.append(name.group())
        position = _SPACE.match(value, name.end()).end()
        if position < len(value) and value[position] == "<":
            position = _generic_end(value, position)
            if position is None:
                return None
            position = _SPACE.match(value, position).end()
        if position == len(value):
            return ".".join(names)
        separator = "::" if value.startswith("::", position) else "."
        if not value.startswith(separator, position):
            return None
        position = _SPACE.match(value, position + len(separator)).end()
    return None


def _parameter_types(parameters: str) -> dict[str, str]:
    from .core import _split_top_level

    result = {}
    for part, _ in _split_top_level(parameters, angle_brackets=True):
        declaration = re.sub(r"^\s*(?:\[[^\]]*\]\s*)*", "", part)
        declaration = declaration.split("=", 1)[0].strip()
        declaration = re.sub(
            r"^(?:(?:this|ref|out|in|params|scoped|readonly)\s+)+", "", declaration
        )
        match = re.fullmatch(r"(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*)", declaration)
        if match and (type_name := _type_spelling(match.group("type"))):
            result[match.group("name")] = type_name
    return result


def _member_shadows(masked: str, type_ranges):
    from .core import (
        _FIELD_RE,
        _PROPERTY_RE,
        _containing_type_range,
        _field_declarators,
        _is_direct_member,
    )

    excluded = non_field_ranges(masked)
    for pattern in (_FIELD_RE, _PROPERTY_RE):
        for match in pattern.finditer(masked):
            owner = _containing_type_range(type_ranges, match.start())
            if owner is None or not _is_direct_member(masked, owner, match.start()):
                continue
            if any(lo <= match.start("name") < hi for lo, hi in excluded):
                continue
            type_name = _type_spelling(match.group("type"))
            if type_name in {
                "class",
                "struct",
                "record",
                "interface",
                "enum",
                "namespace",
            }:
                continue
            names = (
                _field_declarators(masked, match)
                if pattern is _FIELD_RE
                else [(match.group("name"), match.start("name"))]
            )
            for name, _ in names:
                yield name, type_name, owner[0], owner[1]


def _shadows(
    masked: str, type_ranges, receiver_types=None
) -> list[tuple[str, int, int]]:
    from .core import (
        _METHOD_RE,
        _parameter_names,
        _declaration_semicolon,
        _NON_TYPE_STATEMENT_WORDS,
    )

    shadows = []
    parentheses = _paired_ranges(masked, "(", ")")
    for method in _METHOD_RE.finditer(masked):
        opening = method.end() - 1
        end = (
            matching_brace(masked, opening)
            if masked[opening] == "{"
            else _declaration_semicolon(masked, opening)
        )
        if end is None or end < 0:
            continue
        for name in _parameter_names(method.group("params")):
            shadows.append((name, method.start("params"), end))
        if receiver_types is not None:
            receiver_types.extend(
                (name, type_name, method.start("params"), end)
                for name, type_name in _parameter_types(method.group("params")).items()
            )
        for local in _LOCAL_DECLARATION.finditer(masked, opening + 1, end):
            if local.group("type").split()[0] in _NON_TYPE_STATEMENT_WORDS or any(
                lo <= local.start("name") < hi for lo, hi in parentheses
            ):
                continue
            # Restrict a local's shadow to its enclosing block, not the rest of
            # the type. Explicit qualified type names are resolved separately.
            from .core import _containing_block_end

            scope_end = _containing_block_end(masked, opening, local.start())
            if scope_end is None:
                scope_end = end
            shadows.append((local.group("name"), local.start("name"), scope_end))
            if receiver_types is not None:
                type_name = _type_spelling(local.group("type"))
                if type_name == "var":
                    initializer = re.match(
                        r"=\s*new\s+(?P<type>[^();={}]+)\s*\(",
                        masked[local.end() : scope_end],
                    )
                    type_name = (
                        _type_spelling(initializer.group("type"))
                        if initializer is not None
                        else None
                    )
                if type_name:
                    receiver_types.append(
                        (local.group("name"), type_name, local.start("name"), scope_end)
                    )
    for function in re.finditer(
        r"(?P<params>\([^;{}()]*\)|\b[A-Za-z_]\w*)\s*=>", masked
    ):
        parameters = function.group("params")
        if parameters.startswith("("):
            parameters = parameters[1:-1]
        names = _parameter_names(parameters)
        opening = _SPACE.match(masked, function.end()).end()
        if opening >= len(masked):
            continue
        end = (
            matching_brace(masked, opening)
            if masked[opening] == "{"
            else _expression_end(masked, opening)
        )
        if end >= 0:
            shadows.extend((name, function.start("params"), end) for name in names)
    return shadows


def _expression_end(masked: str, start: int) -> int:
    depth = 0
    for offset in range(start, len(masked)):
        char = masked[offset]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return offset
            depth -= 1
        elif char in ",;" and depth == 0:
            return offset
    return len(masked)


def _generic_end(masked: str, opening: int) -> int | None:
    depth = 0
    for offset in range(opening, len(masked)):
        char = masked[offset]
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth == 0:
                return offset + 1
        elif char in ";{}()":
            return None
    return None


def collect_binding_references(masked, type_ranges, declarations, state, append_ref):
    from .core import (
        _containing_type_range,
        _matching_paren,
        _argument_arity,
        _split_top_level,
        _NAMESPACE_RE,
    )

    shadows = (
        state.context.shadows
        if state.context is not None
        else _shadows(masked, type_ranges)
    )
    signatures = _paired_ranges(masked, "(", ")")
    # Attribute lists occur at a declaration boundary, including parameters.
    attributes = re.compile(r"(?m)(?:^|(?<=[;{}(,\]]))\s*\[(?P<body>[^\]\n]*)\]")
    attribute_ranges = []
    ignored_ranges = [item.span() for item in _NAMESPACE_RE.finditer(masked)]
    if state.context is not None:
        ignored_ranges.extend(item.span() for item in state.context.usings)
    for attribute in attributes.finditer(masked):
        before = masked[max(0, attribute.start() - 80) : attribute.start()].rstrip()
        chained = (
            attribute_ranges
            and not masked[attribute_ranges[-1][1] : attribute.start()].strip()
        )
        if before and (
            before[-1].isalnum()
            or before[-1] in ".)"
            or (before[-1] == "]" and not chained)
        ):
            continue
        following = _SPACE.match(masked, attribute.end()).end()
        if following < len(masked) and masked[following] in ";),=.?:":
            continue
        attribute_ranges.append(attribute.span())
        body = attribute.group("body")
        for part, offset in _split_top_level(
            body, attribute.start("body"), angle_brackets=True
        ):
            match = re.match(
                r"\s*(?:(?:assembly|module|return|field|method|param|property|type):\s*)?(?P<name>(?:global::)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
                part,
            )
            if match:
                name = match.group("name").replace("global::", "")
                append_ref(
                    "@attribute:" + name,
                    offset + match.start("name"),
                    state,
                    spelling=name,
                )

    consumed = -1
    for token in _IDENTIFIER.finditer(masked):
        start = token.start()
        if start < consumed or start in declarations:
            continue
        if any(lo <= start < hi for lo, hi in ignored_ranges):
            continue
        before = masked[max(0, start - 80) : start].rstrip()
        if before.endswith(".") or before.endswith("::"):
            continue
        name = token.group()
        if any(bound == name and lo <= start < hi for bound, lo, hi in shadows):
            continue
        if any(lo <= start < hi for lo, hi in attribute_ranges):
            continue
        names = [name]
        position = token.end()
        generic_receiver = False
        while True:
            position = _SPACE.match(masked, position).end()
            if position < len(masked) and masked[position] == "<":
                end = _generic_end(masked, position)
                if end is None:
                    break
                generic_receiver = True
                position = end
                position = _SPACE.match(masked, position).end()
            if position >= len(masked) or masked[position] != ".":
                break
            next_name = _IDENTIFIER.match(masked, position + 1)
            if next_name is None:
                break
            names.append(next_name.group())
            position = next_name.end()
        consumed = position
        if len(names) > 1:
            spelling = ".".join(names)
            append_ref("@member:" + spelling, start, state, spelling=spelling)
            if generic_receiver:
                receiver = ".".join(names[:-1])
                owner = _containing_type_range(type_ranges, start)
                local = [
                    item[2]
                    for item in type_ranges
                    if item[2].rsplit(".", 1)[-1] == names[-2]
                ]
                exact = f"{owner[2]}.{receiver}" if owner else receiver
                if exact in local:
                    append_ref("@type:" + exact, start, state, spelling=receiver)
            if (
                state.context is not None
                and position < len(masked)
                and masked[position] == "("
            ):
                closing = _matching_paren(masked, position)
                if closing is not None:
                    state.context.destination["@member:" + spelling][-1]["arity"] = (
                        _argument_arity(masked[position + 1 : closing])
                    )
        elif not (position < len(masked) and masked[position] == "("):
            # Bare names in value positions may be method-group conversions.
            # The project binder still requires an exact enclosing type or a
            # proven using-static provider; locals and parameters were removed.
            if re.search(r"(?:[=(,]|=>|\breturn)\s*$", before) and re.match(
                r"\s*[,);}]", masked[position:]
            ):
                if not any(
                    lo <= start < hi and _looks_like_signature(masked, lo, hi)
                    for lo, hi in signatures
                ):
                    append_ref("@member:" + name, start, state, spelling=name)


def _looks_like_signature(masked: str, start: int, end: int) -> bool:
    following = masked[end:].lstrip()
    return following.startswith(("{", "=>"))
