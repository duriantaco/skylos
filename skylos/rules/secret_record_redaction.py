"""Redaction-only JWK context for complete or truncated source snippets.

Finding validators require complete records. Display masking deliberately also
protects private fields in unfinished records and never creates a finding.
"""

from __future__ import annotations

import json
import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field

from skylos.rules.secret_decoding import decode_provider_views


_PRIVATE = {
    "RSA": frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"}),
    "EC": frozenset({"d"}),
    "OKP": frozenset({"d"}),
    "oct": frozenset({"k"}),
}
_ALL_PRIVATE = frozenset().union(*_PRIVATE.values())
_MAX_DEPTH = 64
_MAX_PRIVATE_MEMBERS = 64
_MAX_SPANS = 4096
_MAX_TEXT = 131_072
_MAX_VIEWS = 128
_MAX_DECODED_BYTES = 262_144
_MAX_CARRIER_CHARS = 65_536
_MAX_ESCAPE_DEPTH = 3
_RECORD_PREFIXES = (
    "kty",
    '"d"',
    '"k"',
    "AccountKey",
    "private_key",
    "secretAccessKey",
    "secret_access_key",
)
_BASE64_CARRIER = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_PLAUSIBLE_PRIVATE_VALUE = re.compile(r"[A-Za-z0-9_+/=-]{16,}")
_UNFINISHED_PERCENT = re.compile(r"%[0-9A-Fa-f]?\Z")


@dataclass
class _Frame:
    kind: str
    start: int
    expect: str = "key"
    key: str | None = None
    types: set[str] = field(default_factory=set)
    private: list[tuple[str, int, int]] = field(default_factory=list)
    overflow: bool = False
    owner: _Frame | None = field(default=None, repr=False)
    owner_key: str | None = None


def _string_end(text, start):
    position = start + 1
    while position < len(text):
        char = text[position]
        if char == "\\":
            position += 2
        elif char == '"':
            return position + 1, True
        else:
            position += 1
    return len(text), False


def _short_string(text, start, end, complete):
    if not complete or end - start > 256:
        return None
    try:
        return json.loads(text[start:end])
    except ValueError:
        return None


def jwk_fragment_private_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Keep direct-object context, bounded state, and no private value copies."""
    frames = []
    spans = []
    position = 0
    opaque_depth = 0
    opaque_start = None

    def finish(frame, end, *, complete):
        if frame.owner is not None:
            if len(frame.owner.private) < _MAX_PRIVATE_MEMBERS:
                frame.owner.private.append((frame.owner_key, frame.start, end))
            else:
                frame.owner.overflow = True
        names = frozenset().union(*(_PRIVATE[kind] for kind in frame.types))
        ambiguous = not complete and not frame.types
        if ambiguous:
            names = _ALL_PRIVATE
        if frame.overflow and names:
            spans.append((frame.start, end))
        else:
            spans.extend(
                (start, stop)
                for name, start, stop in frame.private
                if name in names
                and (not ambiguous or _PLAUSIBLE_PRIVATE_VALUE.match(text, start, stop))
            )

    while position < len(text):
        if len(spans) > _MAX_SPANS:
            # Thousands of private fragments cannot produce a useful snippet.
            # Mask the whole display rather than dropping protection at a cap.
            return ((0, len(text)),)
        char = text[position]
        frame = frames[-1] if frames else None
        if char == '"':
            end, complete = _string_end(text, position)
            if not opaque_depth and frame is not None and frame.kind == "{":
                if frame.expect == "key":
                    frame.key = _short_string(text, position, end, complete)
                    frame.expect = "colon"
                elif frame.expect == "value":
                    if frame.key == "kty":
                        kind = _short_string(text, position, end, complete)
                        if kind in _PRIVATE:
                            frame.types.add(kind)
                    elif frame.key in _ALL_PRIVATE:
                        if len(frame.private) < _MAX_PRIVATE_MEMBERS:
                            stop = end - 1 if complete else end
                            if position + 1 < stop:
                                frame.private.append((frame.key, position + 1, stop))
                        else:
                            frame.overflow = True
                    frame.expect = "after"
            position = end
            continue
        if char in "{[":
            if opaque_depth:
                opaque_depth += 1
            elif len(frames) >= _MAX_DEPTH:
                opaque_start = position
                opaque_depth = 1
            else:
                owner = None
                owner_key = None
                if frame is not None and frame.expect == "value":
                    if frame.kind == "{" and frame.key in _ALL_PRIVATE:
                        owner, owner_key = frame, frame.key
                    frame.expect = "after"
                frames.append(_Frame(char, position, owner=owner, owner_key=owner_key))
        elif char in "}]":
            if opaque_depth:
                opaque_depth -= 1
                if opaque_depth == 0:
                    spans.append((opaque_start, position + 1))
            elif frame is not None and (frame.kind, char) in {("{", "}"), ("[", "]")}:
                frames.pop()
                finish(frame, position + 1, complete=True)
        elif frame is not None and not opaque_depth:
            if char == ":" and frame.expect == "colon":
                frame.expect = "value"
            elif char == ",":
                frame.expect = "key"
                frame.key = None
        position += 1
    if opaque_depth:
        spans.append((opaque_start, len(text)))
    for frame in reversed(frames):
        finish(frame, len(text), complete=False)
    if len(spans) > _MAX_SPANS:
        return ((0, len(text)),)
    return tuple(spans)


@dataclass(frozen=True)
class _EscapedFragment:
    text: str = field(repr=False)
    coordinates: tuple[tuple[int, int], ...] = field(repr=False)

    def source_range(self, start, end):
        return self.coordinates[start][0], self.coordinates[end - 1][1]


def _unescape_fragment(text, start, end):
    """Tolerate an unfinished display string; never feed this to a detector."""
    characters = []
    coordinates = []
    position = start
    simple = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
    }
    while position < end:
        origin = position
        character = text[position]
        position += 1
        if character == "\\" and position < end:
            marker = text[position]
            if marker in simple:
                character = simple[marker]
                position += 1
            elif marker in {"u", "x"}:
                width = 4 if marker == "u" else 2
                digits = text[position + 1 : position + 1 + width]
                if len(digits) == width and all(
                    item in "0123456789abcdefABCDEF" for item in digits
                ):
                    number = int(digits, 16)
                    if not 0xD800 <= number <= 0xDFFF:
                        character = chr(number)
                        position += width + 1
        characters.append(character)
        coordinates.append((origin, position))
    return _EscapedFragment("".join(characters), tuple(coordinates))


def _unfinished_escape_views(text):
    """Bounded display-only views for missing outer quote/escape suffixes."""
    if "\\" not in text:
        return ()
    results = []
    position = 0
    while position < len(text):
        start = text.find('"', position)
        if start < 0:
            break
        end, complete = _string_end(text, start)
        if "\\" in text[start:end]:
            fragment = _unescape_fragment(text, start + 1, end - 1 if complete else end)
            if fragment.text.lstrip().startswith(("{", "[", '"')):
                results.append(fragment)
                if len(results) > _MAX_VIEWS:
                    raise _RedactionLimit
            if not complete:
                break
        position = end
    # Loggers can strip the enclosing JSON-string quotes and leave escaped
    # object punctuation. This view preserves the original source positions.
    if text.lstrip().startswith(("{", "[")) and (
        '\\"' in text or "\\u0022" in text or "\\x22" in text
    ):
        results.append(_unescape_fragment(text, 0, len(text)))
    return tuple(results)


def _plain_record_spans(text, scanner):
    spans = list(jwk_fragment_private_spans(text))
    scan = scanner(text)
    if scan.issues:
        return [(0, len(text))] if text else []
    for match in scan.matches:
        spans.append((match.start, match.end))
        spans.extend(
            (part.start, part.end)
            for part in match.related_spans
            if part.role != "account_name"
        )
    return spans


class _RedactionLimit(ValueError):
    pass


@dataclass
class _RenderBudget:
    views: int = 0
    decoded_bytes: int = 0

    def charge(self, *, views=0, decoded_bytes=0):
        self.views += views
        self.decoded_bytes += decoded_bytes
        if self.views > _MAX_VIEWS or self.decoded_bytes > _MAX_DECODED_BYTES:
            raise _RedactionLimit


def _local_record_spans(text, scanner, budget):
    spans = _plain_record_spans(text, scanner)
    queue = [(text, ())]
    while queue:
        current, parents = queue.pop()
        for view in _unfinished_escape_views(current):
            if len(parents) >= _MAX_ESCAPE_DEPTH:
                raise _RedactionLimit
            budget.charge(views=1, decoded_bytes=len(view.text.encode("utf-8")))
            lineage = (*parents, view)
            for start, end in _plain_record_spans(view.text, scanner):
                for parent in reversed(lineage):
                    start, end = parent.source_range(start, end)
                spans.append((start, end))
            queue.append((view.text, lineage))
    return spans


def _base64_prefix_text(value):
    """Decode a recoverable prefix when rendering already truncated a carrier.

    Trailing partial quanta/codepoints are dropped only for masking. A prefix
    cannot establish a new finding or a complete encoded record.
    """
    body = value.rstrip("=")
    length = len(body) - len(body) % 4
    if length < 24:
        return None
    normalized = body[:length].translate(str.maketrans("-_", "+/"))
    try:
        data = base64.b64decode(normalized, validate=True)
        if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            codec = "utf-16"
        else:
            codec = "utf-8"
        decoded = codecs.getincrementaldecoder(codec)().decode(data, final=False)
    except (UnicodeError, ValueError, binascii.Error):
        return None
    if not decoded or not all(
        char.isprintable() or char in "\r\n\t" for char in decoded
    ):
        return None
    return decoded


def record_redaction_spans(text, scanner):
    """Protect raw/transported records using bounded display-only evidence.

    Transformations with reversible character maps retain public components.
    Base64 and BOM-led UTF-16 wrappers are replaced as a whole outer carrier:
    masking a decoded offset cannot make the original carrier confidential.
    Exhausting a rendering budget masks the display instead of leaking a tail.
    """
    if not text:
        return ()
    if len(text) > _MAX_TEXT:
        return ((0, len(text)),)
    try:
        return _record_transport_spans(text, scanner)
    except _RedactionLimit:
        return ((0, len(text)),)


def _record_transport_spans(text, scanner):
    budget = _RenderBudget()
    spans = _local_record_spans(text, scanner, budget)
    sources = [text]
    unfinished = _UNFINISHED_PERCENT.search(text)
    if unfinished is not None:
        # CI can cut a valid URL escape after '%' or its first hex digit.
        # Retry only the complete preceding prefix for display masking. It
        # shares original offsets and never becomes a detector input.
        sources.append(text[: unfinished.start()])
    for source in sources:
        decoded = decode_provider_views(
            source,
            provider_prefixes=_RECORD_PREFIXES,
            max_depth=3,
            max_candidates=max(0, _MAX_VIEWS - budget.views),
            max_decoded_bytes=max(0, _MAX_DECODED_BYTES - budget.decoded_bytes),
            max_candidate_chars=_MAX_CARRIER_CHARS,
            include_record_escapes=True,
        )
        if not decoded.complete:
            return ((0, len(text)),)
        budget.charge(
            views=decoded.candidates_checked, decoded_bytes=decoded.decoded_bytes
        )
        for view in decoded.views:
            private = _local_record_spans(view.text, scanner, budget)
            if private and view.frame:
                spans.append(view.frame[0])
            else:
                spans.extend(view.source_range(start, end) for start, end in private)
    for match in _BASE64_CARRIER.finditer(text):
        if match.end() < len(text) and text[match.end()] == "=":
            continue
        if len(match.group()) > _MAX_CARRIER_CHARS:
            return ((0, len(text)),)
        prefix = _base64_prefix_text(match.group())
        if prefix is None:
            continue
        budget.charge(views=1, decoded_bytes=len(prefix.encode("utf-8")))
        if _local_record_spans(prefix, scanner, budget):
            spans.append((match.start(), match.end()))
    if len(spans) > _MAX_SPANS or any(
        not 0 <= start < end <= len(text) for start, end in spans
    ):
        return ((0, len(text)),)
    return tuple(spans)
