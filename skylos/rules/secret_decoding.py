"""Bounded text views for provider-specific secret detection.

This module only decodes text. It never imports source files, evaluates code,
checks credentials online, or decides that a decoded value is a credential.
The caller must apply its normal provider detector and placeholder checks.
"""

from __future__ import annotations

import base64
import binascii
from bisect import bisect_right
import codecs
from collections import deque
from dataclasses import dataclass, field
from html import unescape
import re


_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_ESCAPED_TOKEN = re.compile(r"[^\s\"'`<>]+")
_UNICODE_ESCAPE = re.compile(r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})")
_HTML_ENTITY = re.compile(
    r"&(?:\#(?:[xX][0-9A-Fa-f]{1,8}|[0-9]{1,8})|[A-Za-z][A-Za-z0-9]{1,31});"
)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_RECORD_HINT = re.compile(
    r"kty|AccountKey|private_key|secretAccessKey|secret_access_key", re.I
)
_ENCODED_QUOTE = re.compile(r"&(?:quot|#0*34|#[xX]0*22);|\\u0022|\\x22")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True, slots=True)
class _SourceRun:
    output_start: int
    output_end: int
    input_start: int
    input_end: int


@dataclass(frozen=True, slots=True)
class _SourceMap:
    """A lazy identity map or monotone escape runs into a parent coordinate frame."""

    parent: _SourceMap | None = field(default=None, repr=False)
    runs: tuple[_SourceRun, ...] = field(default=(), repr=False)
    ends: tuple[int, ...] = field(default=(), repr=False)
    offset: int = 0

    def source_range(self, start: int, end: int) -> tuple[int, int]:
        if self.parent is None:
            return self.offset + start, self.offset + end
        first = self.runs[bisect_right(self.ends, start)]
        last = self.runs[bisect_right(self.ends, end - 1)]
        beginning = (
            first.input_start + start - first.output_start
            if first.output_end - first.output_start
            == first.input_end - first.input_start
            else first.input_start
        )
        ending = (
            last.input_start + end - last.output_start
            if last.output_end - last.output_start == last.input_end - last.input_start
            else last.input_end
        )
        return self.parent.source_range(beginning, ending)


@dataclass(frozen=True)
class DecodedSecretView:
    # Deliberately omit decoded credentials from debug representations.
    text: str = field(repr=False)
    start: int
    end: int
    encodings: tuple[str, ...]
    complete_value: bool = True
    frame: tuple[tuple[int, int], ...] = ()
    _source_map: _SourceMap | None = field(default=None, repr=False, compare=False)

    def source_range(self, start: int, end: int) -> tuple[int, int]:
        """Map a decoded substring into this view's coordinate frame.

        The empty frame names original source-line columns. Each Base64 layer
        appends the encoded container's range in its parent frame, then starts
        decoded coordinates at zero. Unicode/HTML escapes keep that frame and
        map back through compressed runs. These are not original source columns
        when ``frame`` is nonempty.
        """
        if (
            type(start) is not int
            or type(end) is not int
            or not 0 <= start < end <= len(self.text)
        ):
            raise ValueError(
                "decoded source range must be nonempty and within its view"
            )
        mapping = self._source_map or _SourceMap(offset=self.start)
        return mapping.source_range(start, end)


@dataclass(frozen=True)
class SecretDecodeResult:
    views: tuple[DecodedSecretView, ...]
    complete: bool
    diagnostics: tuple[str, ...]
    candidates_checked: int
    decoded_bytes: int


@dataclass(frozen=True)
class _Candidate:
    text: str = field(repr=False)
    start: int
    end: int
    encoding: str


@dataclass(frozen=True)
class _DecodedText:
    text: str = field(repr=False)
    runs: tuple[_SourceRun, ...] | None = field(default=None, repr=False)
    extra_encodings: tuple[str, ...] = ()
    intermediate_bytes: int = 0


def _base64_candidate(value: str) -> str | None:
    """Accept one canonical padded or unpadded Base64 alphabet at a time."""
    if len(value) < 24:
        return None
    body = value.rstrip("=")
    padding = len(value) - len(body)
    if len(body) % 4 == 1 or (padding and len(value) % 4):
        return None
    if any(char in body for char in "+/") and any(char in body for char in "-_"):
        return None
    return "base64url" if any(char in body for char in "-_") else "base64"


def _json_string_candidates(text: str):
    """Visit complete double-quoted literals once, including escaped quotes.

    The decoder validates JSON syntax.  This lexer only finds a closing quote
    without treating an escaped quote as a new literal. Unicode-only escapes
    retain their existing decoder path and metadata.
    """
    position = 0
    while position < len(text):
        start = text.find('"', position)
        if start < 0:
            return
        position = start + 1
        has_json_escape = False
        while position < len(text):
            character = text[position]
            if character == "\\":
                if position + 1 < len(text) and text[position + 1] != "u":
                    has_json_escape = True
                position += 2
            elif character == '"':
                position += 1
                if has_json_escape:
                    yield _Candidate(text[start:position], start, position, "json")
                break
            else:
                position += 1
        else:
            return


def _candidates(text: str, *, include_record_escapes: bool = False):
    # Structured credentials need their sibling fields and separators together.
    # Token-sized escape views remain useful for ordinary provider signatures.
    # Whole-line views use exactly the same byte/count/depth/source-map limits.
    if include_record_escapes and (
        _RECORD_HINT.search(text) or ("{" in text and _ENCODED_QUOTE.search(text))
    ):
        if _HTML_ENTITY.search(text):
            yield _Candidate(text, 0, len(text), "html")
        if _UNICODE_ESCAPE.search(text):
            yield _Candidate(text, 0, len(text), "unicode")
    if include_record_escapes:
        yield from _json_string_candidates(text)
    for match in _BASE64_BLOCK.finditer(text):
        # A third pad character is not a boundary around a valid encoding.
        if match.end() < len(text) and text[match.end()] == "=":
            continue
        value = match.group()
        encoding = _base64_candidate(value)
        if encoding is not None:
            yield _Candidate(value, match.start(), match.end(), encoding)
    for match in _ESCAPED_TOKEN.finditer(text):
        value = match.group()
        if _UNICODE_ESCAPE.search(value):
            yield _Candidate(value, match.start(), match.end(), "unicode")
        if _HTML_ENTITY.search(value):
            yield _Candidate(value, match.start(), match.end(), "html")
        if "%" in value and _PERCENT_ESCAPE.search(value):
            yield _Candidate(value, match.start(), match.end(), "percent")


def _unicode_character(match: re.Match[str]) -> str:
    number = int(match.group()[2:], 16)
    if number > 0x10FFFF or 0xD800 <= number <= 0xDFFF:
        return match.group()
    return chr(number)


def _has_printable_base64_prefix(candidate: _Candidate, max_chars: int) -> bool:
    """Reject an oversized block only when its bounded prefix proves nontext.

    A truncated UTF-8 sequence is not evidence of invalid text; the incremental
    decoder retains that unfinished suffix. This is only a rejection prefilter,
    never proof that the rest of an oversized candidate is safe.
    """
    length = min(len(candidate.text), max_chars, 256)
    length -= length % 4
    if length < 4:
        return True
    encoded = candidate.text[:length].translate(str.maketrans("-_", "+/"))
    try:
        data = base64.b64decode(encoded, validate=True)
        codec, _ = _base64_text_encoding(data)
        decoded = codecs.getincrementaldecoder(codec)().decode(data, final=False)
    except (binascii.Error, UnicodeDecodeError):
        return False
    return all(
        character.isprintable() or character in "\n\r\t" for character in decoded
    )


def _decode_escapes(candidate: _Candidate) -> _DecodedText:
    pattern = _UNICODE_ESCAPE if candidate.encoding == "unicode" else _HTML_ENTITY
    pieces = []
    runs = []
    output_position = 0
    previous = 0

    def append(value: str, start: int, end: int) -> None:
        nonlocal output_position
        if value:
            following = output_position + len(value)
            runs.append(
                _SourceRun(
                    output_position,
                    following,
                    candidate.start + start,
                    candidate.start + end,
                )
            )
            pieces.append(value)
            output_position = following

    for match in pattern.finditer(candidate.text):
        append(candidate.text[previous : match.start()], previous, match.start())
        replacement = (
            _unicode_character(match)
            if candidate.encoding == "unicode"
            else unescape(match.group())
        )
        append(replacement, match.start(), match.end())
        previous = match.end()
    append(candidate.text[previous:], previous, len(candidate.text))
    return _DecodedText("".join(pieces), tuple(runs))


def _decode_percent(candidate: _Candidate) -> _DecodedText | None:
    """Decode complete UTF-8 byte escapes without URL form normalization.

    A malformed escape or invalid UTF-8 sequence rejects this view as a whole;
    replacement characters and partial decoding cannot create a provider match.
    Each decoded codepoint maps to all bytes that produced it.
    """
    pieces = []
    runs = []
    output_position = 0
    position = 0
    source = candidate.text

    def append(value: str, start: int, end: int) -> None:
        nonlocal output_position
        following = output_position + len(value)
        runs.append(
            _SourceRun(
                output_position,
                following,
                candidate.start + start,
                candidate.start + end,
            )
        )
        pieces.append(value)
        output_position = following

    while position < len(source):
        if source[position] != "%":
            following = source.find("%", position)
            if following < 0:
                following = len(source)
            append(source[position:following], position, following)
            position = following
            continue
        start = position
        octets = bytearray()
        while position < len(source) and source[position] == "%":
            digits = source[position + 1 : position + 3]
            if len(digits) != 2 or any(digit not in _HEX_DIGITS for digit in digits):
                return None
            octets.append(int(digits, 16))
            position += 3
        try:
            decoded = octets.decode("utf-8")
        except UnicodeDecodeError:
            return None
        previous = start
        for character in decoded:
            following = previous + 3 * len(character.encode("utf-8"))
            append(character, previous, following)
            previous = following
    return _DecodedText("".join(pieces), tuple(runs))


def _decode_json_string(candidate: _Candidate) -> _DecodedText | None:
    """Strict JSON string decoding with a compressed original-source map."""
    source = candidate.text
    if len(source) < 2 or source[0] != '"' or source[-1] != '"':
        return None
    pieces = []
    runs = []
    output_position = 0
    position = 1
    limit = len(source) - 1
    escapes = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }

    def append(value: str, start: int, end: int) -> None:
        nonlocal output_position
        following = output_position + len(value)
        runs.append(
            _SourceRun(
                output_position,
                following,
                candidate.start + start,
                candidate.start + end,
            )
        )
        pieces.append(value)
        output_position = following

    while position < limit:
        start = position
        character = source[position]
        if character != "\\":
            while position < limit and source[position] != "\\":
                number = ord(source[position])
                if source[position] == '"' or number < 32 or 0xD800 <= number <= 0xDFFF:
                    return None
                position += 1
            append(source[start:position], start, position)
            continue
        if position + 1 >= limit:
            return None
        marker = source[position + 1]
        if marker in escapes:
            position += 2
            append(escapes[marker], start, position)
            continue
        if marker != "u" or position + 6 > limit:
            return None
        digits = source[position + 2 : position + 6]
        if any(character not in _HEX_DIGITS for character in digits):
            return None
        number = int(digits, 16)
        position += 6
        if 0xD800 <= number <= 0xDBFF:
            if position + 6 > limit or source[position : position + 2] != "\\u":
                return None
            digits = source[position + 2 : position + 6]
            if any(character not in _HEX_DIGITS for character in digits):
                return None
            low = int(digits, 16)
            if not 0xDC00 <= low <= 0xDFFF:
                return None
            number = 0x10000 + ((number - 0xD800) << 10) + low - 0xDC00
            position += 6
        elif 0xDC00 <= number <= 0xDFFF:
            return None
        append(chr(number), start, position)
    return _DecodedText("".join(pieces), tuple(runs))


def _base64_text_encoding(data: bytes) -> tuple[str, str | None]:
    """Only an explicit byte-order mark selects UTF-16 interpretation."""
    if data.startswith(codecs.BOM_UTF16_LE):
        return "utf-16", "utf16le"
    if data.startswith(codecs.BOM_UTF16_BE):
        return "utf-16", "utf16be"
    return "utf-8", None


def _decode(candidate: _Candidate) -> _DecodedText | None:
    if candidate.encoding in {"base64", "base64url"}:
        encoded = candidate.text
        normalized = encoded.translate(str.maketrans("-_", "+/"))
        normalized += "=" * (-len(normalized) % 4)
        try:
            data = base64.b64decode(normalized, validate=True)
            # Reject unused pad bits and other noncanonical representations.
            if base64.b64encode(data).decode().rstrip("=") != normalized.rstrip("="):
                return None
            codec, extra_encoding = _base64_text_encoding(data)
            result = _DecodedText(
                data.decode(codec),
                extra_encodings=(extra_encoding,) if extra_encoding else (),
                intermediate_bytes=len(data) if extra_encoding else 0,
            )
        except (binascii.Error, UnicodeDecodeError):
            return None
    elif candidate.encoding == "percent":
        result = _decode_percent(candidate)
        if result is None:
            return None
    elif candidate.encoding == "json":
        result = _decode_json_string(candidate)
        if result is None:
            return None
    else:
        result = _decode_escapes(candidate)
    decoded = result.text
    if decoded == candidate.text or not decoded:
        return None
    if not all(
        character.isprintable() or character in "\n\r\t" for character in decoded
    ):
        return None
    return result


def _may_have_another_layer(text: str) -> bool:
    return bool(
        _UNICODE_ESCAPE.search(text)
        or _HTML_ENTITY.search(text)
        or _PERCENT_ESCAPE.search(text)
        or any(
            _base64_candidate(match.group()) is not None
            for match in _BASE64_BLOCK.finditer(text)
        )
    )


def _canonical_views(views: list[DecodedSecretView]) -> tuple[DecodedSecretView, ...]:
    """Canonicalize nested representations of the same complete value only."""
    groups = {}
    chosen = []
    for index, view in enumerate(views):
        if view.complete_value:
            groups.setdefault(view.text, []).append((index, view))
        else:
            chosen.append((index, view))
    for group in groups.values():
        outer = None
        for index, view in sorted(
            group, key=lambda entry: (entry[1].start, -entry[1].end, entry[0])
        ):
            if (
                outer is not None
                and outer[1].start <= view.start
                and view.end <= outer[1].end
            ):
                outer[0] = min(outer[0], index)
            else:
                outer = [index, view]
                chosen.append(outer)
    return tuple(view for _, view in sorted(chosen, key=lambda entry: entry[0]))


def decode_provider_views(
    text: str,
    *,
    provider_prefixes: tuple[str, ...],
    max_depth: int = 2,
    max_candidates: int = 128,
    max_decoded_bytes: int = 65_536,
    max_candidate_chars: int = 65_536,
    include_record_escapes: bool = False,
) -> SecretDecodeResult:
    """Return decoded views that may contain a known provider signature.

    ``start``/``end`` identify the original encoded container in ``text``. The
    ``frame`` and ``source_range`` method distinguish occurrences within decoded
    containers without pretending they have original source columns. Nested
    encodings retain the same original container span. ``complete_value=False``
    means a nested step selected only part of a
    larger decoded container; its text cannot prove what that whole container
    contains. Input is one physical source line. Base64-wrapped UTF-16 with an
    explicit BOM uses two transformations; raw binary files and archives are
    outside this helper's scope.

    Retained candidate views are bounded across the whole call. Reaching a
    plausible encoded candidate beyond a budget returns ``complete=False`` with
    a static diagnostic;
    callers must expose that incomplete analysis separately from secret findings.
    Ordinary raw source is not truncated and belongs to the caller's normal scan.
    """
    if (
        not 1 <= max_depth <= 3
        or max_candidates < 0
        or max_decoded_bytes < 0
        or max_candidate_chars < 1
    ):
        raise ValueError("secret decoding requires valid bounded limits")
    prefixes = tuple(dict.fromkeys(provider_prefixes))
    if any(not isinstance(prefix, str) or not prefix for prefix in prefixes):
        raise ValueError("provider prefixes must be nonempty strings")
    if not prefixes:
        return SecretDecodeResult((), True, (), 0, 0)
    # Hints only route text to provider validators. Scheme/authority casing
    # must not lose a candidate; exact credential syntax remains their job.
    prefixes = tuple(dict.fromkeys(prefix.casefold() for prefix in prefixes))

    queue = deque([DecodedSecretView(text, 0, len(text), (), _source_map=_SourceMap())])
    seen = {((), (0, len(text)), text, True)}
    views = []
    diagnostics = []
    checked = decoded_bytes = 0
    exhausted = False

    def incomplete(reason: str) -> None:
        if reason not in diagnostics:
            diagnostics.append(reason)

    while queue and not exhausted:
        current = queue.popleft()
        for candidate in _candidates(
            current.text, include_record_escapes=include_record_escapes
        ):
            if len(candidate.text) > max_candidate_chars:
                if candidate.encoding in {"base64", "base64url"} and not (
                    _has_printable_base64_prefix(candidate, max_candidate_chars)
                ):
                    continue
                incomplete("secret_decode_candidate_limit")
                continue
            decoded_text = _decode(candidate)
            if decoded_text is None:
                continue
            decoded = decoded_text.text
            hint_text = decoded.casefold()
            has_provider = any(prefix in hint_text for prefix in prefixes)
            has_json_layer = (
                include_record_escapes
                and next(_json_string_candidates(decoded), None) is not None
            )
            if (
                not has_provider
                and not _may_have_another_layer(decoded)
                and not has_json_layer
            ):
                # Many ordinary HTML strings contain entities. Their direct
                # decoded prose has no credential signature or remaining
                # encoding, so it need not enter the recursive work queue.
                continue
            if checked >= max_candidates:
                incomplete("secret_decode_candidate_count_limit")
                exhausted = True
                break
            checked += 1
            size = len(decoded.encode("utf-8")) + decoded_text.intermediate_bytes
            if size > max_decoded_bytes - decoded_bytes:
                incomplete("secret_decode_byte_limit")
                continue
            decoded_bytes += size
            start, end = (
                (candidate.start, candidate.end)
                if not current.encodings
                else (current.start, current.end)
            )
            complete_value = current.complete_value and (
                not current.encodings
                or (candidate.start == 0 and candidate.end == len(current.text))
            )
            if decoded_text.runs is None:
                frame = (
                    *current.frame,
                    current.source_range(candidate.start, candidate.end),
                )
                source_map = _SourceMap()
            else:
                frame = current.frame
                source_map = _SourceMap(
                    parent=current._source_map or _SourceMap(offset=current.start),
                    runs=decoded_text.runs,
                    ends=tuple(run.output_end for run in decoded_text.runs),
                )
            identity = (
                frame,
                source_map.source_range(0, len(decoded)),
                decoded,
                complete_value,
            )
            if identity in seen:
                continue
            seen.add(identity)
            transformations = (candidate.encoding, *decoded_text.extra_encodings)
            if len(current.encodings) + len(transformations) > max_depth:
                if (
                    "json" in (*current.encodings, *transformations)
                    and decoded.strip().casefold()
                    in {prefix.strip() for prefix in prefixes}
                    and not _may_have_another_layer(decoded)
                    and next(_json_string_candidates(decoded), None) is None
                ):
                    # A decoded marker with no payload cannot hold a provider
                    # credential. Source fragments often concatenate a prefix
                    # with a runtime value; the extra JSON representation of
                    # that prefix alone must not add incomplete-analysis noise.
                    continue
                incomplete("secret_decode_depth_limit")
                continue
            view = DecodedSecretView(
                decoded,
                start,
                end,
                (*current.encodings, *transformations),
                complete_value,
                frame,
                source_map,
            )
            if has_provider:
                views.append(view)
            queue.append(view)

    return SecretDecodeResult(
        _canonical_views(views),
        not diagnostics,
        tuple(diagnostics),
        checked,
        decoded_bytes,
    )
