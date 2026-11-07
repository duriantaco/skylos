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


def _candidates(text: str):
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
        decoded = codecs.getincrementaldecoder("utf-8")().decode(data, final=False)
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
            result = _DecodedText(data.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError):
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
) -> SecretDecodeResult:
    """Return decoded views that may contain a known provider signature.

    ``start``/``end`` identify the original encoded container in ``text``. The
    ``frame`` and ``source_range`` method distinguish occurrences within decoded
    containers without pretending they have original source columns. Nested
    encodings retain the same original container span. ``complete_value=False``
    means a nested step selected only part of a
    larger decoded container; its text cannot prove what that whole container
    contains. Input is one physical source line; binary/UTF-16 files and archive
    extraction are outside this helper's scope.

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
        for candidate in _candidates(current.text):
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
            has_provider = any(prefix in decoded for prefix in prefixes)
            if not has_provider and not _may_have_another_layer(decoded):
                # Many ordinary HTML strings contain entities. Their direct
                # decoded prose has no credential signature or remaining
                # encoding, so it need not enter the recursive work queue.
                continue
            if checked >= max_candidates:
                incomplete("secret_decode_candidate_count_limit")
                exhausted = True
                break
            checked += 1
            size = len(decoded.encode("utf-8"))
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
            if len(current.encodings) >= max_depth:
                incomplete("secret_decode_depth_limit")
                continue
            view = DecodedSecretView(
                decoded,
                start,
                end,
                (*current.encodings, candidate.encoding),
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
