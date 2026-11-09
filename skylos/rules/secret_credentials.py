"""Bounded, offline evidence from literal credential records.

These parsers use issuer field definitions, not another scanner's expressions.
They recognize complete records without establishing issuance, validity, or access.
No decoded credential value is exposed through the public match objects.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


MAX_RECORD_TEXT = 2 * 1024 * 1024
MAX_JSON_NODES = 50_000
MAX_JSON_DEPTH = 64
MAX_JSON_RECORDS = 2_048
MAX_JSON_STRING = 64 * 1024
MAX_JSON_WORK = 16 * 1024 * 1024
MAX_CONNECTION_RECORD = 16 * 1024


@dataclass(frozen=True)
class JsonScalar:
    value: str = field(repr=False)
    start: int
    end: int


@dataclass(frozen=True)
class JsonRecord:
    fields: dict[str, JsonScalar] = field(repr=False)
    start: int
    end: int


@dataclass(frozen=True)
class JsonRecordScan:
    records: tuple[JsonRecord, ...]
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class CredentialRelatedSpan:
    role: str
    start: int
    end: int


@dataclass(frozen=True)
class CredentialMatch:
    provider: str
    start: int
    end: int
    evidence: dict[str, str | bool | int]
    related_spans: tuple[CredentialRelatedSpan, ...] = ()


@dataclass(frozen=True)
class CredentialScan:
    matches: tuple[CredentialMatch, ...]
    issues: tuple[str, ...] = ()


class _InvalidJson(ValueError):
    pass


class _JsonLimit(ValueError):
    pass


_SPACE = re.compile(r"[ \t\r\n]*")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_DECODER = json.JSONDecoder()


class _JsonRecords:
    """Parse direct string members once; never pair across child objects."""

    def __init__(self, text):
        self.text = text
        self.records = []
        self.nodes = 0
        self.work = 0

    def charge(self, amount):
        self.work += amount
        if self.work > MAX_JSON_WORK:
            raise _JsonLimit("json_record_work_limit")

    def whitespace(self, position):
        end = _SPACE.match(self.text, position).end()
        self.charge(end - position)
        return end

    def string(self, position):
        try:
            value, end = _DECODER.raw_decode(self.text, position)
        except (ValueError, RecursionError) as exc:
            raise _InvalidJson from exc
        self.charge(end - position)
        if not isinstance(value, str):
            raise _InvalidJson
        if end - position > MAX_JSON_STRING:
            raise _JsonLimit("json_record_string_limit")
        return JsonScalar(value, position + 1, end - 1), end

    def value(self, position, depth):
        self.nodes += 1
        if self.nodes > MAX_JSON_NODES:
            raise _JsonLimit("json_record_node_limit")
        if depth > MAX_JSON_DEPTH:
            raise _JsonLimit("json_record_depth_limit")
        position = self.whitespace(position)
        if position >= len(self.text):
            raise _InvalidJson
        marker = self.text[position]
        if marker == '"':
            return self.string(position)
        if marker == "{":
            return None, self.object(position, depth)
        if marker == "[":
            return None, self.array(position, depth)
        for literal in ("true", "false", "null"):
            if self.text.startswith(literal, position):
                self.charge(len(literal))
                return None, position + len(literal)
        match = _NUMBER.match(self.text, position)
        if match:
            self.charge(match.end() - position)
            return None, match.end()
        raise _InvalidJson

    def object(self, start, depth):
        self.charge(1)
        position = self.whitespace(start + 1)
        fields = {}
        seen = set()
        duplicate = False
        if position < len(self.text) and self.text[position] == "}":
            self.charge(1)
            return position + 1
        while position < len(self.text):
            if self.text[position] != '"':
                raise _InvalidJson
            key, position = self.string(position)
            duplicate |= key.value in seen
            seen.add(key.value)
            position = self.whitespace(position)
            if position >= len(self.text) or self.text[position] != ":":
                raise _InvalidJson
            self.charge(1)
            value, position = self.value(position + 1, depth + 1)
            if value is not None:
                fields[key.value] = value
            position = self.whitespace(position)
            if position >= len(self.text):
                raise _InvalidJson
            marker = self.text[position]
            self.charge(1)
            position += 1
            if marker == "}":
                if fields and not duplicate:
                    if len(self.records) >= MAX_JSON_RECORDS:
                        raise _JsonLimit("json_record_count_limit")
                    self.records.append(JsonRecord(fields, start, position))
                return position
            if marker != ",":
                raise _InvalidJson
            position = self.whitespace(position)
        raise _InvalidJson

    def array(self, start, depth):
        self.charge(1)
        position = self.whitespace(start + 1)
        if position < len(self.text) and self.text[position] == "]":
            self.charge(1)
            return position + 1
        while position < len(self.text):
            _, position = self.value(position, depth + 1)
            position = self.whitespace(position)
            if position >= len(self.text):
                raise _InvalidJson
            marker = self.text[position]
            self.charge(1)
            position += 1
            if marker == "]":
                return position
            if marker != ",":
                raise _InvalidJson
        raise _InvalidJson


def iter_json_string_records(text: str) -> JsonRecordScan:
    """Return literal direct-member records, including nested JSON objects.

    Text surrounding a JSON object may be source or prose. Failed outer source
    constructs are retried at the next opening brace; all retries share the same
    work/node budgets. Successfully parsed roots are skipped in one step.
    """
    if len(text) > MAX_RECORD_TEXT:
        return JsonRecordScan((), ("credential_record_text_limit",))
    parser = _JsonRecords(text)
    position = 0
    issues = []
    try:
        while position < len(text):
            start = text.find("{", position)
            if start < 0:
                break
            count = len(parser.records)
            try:
                _, position = parser.value(start, 0)
            except _InvalidJson:
                # No object produced by an invalid root is trusted. Retrying
                # may still prove an independently complete nested object.
                del parser.records[count:]
                position = start + 1
    except _JsonLimit as exc:
        issues.append(str(exc))
    return JsonRecordScan(tuple(parser.records), tuple(issues))


_AWS_ID = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}\Z")
_AWS_SECRET = re.compile(r"[A-Za-z0-9/+=]{40}\Z")
_AWS_SESSION = re.compile(r"[A-Za-z0-9/+=]{16,4096}\Z")
_AWS_FIELDS = {
    "id": ("aws_access_key_id", "AWS_ACCESS_KEY_ID", "accessKeyId", "AccessKeyId"),
    "secret": (
        "aws_secret_access_key",
        "AWS_SECRET_ACCESS_KEY",
        "secretAccessKey",
        "SecretAccessKey",
    ),
    "session": (
        "aws_session_token",
        "AWS_SESSION_TOKEN",
        "sessionToken",
        "SessionToken",
    ),
}
_AWS_DOCUMENTED_ID = "AKIAIOSFODNN7EXAMPLE"
_AWS_DOCUMENTED_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _single_field(fields, aliases):
    values = [fields[name] for name in aliases if name in fields]
    return values[0] if len(values) == 1 else None


def _marker_body(value):
    return bool(value) and (len(set(value)) == 1 or not value.strip("xX"))


def _aws_pair(fields, record_kind):
    identifier = _single_field(fields, _AWS_FIELDS["id"])
    secret = _single_field(fields, _AWS_FIELDS["secret"])
    session = _single_field(fields, _AWS_FIELDS["session"])
    if identifier is None or secret is None:
        return None
    if not _AWS_ID.fullmatch(identifier.value) or not _AWS_SECRET.fullmatch(
        secret.value
    ):
        return None
    if identifier.value == _AWS_DOCUMENTED_ID or secret.value == _AWS_DOCUMENTED_SECRET:
        return None
    if _marker_body(identifier.value[4:]) or _marker_body(secret.value):
        return None
    temporary = identifier.value.startswith("ASIA")
    if temporary and (session is None or not _AWS_SESSION.fullmatch(session.value)):
        return None
    related = [CredentialRelatedSpan("access_key_id", identifier.start, identifier.end)]
    components = 2
    if session is not None and _AWS_SESSION.fullmatch(session.value):
        components += 1
        related.append(
            CredentialRelatedSpan("session_token", session.start, session.end)
        )
    return CredentialMatch(
        "aws_secret_access_key",
        secret.start,
        secret.end,
        {
            "credential_record": "aws_pair",
            "record_format": record_kind,
            "complete_components": components,
            "temporary": temporary,
            "validation": "structural",
            "verified": False,
        },
        tuple(related),
    )


_INI_SECTION = re.compile(r"\s*\[([^\]\r\n]+)\]\s*(?:[;#].*)?\Z")
_INI_ASSIGNMENT = re.compile(
    r"[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*?)[ \t]*\Z"
)


def _ini_pairs(text):
    """AWS profile boundaries are explicit sections, never line proximity."""
    fields = {}
    duplicate = False
    active = False
    offset = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if _INI_SECTION.fullmatch(content):
            if active and not duplicate:
                match = _aws_pair(fields, "ini_profile")
                if match:
                    yield match
            fields = {}
            duplicate = False
            active = True
        elif active and content.strip() and not content.lstrip().startswith(("#", ";")):
            assignment = _INI_ASSIGNMENT.fullmatch(content)
            if assignment:
                key, value = assignment.groups()
                if key in fields:
                    duplicate = True
                fields[key] = JsonScalar(
                    value, offset + assignment.start(2), offset + assignment.end(2)
                )
            else:
                # A malformed profile cannot establish which settings apply.
                duplicate = True
        offset += len(line)
    if active and not duplicate:
        match = _aws_pair(fields, "ini_profile")
        if match:
            yield match


_AZURE_FIELD = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9]*)[ \t]*=[ \t]*([^;\r\n\"'<>`]+)"
)
_AZURE_NAME = re.compile(r"[a-z0-9]{3,24}\Z")
_AZURE_KNOWN_FIELDS = frozenset(
    {
        "defaultendpointsprotocol",
        "accountname",
        "accountkey",
        "endpointsuffix",
        "blobendpoint",
        "queueendpoint",
        "tableendpoint",
        "fileendpoint",
        "usedevelopmentstorage",
        "developmentstorageproxyuri",
        "sharedaccesssignature",
    }
)
_AZURE_EMULATOR_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6"
    "IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)


def _azure_key(value):
    # Azure account access keys are 512-bit secrets represented as Base64.
    if len(value) != 88 or not value.endswith("=="):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return (
        len(decoded) == 64
        and len(set(decoded)) > 1
        and base64.b64encode(decoded).decode("ascii") == value
    )


def _valid_endpoint(value):
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def _azure_record(fields):
    name = fields.get("accountname")
    key = fields.get("accountkey")
    if name is None or key is None or not _AZURE_NAME.fullmatch(name.value):
        return None
    if key.value == _AZURE_EMULATOR_KEY:
        return None
    if not _azure_key(key.value):
        return None
    protocol = fields.get("defaultendpointsprotocol")
    endpoints = [
        fields[n]
        for n in ("blobendpoint", "queueendpoint", "tableendpoint", "fileendpoint")
        if n in fields
    ]
    if protocol is not None and protocol.value not in {"http", "https"}:
        return None
    if any(not _valid_endpoint(endpoint.value) for endpoint in endpoints):
        return None
    # The official minimal record needs only AccountName and AccountKey.
    return CredentialMatch(
        "azure_storage_account_key",
        key.start,
        key.end,
        {
            "credential_record": "azure_storage_connection_string",
            "record_format": "connection_string",
            "complete_components": 2,
            "key_bytes": 64,
            "validation": "structural",
            "verified": False,
        },
        (CredentialRelatedSpan("account_name", name.start, name.end),),
    )


def _azure_records(text):
    """Semicolon-delimited fields must be contiguous within one literal line."""
    fields = {}
    duplicate = False
    previous_end = None
    start = 0
    for match in _AZURE_FIELD.finditer(text):
        key = match.group(1).lower()
        contiguous = (
            previous_end is not None
            and re.fullmatch(r"[ \t]*;[ \t]*", text[previous_end : match.start()])
            is not None
        )
        if not contiguous or key not in _AZURE_KNOWN_FIELDS:
            if fields and not duplicate:
                finding = _azure_record(fields)
                if finding:
                    yield finding
            fields = {}
            duplicate = False
            start = match.start()
        if key in _AZURE_KNOWN_FIELDS:
            duplicate |= key in fields
            raw_value = match.group(2)
            value = raw_value.rstrip()
            fields[key] = JsonScalar(value, match.start(2), match.start(2) + len(value))
            if match.end() - start > MAX_CONNECTION_RECORD:
                raise _JsonLimit("connection_record_limit")
        previous_end = match.end()
    if fields and not duplicate:
        finding = _azure_record(fields)
        if finding:
            yield finding


_GOOGLE_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.iam\.gserviceaccount\.com\Z")
_CREDENTIAL_HINT = re.compile(
    r"AccountKey|aws_secret_access_key|secretAccessKey|private_key|AKIA|ASIA", re.I
)


def _google_record(fields):
    kind = fields.get("type")
    key = fields.get("private_key")
    email = fields.get("client_email")
    if kind is None or kind.value != "service_account" or key is None or email is None:
        return None
    if not _GOOGLE_EMAIL.fullmatch(email.value):
        return None
    # Function-local import keeps the bounded record reader reusable by the
    # JWK detector without creating an import cycle.
    from skylos.rules.secret_key_material import inspect_pem_private_key

    proof = inspect_pem_private_key(key.value)
    if proof is None or proof.encrypted or proof.algorithm != "RSA":
        return None
    return CredentialMatch(
        "google_service_account",
        key.start,
        key.end,
        {
            "credential_record": "google_service_account",
            "record_format": "json",
            "complete_components": 3,
            "key_format": proof.format,
            "key_algorithm": proof.algorithm,
            "validation": "structural",
            "verified": False,
        },
        (CredentialRelatedSpan("client_email", email.start, email.end),),
    )


def scan_credential_records(text: str, *, file_kind: str = "") -> CredentialScan:
    """Find issuer-specific complete records; never join separate records."""
    # Search all text before applying a cap, so a late relevant record cannot
    # silently disappear. Unrelated lockfiles do not incur a new parser limit.
    if not _CREDENTIAL_HINT.search(text):
        return CredentialScan(())
    if len(text) > MAX_RECORD_TEXT:
        return CredentialScan((), ("credential_record_text_limit",))
    matches = []
    issues = []
    records = iter_json_string_records(text)
    issues.extend(records.issues)
    for record in records.records:
        aws = _aws_pair(record.fields, "json")
        if aws:
            matches.append(aws)
        google = _google_record(record.fields)
        if google:
            matches.append(google)
    try:
        matches.extend(_azure_records(text))
    except _JsonLimit as exc:
        issues.append(str(exc))
    name = str(file_kind).replace("\\", "/").rsplit("/", 1)[-1].lower()
    suffix = name.rsplit(".", 1)[-1]
    if suffix in {"ini", "cfg", "conf", "credentials", "config"}:
        matches.extend(_ini_pairs(text))
    return CredentialScan(tuple(matches), tuple(dict.fromkeys(issues)))
