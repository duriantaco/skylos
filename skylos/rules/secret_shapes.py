"""Secret-shaped values that are public or structural by construction.

The secrets scan flags long, high-entropy tokens and values assigned to
secret-sounding names. Each predicate here rules out one narrow shape, and
only on positive structural evidence: a hex digest that names its
algorithm, a public-key encoding, an id inside a public document URL, a
reference to a secret stored elsewhere. Provider-shaped credentials (AWS,
GitHub, Stripe, Slack, ...) are matched separately and never pass through
these predicates.
"""

from __future__ import annotations

import re
from functools import lru_cache

# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------

_HEX_DIGEST_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}
_PREFIXED_HEX_DIGEST_RE = re.compile(
    r"(?P<algorithm>md5|sha1|sha224|sha256|sha384|sha512)[:=-](?P<digest>[0-9a-f]+)"
)


def is_prefixed_hex_digest(value: str) -> bool:
    """``sha256:<64 hex>`` (OCI, devcontainer locks, content hashes): the
    algorithm is named and the length is exactly that digest's."""
    match = _PREFIXED_HEX_DIGEST_RE.fullmatch(value.strip())
    return bool(
        match
        and len(match.group("digest")) == _HEX_DIGEST_LENGTHS[match.group("algorithm")]
    )


# ---------------------------------------------------------------------------
# Values assigned to secret-sounding names
# ---------------------------------------------------------------------------

# ${{ secrets.NAME }}, ${{ env.NAME }}: no fallback literal (``||``) allowed.
_ACTIONS_EXPRESSION_RE = re.compile(r"\$\{\{\s*[A-Za-z_][\w.\-\[\]' ]*\}\}")
# ${name}, $NAME, %NAME% (no ``${NAME:-default}``: a default can be a secret;
# an unbraced ``$Name`` could be a password that starts with "$").
_SHELL_REFERENCE_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%"
)
# {{ .Values.token }}, {{ vault_token | b64encode }}: no quoted literal inside.
_TEMPLATE_REFERENCE_RE = re.compile(r"\{\{\s*[A-Za-z_.$][\w.\-\[\] |]*\}\}")
_ENV_NAME_WORD_RE = re.compile(r"[A-Z]+[0-9]{0,2}|[0-9]{1,4}")
_ENV_NAME_LIST_RE = re.compile(
    r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+(?:\s*[,; ]\s*[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)*"
)
_LOCATION_KEY_SUFFIXES = (
    "url",
    "uri",
    "urls",
    "endpoint",
    "href",
    "link",
    "host",
    "domain",
    "redirect",
    "callback",
    "issuer",
)
_PLAIN_HTTP_URL_RE = re.compile(
    r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:[/?#][^\s'\"`@]*)?"
)


def is_reference(value: str) -> bool:
    """The whole value names a secret kept elsewhere: ``${{ secrets.X }}``,
    ``${X}``, ``$X``, ``%X%`` or a ``{{ template.var }}``."""
    stripped = value.strip()
    return any(
        pattern.fullmatch(stripped)
        for pattern in (
            _ACTIONS_EXPRESSION_RE,
            _SHELL_REFERENCE_RE,
            _TEMPLATE_REFERENCE_RE,
        )
    )


def is_env_name_list(value: str) -> bool:
    """``GH_TOKEN,NPM_TOKEN``: environment variable names, not values."""
    stripped = value.strip()
    if not _ENV_NAME_LIST_RE.fullmatch(stripped):
        return False
    words = [word for word in re.split(r"[^A-Z0-9]+", stripped) if word]
    return all(_ENV_NAME_WORD_RE.fullmatch(word) for word in words)


def _normalized_name(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def names_its_key(key: str, value: str) -> bool:
    """``ADMIN_PASSWORD: "adminPassword"``: the value is the key's own name
    in another case (a field or form name), not a credential."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value.strip()):
        return False
    normalized = _normalized_name(value)
    return len(normalized) >= 8 and normalized == _normalized_name(
        key.rsplit(".", 1)[-1]
    )


_CREDENTIAL_LABEL_WORDS = frozenset(
    {
        "access",
        "api",
        "auth",
        "authentication",
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "credentials",
        "encryption",
        "key",
        "keys",
        "login",
        "oauth",
        "otp",
        "passphrase",
        "passwd",
        "password",
        "private",
        "pwd",
        "refresh",
        "secret",
        "secrets",
        "session",
        "signature",
        "signing",
    }
)
# Data/text/input describe the representation; event/batch/item/node/query
# describe the measured unit; model/type/value describe its semantic role.
# Keep this vocabulary explicit: an arbitrary short word can be a credential.
_TOKEN_LABEL_QUALIFIERS = frozenset(
    {
        "batch",
        "data",
        "event",
        "input",
        "item",
        "model",
        "node",
        "query",
        "text",
        "type",
        "value",
    }
)


def describes_token_label(key: str, value: str) -> bool:
    """A descriptive token label that restates its segmented field name.

    This is only evidence against a generic entropy candidate, never against
    a provider credential. Spaces alone do not establish a label: every key
    word must occur in order, with at most one known interior qualifier and
    no extra prefix or suffix. Credential fields are deliberately excluded.
    A secret deliberately identical to its descriptive field label remains
    ambiguous; this does not classify unrelated prose or English passphrases.
    """
    if len(key) > 128 or len(value) > 192:
        return False
    name = key.rsplit(".", 1)[-1]
    if not re.fullmatch(r"[A-Za-z]{2,16}(?:[_-][A-Za-z]{2,16}){2,}", name):
        return False
    key_words = re.split(r"[_-]", name.lower())
    if key_words[-1] != "token" or _CREDENTIAL_LABEL_WORDS.intersection(key_words):
        return False
    # Only literal lowercase ASCII words and ordinary phrase separators:
    # case changes, digits, encodings, tabs and escaped newlines stay scanned.
    if not re.fullmatch(r"[a-z]+(?:[ /-]+[a-z]+)+", value):
        return False
    value_words = re.split(r"[ /-]+", value)
    if _CREDENTIAL_LABEL_WORDS.intersection(value_words):
        return False
    if value_words == key_words:
        return True
    if len(value_words) != len(key_words) + 1:
        return False
    return any(
        value_words[index] in _TOKEN_LABEL_QUALIFIERS
        and value_words[:index] + value_words[index + 1 :] == key_words
        for index in range(1, len(value_words) - 1)
    )


def is_location_value(key: str, value: str) -> bool:
    """``TOKEN_URL = "https://host/oauth/token"``: a URL assigned to a name
    that says it holds a location, with no user info in it. The URL's own
    parts are still scanned as bare tokens."""
    normalized = _normalized_name(key.rsplit(".", 1)[-1])
    return normalized.endswith(_LOCATION_KEY_SUFFIXES) and bool(
        _PLAIN_HTTP_URL_RE.fullmatch(value.strip())
    )


# ---------------------------------------------------------------------------
# Bare high-entropy tokens
# ---------------------------------------------------------------------------

_SLUG_WORD_RE = re.compile(
    r"(?:[A-Z]?[a-z]+){1,3}"  # words, camelCase words
    r"|[A-Z]{1,6}"  # acronyms
    r"|[0-9]{1,8}"  # numbers, dates
    r"|[A-Za-z]{1,3}[0-9]{1,4}"  # v2, H264
    r"|[0-9]{1,4}[A-Za-z]{1,3}"  # 3L, 2xl
)
_EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_URL_RE = re.compile(
    r"https?://(?P<host>[A-Za-z0-9.-]+)(?::\d+)?(?P<path>/[^\s'\"`<>?#]*)?"
)
# Hosts whose URL paths carry public document, form or video ids.
_PUBLIC_DOCUMENT_HOSTS = frozenset(
    {
        "docs.google.com",
        "drive.google.com",
        "sheets.google.com",
        "slides.google.com",
        "forms.gle",
        "forms.office.com",
        "youtube.com",
        "www.youtube.com",
        "youtu.be",
        "figma.com",
        "www.figma.com",
        "notion.so",
        "www.notion.so",
    }
)
_SSH_PUBLIC_KEY_RE = re.compile(
    r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)"
    r"\s+(?P<blob>AAAA[A-Za-z0-9+/]+={0,3})"
)
# Public members of a JSON Web Key: EC/OKP coordinates, RSA modulus and
# exponent. The private members (d, p, q, dp, dq, qi, k) stay visible.
_JWK_PUBLIC_MEMBER_RE = re.compile(
    r"""^\s*(?P<q>["']?)(?:x|y|n|e)(?P=q)\s*:\s*["'](?P<value>[A-Za-z0-9_-]+)["']"""
)
_JWK_MARKER_RE = re.compile(r"""(?P<q>["']?)(?:kty|crv)(?P=q)\s*:""")
_JWK_WINDOW = 8
_PUBLIC_PEM_TYPES = (
    "PUBLIC KEY",
    "RSA PUBLIC KEY",
    "CERTIFICATE",
    "TRUSTED CERTIFICATE",
    "CERTIFICATE REQUEST",
    "NEW CERTIFICATE REQUEST",
    "X509 CRL",
    "PGP PUBLIC KEY BLOCK",
    "SSH2 PUBLIC KEY",
)
_PEM_BEGIN_RE = re.compile(r"-----BEGIN (?P<type>[A-Z0-9 ]+)-----")
_PEM_MAX_LINES = 400
# DER (certificates, SPKI keys) encodes to "M...", an OpenPGP key packet to
# "m...", an RFC 4716 SSH key to "AAAA...".
_PUBLIC_PEM_BODY_RE = re.compile(r"(?:M|m|AAAA)[A-Za-z0-9+/]")
_MINIFIED_LINE_LENGTH = 1000
_BUNDLE_SUFFIXES = (".js", ".mjs", ".cjs")
_BUNDLE_OUTPUT_DIRECTORIES = frozenset(
    {"dist", "build", "out", ".next", ".nuxt", ".output"}
)
_SOURCE_DIRECTORIES = frozenset({"src", "lib", "app", "server", "services"})


def is_word_slug(token: str) -> bool:
    """``build-guide-v2``, ``TEAM-001-v2``:
    three or more short, word-shaped parts. A random token has long mixed
    parts between its separators."""
    parts = [part for part in re.split(r"[-_]+", token) if part]
    return len(parts) >= 3 and all(
        len(part) <= 16 and _SLUG_WORD_RE.fullmatch(part) for part in parts
    )


def is_evm_address(token: str) -> bool:
    """An Ethereum-style contract or wallet address: public by design (a
    private key is 64 hex digits)."""
    return bool(_EVM_ADDRESS_RE.fullmatch(token))


def in_public_document_url(line: str, start: int, end: int) -> bool:
    """A Google Forms/Docs/Drive, YouTube, Figma or Notion id in the path of
    its share URL."""
    for match in _URL_RE.finditer(line):
        if match.group("host").lower() not in _PUBLIC_DOCUMENT_HOSTS:
            continue
        if (
            match.group("path")
            and match.start("path") <= start
            and end <= match.end("path")
        ):
            return True
    return False


def in_ssh_public_key(line: str, start: int, end: int) -> bool:
    """Part of the base64 blob of an ``ssh-ed25519 AAAA...`` public key."""
    return any(
        match.start("blob") <= start and end <= match.end("blob")
        for match in _SSH_PUBLIC_KEY_RE.finditer(line)
    )


def is_jwk_public_member(lines: list[str], index: int, token: str) -> bool:
    """``"x": "<token>"`` in a JSON Web Key (a ``kty`` or ``crv`` member
    within a few lines): a public coordinate or modulus."""
    match = _JWK_PUBLIC_MEMBER_RE.match(lines[index])
    if match is None or match.group("value") != token:
        return False
    window = lines[max(0, index - _JWK_WINDOW) : index + _JWK_WINDOW + 1]
    return any(_JWK_MARKER_RE.search(line) for line in window)


def is_minified_bundle_line(rel_path: str, line: str) -> bool:
    """A long JavaScript line within an established build-output directory.

    Line length or a minified-looking filename alone cannot establish an
    artifact context. An earlier source directory also prevents treating a
    source subtree named ``build`` or ``dist`` as generated output. Keyed
    and provider secrets remain reported even in recognized artifacts.
    """
    normalized = rel_path.replace("\\", "/").lower()
    if (
        not normalized.endswith(_BUNDLE_SUFFIXES)
        or len(line) <= _MINIFIED_LINE_LENGTH
    ):
        return False
    for directory in normalized.split("/")[:-1]:
        if directory in _SOURCE_DIRECTORIES:
            return False
        if directory in _BUNDLE_OUTPUT_DIRECTORIES:
            return True
    return False


def _pem_end(pem_type: str) -> str:
    return f"-----END {pem_type}-----"


def public_pem_spans(lines: list[str]) -> dict[int, list[tuple[int, int]]]:
    """Columns, per 1-based line, inside a public-key or certificate PEM
    block whose END marker is present and whose body is DER, OpenPGP or
    SSH key data. Covers blocks written on one line with ``\\n`` escapes."""
    spans: dict[int, list[tuple[int, int]]] = {}
    for index, line in enumerate(lines):
        for match in _PEM_BEGIN_RE.finditer(line):
            pem_type = match.group("type")
            if pem_type not in _PUBLIC_PEM_TYPES:
                continue
            end_marker = _pem_end(pem_type)
            same_line = line.find(end_marker, match.end())
            if same_line >= 0:
                body = re.sub(r"\\[nr]|\s", "", line[match.end() : same_line])
                if _PUBLIC_PEM_BODY_RE.match(body):
                    spans.setdefault(index + 1, []).append((match.end(), same_line))
                continue
            _block_spans(lines, index, end_marker, spans)
    return spans


def _block_spans(lines, begin_index, end_marker, spans) -> None:
    stop = min(len(lines), begin_index + 1 + _PEM_MAX_LINES)
    end_index = next(
        (i for i in range(begin_index + 1, stop) if end_marker in lines[i]), None
    )
    if end_index is None or end_index == begin_index + 1:
        return
    first_body = re.sub(r"[\s'\"`+,]", "", lines[begin_index + 1])
    if not _PUBLIC_PEM_BODY_RE.match(first_body) and not first_body.startswith(
        ("Version:", "Comment:")
    ):
        return
    for i in range(begin_index + 1, end_index):
        spans.setdefault(i + 1, []).append((0, len(lines[i])))


def covered(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(left <= start and end <= right for left, right in spans)


# ---------------------------------------------------------------------------
# URLs and file paths
# ---------------------------------------------------------------------------

_URI_RE = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,30}://[^\s'\"`<>]+")
# Query/fragment parameters that carry a credential: api_key, access_token,
# client_secret, password, X-Amz-Signature, sig (Azure SAS), auth.
_SECRET_PARAM_NAME_RE = re.compile(
    r"(?i)key|token|secret|passw|pwd|sig|auth|credential"
)
# Hosts and path segments of URLs that carry a credential in their path:
# /api/webhooks/<id>/<token>, /bot<id>:<token>/, /tokens/<token>.
_CREDENTIAL_PATH_MARKER_RE = re.compile(
    r"(?i)webhook|hook|token|secret|key|auth|credential|passw|signature"
    r"|^sig$|^bot\d+:"
)
_PATH_CHUNK_DELIMITERS = frozenset(" \t\r\n'\"`()[]{}<>,;|")
_FILE_PATH_RE = re.compile(r"(?:[A-Za-z]:)?[\\/]*(?:[\w.~-]+[\\/]+)+[\w.~-]*")
_FILE_PATH_ANCHOR_RE = re.compile(r"(?:/|\.{1,2}[\\/]|~/|[A-Za-z]:[\\/])")
_FILE_EXTENSION_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,7}$")


@lru_cache(maxsize=64)
def _uri_spans(line: str) -> tuple[tuple[int, int, str], ...]:
    # One pass per line: a long line can hold hundreds of candidates.
    return tuple(
        (match.start(), match.end(), match.group(0)) for match in _URI_RE.finditer(line)
    )


def _uri_containing(line: str, start: int, end: int):
    for uri_start, uri_end, uri in _uri_spans(line):
        if uri_start <= start and end <= uri_end:
            return uri_start, uri
        if uri_start > start:
            break
    return None


def in_public_location(line: str, start: int, end: int) -> bool:
    """The token is part of a URL or a file path, and not the part of a URL
    that carries a credential (user info, a secret-named query parameter, or
    a webhook/token path)."""
    found = _uri_containing(line, start, end)
    if found is not None:
        uri_start, uri = found
        return not _uri_part_carries_credential(
            uri, start - uri_start, end - uri_start
        )
    return _in_file_path(line, start, end)


def in_url_credential(line: str, start: int, end: int) -> bool:
    """The token is the credential part of a URL on the line."""
    found = _uri_containing(line, start, end)
    if found is None:
        return False
    uri_start, uri = found
    return _uri_part_carries_credential(uri, start - uri_start, end - uri_start)


def is_public_url_value(value: str) -> bool:
    """The whole value is a URL with no user info and no secret-named query
    or fragment parameter."""
    text = value.strip()
    if _URI_RE.fullmatch(text) is None:
        return False
    authority_start = text.index("://") + 3
    authority_end = authority_start
    while authority_end < len(text) and text[authority_end] not in "/?#":
        authority_end += 1
    if "@" in text[authority_start:authority_end]:
        return False
    query_start = authority_end
    while query_start < len(text) and text[query_start] not in "?#":
        query_start += 1
    return not _secret_parameter_at(text, query_start, None)


def is_file_path_value(value: str) -> bool:
    """The whole value is a file path (see ``_is_file_path``)."""
    return _is_file_path(value.strip())


def _uri_part_carries_credential(uri: str, start: int, end: int) -> bool:
    """Whether ``uri[start:end]`` is where a URL carries a credential: user
    info, the value of a secret-named parameter, or a path under a
    webhook/token-like host or segment."""
    authority_start = uri.index("://") + 3
    authority_end = authority_start
    while authority_end < len(uri) and uri[authority_end] not in "/?#":
        authority_end += 1
    user_info_end = uri.rfind("@", authority_start, authority_end)
    if start < authority_end:
        return user_info_end != -1 and start < user_info_end
    query_start = authority_end
    while query_start < len(uri) and uri[query_start] not in "?#":
        query_start += 1
    if start >= query_start:
        return _secret_parameter_at(uri, query_start, start)
    host = uri[max(authority_start, user_info_end + 1) : authority_end]
    parts = [*host.split("."), *uri[authority_end:query_start].split("/")]
    return any(part and _CREDENTIAL_PATH_MARKER_RE.search(part) for part in parts)


def _secret_parameter_at(uri: str, query_start: int, token_start) -> bool:
    """A secret-named query or fragment parameter with a value; when
    ``token_start`` is given, only the parameter whose value holds it."""
    position = query_start + 1
    for pair in re.split(r"[&;#?]", uri[query_start + 1 :]):
        name, separator, value = pair.partition("=")
        value_start = position + len(name) + len(separator)
        value_end = position + len(pair)
        holds_token = token_start is None or value_start <= token_start < value_end
        if separator and value and holds_token and _SECRET_PARAM_NAME_RE.search(name):
            return True
        position = value_end + 1
    return False


def _in_file_path(line: str, start: int, end: int) -> bool:
    low = start
    while low > 0 and line[low - 1] not in _PATH_CHUNK_DELIMITERS:
        low -= 1
    high = end
    while high < len(line) and line[high] not in _PATH_CHUNK_DELIMITERS:
        high += 1
    return _is_file_path(line[low:high])


def _is_file_path(chunk: str) -> bool:
    """``/srv/app/data/<name>``, ``./x/y``, ``C:\\x\\y`` or ``dir/name.ext``:
    path characters only (no ``+``, ``=``, ``%``, ``@``), at least two
    segments, and either anchored like a path or ending in a file extension.
    A base64 value with slashes has neither."""
    if not _FILE_PATH_RE.fullmatch(chunk):
        return False
    segments = [part for part in re.split(r"[\\/]", chunk) if part]
    if len(segments) < 2:
        return False
    return bool(
        _FILE_PATH_ANCHOR_RE.match(chunk)
        or _FILE_EXTENSION_RE.search(chunk.rstrip("/\\"))
    )


# ---------------------------------------------------------------------------
# Private key headers
# ---------------------------------------------------------------------------

# Headers the legacy provider pattern does not match: PKCS#8, encrypted
# PKCS#8 and OpenPGP secret keys. These are reported only with key material
# after them.
EXTRA_PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----"
)
_KEY_MATERIAL_RE = re.compile(r"[A-Za-z0-9+/]{16,}|Proc-Type:|Version:")
_PLACEHOLDER_MATERIAL_RE = re.compile(
    r"(?i)\.\.\.|…|<|\[|\{|\$|%|-----END|your|redacted|x{3,}|placeholder|insert|paste"
)
_ESCAPED_BREAK_RE = re.compile(r"^(?:\\[nr]|[\s'\"`+,])+")
_PROSE_RE = re.compile(r"^\s*(?:</?[A-Za-z]|[`*_)\]]|[A-Za-z]{1,12}\s)")


def private_key_header_material(
    line: str, header_end: int, following: list[str]
) -> str:
    """What follows a ``-----BEGIN ... PRIVATE KEY-----`` header:

    "key" (base64 key data or PEM headers), "documentation" (prose, markup
    or a placeholder such as ``...``), or "unknown" (the header ends the
    string and nothing on the next line says which).
    """
    rest = line[header_end:]
    if _PROSE_RE.match(rest):
        return "documentation"
    material = _ESCAPED_BREAK_RE.sub("", rest)
    if not material.strip():
        material = next(
            (
                _ESCAPED_BREAK_RE.sub("", text)
                for text in following[:2]
                if _ESCAPED_BREAK_RE.sub("", text).strip()
            ),
            "",
        )
    if _KEY_MATERIAL_RE.match(material):
        return "key"
    if _PLACEHOLDER_MATERIAL_RE.match(material):
        return "documentation"
    return "unknown"
