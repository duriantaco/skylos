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

import base64
import binascii
import hashlib
import re
import unicodedata
from functools import lru_cache
from itertools import pairwise

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
_DOTTED_REFERENCE_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\}"
)
_RESOLVER_REFERENCE_RE = re.compile(
    r"\$\{[A-Za-z][A-Za-z0-9_.]*:\s*[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\s*\}"
)
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
    ``${X}``, ``$X``, ``%X%``, a ``{{ template.var }}``, a dotted
    ``${var.x}`` or a resolver over a variable name (``${oc.env:X_KEY}``)."""
    stripped = value.strip()
    return any(
        pattern.fullmatch(stripped)
        for pattern in (
            _ACTIONS_EXPRESSION_RE,
            _SHELL_REFERENCE_RE,
            _TEMPLATE_REFERENCE_RE,
            _DOTTED_REFERENCE_RE,
            _RESOLVER_REFERENCE_RE,
        )
    )


_CALL_VALUE_RE = re.compile(r"[A-Za-z_][\w.]*\s*\(.*\)")
_ENV_READ_PREFIXES = ("process.env.", "os.environ", "import.meta.env.")


_QUOTED_ARGUMENT_RE = re.compile(r"""(["'])(.*?)\1""")
_ENV_NAME_ARGUMENT_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def is_indirect_value(value: str) -> bool:
    """``os.getenv("API_KEY")``, ``process.env.TOKEN``: code that reads the
    secret at run time. A call that also carries a literal
    (``getenv("API_KEY", "sk_live_…")``) still holds a secret."""
    stripped = value.strip()
    if stripped.startswith(_ENV_READ_PREFIXES):
        return True
    if not _CALL_VALUE_RE.fullmatch(stripped):
        return False
    return all(
        _ENV_NAME_ARGUMENT_RE.fullmatch(match.group(2))
        for match in _QUOTED_ARGUMENT_RE.finditer(stripped)
    )


_IDENTIFIER_LABEL_RE = re.compile(
    r"(?P<label>[A-Za-z][A-Za-z0-9_]*)\s*[\"']?\s*[:=]\s*[\"']?\s*$"
)
_IDENTIFIER_SUFFIXES = ("id", "ids", "uuid", "guid", "identifier")
_CREDENTIAL_WORDS = ("session", "secret", "token", "key", "pass", "auth", "cred")
_QUERY_PARAMETER_RE = re.compile(
    r"(?:^|[?&;\s\"'`])(?P<name>[A-Za-z][A-Za-z0-9_.\-]{0,40})=$"
)
_CREDENTIAL_PARAMETER_NAMES = frozenset(
    {
        "token",
        "accesstoken",
        "authtoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "key",
        "secret",
        "clientsecret",
        "password",
        "passwd",
        "pwd",
        "pass",
        "sig",
        "signature",
        "auth",
        "authorization",
        "bearer",
        "session",
        "sessionid",
        "sid",
        "privatekey",
        "credential",
        "credentials",
    }
)
_CREDENTIAL_NAME_RE = re.compile(r"(?i)key|secret|token|passw|auth|cred")
_EVIDENCE_WINDOW = 160


def names_a_credential(text: str) -> bool:
    """The text before a value names a credential (``API_KEY =``)."""
    return bool(_CREDENTIAL_NAME_RE.search(text))


def public_identifier_evidence(lines: list[str], line: str, token: str, start: int) -> str | None:
    """Why an unkeyed high-entropy value looks like a public identifier, or
    None. This is evidence for hiding a finding by default, never for
    dropping it: each signal is context that code could fabricate."""
    before = line[max(0, start - _EVIDENCE_WINDOW) : start]
    match = _IDENTIFIER_LABEL_RE.search(before)
    if match is not None:
        label = match.group("label").lower()
        if label.endswith(_IDENTIFIER_SUFFIXES) and not any(
            word in label for word in _CREDENTIAL_WORDS
        ):
            return f"introduced as an identifier ('{match.group('label')}')"
    parameter = _QUERY_PARAMETER_RE.search(before)
    if parameter is not None:
        name = parameter.group("name")
        if re.sub(r"[^a-z0-9]", "", name.lower()) not in _CREDENTIAL_PARAMETER_NAMES:
            return f"value of the non-credential parameter '{name}'"
    if is_character_table(token):
        return "each character appears once: an encoding alphabet"
    path_segment = re.compile(
        r"https?://[^\s'\"`?#]*/" + re.escape(token) + r"(?=$|[/?#'\"`\s])"
    )
    if any(token in other and path_segment.search(other) for other in lines):
        return "a path segment of a URL in this file"
    return None


def is_character_table(token: str) -> bool:
    """``ABC…xyz0123+/`` shuffled: an encoding alphabet. A random secret of
    32 or more characters rarely uses each character once."""
    return len(token) >= 32 and len(set(token)) == len(token)


_DIGITS = "0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
# Encoding alphabets of 32 or more characters: base64 (standard, URL-safe and
# crypt/bcrypt), base62, base58 (Bitcoin and Flickr), base36 and the base32
# variants (RFC 4648, base32hex, Crockford, z-base-32).
_ENCODING_ALPHABETS = tuple(
    frozenset(alphabet)
    for alphabet in (
        _UPPER + _LOWER + _DIGITS + "+/",
        _UPPER + _LOWER + _DIGITS + "-_",
        "./" + _DIGITS + _UPPER + _LOWER,
        _DIGITS + _UPPER + _LOWER,
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",
        _DIGITS + _LOWER,
        _DIGITS + _UPPER,
        _UPPER + "234567",
        _DIGITS + "ABCDEFGHIJKLMNOPQRSTUV",
        _DIGITS + "ABCDEFGHJKMNPQRSTVWXYZ",
        "ybndrfg8ejkmcpqxot1uwisza345h769",
    )
)


def is_alphabet_permutation(token: str) -> bool:
    """Every character of a standard encoding alphabet exactly once, in any
    order: an encoding table such as a shuffled base64 alphabet. A random
    32+ character credential repeats characters; the chance that one is a
    permutation of a whole alphabet is negligible (about 1e-26 for base64)."""
    if len(token) < 32 or len(set(token)) != len(token):
        return False
    characters = frozenset(token)
    return any(characters == alphabet for alphabet in _ENCODING_ALPHABETS)


_ALPHABET_CONTEXT_RE = re.compile(
    r"(?i)[A-Za-z0-9_]*(?:alphabet|charset)[A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)*"
    r"\s*(?:\(|(?::\s*[^=;(]+)?=)\s*$"
)


def is_declared_alphabet(line: str, start: int, end: int, token: str) -> bool:
    """A whole string literal that permutes a standard encoding alphabet and
    is passed to an alphabet constructor or bound to an alphabet/charset name
    (``Alphabet::new("…")``, ``const ALPHABET: &str = "…"``). Without that
    context a shuffled alphabet stays a (demoted) finding, because a
    substitution table can itself be an obfuscation key."""
    if start < 1 or end >= len(line) or line[start - 1] not in "\"'":
        return False
    if line[end] != line[start - 1] or not is_alphabet_permutation(token):
        return False
    return bool(_ALPHABET_CONTEXT_RE.search(line[: start - 1]))


def is_prose(token: str) -> bool:
    """Three or more words separated by spaces: a sentence or label whose
    entropy comes from the variety of letters, not from randomness. Callers
    apply it only to values that no credential key names, because a keyed
    phrase can be a passphrase."""
    return len(token.split()) >= 3


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


_NAME_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_NAMESPACED_NAME_RE = re.compile(r"[A-Za-z@][A-Za-z0-9_.:/@-]*")
_MAX_NAMESPACE_WORDS = 2
_MAX_NAMESPACE_WORD_LENGTH = 12


def _name_words(text: str) -> list[str]:
    return [word.lower() for word in _NAME_WORD_RE.findall(text)]


def restates_its_key(key: str, value: str) -> bool:
    """``LOGIN_CREDENTIALS: "shop_login_credentials"``: a storage or field
    name built from the key's own words behind a short namespace. A value
    with any other word, digit run or random part is not one."""
    stripped = value.strip()
    if not _NAMESPACED_NAME_RE.fullmatch(stripped):
        return False
    key_words = _name_words(key.rsplit(".", 1)[-1])
    value_words = _name_words(stripped)
    extra = len(value_words) - len(key_words)
    if len(key_words) < 2 or not 0 <= extra <= _MAX_NAMESPACE_WORDS:
        return False
    if value_words[extra:] != key_words:
        return False
    return all(
        word.isalpha() and len(word) <= _MAX_NAMESPACE_WORD_LENGTH
        for word in value_words[:extra]
    )


# Placeholders a message carries for the program to fill in: printf
# (``%s``, ``%1$d``, ``%(name)s``, ``%@``) and markup tags (``<b>``,
# ``</0>``, ``<a href="...">``). Braces (``{{x}}``, ``{x}``, ``${x}``, ICU)
# are matched by ``_without_placeholders`` itself.
_PRINTF_PLACEHOLDER_RE = re.compile(
    r"%(?:\d+\$)?(?:\([A-Za-z_][\w.]*\))?[-+ #0]*(?:\d+|\*)?(?:\.\d+)?"
    r"(?:hh|h|ll|l|L|z|j|t)?[sSdiufFeEgGxXocpr@]"
)
_MARKUP_TAG_RE = re.compile(r"</?[A-Za-z0-9][\w.:-]*(?:\s[^<>]{0,160})?/?>")
_ICU_SELECTOR_RE = re.compile(
    r"\s*[\w.]+\s*,\s*(?:plural|select|selectordinal)\s*,", re.IGNORECASE
)
_MAX_PLACEHOLDER_NESTING = 8
# Sentence ends in Latin, CJK (。！？), Devanagari (। ॥), Urdu (۔), Arabic
# (؟), Myanmar (။), Khmer (។ ៕), Ethiopic (።), Armenian (։) and Greek (;).
_SENTENCE_END = frozenset(
    ".:!?\u2026\u3002\uff01\uff1f\uff61\u0964\u0965\u06d4\u061f"
    "\u104b\u17d4\u17d5\u1362\u0589\u037e"
)
_SENTENCE_CLAUSE_RE = re.compile("[,;:.!?\u060c\u061b] |[\u3001\uff0c\uff1b\uff1a]")
_MAX_SENTENCE_WORD_LENGTH = 24
# Compound words in a catalog (German ``Zwöifaktorouthentisierigs``).
_MAX_CATALOG_WORD_PART = 32
# Scripts written without spaces between words: one token is a phrase.
_UNSPACED_SCRIPT_PREFIXES = (
    "CJK",
    "HIRAGANA",
    "KATAKANA",
    "THAI",
    "LAO",
    "KHMER",
    "MYANMAR",
    "TIBETAN",
    "HANGUL SYLLABLE",
)
_UNSPACED_LETTERS_PER_WORD = 3
# Symbols that belong to code or credentials, never to a punctuation token.
_CODE_SYMBOLS = frozenset("#@*\\$^=+~|`_<>{}")
# Letters and digits fused into one word (``2FA``, ``IPv6``, ``B2B``) are
# short; a longer mix of Latin letters and digits is how passwords look.
_MAX_MIXED_LATIN_WORD = 5
_MAX_NUMBER_DIGITS = 4


def _closing_brace(text: str, start: int) -> int | None:
    depth = 0
    for index in range(start, min(len(text), start + 800)):
        char = text[index]
        if char == "{":
            depth += 1
            if depth > _MAX_PLACEHOLDER_NESTING:
                return None
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _icu_branch_texts(body: str, depth: int) -> str:
    """The reader text of ``n, plural, one {# day} other {# days}``."""
    selector = _ICU_SELECTOR_RE.match(body)
    texts = []
    index = selector.end() if selector else 0
    while index < len(body):
        if body[index] != "{":
            index += 1
            continue
        end = _closing_brace(body, index)
        if end is None:
            break
        branch, _ = _without_placeholders(body[index + 1 : end], depth + 1)
        texts.append(branch.replace("#", " "))
        index = end + 1
    return " ".join(texts)


def _without_placeholders(value: str, depth: int = 0) -> tuple[str, int]:
    """``value`` with every placeholder replaced by a space, and how many
    there were. The branches of an ICU ``plural``/``select`` are reader text
    and are kept; an unclosed brace is left in place."""
    if depth > _MAX_PLACEHOLDER_NESTING:
        return value, 0
    parts = []
    found = 0
    index = 0
    while index < len(value):
        char = value[index]
        opens = char == "{" or (char == "$" and value[index + 1 : index + 2] == "{")
        if not opens:
            parts.append(char)
            index += 1
            continue
        brace = index if char == "{" else index + 1
        end = _closing_brace(value, brace)
        if end is None:
            parts.append(char)
            index += 1
            continue
        body = value[brace + 1 : end]
        found += 1
        if char == "{" and _ICU_SELECTOR_RE.match(body):
            parts.append(" " + _icu_branch_texts(body, depth) + " ")
        else:
            parts.append(" ")
        index = end + 1
    text = "".join(parts)
    text, printf = _PRINTF_PLACEHOLDER_RE.subn(" ", text)
    text, tags = _MARKUP_TAG_RE.subn(" ", text)
    return text, found + printf + tags


def _is_unspaced_letter(char: str) -> bool:
    return unicodedata.name(char, "").startswith(_UNSPACED_SCRIPT_PREFIXES)


def _is_separator_token(token: str) -> bool:
    """Punctuation, dashes, emoji or a short number standing alone."""
    stripped = token.strip(".,:;%)(")
    if stripped.isdigit() and len(stripped) <= _MAX_NUMBER_DIGITS:
        return True
    return all(
        unicodedata.category(char)[0] in "PS" and char not in _CODE_SYMBOLS
        for char in token
    )


def _without_word_marks(word: str) -> str:
    """Drop vowel signs, viramas and joiners: in Devanagari, Thai or Myanmar
    they are part of the letters around them, not separate characters."""
    return "".join(
        char
        for char in word
        if unicodedata.category(char)[0] != "M" and char not in "\u200c\u200d"
    )


def _natural_word_part(part: str) -> bool:
    if part.isalpha():
        changes = sum(
            1
            for before, after in pairwise(part)
            if before.isascii()
            and after.isascii()
            and before.islower()
            and after.isupper()
        )
        return changes < 2
    runs = re.findall(r"\d+|[^\W\d_]+|.", part)
    if any(not (run.isdigit() or run.isalpha()) for run in runs):
        return False
    for index, run in enumerate(runs):
        if not run.isdigit():
            continue
        if len(run) > _MAX_NUMBER_DIGITS:
            return False
        neighbours = runs[max(0, index - 1) : index] + runs[index + 1 : index + 2]
        if any(neighbour.isascii() for neighbour in neighbours) and (
            len(part) > _MAX_MIXED_LATIN_WORD
        ):
            return False
    return True


def _is_word_punctuation(char: str) -> bool:
    return unicodedata.category(char)[0] == "P" and char not in _CODE_SYMBOLS


def _natural_word(token: str, max_part: int) -> tuple[bool, int]:
    """Whether ``token`` is a word of natural language, and how many words
    it stands for. Punctuation around and inside it (hyphens, apostrophes,
    slashes, an ideographic full stop) separates its parts; each part is
    letters of any script with their marks, with digits only as in ``2FA``
    or ``有6個``."""
    core = _without_word_marks(token)
    while (
        core
        and unicodedata.category(core[-1])[0] == "S"
        and core[-1] not in _CODE_SYMBOLS
    ):
        core = core[:-1]
    while (
        core
        and unicodedata.category(core[0])[0] == "S"
        and core[0] not in _CODE_SYMBOLS
    ):
        core = core[1:]
    parts = []
    current = []
    for char in core:
        if _is_word_punctuation(char):
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    parts = [part for part in parts if part]
    if not parts:
        return False, 0
    for part in parts:
        if not _natural_word_part(part):
            return False, 0
    unspaced = sum(1 for part in parts for char in part if _is_unspaced_letter(char))
    if unspaced:
        return True, max(1, unspaced // _UNSPACED_LETTERS_PER_WORD)
    if any(len(part) > max_part for part in parts):
        return False, 0
    return True, 1


def _reader_words(text: str, max_part: int = _MAX_SENTENCE_WORD_LENGTH) -> int | None:
    """How many natural words ``text`` has, or None when a token is neither
    a natural word nor punctuation."""
    words = 0
    for token in text.split():
        natural, weight = _natural_word(token, max_part)
        if natural:
            words += weight
        elif not _is_separator_token(token):
            return None
    return words


def _first_letter(text: str) -> str:
    for char in text:
        if char.isalpha():
            return char
        if char.isdigit():
            return ""
    return ""


def is_message_sentence(value: str) -> bool:
    """``"Sign-in failed: wrong user name or password."``: text written for
    a reader. It starts with a capital letter (or a letter of a script with
    no case, or a placeholder), is made only of natural words in any script
    (letters with their marks, inner hyphens, apostrophes or slashes), has
    three or more of them and carries sentence punctuation. Placeholders
    (``{{length}}``, ``{n}``, ``%s``, ``<b>``) are left out. A lowercase run
    of words can be a generated passphrase and is not a sentence here; a
    word with digits or symbols in it is not a natural word."""
    text, _ = _without_placeholders(value)
    words = _reader_words(text)
    if words is None or words < 3:
        return False
    starts_with_placeholder = value.lstrip()[:1] in {"{", "$", "%", "<"}
    first = _first_letter(text)
    if not first or (first.islower() and not starts_with_placeholder):
        return False
    stripped = text.rstrip()
    while stripped and unicodedata.category(stripped[-1]) in {"Pe", "Pf"} | {"Zs"}:
        stripped = stripped[:-1]
    if stripped[-1:] in {'"', "'"}:
        stripped = stripped[:-1].rstrip()
    return stripped[-1:] in _SENTENCE_END or bool(_SENTENCE_CLAUSE_RE.search(text))


def is_catalog_text(value: str) -> bool:
    """A value of a translation catalog that is text for a reader: natural
    words in any script, with placeholders and punctuation, and no token
    shaped like a password or key (``Sommer2024``, ``aB3dE5fG``). In a
    catalog a label (``Confirm your current password``) or a single word
    (``API-Schlüssel``) is a translation, not a credential."""
    text, _ = _without_placeholders(value)
    words = _reader_words(text, _MAX_CATALOG_WORD_PART)
    return bool(words) and sum(char.isalpha() for char in text) >= 2


_PROSE_ATTRIBUTE_WORDS = frozenset(
    {
        "caption",
        "comment",
        "desc",
        "description",
        "error",
        "help",
        "hint",
        "instructions",
        "label",
        "message",
        "msg",
        "note",
        "notes",
        "placeholder",
        "prompt",
        "title",
        "tooltip",
    }
)
_MIXED_WORD_MIN_LENGTH = 12


def describes_its_key(key: str, value: str) -> bool:
    """``api_key_description: "Acme API key for image search"``: the key's
    last word says the value is text about the credential, and the value is
    prose. A word that mixes letters and digits at password length keeps the
    finding, as does a value without spaces."""
    words = [word for word in re.split(r"[_-]+", key.rsplit(".", 1)[-1].lower()) if word]
    if len(words) < 2 or words[-1] not in _PROSE_ATTRIBUTE_WORDS:
        return False
    if not is_prose(value):
        return False
    for token in value.split():
        if "://" in token:
            continue
        core = token.strip("()[]{}<>\"'.,:;!?")
        if (
            len(core) >= _MIXED_WORD_MIN_LENGTH
            and any(char.isdigit() for char in core)
            and any(char.isalpha() for char in core)
        ):
            return False
    return True


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
# ``ELBSecurityPolicy``, ``HTTPServerConfig``: an acronym, then words.
_ACRONYM_WORDS_RE = re.compile(r"[A-Z]{2,6}(?:[A-Z][a-z]+){1,3}")
_MAX_SLUG_PART = 16
_MAX_ACRONYM_WORDS_PART = 24
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
        (len(part) <= _MAX_SLUG_PART and _SLUG_WORD_RE.fullmatch(part))
        or (len(part) <= _MAX_ACRONYM_WORDS_PART and _ACRONYM_WORDS_RE.fullmatch(part))
        for part in parts
    )


_CAMEL_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_CAMEL_NAME_MIN_WORDS = 3
_CAMEL_NAME_MAX_WORDS = 8
_CAMEL_NAME_MAX_WORD = 12
_VOWELS = frozenset("aeiouyAEIOUY")


def is_camel_case_name(token: str) -> bool:
    """``web3SandboxChallenge``, ``loginAdminChallenge2``: a name made of
    three to eight camel-case words, each a word of three or more letters
    with a vowel (an all-capital acronym needs none) or a short number. A
    random token splits into one- and two-letter fragments."""
    words = _CAMEL_WORD_RE.findall(token)
    if "".join(words) != token or not (
        _CAMEL_NAME_MIN_WORDS <= len(words) <= _CAMEL_NAME_MAX_WORDS
    ):
        return False
    long_words = 0
    for word in words:
        if word.isdigit():
            if len(word) > 4:
                return False
            continue
        if not 3 <= len(word) <= _CAMEL_NAME_MAX_WORD:
            return False
        if not word.isupper() and not _VOWELS.intersection(word):
            return False
        if len(word) >= 4:
            long_words += 1
    return long_words >= 2


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: index for index, char in enumerate(_BASE58_ALPHABET)}
_BASE58_ADDRESS_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{25,35}")
# A pay-to-hash address: a version byte, a 20-byte hash and a 4-byte check.
# A WIF private key (33-34 payload bytes) or an extended key is longer.
_BASE58_ADDRESS_BYTES = 25
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_ADDRESS_RE = re.compile(
    r"(?P<hrp>bc|tb|bcrt|ltc|tltc)1(?P<data>[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8,87})"
)
_BECH32_CONSTANTS = (1, 0x2BC830A3)  # BIP-173 bech32, BIP-350 bech32m


def _base58_decode(token: str) -> bytes | None:
    number = 0
    for char in token:
        index = _BASE58_INDEX.get(char)
        if index is None:
            return None
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(token) - len(token.lstrip("1"))
    return b"\x00" * leading + body


def _is_base58check_address(token: str) -> bool:
    if not _BASE58_ADDRESS_RE.fullmatch(token):
        return False
    raw = _base58_decode(token)
    if raw is None or len(raw) != _BASE58_ADDRESS_BYTES:
        return False
    payload, check = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == check


def _bech32_polymod(values) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for bit in range(5):
            if (top >> bit) & 1:
                checksum ^= generator[bit]
    return checksum


def _is_bech32_address(token: str) -> bool:
    match = _BECH32_ADDRESS_RE.fullmatch(token.lower())
    if match is None or (token != token.lower() and token != token.upper()):
        return False
    hrp = match.group("hrp")
    data = [_BECH32_CHARSET.index(char) for char in match.group("data")]
    expanded = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    return _bech32_polymod(expanded + data) in _BECH32_CONSTANTS


def is_crypto_address(token: str) -> bool:
    """A cryptocurrency receiving address, public by design: a Base58Check
    pay-to-hash address whose checksum verifies (Bitcoin ``1…``/``3…``,
    Litecoin, Dogecoin, Dash ``X…``, Tron ``T…``), a SegWit bech32 or
    bech32m address with a valid checksum (``bc1…``), or an ``0x`` + 40-hex
    account. A private key (WIF, ``xprv``) has another length and stays."""
    return (
        is_evm_address(token)
        or _is_base58check_address(token)
        or _is_bech32_address(token)
    )


# Modular-crypt password hashes: bcrypt, argon2, scrypt, sha-crypt, PBKDF2.
_PASSWORD_HASH_RE = re.compile(
    r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"
    r"|\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"
    r"|\$scrypt\$[^\s$]+\$[A-Za-z0-9+/.=]+\$[A-Za-z0-9+/.=]+"
    r"|\$[156]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86}"
    r"|\$pbkdf2(?:-sha\d+)?\$\d+\$[./A-Za-z0-9+]+\$[./A-Za-z0-9+]+"
    r"|pbkdf2_sha(?:1|256|512)\$\d+\$[^\s$]+\$[A-Za-z0-9+/=]+"
)


def is_password_hash(value: str) -> bool:
    """A salted password hash in modular-crypt form (``$2a$10$…``,
    ``$argon2id$v=19$…``, ``pbkdf2_sha256$…``): what a database stores, not
    the password."""
    return bool(_PASSWORD_HASH_RE.fullmatch(value.strip()))


_INTERPOLATION_DEFAULT_RE = re.compile(r":-|:=|:\?|\|\||\?\?")
_LITERAL_RANDOM_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def is_interpolated_expression(value: str) -> bool:
    """``${var.project_name}-sqlite-data``, or a template expression cut at
    an inner quote (``${security.hash(req.body.password || ``): text built
    around ``${…}`` interpolations, not a literal secret. A default inside
    the braces (``${TOKEN:-…}``) or a long run of letters and digits
    anywhere in the value (``${TOKEN:q7Rk…}``) keeps the value scanned."""
    if "${" not in value:
        return False
    index = 0
    while True:
        start = value.find("${", index)
        if start < 0:
            break
        end = value.find("}", start)
        if end < 0:
            break  # cut at a quote inside the expression: the rest is code
        if _INTERPOLATION_DEFAULT_RE.search(value[start:end]):
            return False
        index = end + 1
    return not any(
        any(char.isdigit() for char in run) and any(char.isalpha() for char in run)
        for run in _LITERAL_RANDOM_RE.findall(value)
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


_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_BASE64_URL_TO_STANDARD = str.maketrans("-_", "+/")
_PLAIN_TEXT_BYTES = frozenset((*range(0x20, 0x7F), 0x09, 0x0A, 0x0D))
_MIN_PLAIN_TEXT_BYTES = 12
_MIN_CONTINUATION_LENGTH = 32
_USER_PASSWORD_PAIR_RE = re.compile(r"[A-Za-z0-9._%+@-]{1,64}:(?!//)\S{4,}")


def _decode_plain_text(body: str) -> str | None:
    usable = body
    if len(usable) % 4 == 1:
        usable = usable[:-1]
    usable += "=" * (-len(usable) % 4)
    try:
        decoded = base64.b64decode(usable, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) < _MIN_PLAIN_TEXT_BYTES or not _PLAIN_TEXT_BYTES.issuperset(decoded):
        return None
    return decoded.decode("ascii")


def decoded_plain_text(token: str) -> str | None:
    """The printable ASCII text a base64 token encodes, or None.

    Random bytes decode to printable ASCII with probability 0.37 per byte,
    so twelve or more printable bytes mean the token encodes text and its
    entropy comes from the encoding. A long token may be the continuation of
    a literal split across lines; it then starts inside a 4-character group,
    so the three other alignments are tried as well."""
    if not _BASE64_TOKEN_RE.fullmatch(token):
        return None
    body = token.rstrip("=").translate(_BASE64_URL_TO_STANDARD)
    offsets = (0,)
    if len(body) >= _MIN_CONTINUATION_LENGTH:
        offsets = (0, 1, 2, 3)
    for offset in offsets:
        text = _decode_plain_text(body[offset:])
        if text is not None:
            return text
    return None


def is_user_password_pair(text: str) -> bool:
    """``user:password``: the payload of an HTTP Basic credential."""
    return bool(_USER_PASSWORD_PAIR_RE.fullmatch(text.strip()))


_CLASS_ATTRIBUTE_RE = re.compile(
    r"""(?<![A-Za-z0-9_-])class(?:Name)?\s*=\s*(?P<q>["'])(?P<names>[^"'<>{}$]*)(?P=q)"""
)


def in_class_attribute(line: str, start: int, end: int) -> bool:
    """One of the names in an HTML/JSX ``class="..."`` attribute: a CSS
    class, whose hash suffix is a build artifact."""
    return any(
        match.start("names") <= start and end <= match.end("names")
        for match in _CLASS_ATTRIBUTE_RE.finditer(line)
    )


# ---------------------------------------------------------------------------
# URLs and file paths
# ---------------------------------------------------------------------------

_URI_RE = re.compile(
    r"(?:(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,30}://"
    r"|(?<=[\"'`])//(?=[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:[/?#:\"'`]|$)))"
    r"[^\s'\"`<>]+"
)
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


def _authority_start(uri: str) -> int:
    if uri.startswith("//"):
        return 2
    return uri.index("://") + 3


def is_public_url_value(value: str) -> bool:
    """The whole value is a URL (``scheme://`` or scheme-relative ``//host``)
    with no user info and no secret-named query or fragment parameter."""
    text = value.strip()
    if _URI_RE.fullmatch('"' + text, 1) is None:
        return False
    authority_start = _authority_start(text)
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
    authority_start = _authority_start(uri)
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


# A line that stands for omitted key data: ``...``, ``…``, ``[...]``,
# ``<snip>``. A PEM body with one is an excerpt, not a usable key.
_ELIDED_BODY_LINE_RE = re.compile(
    r"^(?:\.{3,}|…+|\[\s*(?:\.{3,}|…|snip|truncated)\s*\]"
    r"|<\s*(?:\.{3,}|…|snip|truncated)\s*>)$",
    re.IGNORECASE,
)
_PEM_BODY_SPLIT_RE = re.compile(r"\\[nr]|\n")
_PEM_BODY_STRIP = " \t\r'\"`+,;"
_MAX_PEM_BODY_LINES = 80


def private_key_body_is_elided(
    line: str, header_end: int, following: list[str]
) -> bool:
    """The key body after a ``-----BEGIN ... PRIVATE KEY-----`` header, up to
    its ``-----END`` line, contains an elision line such as ``...``."""
    segments = _PEM_BODY_SPLIT_RE.split(line[header_end:])
    for text in following[:_MAX_PEM_BODY_LINES]:
        segments.extend(_PEM_BODY_SPLIT_RE.split(text))
    for segment in segments[: _MAX_PEM_BODY_LINES * 2]:
        body = segment.strip(_PEM_BODY_STRIP)
        if body.startswith("-----END"):
            return False
        if _ELIDED_BODY_LINE_RE.match(body):
            return True
    return False


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
