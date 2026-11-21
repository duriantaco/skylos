"""Which data files are translation (message) catalogs.

A catalog holds the text an application shows its users, one file per
language: ``locales/en.json``, ``i18n/fa_IR.json``, ``config/locales/de.yml``,
``public/locales/pt-BR/common.json``, ``l10n/app_en.arb``. Its values are
written for readers in every script, so keys that mention a password or a
token label text about the credential, and the invisible characters some
scripts need (ZWNJ in Persian, a word break in Khmer) are spelling.

The file is judged by its path alone: a JSON, YAML or ARB file inside a
localisation folder named for a language, or named for a language and
region (``pt_BR.json``) anywhere. Callers use it only to read values as
text; a random token or a provider credential in a catalog stays reported.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import PurePosixPath

CATALOG_SUFFIXES = frozenset({".json", ".yml", ".yaml", ".arb"})

LOCALE_DIRECTORIES = frozenset(
    {
        "i18n",
        "l10n",
        "intl",
        "lang",
        "langs",
        "language",
        "languages",
        "locale",
        "locales",
        "localization",
        "localizations",
        "localisation",
        "localisations",
        "nls",
        "translation",
        "translations",
    }
)

# ISO 639-1 language codes.
_ISO_639_1 = frozenset(
    {
        "aa",
        "ab",
        "ae",
        "af",
        "ak",
        "am",
        "an",
        "ar",
        "as",
        "av",
        "ay",
        "az",
        "ba",
        "be",
        "bg",
        "bh",
        "bi",
        "bm",
        "bn",
        "bo",
        "br",
        "bs",
        "ca",
        "ce",
        "ch",
        "co",
        "cr",
        "cs",
        "cu",
        "cv",
        "cy",
        "da",
        "de",
        "dv",
        "dz",
        "ee",
        "el",
        "en",
        "eo",
        "es",
        "et",
        "eu",
        "fa",
        "ff",
        "fi",
        "fj",
        "fo",
        "fr",
        "fy",
        "ga",
        "gd",
        "gl",
        "gn",
        "gu",
        "gv",
        "ha",
        "he",
        "hi",
        "ho",
        "hr",
        "ht",
        "hu",
        "hy",
        "hz",
        "ia",
        "id",
        "ie",
        "ig",
        "ii",
        "ik",
        "io",
        "is",
        "it",
        "iu",
        "ja",
        "jv",
        "ka",
        "kg",
        "ki",
        "kj",
        "kk",
        "kl",
        "km",
        "kn",
        "ko",
        "kr",
        "ks",
        "ku",
        "kv",
        "kw",
        "ky",
        "la",
        "lb",
        "lg",
        "li",
        "ln",
        "lo",
        "lt",
        "lu",
        "lv",
        "mg",
        "mh",
        "mi",
        "mk",
        "ml",
        "mn",
        "mr",
        "ms",
        "mt",
        "my",
        "na",
        "nb",
        "nd",
        "ne",
        "ng",
        "nl",
        "nn",
        "no",
        "nr",
        "nv",
        "ny",
        "oc",
        "oj",
        "om",
        "or",
        "os",
        "pa",
        "pi",
        "pl",
        "ps",
        "pt",
        "qu",
        "rm",
        "rn",
        "ro",
        "ru",
        "rw",
        "sa",
        "sc",
        "sd",
        "se",
        "sg",
        "si",
        "sk",
        "sl",
        "sm",
        "sn",
        "so",
        "sq",
        "sr",
        "ss",
        "st",
        "su",
        "sv",
        "sw",
        "ta",
        "te",
        "tg",
        "th",
        "ti",
        "tk",
        "tl",
        "tn",
        "to",
        "tr",
        "ts",
        "tt",
        "tw",
        "ty",
        "ug",
        "uk",
        "ur",
        "uz",
        "ve",
        "vi",
        "vo",
        "wa",
        "wo",
        "xh",
        "yi",
        "yo",
        "za",
        "zh",
        "zu",
    }
)

# en, en-US, zh_Hans, zh-Hant-TW, es-419, tlh_AA: a language, an optional
# script and an optional region.
_LOCALE_TAG_RE = re.compile(
    r"(?P<language>[a-z]{2,3})(?:[-_](?P<script>[a-z]{4}))?"
    r"(?:[-_](?P<region>[a-z]{2}|[0-9]{3}))?"
)
# ``devise.en``, ``app_en``, ``messages-pt-br``: a namespace, then the tag.
_SUFFIXED_TAG_RE = re.compile(r".+?[._-](?P<tag>[a-z]{2,3}(?:[-_][a-z0-9]{2,4}){0,2})")


def _is_locale_tag(text: str, *, regional_only: bool = False) -> bool:
    match = _LOCALE_TAG_RE.fullmatch(text)
    if match is None:
        return False
    language = match.group("language")
    regional = match.group("region") is not None
    if regional_only:
        # Outside a localisation folder only ``pt_BR``-shaped names count:
        # ``id.json`` or ``it.yml`` alone could be anything.
        return language in _ISO_639_1 and regional
    # A three-letter code (``tlh_AA``, ``fil_PH``) needs its region, so that
    # ``app`` or ``src`` is not read as a language.
    return language in _ISO_639_1 or (len(language) == 3 and regional)


def _names_a_locale(stem: str) -> bool:
    if _is_locale_tag(stem):
        return True
    match = _SUFFIXED_TAG_RE.fullmatch(stem)
    return match is not None and _is_locale_tag(match.group("tag"))


@lru_cache(maxsize=4096)
def is_message_catalog_path(path: str) -> bool:
    """Whether ``path`` (relative to the scan root) is a translation catalog."""
    if not path:
        return False
    posix = PurePosixPath(str(path).replace("\\", "/").lower())
    if posix.suffix not in CATALOG_SUFFIXES:
        return False
    stem = posix.name[: -len(posix.suffix)]
    folders = posix.parts[:-1]
    if any(folder in LOCALE_DIRECTORIES for folder in folders):
        return _names_a_locale(stem) or any(
            _is_locale_tag(folder) for folder in folders
        )
    return _is_locale_tag(stem, regional_only=True)
