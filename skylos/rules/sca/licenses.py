"""Dependency license collection, SPDX normalization, and license policy.

License data is collected offline by default from evidence Skylos can read
without executing anything:

* npm: ``package-lock.json`` / ``npm-shrinkwrap.json`` v2/v3 ``packages``
  entries, then an installed ``node_modules/<pkg>/package.json`` whose name
  and version match the locked identity exactly.
* PyPI: installed distribution metadata (``License-Expression``, then
  ``License``, then trove classifiers) from a project-local ``.venv``/``venv``
  or the running interpreter, only when name *and* version match exactly.
* Go (and anything else): no offline source, so the license stays
  ``NOASSERTION``.

Normalization never guesses. A value is mapped to an SPDX identifier or
expression only when it is an SPDX identifier/expression already or appears
in a small table of unambiguous variants ("MIT License" -> MIT, "Apache 2.0"
-> Apache-2.0). Ambiguous values ("BSD", "GPLv3", "Apache Software License")
become ``NOASSERTION``.

Network lookups (deps.dev) happen only when a caller passes ``lookup=True``.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote

from skylos.core.safe_cache_io import read_project_text_no_symlink

NOASSERTION = "NOASSERTION"
LICENSE_RULE_ID = "SKY-SCA-LIC001"
DEFAULT_LICENSE_SEVERITY = "HIGH"
_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

MAX_LOCKFILE_BYTES = 10_000_000
MAX_PACKAGE_JSON_BYTES = 1_000_000
MAX_RAW_LICENSE_CHARS = 200
MAX_EXPRESSION_CHARS = 512
LOOKUP_TIMEOUT_SECONDS = 5.0
LOOKUP_DEADLINE_SECONDS = 60.0
MAX_LOOKUPS = 1_000
MAX_LOOKUP_RESPONSE_BYTES = 2_000_000
DEPS_DEV_URL = (
    "https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{version}"
)
_DEPS_DEV_SYSTEMS = {"npm": "npm", "PyPI": "pypi", "Go": "go"}
_NPM_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json"}

# Common SPDX license list identifiers (canonical case). Identifiers outside
# this list are not accepted from free text; LicenseRef-* is accepted as-is.
_SPDX_IDS = """
0BSD AAL AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 AGPL-1.0-only
AGPL-1.0-or-later AGPL-3.0-only AGPL-3.0-or-later Apache-1.0 Apache-1.1
Apache-2.0 APSL-2.0 Artistic-1.0 Artistic-1.0-Perl Artistic-2.0 BlueOak-1.0.0
BSD-1-Clause BSD-2-Clause BSD-2-Clause-Patent BSD-3-Clause BSD-3-Clause-Clear
BSD-3-Clause-LBNL BSD-4-Clause BSL-1.0 BUSL-1.1 bzip2-1.0.6 CAL-1.0 CC-BY-3.0
CC-BY-4.0 CC-BY-NC-4.0 CC-BY-NC-SA-4.0 CC-BY-ND-4.0 CC-BY-SA-3.0 CC-BY-SA-4.0
CC-PDDC CC0-1.0 CDDL-1.0 CDDL-1.1 CECILL-2.1 CPAL-1.0 CPL-1.0 curl ECL-2.0
EFL-2.0 Elastic-2.0 EPL-1.0 EPL-2.0 EUPL-1.1 EUPL-1.2 FSFAP FTL
GFDL-1.3-only GFDL-1.3-or-later GPL-1.0-only GPL-1.0-or-later GPL-2.0-only
GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later Hippocratic-2.1 HPND ICU IJG
ImageMagick Intel IPA IPL-1.0 ISC JSON LGPL-2.0-only LGPL-2.0-or-later
LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later Libpng
libpng-2.0 LPL-1.02 LPPL-1.3c MirOS MIT MIT-0 MIT-CMU MIT-Modern-Variant
MPL-1.0 MPL-1.1 MPL-2.0 MPL-2.0-no-copyleft-exception MS-PL MS-RL MulanPSL-2.0
NCSA Nokia NPOSL-3.0 NTP OFL-1.0 OFL-1.1 OGL-UK-3.0 OLDAP-2.8 OpenSSL OSL-1.0
OSL-2.0 OSL-2.1 OSL-3.0 PHP-3.0 PHP-3.01 PostgreSQL PSF-2.0 Python-2.0
Python-2.0.1 QPL-1.0 Ruby SGI-B-2.0 SISSL SPL-1.0 SSPL-1.0 TCL UCL-1.0
Unicode-3.0 Unicode-DFS-2015 Unicode-DFS-2016 Unlicense UPL-1.0 Vim W3C
W3C-20150513 WTFPL X11 XFree86-1.1 Xnet Zlib zlib-acknowledgement ZPL-1.1
ZPL-2.0 ZPL-2.1
"""
_SPDX_EXCEPTIONS = """
Autoconf-exception-3.0 Bison-exception-2.2 Bootloader-exception
Classpath-exception-2.0 FLTK-exception GCC-exception-2.0 GCC-exception-3.1
LLVM-exception OCaml-LGPL-linking-exception Qt-GPL-exception-1.0
Qt-LGPL-exception-1.1 Universal-FOSS-exception-1.0 WxWindows-exception-3.1
"""
_CANONICAL_IDS = {item.lower(): item for item in _SPDX_IDS.split()}
_CANONICAL_EXCEPTIONS = {item.lower(): item for item in _SPDX_EXCEPTIONS.split()}

# Deprecated SPDX identifiers with an exact current equivalent.
_DEPRECATED_IDS = {
    "gpl-1.0": "GPL-1.0-only",
    "gpl-1.0+": "GPL-1.0-or-later",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0+": "GPL-3.0-or-later",
    "lgpl-2.0": "LGPL-2.0-only",
    "lgpl-2.0+": "LGPL-2.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0+": "LGPL-3.0-or-later",
    "agpl-1.0": "AGPL-1.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "gfdl-1.3": "GFDL-1.3-only",
}

# Unambiguous free-text variants seen in package metadata. Keys are compared
# after lowercasing and collapsing whitespace. Anything version-ambiguous
# ("BSD", "GPLv3", "Apache Software License") is deliberately absent.
_ALIASES = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit licence": "MIT",
    "mit-license": "MIT",
    "expat": "MIT",
    "mit no attribution": "MIT-0",
    "apache 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache v2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license v2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "apache software license, version 2.0": "Apache-2.0",
    "apache-2.0 license": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "bsd-2": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 2 clause": "BSD-2-Clause",
    "2-clause bsd": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "freebsd": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd 3 clause": "BSD-3-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    "revised bsd": "BSD-3-Clause",
    "isc license": "ISC",
    "iscl": "ISC",
    "mpl 2.0": "MPL-2.0",
    "mpl-2": "MPL-2.0",
    "mpl2": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "eclipse public license 2.0": "EPL-2.0",
    "epl 2.0": "EPL-2.0",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0 1.0": "CC0-1.0",
    "cc0 1.0 universal": "CC0-1.0",
    "boost software license 1.0": "BSL-1.0",
    "gplv2+": "GPL-2.0-or-later",
    "gplv3+": "GPL-3.0-or-later",
    "lgplv2+": "LGPL-2.0-or-later",
    "lgplv3+": "LGPL-3.0-or-later",
    "agplv3+": "AGPL-3.0-or-later",
    "gnu gpl v3 or later": "GPL-3.0-or-later",
    "gnu gpl v2 or later": "GPL-2.0-or-later",
    "gnu lgpl v3 or later": "LGPL-3.0-or-later",
    "python software foundation license 2.0": "PSF-2.0",
    "zlib license": "Zlib",
    "zlib/libpng": "Zlib",
    "wtfpl license": "WTFPL",
    "0-clause bsd": "0BSD",
}

# Trove classifier tails ("License :: OSI Approved :: <tail>").
_CLASSIFIERS = {
    "mit license": "MIT",
    "mit no attribution license (mit-0)": "MIT-0",
    "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mozilla public license 1.1 (mpl 1.1)": "MPL-1.1",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "the unlicense (unlicense)": "Unlicense",
    "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
    "boost software license 1.0 (bsl-1.0)": "BSL-1.0",
    "eclipse public license 2.0 (epl-2.0)": "EPL-2.0",
    "eclipse public license 1.0 (epl-1.0)": "EPL-1.0",
    "european union public licence 1.2 (eupl 1.2)": "EUPL-1.2",
    "universal permissive license (upl)": "UPL-1.0",
    "zero-clause bsd (0bsd)": "0BSD",
    "blue oak model license (blueoak-1.0.0)": "BlueOak-1.0.0",
    "apache software license 2.0": "Apache-2.0",
}

_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")
_LICENSE_REF_RE = re.compile(
    r"(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+\Z"
)


def _clean(value: str) -> str:
    return " ".join(value.strip().split())


def _license_id(token: str) -> str | None:
    lowered = token.lower()
    if lowered in _DEPRECATED_IDS:
        return _DEPRECATED_IDS[lowered]
    if lowered in _CANONICAL_IDS:
        return _CANONICAL_IDS[lowered]
    if _LICENSE_REF_RE.fullmatch(token):
        return token
    if lowered.endswith("+") and lowered[:-1] in _CANONICAL_IDS:
        base = _CANONICAL_IDS[lowered[:-1]]
        if base.endswith(("-only", "-or-later")):
            return None
        return base + "+"
    return None


def _parse_expression(text: str) -> str | None:
    """Validate an SPDX license expression built from known identifiers."""
    tokens = _TOKEN_RE.findall(text)
    if not tokens or len(text) > MAX_EXPRESSION_CHARS:
        return None
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def advance():
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def primary():
        token = peek()
        if token is None:
            raise ValueError
        if token == "(":
            advance()
            inner = disjunction()
            if peek() != ")":
                raise ValueError
            advance()
            return f"({inner})" if " " in inner else inner
        if token == ")" or token.upper() in {"AND", "OR", "WITH"}:
            raise ValueError
        identifier = _license_id(advance())
        if identifier is None:
            raise ValueError
        if (peek() or "").upper() == "WITH":
            advance()
            exception = _CANONICAL_EXCEPTIONS.get((peek() or "").lower())
            if exception is None:
                raise ValueError
            advance()
            return f"{identifier} WITH {exception}"
        return identifier

    def conjunction():
        parts = [primary()]
        while (peek() or "").upper() == "AND":
            advance()
            parts.append(primary())
        return " AND ".join(parts)

    def disjunction():
        parts = [conjunction()]
        while (peek() or "").upper() == "OR":
            advance()
            parts.append(conjunction())
        return " OR ".join(parts)

    try:
        result = disjunction()
    except (ValueError, IndexError):
        return None
    if position != len(tokens):
        return None
    if result.startswith("(") and result.endswith(")") and _balanced(result[1:-1]):
        result = result[1:-1]
    return result


def _balanced(text: str) -> bool:
    depth = 0
    for char in text:
        depth += char == "("
        depth -= char == ")"
        if depth < 0:
            return False
    return depth == 0


def normalize_license(value: object) -> str | None:
    """Return an SPDX identifier/expression, or None when not provable."""
    if isinstance(value, dict):
        # Legacy npm: {"type": "MIT", "url": "..."}
        return normalize_license(value.get("type"))
    if isinstance(value, (list, tuple)):
        # Legacy npm "licenses" arrays mean a choice (npm docs: use OR).
        items = [normalize_license(item) for item in value]
        if not items or any(item is None for item in items):
            return None
        unique = list(dict.fromkeys(items))
        if len(unique) == 1:
            return unique[0]
        return " OR ".join(f"({item})" if " " in item else item for item in unique)
    if not isinstance(value, str):
        return None
    text = _clean(value)
    if not text or len(text) > MAX_EXPRESSION_CHARS:
        return None
    lowered = text.lower()
    if lowered in _ALIASES:
        return _ALIASES[lowered]
    if lowered.startswith("license :: "):
        return normalize_classifier(text)
    return _parse_expression(text)


def normalize_classifier(value: str) -> str | None:
    """Map a trove ``License ::`` classifier to SPDX only when unambiguous."""
    if not isinstance(value, str):
        return None
    parts = [part.strip() for part in value.split("::")]
    if len(parts) < 2 or parts[0].lower() != "license":
        return None
    tail = parts[-1].lower()
    return _CLASSIFIERS.get(tail)


def license_ids(expression: str) -> list[str]:
    """License terms of a normalized expression (``X WITH Y`` stays one term)."""
    tokens = _TOKEN_RE.findall(expression or "")
    terms = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"(", ")"} or token in {"AND", "OR"}:
            index += 1
            continue
        if index + 2 < len(tokens) and tokens[index + 1] == "WITH":
            terms.append(f"{token} WITH {tokens[index + 2]}")
            index += 3
            continue
        terms.append(token)
        index += 1
    return terms


def _raw(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = _clean(value)
    else:
        try:
            text = json.dumps(value, sort_keys=True, ensure_ascii=True)
        except (TypeError, ValueError):
            return None
    return text[:MAX_RAW_LICENSE_CHARS] if text else None


def _record(value: object, source: str) -> dict:
    expression = normalize_license(value)
    return {
        "license": expression or NOASSERTION,
        "source": source if expression else "unrecognized:" + source,
        "declared": _raw(value),
    }


def identity_key(dependency: dict) -> tuple[str, str, str]:
    return (dependency["ecosystem"], dependency["name"], str(dependency["version"]))


# --------------------------------------------------------------------------- npm


def _read_json(root: Path, path: Path, max_bytes: int) -> object | None:
    text = read_project_text_no_symlink(root, path, max_bytes=max_bytes)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _npm_license_value(entry: dict) -> object | None:
    if "license" in entry:
        return entry["license"]
    if "licenses" in entry:
        return entry["licenses"]
    return None


def _npm_installed_candidates(dependency: dict) -> list[Path]:
    candidates = []
    for occurrence in dependency.get("dependency_occurrences", [dependency]):
        file = occurrence.get("file")
        if not isinstance(file, str):
            continue
        base = Path(file).parent
        package_path = occurrence.get("package_path")
        if (
            Path(file).name in _NPM_LOCKFILES
            and isinstance(package_path, str)
            and package_path.startswith("node_modules/")
        ):
            candidates.append(base / package_path / "package.json")
        candidates.append(base / "node_modules" / dependency["name"] / "package.json")
    return list(dict.fromkeys(candidates))


def _collect_npm(dependency: dict, root: Path, lock_cache: dict) -> dict | None:
    fallback = None
    for occurrence in dependency.get("dependency_occurrences", [dependency]):
        file = occurrence.get("file")
        package_path = occurrence.get("package_path")
        if (
            not isinstance(file, str)
            or Path(file).name not in _NPM_LOCKFILES
            or not isinstance(package_path, str)
        ):
            continue
        if file not in lock_cache:
            lock_cache[file] = _read_json(root, Path(file), MAX_LOCKFILE_BYTES)
        data = lock_cache[file]
        packages = data.get("packages") if isinstance(data, dict) else None
        entry = packages.get(package_path) if isinstance(packages, dict) else None
        if isinstance(entry, dict):
            value = _npm_license_value(entry)
            if value is not None:
                record = _record(value, Path(file).name)
                if record["license"] != NOASSERTION:
                    return record
                fallback = fallback or record
    for candidate in _npm_installed_candidates(dependency):
        data = _read_json(root, candidate, MAX_PACKAGE_JSON_BYTES)
        if (
            isinstance(data, dict)
            and data.get("name") == dependency["name"]
            and data.get("version") == dependency["version"]
        ):
            value = _npm_license_value(data)
            if value is not None:
                record = _record(value, "node_modules/package.json")
                if record["license"] != NOASSERTION:
                    return record
                fallback = fallback or record
    return fallback


# ------------------------------------------------------------------------ PyPI


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _same_version(left: str, right: str) -> bool:
    if left.lower() == right.lower():
        return True
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return False
    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return False


def _project_site_packages(root: Path) -> list[Path]:
    paths = []
    for venv in (".venv", "venv"):
        base = root / venv
        try:
            if base.is_symlink() or not base.is_dir():
                continue
        except OSError:
            continue
        for pattern in ("lib/python*/site-packages", "Lib/site-packages"):
            for candidate in sorted(base.glob(pattern)):
                try:
                    resolved = candidate.resolve(strict=True)
                    resolved.relative_to(root.resolve())
                except (OSError, ValueError):
                    continue
                if candidate.is_dir():
                    paths.append(candidate)
    return paths


class _PythonMetadataIndex:
    """Lazy {normalized name: [Distribution]} index over matching environments."""

    def __init__(self, root: Path):
        self._root = root
        self._index: dict[str, list] | None = None

    def _build(self) -> dict[str, list]:
        from importlib import metadata

        index: dict[str, list] = {}
        sources = [
            metadata.distributions(path=[str(p)])
            for p in _project_site_packages(self._root)
        ]
        sources.append(metadata.distributions(path=list(sys.path)))
        for source in sources:
            try:
                for dist in source:
                    try:
                        name = dist.metadata.get("Name")
                    except Exception:
                        continue
                    if isinstance(name, str) and name:
                        index.setdefault(_pep503(name), []).append(dist)
            except Exception:
                continue
        return index

    def find(self, name: str, version: str):
        if self._index is None:
            self._index = self._build()
        for dist in self._index.get(_pep503(name), []):
            try:
                if _same_version(str(dist.version), version):
                    return dist
            except Exception:
                continue
        return None


def python_metadata_license(meta) -> dict | None:
    """License from core metadata: License-Expression > License > classifiers."""
    expression = meta.get("License-Expression")
    if expression:
        record = _record(expression, "python-metadata:License-Expression")
        if record["license"] != NOASSERTION:
            return record
    license_field = meta.get("License")
    if license_field and len(license_field) <= MAX_EXPRESSION_CHARS:
        record = _record(license_field, "python-metadata:License")
        if record["license"] != NOASSERTION:
            return record
    classifiers = [
        item
        for item in (meta.get_all("Classifier") or [])
        if isinstance(item, str) and item.lower().startswith("license ::")
    ]
    mapped = {normalize_classifier(item) for item in classifiers}
    if classifiers and None not in mapped and len(mapped) == 1:
        return {
            "license": mapped.pop(),
            "source": "python-metadata:Classifier",
            "declared": _raw(classifiers[0]),
        }
    declared = expression or license_field or (classifiers[0] if classifiers else None)
    if declared:
        return {
            "license": NOASSERTION,
            "source": "unrecognized:python-metadata",
            "declared": _raw(declared),
        }
    return None


def _collect_pypi(dependency: dict, index: _PythonMetadataIndex) -> dict | None:
    dist = index.find(dependency["name"], str(dependency["version"]))
    if dist is None:
        return None
    try:
        return python_metadata_license(dist.metadata)
    except Exception:
        return None


# ---------------------------------------------------------------------- network


def _deps_dev_lookup(dependency: dict, timeout: float) -> dict | None:
    import urllib.request

    system = _DEPS_DEV_SYSTEMS.get(dependency["ecosystem"])
    if system is None:
        return None
    version = str(dependency["version"])
    if system == "go":
        version = "v" + version.removeprefix("v")
    url = DEPS_DEV_URL.format(
        system=system,
        name=quote(dependency["name"], safe=""),
        version=quote(version, safe=""),
    )
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    # Fixed https host; name and version are percent-encoded path segments.
    with urllib.request.urlopen(  # skylos: ignore[SKY-D216] fixed deps.dev host
        request, timeout=timeout
    ) as response:
        body = response.read(MAX_LOOKUP_RESPONSE_BYTES + 1)
    if len(body) > MAX_LOOKUP_RESPONSE_BYTES:
        return None
    data = json.loads(body.decode("utf-8"))
    licenses = data.get("licenses") if isinstance(data, dict) else None
    if not isinstance(licenses, list) or not licenses:
        return None
    normalized = {normalize_license(item) for item in licenses}
    if None in normalized or len(normalized) != 1:
        return {
            "license": NOASSERTION,
            "source": "unrecognized:deps.dev",
            "declared": _raw(licenses),
        }
    return {
        "license": normalized.pop(),
        "source": "deps.dev",
        "declared": _raw(licenses),
    }


# ----------------------------------------------------------------------- public


class LicenseInventory(dict):
    """{(ecosystem, name, version): record} plus a collection receipt."""

    def __init__(self, records=(), *, receipt=None):
        super().__init__(records)
        self.receipt = dict(receipt or {})

    def get_record(self, dependency: dict) -> dict:
        return self.get(identity_key(dependency)) or {
            "license": NOASSERTION,
            "source": "none",
            "declared": None,
        }


def _collect_offline(inventory, root: Path) -> dict:
    lock_cache: dict = {}
    python_index = _PythonMetadataIndex(root)
    records: dict = {}
    for dependency in inventory:
        key = identity_key(dependency)
        if key in records:
            continue
        record = None
        try:
            if dependency["ecosystem"] == "npm":
                record = _collect_npm(dependency, root, lock_cache)
            elif dependency["ecosystem"] == "PyPI":
                record = _collect_pypi(dependency, python_index)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            record = None  # unreadable metadata is unknown, not an error
        if record is not None:
            records[key] = record
    return records


def _lookup_missing(
    inventory, records: dict, fetch, timeout: float, deadline: float
) -> dict:
    """Fill NOASSERTION records from the network. Bounded by count and time."""
    started = time.monotonic()
    attempted = errors = 0
    receipt: dict = {"enabled": True, "provider": "deps.dev"}
    candidates = {
        identity_key(dependency): dependency
        for dependency in inventory
        if dependency["ecosystem"] in _DEPS_DEV_SYSTEMS
    }
    for key, dependency in sorted(candidates.items()):
        existing = records.get(key)
        if existing and existing["license"] != NOASSERTION:
            continue
        if attempted >= MAX_LOOKUPS or time.monotonic() - started > deadline:
            receipt["truncated"] = True
            break
        attempted += 1
        try:
            record = fetch(dependency, timeout)
        except Exception:  # network/parse failure: the license stays unknown
            errors += 1
            continue
        if record is not None and (
            existing is None or record["license"] != NOASSERTION
        ):
            records[key] = record
    receipt.update({"attempted": attempted, "errors": errors})
    return receipt


def _collection_receipt(inventory, records: dict, lookup_receipt: dict) -> dict:
    identities = {identity_key(item) for item in inventory}
    sources: dict[str, int] = {}
    known = 0
    for key in identities:
        record = records.get(key, {})
        known += record.get("license", NOASSERTION) != NOASSERTION
        source = record.get("source", "none")
        sources[source] = sources.get(source, 0) + 1
    return {
        "mode": "offline+lookup" if lookup_receipt["enabled"] else "offline",
        "package_count": len(identities),
        "declared_count": known,
        "noassertion_count": len(identities) - known,
        "sources": dict(sorted(sources.items())),
        "lookup": lookup_receipt,
    }


def collect_licenses(
    inventory,
    root: Path,
    *,
    lookup: bool = False,
    timeout: float = LOOKUP_TIMEOUT_SECONDS,
    deadline: float = LOOKUP_DEADLINE_SECONDS,
    fetch=None,
) -> LicenseInventory:
    """Collect declared licenses for inventory identities. Offline unless lookup."""
    records = _collect_offline(inventory, Path(root).resolve())
    lookup_receipt = (
        _lookup_missing(
            inventory, records, fetch or _deps_dev_lookup, timeout, deadline
        )
        if lookup
        else {"enabled": False}
    )
    return LicenseInventory(
        records, receipt=_collection_receipt(inventory, records, lookup_receipt)
    )


# ----------------------------------------------------------------------- policy


def _patterns(values) -> list[str]:
    patterns = []
    for value in values or []:
        if not isinstance(value, str) or not value.strip():
            continue
        text = value.strip()
        if any(char in text for char in "*?["):
            patterns.append(text)
            continue
        normalized = normalize_license(text)
        patterns.append(normalized or text)
    return patterns


def _matches(term: str, patterns: list[str]) -> bool:
    base = term.split(" WITH ", 1)[0]
    for pattern in patterns:
        lowered = pattern.lower()
        for candidate in (term, base):
            if fnmatch.fnmatchcase(candidate.lower(), lowered):
                return True
    return False


def _term_permitted(term: str, deny: list[str], allow: list[str]) -> bool:
    if _matches(term, deny):
        return False
    if allow and not _matches(term, allow):
        return False
    return True


def _satisfiable(expression: str, deny: list[str], allow: list[str]) -> bool:
    """True when some choice under the expression uses only permitted terms."""
    tokens = _TOKEN_RE.findall(expression)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def primary():
        nonlocal position
        token = tokens[position]
        position += 1
        if token == "(":
            value = disjunction()
            position += 1  # ")"
            return value
        if peek() == "WITH":
            position += 2
            return _term_permitted(f"{token} WITH {tokens[position - 1]}", deny, allow)
        return _term_permitted(token, deny, allow)

    def conjunction():
        nonlocal position
        value = primary()
        while peek() == "AND":
            position += 1
            value = primary() and value
        return value

    def disjunction():
        nonlocal position
        value = conjunction()
        while peek() == "OR":
            position += 1
            value = conjunction() or value
        return value

    return disjunction()


def _severity(value) -> str:
    if isinstance(value, str) and value.strip().upper() in _SEVERITIES:
        return value.strip().upper()
    return DEFAULT_LICENSE_SEVERITY


def license_policy_configured(config: dict | None) -> bool:
    config = config or {}
    return bool(
        _patterns(config.get("license_deny")) or _patterns(config.get("license_allow"))
    )


def _excepted(dependency: dict, exceptions) -> bool:
    name = dependency["name"]
    version = str(dependency["version"])
    for item in exceptions or []:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if dependency["ecosystem"] == "PyPI":
            left, _, right = text.partition("@")
            if _pep503(left) == _pep503(name) and (
                not right or _same_version(right, version)
            ):
                return True
            continue
        if text == name or text == f"{name}@{version}":
            return True
    return False


def _inline_ignored(dependency: dict, root: Path, cache: dict) -> bool:
    """``# skylos: ignore[SKY-SCA-LIC001]`` on any line declaring the package."""
    from skylos.analysis.finding_filter import finding_is_inline_ignored
    from skylos.config import get_skylos_ignore_lines, get_skylos_ignore_rules_by_line

    for occurrence in dependency.get("dependency_occurrences", [dependency]):
        file = occurrence.get("file")
        if not isinstance(file, str):
            continue
        if file not in cache:
            text = read_project_text_no_symlink(
                root, Path(file), max_bytes=MAX_LOCKFILE_BYTES, errors="ignore"
            )
            cache[file] = (
                (get_skylos_ignore_lines(text), get_skylos_ignore_rules_by_line(text))
                if text
                else (set(), {})
            )
        lines, rules = cache[file]
        probe = {"rule_id": LICENSE_RULE_ID, "line": occurrence.get("line", 1)}
        if finding_is_inline_ignored(probe, lines, rules):
            return True
    return False


def _license_finding(
    dependency: dict, record: dict, deny: list[str], allow: list[str], severity: str
) -> dict:
    expression = record["license"]
    terms = license_ids(expression)
    denied = list(dict.fromkeys(term for term in terms if _matches(term, deny)))
    not_allowed = list(
        dict.fromkeys(term for term in terms if allow and not _matches(term, allow))
    )
    reason = (
        f"denied by license_deny ({', '.join(denied)})"
        if denied
        else f"not in license_allow ({', '.join(not_allowed)})"
    )
    name, version = dependency["name"], dependency["version"]
    metadata = {
        "ecosystem": dependency["ecosystem"],
        "package_name": name,
        "package_version": version,
        "license": expression,
        "license_source": record["source"],
        "license_declared": record.get("declared"),
        "denied_licenses": sorted(denied),
        "disallowed_licenses": sorted(not_allowed),
        "policy": "deny" if denied else "allow",
    }
    if "dependency_occurrences" in dependency:
        metadata["dependency_occurrences"] = dependency["dependency_occurrences"]
    line = dependency.get("line", 1)
    return {
        "rule_id": LICENSE_RULE_ID,
        "category": "DEPENDENCY",
        "severity": severity,
        "message": f"{name}@{version}: license {expression} is {reason}.",
        "file": dependency["file"],
        "file_path": dependency["file"],
        "line": line,
        "line_number": line,
        "snippet": dependency.get("snippet", ""),
        "symbol": f"{name}@{version}",
        "metadata": metadata,
    }


def evaluate_license_policy(
    inventory,
    licenses: LicenseInventory,
    config: dict | None,
    root: Path,
    *,
    project_ignore=None,
    suppressed: list | None = None,
) -> list[dict]:
    """Findings for dependencies whose declared license violates the policy.

    NOASSERTION never produces a finding: an unknown license is reported in the
    SBOM, not guessed into a violation.
    """
    config = config or {}
    deny = _patterns(config.get("license_deny"))
    allow = _patterns(config.get("license_allow"))
    ignored = {str(item).upper() for item in (project_ignore or ())}
    if (not deny and not allow) or LICENSE_RULE_ID in ignored:
        return []
    severity = _severity(config.get("license_severity"))
    exceptions = config.get("license_exceptions") or []
    root = Path(root).resolve()
    ignore_cache: dict = {}
    findings = []
    seen = set()
    for dependency in inventory:
        key = identity_key(dependency)
        record = licenses.get_record(dependency)
        if (
            key in seen
            or record["license"] == NOASSERTION
            or _satisfiable(record["license"], deny, allow)
            or _excepted(dependency, exceptions)
        ):
            continue
        seen.add(key)
        finding = _license_finding(dependency, record, deny, allow, severity)
        if not _inline_ignored(dependency, root, ignore_cache):
            findings.append(finding)
        elif suppressed is not None:
            suppressed.append(
                {**finding, "category": "dependency", "reason": "inline ignore comment"}
            )
    return findings


def scan_license_policy(
    root: Path, config: dict | None, *, project_ignore=None, suppressed=None
) -> list[dict]:
    """Offline license-policy scan used by ``-a`` / ``--sca`` runs."""
    if not license_policy_configured(config):
        return []
    from skylos.rules.sca.vulnerability_scanner import collect_dependencies

    inventory = collect_dependencies(Path(root))
    licenses = collect_licenses(inventory, Path(root))
    return evaluate_license_policy(
        inventory,
        licenses,
        config,
        Path(root),
        project_ignore=project_ignore,
        suppressed=suppressed,
    )
