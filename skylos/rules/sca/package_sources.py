"""Where a dependency comes from, read as data from manifests and lockfiles.

Supply-chain checks need three facts the advisory query does not: the
registry an entry resolves from, the integrity hash a lockfile recorded, and
for Git or URL dependencies whether the source is immutable (a full commit or
a hash). Nothing here fetches, resolves or executes anything.

Source URLs are reported back to the user and may be uploaded, so credentials
(user info) and query values other than Git refs are removed before a URL is
kept. Archive URLs keep only their scheme, host and file name, so a private
registry's paths do not leave the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from skylos.core.python_requirements import _logical_lines

SOURCE_REGISTRY = "registry"
SOURCE_GIT = "git"
SOURCE_URL = "url"
SOURCE_PATH = "path"
PYPI_SIMPLE_URL = "https://pypi.org/simple"
NPM_REGISTRY_URL = "https://registry.npmjs.org"
MAX_SOURCE_URL_CHARS = 2048
MAX_SOURCE_RECORDS = 5000
_FULL_COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_SAFE_QUERY_KEYS = frozenset({"rev", "tag", "branch", "ref", "subdirectory", "egg"})
_URL_HASH_RE = re.compile(
    r"(?:^|[#&])(?:sha256|sha384|sha512|md5|sha1)=[0-9A-Za-z+/=_-]+"
)
_HASH_OPTION_RE = re.compile(r"--hash(?:\s*=\s*|\s+)(\S+)")
_INDEX_RE = re.compile(
    r"^(?P<option>--index-url|--extra-index-url|-i)(?:\s*=\s*|\s+)(?P<url>\S+)"
)
_REQUIREMENT_URL_RE = re.compile(
    r"^(?:git\+|hg\+|svn\+|bzr\+|https?://|file:|\.{0,2}/)"
)
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9_.-]*)")
_PEP508_REFERENCE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^\]]*\])?\s*@\s*(?P<url>\S+)"
)
_ARCHIVE_NAME_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*?)-(?P<version>[0-9][A-Za-z0-9_.+!]*)"
    r"(?:\.tar\.gz|\.tgz|\.zip|\.tar\.bz2|-[^/]*\.whl)$"
)


def sanitize_source_url(value: object) -> str | None:
    """A source URL without credentials or unexpected query values."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_SOURCE_URL_CHARS:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        return None
    prefix = ""
    for vcs in ("git+", "hg+", "svn+", "bzr+"):
        if text.startswith(vcs):
            prefix, text = vcs, text[len(vcs) :]
            break
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        if "@" in text.split("/", 1)[0] and ":" in text:
            return prefix + text.split("@", 1)[1]
        return prefix + text
    host = parts.hostname or ""
    if port is not None:
        host = f"{host}:{port}"
    if parts.username == "git" and parts.password is None:
        host = f"git@{host}"
    query = urlencode(
        [(key, item) for key, item in parse_qsl(parts.query) if key in _SAFE_QUERY_KEYS]
    )
    return prefix + urlunsplit((parts.scheme, host, parts.path, query, parts.fragment))


NPM_REGISTRY_HOST = "registry.npmjs.org"
PYPI_REGISTRY_HOST = "pypi.org"
PUBLIC_REGISTRY_URLS = {
    NPM_REGISTRY_HOST: NPM_REGISTRY_URL,
    PYPI_REGISTRY_HOST: PYPI_SIMPLE_URL,
}


def npm_registry_for(source_type: object) -> str | None:
    """The public registry an npm lockfile entry names, when the lockfile
    says. Dependency records name public registries by host only; parsed
    inventories never carry source URLs."""
    if source_type == "npm_registry":
        return NPM_REGISTRY_HOST
    return None


def registry_url(value: object) -> str | None:
    """The index URL for a dependency record's ``registry`` value."""
    if not isinstance(value, str) or not value:
        return None
    return PUBLIC_REGISTRY_URLS.get(value, value)


def is_full_commit(ref: object) -> bool:
    return isinstance(ref, str) and bool(_FULL_COMMIT_RE.fullmatch(ref.strip()))


def git_ref_from_url(url: str | None) -> str | None:
    """The ref a Git URL names: ``@ref`` in the path (pip), else the fragment
    (npm, uv) or a ``rev``/``tag``/``branch`` query value."""
    if not isinstance(url, str) or not url:
        return None
    text = url
    for vcs in ("git+",):
        text = text.removeprefix(vcs)
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    fragment = parts.fragment
    if fragment and "=" not in fragment.split("&", 1)[0]:
        return fragment
    if fragment.startswith("commit="):
        return fragment.split("=", 1)[1].split("&", 1)[0]
    path = parts.path
    if not parts.netloc and ":" in path and "@" in path.split(":", 1)[0]:
        path = path.split(":", 1)[1]
    if "@" in path:
        return path.rsplit("@", 1)[1] or None
    for key, item in parse_qsl(parts.query):
        if key in {"rev", "tag", "branch", "ref"} and item:
            return item
    return None


def url_hash(url: str | None) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        fragment = urlsplit(url).fragment
    except ValueError:
        return None
    match = _URL_HASH_RE.search("#" + fragment)
    if match is None:
        return None
    return match.group(0).lstrip("#&").replace("=", ":", 1)


def _archive_display_url(clean: str | None) -> str | None:
    if clean is None:
        return None
    try:
        parts = urlsplit(clean)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return clean
    segments = [segment for segment in parts.path.split("/") if segment]
    if not segments:
        return f"{parts.scheme}://{parts.netloc}/"
    return f"{parts.scheme}://{parts.netloc}/.../{segments[-1]}"


def source_is_mutable(record: dict) -> bool:
    """A Git source not pinned to a full commit, or a URL without a hash."""
    kind = record.get("source_kind")
    if kind == SOURCE_GIT:
        return not is_full_commit(record.get("source_ref"))
    if kind == SOURCE_URL:
        integrity = record.get("integrity")
        return not (isinstance(integrity, str) and integrity.strip())
    return False


def source_record(
    *,
    ecosystem: str,
    name: str | None,
    version: str | None,
    kind: str,
    url: object,
    file: str,
    line: int,
    ref: str | None = None,
    integrity: str | None = None,
    direct: bool = True,
    dev: bool = False,
) -> dict | None:
    """A non-registry dependency entry for supply-chain checks."""
    clean = sanitize_source_url(url)
    if kind != SOURCE_PATH and clean is None:
        return None
    if ref is None and kind == SOURCE_GIT:
        ref = git_ref_from_url(url)
    if integrity is None and kind == SOURCE_URL:
        integrity = url_hash(url)
    if kind == SOURCE_URL:
        clean = _archive_display_url(clean)
    if not isinstance(line, int) or line < 1:
        line = 1
    return {
        "ecosystem": ecosystem,
        "name": name or "",
        "version": version or "",
        "source_kind": kind,
        "source_url": clean,
        "source_ref": ref,
        "integrity": integrity,
        "file": file,
        "line": line,
        "direct": direct,
        "dev": dev,
    }


def _requirement_url_kind(url: str) -> str:
    if url.startswith(("git+", "hg+", "svn+", "bzr+")):
        return SOURCE_GIT
    if url.startswith(("http://", "https://")):
        return SOURCE_URL
    return SOURCE_PATH


def _archive_identity(url: str) -> tuple[str | None, str | None]:
    try:
        tail = urlsplit(url).path.rsplit("/", 1)[-1]
    except ValueError:
        return None, None
    match = _ARCHIVE_NAME_RE.match(tail)
    if match is None:
        return None, None
    return match.group("name"), match.group("version")


@dataclass
class RequirementSources:
    """Index options, per-line hashes and direct references of one file."""

    path: Path
    index_url: str | None = None
    extra_index_urls: list = field(default_factory=list)
    hashes: dict = field(default_factory=dict)
    references: list = field(default_factory=list)

    def registry(self) -> tuple[str | None, str | None, list[str]]:
        """(registry, mode, every index): ``--extra-index-url`` merges its
        index with the main one (pip picks the highest version across all),
        ``--index-url`` alone is exclusive."""
        main = self.index_url or PYPI_SIMPLE_URL
        if self.extra_index_urls:
            return self.index_url, "merged", [main, *self.extra_index_urls]
        if self.index_url:
            return self.index_url, "exclusive", [self.index_url]
        return None, None, []


def requirements_sources(text: str, path: Path) -> RequirementSources:
    """Read the parts of a pip requirements file that say where packages
    come from. Only this file; ``-r`` includes are read by the caller."""
    found = RequirementSources(Path(path))
    for number, logical, _first in _logical_lines(text):
        content = re.sub(r"(^|\s+)#.*$", "", logical).strip()
        if not content:
            continue
        index = _INDEX_RE.match(content)
        if index is not None:
            url = sanitize_source_url(index.group("url"))
            if url is None:
                continue
            if index.group("option") == "--extra-index-url":
                found.extra_index_urls.append(url)
            else:
                found.index_url = url
            continue
        if content.startswith("-"):
            continue
        hashes = _HASH_OPTION_RE.findall(content)
        spec = _HASH_OPTION_RE.sub("", content).strip()
        first_hash = None
        if hashes:
            first_hash = hashes[0]
            found.hashes[number] = first_hash
        name = None
        url = None
        reference = _PEP508_REFERENCE_RE.match(spec)
        if reference is not None:
            name, url = reference.group("name"), reference.group("url")
        elif _REQUIREMENT_URL_RE.match(spec):
            url = spec.split()[0]
            egg = _EGG_RE.search(url)
            if egg is not None:
                name = egg.group(1)
        if url is None:
            continue
        kind = _requirement_url_kind(url)
        version = None
        if name is None and kind != SOURCE_GIT:
            name, version = _archive_identity(url)
        record = source_record(
            ecosystem="PyPI",
            name=name,
            version=version,
            kind=kind,
            url=url,
            file=str(path),
            line=number,
            integrity=first_hash,
        )
        if record is not None:
            found.references.append(record)
    return found


def pep508_reference(requirement: object) -> tuple[str, str] | None:
    """``name @ url`` from a PEP 508 requirement string."""
    if not isinstance(requirement, str):
        return None
    match = _PEP508_REFERENCE_RE.match(requirement.split(";", 1)[0])
    if match is None:
        return None
    return match.group("name"), match.group("url")


def requirement_url_kind(url: str) -> str:
    return _requirement_url_kind(url)


_NPM_GIT_PREFIXES = ("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:")
_NPM_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:#.*)?$")


def npm_spec_source(spec: object) -> tuple[str, str] | None:
    """(kind, url) for a package.json spec that is not a registry range."""
    if not isinstance(spec, str):
        return None
    text = spec.strip()
    if text.startswith(_NPM_GIT_PREFIXES) or _NPM_SHORTHAND_RE.match(text):
        return SOURCE_GIT, text
    if text.startswith(("http://", "https://")):
        if text.split("#", 1)[0].endswith(".git"):
            return SOURCE_GIT, text
        return SOURCE_URL, text
    return None


def npm_git_ref(spec: str) -> str | None:
    if "#" not in spec:
        return None
    ref = spec.rsplit("#", 1)[1]
    if ref.startswith("semver:"):
        return None
    return ref or None


__all__ = [
    "MAX_SOURCE_RECORDS",
    "NPM_REGISTRY_HOST",
    "NPM_REGISTRY_URL",
    "PUBLIC_REGISTRY_URLS",
    "PYPI_REGISTRY_HOST",
    "PYPI_SIMPLE_URL",
    "SOURCE_GIT",
    "SOURCE_PATH",
    "SOURCE_REGISTRY",
    "SOURCE_URL",
    "RequirementSources",
    "git_ref_from_url",
    "is_full_commit",
    "npm_git_ref",
    "npm_registry_for",
    "npm_spec_source",
    "pep508_reference",
    "registry_url",
    "requirement_url_kind",
    "requirements_sources",
    "sanitize_source_url",
    "source_is_mutable",
    "source_record",
    "url_hash",
]
