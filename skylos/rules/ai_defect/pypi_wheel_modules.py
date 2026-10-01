"""Which top-level modules a PyPI distribution provides, read from its wheel.

An import name is often not the distribution name: django-money ships
``djmoney`` and the sphinxcontrib-* distributions share the ``sphinxcontrib``
namespace. The authoritative answer is the file list inside the
distribution's wheel. Only the zip central directory at the end of the wheel
is fetched (HTTP range requests), so nothing is downloaded in full, unpacked
or installed.
"""

from __future__ import annotations

import http.client
import json
import platform
import re
import struct
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
WHEEL_HOST = "files.pythonhosted.org"
USER_AGENT = "skylos-dep-scanner/1.0"
TIMEOUT_SECONDS = 5
MAX_PYPI_JSON_BYTES = 32_000_000
MAX_CENTRAL_DIRECTORY_BYTES = 8_000_000

# Results that are a final answer and safe to cache.
STATUS_NOT_ON_PYPI = "missing"
STATUS_NO_WHEEL = "no_wheel"
STATUS_UNREADABLE = "unreadable"
STATUS_UNSUPPORTED = "unsupported"

_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_SIZE = 22
_MAX_ZIP_COMMENT = 65_535
_CENTRAL_ENTRY_SIGNATURE = b"PK\x01\x02"
_CENTRAL_ENTRY_SIZE = 46
_WHEEL_DATA_LIB = re.compile(r"^[^/]+\.data/(?:purelib|platlib)/")
_NATIVE_MODULE_SUFFIX = re.compile(
    r"(?:so|pyd|abi\d+\.so|cpython-\d+[A-Za-z0-9_-]*\.so|"
    r"pypy\d+[A-Za-z0-9_-]*\.so|cp\d+[A-Za-z0-9_-]*\.pyd)\Z"
)
_PYTHON_VERSION = Version(platform.python_version())


class LookupUnavailable(Exception):
    """PyPI could not answer (network error, timeout, unexpected reply)."""


class _Unreadable(Exception):
    """The wheel's zip index is not something this reader accepts."""


def _public_host(url):
    try:
        parts = urlsplit(url)
        if (
            parts.scheme == "https"
            and parts.hostname in {"pypi.org", WHEEL_HOST}
            and parts.username is None
            and parts.port in {None, 443}
        ):
            return parts.hostname
    except ValueError:
        pass
    raise LookupUnavailable("registry URL is outside approved HTTPS hosts")


class _TrustedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if _public_host(new_url) != _public_host(request.full_url):
            raise LookupUnavailable("registry redirect changed host")
        return super().redirect_request(
            request, response, code, message, headers, new_url
        )


def _urlopen(request, timeout):
    """A local opener rejects unexpected redirects before following them."""
    _public_host(request.full_url)
    return urllib.request.build_opener(_TrustedRedirectHandler()).open(
        request, timeout=timeout
    )


def fetch_distribution_modules(dist_name: str, *, specifier: str = "") -> dict:
    """Read a compatible declared release, without importing or installing it.

    Successful answers contain ``modules`` (roots), ``module_paths`` (dotted
    import paths), ``concrete_module_paths`` and ``namespace_paths``, plus the
    selected ``version``. ``complete_for_requirement`` only permits absence
    proof for an exact pin; one selected release cannot disprove providers in
    other permitted releases. Unsupported artifacts are also unknown.

    Raises LookupUnavailable when PyPI could not be asked; that result says
    nothing about the distribution and must not be cached.
    """
    try:
        requirement = Requirement(dist_name)
        declared = SpecifierSet(str(requirement.specifier)) & SpecifierSet(specifier)
    except (InvalidRequirement, InvalidSpecifier, TypeError):
        return {"status": STATUS_UNSUPPORTED}
    if requirement.url is not None or requirement.marker is not None:
        return {"status": STATUS_UNSUPPORTED}
    name = canonicalize_name(requirement.name)
    body = _http_get(
        PYPI_JSON_URL.format(name=quote(name, safe="")),
        max_bytes=MAX_PYPI_JSON_BYTES,
    )
    if body is None:
        return {"status": STATUS_NOT_ON_PYPI}
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("expected an object")
    except (ValueError, AttributeError) as exc:
        raise LookupUnavailable(f"bad PyPI JSON for {dist_name}") from exc

    release_files, version = _select_release(data, declared)
    if release_files is None:
        return {"status": STATUS_UNSUPPORTED}
    allow_yanked = _exact_pin(declared)
    candidates = _wheel_candidates(
        release_files, allow_yanked=allow_yanked, expected_version=version
    )
    wheel = _preferred_wheel(candidates)
    if wheel is None:
        has_wheel = any(
            isinstance(item, dict)
            and item.get("packagetype") == "bdist_wheel"
            and (allow_yanked or not item.get("yanked"))
            for item in release_files
        )
        return {"status": STATUS_UNSUPPORTED if has_wheel else STATUS_NO_WHEEL}
    url, size = wheel
    try:
        names = _wheel_file_names(url, size)
    except _Unreadable:
        return {"status": STATUS_UNREADABLE}
    return {
        **module_inventory(names),
        "version": version,
        "complete_for_requirement": bool(
            version is not None and _exact_pin(declared) and len(candidates) == 1
        ),
    }


def module_inventory(file_names) -> dict:
    """Import paths inferred from wheel/installed RECORD names, without I/O."""
    paths, concrete_paths, plain_paths, package_paths = _module_inventory(file_names)
    namespace_paths = paths - concrete_paths
    return {
        "modules": sorted({path.split(".", 1)[0] for path in paths}),
        "module_paths": sorted(paths),
        "concrete_module_paths": sorted(concrete_paths),
        "plain_module_paths": sorted(plain_paths),
        "package_paths": sorted(package_paths),
        "namespace_paths": sorted(namespace_paths),
        "namespace_roots": sorted(path for path in namespace_paths if "." not in path),
    }


def _exact_pin(specifier):
    return any(
        part.operator in {"==", "==="} and "*" not in part.version for part in specifier
    )


def _python_compatible(item):
    requires_python = item.get("requires_python")
    if requires_python is None or requires_python == "":
        return True
    if not isinstance(requires_python, str):
        return False
    try:
        return SpecifierSet(requires_python).contains(_PYTHON_VERSION, prereleases=True)
    except InvalidSpecifier:
        return False


def _select_release(data, specifier):
    """Highest permitted, non-yanked release compatible with this interpreter."""
    releases = data.get("releases")
    allow_yanked = _exact_pin(specifier)
    if isinstance(releases, dict):
        by_version = {}
        for label, files in releases.items():
            if not isinstance(label, str) or not isinstance(files, list):
                continue
            try:
                version = Version(label)
            except InvalidVersion:
                continue
            if any(
                isinstance(item, dict)
                and (allow_yanked or not item.get("yanked"))
                and _python_compatible(item)
                for item in files
            ):
                by_version[version] = (label, files)
        permitted = list(specifier.filter(by_version))
        if not permitted:
            return None, None
        return by_version[max(permitted)][1], by_version[max(permitted)][0]

    # Older/simple registry replies can still identify the current release.
    files = data.get("urls")
    if not isinstance(files, list):
        raise LookupUnavailable("PyPI reply has no release file list")
    info = data.get("info")
    label = info.get("version") if isinstance(info, dict) else None
    if specifier:
        try:
            if not isinstance(label, str) or not specifier.contains(Version(label)):
                return None, None
        except InvalidVersion:
            return None, None
    return files, label if isinstance(label, str) else None


def top_level_modules(file_names) -> set[str]:
    """Importable top-level names in a wheel, from its file list."""
    paths, _concrete, _plain, _packages = _module_inventory(file_names)
    return {path.split(".", 1)[0] for path in paths}


def _module_inventory(file_names):
    paths = set()
    concrete = set()
    packages = set()
    ordinary_modules = set()
    for name in file_names:
        name = _WHEEL_DATA_LIB.sub("", name)
        parts = name.split("/")
        if not parts or parts[0].endswith((".dist-info", ".data")):
            continue
        parents = parts[:-1]
        if not all(part.isidentifier() for part in parents):
            continue
        # A nonempty file inside an identifier directory can establish a PEP
        # 420 namespace package even when the file itself is only data.
        if parts[-1]:
            paths.update(
                ".".join(parents[:index]) for index in range(1, len(parents) + 1)
            )
        filename = parts[-1]
        stem, dot, suffix = filename.partition(".")
        if not dot or not stem.isidentifier():
            continue
        if suffix != "py" and not _NATIVE_MODULE_SUFFIX.fullmatch(suffix):
            continue
        if stem == "__init__" and parents:
            module_path = ".".join(parents)
            packages.add(module_path)
        else:
            module_path = ".".join((*parents, stem))
            ordinary_modules.add(module_path)
        paths.add(module_path)
        concrete.add(module_path)
    # A foo.py module wins over a markerless foo/ namespace directory, and
    # therefore cannot make foo.child importable. A real package marker wins
    # over the same-name ordinary module, matching Python's FileFinder.
    blockers = ordinary_modules - packages
    blocked = {
        path
        for path in paths
        if any(
            ".".join(path.split(".")[:index]) in blockers
            for index in range(1, len(path.split(".")))
        )
    }
    paths.difference_update(blocked)
    concrete.difference_update(blocked)
    packages.intersection_update(paths)
    blockers.intersection_update(paths)
    return paths, concrete, blockers, packages


def _pick_wheel(release_files, *, allow_yanked=False, expected_version=None):
    return _preferred_wheel(
        _wheel_candidates(
            release_files, allow_yanked=allow_yanked, expected_version=expected_version
        )
    )


def _wheel_candidates(release_files, *, allow_yanked=False, expected_version=None):
    if not isinstance(release_files, list):
        return []
    supported = {tag: rank for rank, tag in enumerate(sys_tags())}
    wheels = []
    for item in release_files:
        if not isinstance(item, dict) or item.get("packagetype") != "bdist_wheel":
            continue
        if item.get("yanked") and not allow_yanked:
            continue
        url, size, filename = item.get("url"), item.get("size"), item.get("filename")
        if not isinstance(url, str) or type(size) is not int or size <= 0:
            continue
        try:
            parts = urlsplit(url)
            if (
                parts.scheme != "https"
                or parts.hostname != WHEEL_HOST
                or parts.username is not None
                or parts.port not in {None, 443}
            ):
                continue
        except ValueError:
            continue
        if not isinstance(filename, str):
            continue
        try:
            _name, _version, _build, tags = parse_wheel_filename(filename)
        except InvalidWheelFilename:
            continue
        if expected_version is not None:
            try:
                if _version != Version(expected_version):
                    continue
            except InvalidVersion:
                continue
        matches = [(supported[tag], tag) for tag in tags if tag in supported]
        if not _python_compatible(item) or not matches:
            # Keep alternate artifacts in the ambiguity count: the target's
            # interpreter/platform can differ from the scanner's environment.
            rank, portable = float("inf"), False
        else:
            rank, best_tag = min(matches)
            portable = best_tag.abi == "none" and best_tag.platform == "any"
        wheels.append((rank, size, url, portable))
    return sorted(wheels)


def _preferred_wheel(candidates):
    if not candidates:
        return None
    rank, size, url, portable = candidates[0]
    # Follow the installer's supported-tag order. A preferred platform wheel
    # makes an arbitrary portable artifact insufficient provider evidence.
    if rank == float("inf") or not portable:
        return None
    return url, size


def _wheel_file_names(url: str, size: int) -> list[str]:
    tail_start = max(0, size - (_EOCD_SIZE + _MAX_ZIP_COMMENT))
    tail = _http_get(
        url,
        max_bytes=size - tail_start,
        byte_range=(tail_start, size - 1),
        expected_size=size,
    )
    if tail is None or len(tail) != size - tail_start:
        raise LookupUnavailable(f"short read of {url}")

    candidates = []
    at = tail.find(_EOCD_SIGNATURE)
    while at >= 0:
        if len(tail) - at >= _EOCD_SIZE:
            (
                _signature,
                disk,
                index_disk,
                disk_entries,
                entries,
                cd_size,
                cd_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2IH", tail, at)
            absolute_at = tail_start + at
            if (
                at + _EOCD_SIZE + comment_size == len(tail)
                and disk == index_disk == 0
                and disk_entries == entries
                and entries != 0xFFFF
                and cd_offset != 0xFFFFFFFF
                and cd_size != 0xFFFFFFFF
                and cd_size <= MAX_CENTRAL_DIRECTORY_BYTES
                and cd_offset + cd_size == absolute_at
            ):
                candidates.append((at, entries, cd_size, cd_offset))
        at = tail.find(_EOCD_SIGNATURE, at + len(_EOCD_SIGNATURE))
    if len(candidates) != 1:
        # A signature embedded in the ZIP comment is not the end record.
        # Reject ambiguous records rather than accepting partial inventories.
        raise _Unreadable("missing, ambiguous or unsupported zip end record")
    _at, entries, cd_size, cd_offset = candidates[0]

    relative = cd_offset - tail_start
    if cd_size == 0:
        directory = b""
    elif relative >= 0:
        directory = tail[relative : relative + cd_size]
    else:
        directory = _http_get(
            url,
            max_bytes=cd_size,
            byte_range=(cd_offset, cd_offset + cd_size - 1),
            expected_size=size,
        )
        if directory is None:
            raise LookupUnavailable(f"zip index of {url} disappeared")
    if len(directory) != cd_size:
        raise _Unreadable("truncated zip index")
    return _central_directory_names(directory, entries, cd_offset=cd_offset)


def _central_directory_names(
    directory: bytes, entries: int, *, cd_offset: int | None = None
) -> list[str]:
    names = []
    pos = 0
    for _ in range(entries):
        header_end = pos + _CENTRAL_ENTRY_SIZE
        if (
            header_end > len(directory)
            or directory[pos : pos + 4] != _CENTRAL_ENTRY_SIGNATURE
        ):
            raise _Unreadable("bad zip index entry")
        name_len, extra_len, comment_len = struct.unpack_from(
            "<HHH", directory, pos + 28
        )
        name_end = header_end + name_len
        entry_end = name_end + extra_len + comment_len
        if not name_len or entry_end > len(directory):
            raise _Unreadable("bad zip index entry")
        flags = struct.unpack_from("<H", directory, pos + 8)[0]
        method = struct.unpack_from("<H", directory, pos + 10)[0]
        compressed_size, uncompressed_size = struct.unpack_from(
            "<II", directory, pos + 20
        )
        start_disk = struct.unpack_from("<H", directory, pos + 34)[0]
        local_offset = struct.unpack_from("<I", directory, pos + 42)[0]
        if (
            flags & (0x1 | 0x40 | 0x2000)
            or method not in {0, 8}
            or compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or start_disk != 0
            or local_offset == 0xFFFFFFFF
            or (
                cd_offset is not None
                and local_offset + 30 + name_len + compressed_size > cd_offset
            )
        ):
            raise _Unreadable("unsupported zip index offsets")
        try:
            name = directory[header_end:name_end].decode(
                "utf-8" if flags & 0x800 else "cp437"
            )
        except UnicodeError as exc:
            raise _Unreadable("invalid zip filename encoding") from exc
        parts = name.rstrip("/").split("/")
        if (
            name.startswith("/")
            or "\\" in name
            or "\x00" in name
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise _Unreadable("unsafe zip filename")
        names.append(name)
        pos = entry_end
    if pos != len(directory):
        raise _Unreadable("zip index count does not match its size")
    return names


def _http_get(url, *, max_bytes, byte_range=None, expected_size=None):
    """Body bytes, or None for 404. Raises LookupUnavailable otherwise."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if byte_range is not None:
        request.add_header("Range", f"bytes={byte_range[0]}-{byte_range[1]}")
    try:
        with _urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if byte_range is not None and status != 206:
                # A full 200 reply would mean reading the whole wheel.
                raise LookupUnavailable(f"range request not honoured by {url}")
            if byte_range is not None:
                headers = getattr(response, "headers", {})
                content_range = headers.get("Content-Range", "")
                match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range)
                if (
                    match is None
                    or (int(match[1]), int(match[2])) != byte_range
                    or int(match[3]) <= byte_range[1]
                    or (expected_size is not None and int(match[3]) != expected_size)
                ):
                    raise LookupUnavailable(f"incorrect range reply from {url}")
            body = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise LookupUnavailable(f"HTTP {exc.code} from {url}") from exc
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        ValueError,
        http.client.HTTPException,
    ) as exc:
        raise LookupUnavailable(f"could not reach {url}: {exc}") from exc
    if len(body) > max_bytes:
        raise LookupUnavailable(f"reply from {url} is larger than expected")
    return body
