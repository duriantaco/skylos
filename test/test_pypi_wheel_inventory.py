"""Untrusted wheel metadata must not become incomplete import-provider proof."""

import io
import json
import struct
import zipfile

import pytest
from packaging.version import Version
from packaging.tags import Tag

from skylos.rules.ai_defect import pypi_wheel_modules as wheel_modules


def _wheel(names, *, comment=b""):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name in names:
            archive.writestr(name, b"# inventory only; never executed\n")
        archive.comment = comment
    return output.getvalue()


def _file(version, *, requires_python=None, tag="py3-none-any", yanked=False):
    filename = f"sample-{version}-{tag}.whl"
    return {
        "packagetype": "bdist_wheel",
        "filename": filename,
        "url": f"https://files.pythonhosted.org/packages/{filename}",
        "requires_python": requires_python,
        "yanked": yanked,
    }


def _registry(monkeypatch, versions, *, data=None):
    """Serve only metadata and byte ranges of synthetic in-memory wheels."""
    bodies = {}
    releases = {}
    for version, (body, item) in versions.items():
        item = {**item, "size": len(body)}
        bodies[item["url"]] = body
        releases[version] = [item]
    if data is None:
        latest = max(releases, key=Version)
        data = {
            "info": {"version": latest},
            "urls": releases[latest],
            "releases": releases,
        }
    requests = []

    def fake_get(url, *, max_bytes, byte_range=None, expected_size=None):
        requests.append((url, byte_range, max_bytes))
        if byte_range is None:
            assert url == "https://pypi.org/pypi/sample/json"
            return json.dumps(data).encode()
        body = bodies[url]
        assert expected_size == len(body)
        selected = body[byte_range[0] : byte_range[1] + 1]
        assert len(selected) <= max_bytes
        return selected

    monkeypatch.setattr(wheel_modules, "_http_get", fake_get)
    return requests


def _artifact_registry(monkeypatch, artifacts):
    files = []
    bodies = {}
    for body, item in artifacts:
        files.append({**item, "size": len(body)})
        bodies[item["url"]] = body
    data = {
        "info": {"version": "1.0"},
        "urls": files,
        "releases": {"1.0": files},
    }
    requests = []

    def fake_get(url, *, max_bytes, byte_range=None, expected_size=None):
        requests.append((url, byte_range))
        if byte_range is None:
            return json.dumps(data).encode()
        body = bodies[url]
        assert expected_size == len(body)
        result = body[byte_range[0] : byte_range[1] + 1]
        assert len(result) <= max_bytes
        return result

    monkeypatch.setattr(wheel_modules, "_http_get", fake_get)
    return requests


def test_asset_suffixes_are_not_native_extension_modules():
    assert (
        wheel_modules.top_level_modules(
            [
                "invented.iso",
                "other.also",
                "third.notpyd",
                "fourth.invalid.so",
                "fifth.invalid.pyd",
                "README.md",
            ]
        )
        == set()
    )
    assert wheel_modules.top_level_modules(
        [
            "plain.so",
            "_native.cpython-312-x86_64-linux-gnu.so",
            "stable.abi3.so",
            "windows.cp312-win_amd64.pyd",
            "six.py",
        ]
    ) == {"plain", "_native", "stable", "windows", "six"}


def test_plain_module_does_not_prove_same_named_directory_children():
    inventory = wheel_modules.module_inventory(
        [
            "foo.py",
            "foo/child.py",
            "regular/__init__.py",
            "regular/sub.py",
            "regular/sub/child.py",
        ]
    )

    assert inventory["module_paths"] == ["foo", "regular", "regular.sub"]
    assert inventory["plain_module_paths"] == ["foo", "regular.sub"]
    assert inventory["package_paths"] == ["regular"]
    assert "foo.child" not in inventory["module_paths"]
    assert "regular.sub.child" not in inventory["module_paths"]


def test_regular_package_wins_over_same_named_plain_module():
    inventory = wheel_modules.module_inventory(
        ["foo.py", "foo/__init__.py", "foo/child.py"]
    )

    assert inventory["module_paths"] == ["foo", "foo.child"]
    assert inventory["plain_module_paths"] == ["foo.child"]
    assert inventory["package_paths"] == ["foo"]


def test_preferred_supported_tag_wins_over_smaller_portable_wheel(monkeypatch):
    monkeypatch.setattr(
        wheel_modules,
        "sys_tags",
        lambda: iter([Tag("cp314", "none", "any"), Tag("py3", "none", "any")]),
    )
    requests = _artifact_registry(
        monkeypatch,
        [
            (_wheel(["generic.py"]), _file("1.0")),
            (
                _wheel(["preferred.py", "extra/data.bin"]),
                _file("1.0", tag="cp314-none-any"),
            ),
        ],
    )

    result = wheel_modules.fetch_distribution_modules("sample", specifier="==1.0")

    assert "preferred" in result["modules"]
    assert "generic" not in result["modules"]
    assert result["complete_for_requirement"] is False
    assert all(
        "cp314-none-any" in url
        for url, byte_range in requests
        if byte_range is not None
    )


def test_preferred_platform_wheel_prevents_arbitrary_portable_inventory(monkeypatch):
    monkeypatch.setattr(
        wheel_modules,
        "sys_tags",
        lambda: iter([Tag("cp314", "cp314", "win_amd64"), Tag("py3", "none", "any")]),
    )
    requests = _artifact_registry(
        monkeypatch,
        [
            (_wheel(["generic.py"]), _file("1.0")),
            (
                _wheel(["native_provider.py"]),
                _file("1.0", tag="cp314-cp314-win_amd64"),
            ),
        ],
    )

    assert wheel_modules.fetch_distribution_modules("sample", specifier="==1.0") == {
        "status": wheel_modules.STATUS_UNSUPPORTED
    }
    assert len(requests) == 1  # metadata only; neither artifact is read


def test_other_platform_artifact_keeps_portable_exact_pin_absence_unverified(
    monkeypatch,
):
    monkeypatch.setattr(
        wheel_modules,
        "sys_tags",
        lambda: iter([Tag("py3", "none", "any")]),
    )
    _artifact_registry(
        monkeypatch,
        [
            (_wheel(["generic.py"]), _file("1.0")),
            (
                _wheel(["another_platform.py"]),
                _file("1.0", tag="cp314-cp314-win_amd64"),
            ),
        ],
    )

    result = wheel_modules.fetch_distribution_modules("sample", specifier="==1.0")

    assert result["modules"] == ["generic"]
    assert result["complete_for_requirement"] is False


def test_full_module_paths_distinguish_namespace_portions(monkeypatch):
    body = _wheel(
        [
            "sphinxcontrib/applehelp/__init__.py",
            "sphinxcontrib/applehelp/extension.py",
            "regular/__init__.py",
            "regular/namespace/data.bin",
            "sample-1.0.data/purelib/vendored/tools.py",
            "invented.iso",
            "sample-1.0.dist-info/RECORD",
        ]
    )
    _registry(monkeypatch, {"1.0": (body, _file("1.0"))})

    result = wheel_modules.fetch_distribution_modules("sample")

    assert result["modules"] == ["regular", "sphinxcontrib", "vendored"]
    assert result["concrete_module_paths"] == [
        "regular",
        "sphinxcontrib.applehelp",
        "sphinxcontrib.applehelp.extension",
        "vendored.tools",
    ]
    assert result["namespace_paths"] == [
        "regular.namespace",
        "sphinxcontrib",
        "vendored",
    ]
    assert result["namespace_roots"] == ["sphinxcontrib", "vendored"]
    assert "sphinxcontrib.serializinghtml" not in result["module_paths"]
    assert result["version"] == "1.0"
    assert result["complete_for_requirement"] is False


@pytest.mark.parametrize("specifier", ["==1.0", ">=1,<2", "~=1.0.0", "==1.*"])
def test_declared_version_inventory_does_not_use_latest_release(monkeypatch, specifier):
    requests = _registry(
        monkeypatch,
        {
            "1.0": (_wheel(["old_provider/__init__.py"]), _file("1.0")),
            "2.0": (_wheel(["new_provider/__init__.py"]), _file("2.0")),
        },
    )

    result = wheel_modules.fetch_distribution_modules("sample", specifier=specifier)

    assert result["version"] == "1.0"
    assert result["modules"] == ["old_provider"]
    assert "new_provider" not in result["module_paths"]
    assert result["complete_for_requirement"] is (specifier == "==1.0")
    assert all("sample-2.0" not in url for url, byte_range, _ in requests if byte_range)


def test_requirement_string_specifier_is_combined_with_explicit_constraint(monkeypatch):
    _registry(
        monkeypatch,
        {
            "1.0": (_wheel(["old.py"]), _file("1.0")),
            "2.0": (_wheel(["middle.py"]), _file("2.0")),
            "3.0": (_wheel(["new.py"]), _file("3.0")),
        },
    )

    result = wheel_modules.fetch_distribution_modules("sample>=1", specifier="<3")

    assert result["version"] == "2.0"
    assert result["modules"] == ["middle"]
    assert result["complete_for_requirement"] is False


def test_prerelease_is_not_selected_unless_permitted(monkeypatch):
    _registry(
        monkeypatch,
        {
            "1.0": (_wheel(["stable.py"]), _file("1.0")),
            "2.0a1": (_wheel(["preview.py"]), _file("2.0a1")),
        },
    )
    assert wheel_modules.fetch_distribution_modules("sample")["version"] == "1.0"
    assert (
        wheel_modules.fetch_distribution_modules("sample", specifier="==2.0a1")[
            "version"
        ]
        == "2.0a1"
    )


def test_requires_python_prevents_inventory_from_incompatible_release(monkeypatch):
    monkeypatch.setattr(wheel_modules, "_PYTHON_VERSION", Version("3.12"))
    _registry(
        monkeypatch,
        {
            "1.0": (_wheel(["compatible.py"]), _file("1.0", requires_python=">=3.9")),
            "2.0": (_wheel(["future.py"]), _file("2.0", requires_python=">=3.13")),
        },
    )

    assert wheel_modules.fetch_distribution_modules("sample")["version"] == "1.0"
    assert wheel_modules.fetch_distribution_modules("sample", specifier="==2.0") == {
        "status": wheel_modules.STATUS_UNSUPPORTED
    }


def test_exact_pin_can_read_yanked_release_but_unpinned_cannot(monkeypatch):
    _registry(
        monkeypatch,
        {
            "1.0": (_wheel(["stable.py"]), _file("1.0")),
            "2.0": (_wheel(["yanked.py"]), _file("2.0", yanked=True)),
        },
    )
    assert wheel_modules.fetch_distribution_modules("sample")["version"] == "1.0"
    assert wheel_modules.fetch_distribution_modules("sample", specifier="==2.0")[
        "modules"
    ] == ["yanked"]


@pytest.mark.parametrize(
    "requirement,specifier",
    [
        ("sample @ https://private.example/sample.whl", ""),
        ("sample @ file:///tmp/sample.whl", ""),
        ("sample; python_version < '3'", ""),
        ("not a requirement", ""),
        ("sample", "not-a-specifier"),
    ],
)
def test_unsupported_declarations_never_query_public_registry(
    monkeypatch, requirement, specifier
):
    def do_not_query(*args, **kwargs):
        pytest.fail("unsupported/private declaration queried public registry")

    monkeypatch.setattr(wheel_modules, "_http_get", do_not_query)

    assert wheel_modules.fetch_distribution_modules(
        requirement, specifier=specifier
    ) == {"status": wheel_modules.STATUS_UNSUPPORTED}


@pytest.mark.parametrize(
    "tag,requires_python",
    [
        ("cp312-cp312-win_amd64", None),
        ("py2-none-any", None),
        ("py3-none-any", ">=999"),
        ("py3-none-any", "invalid specifier"),
    ],
)
def test_platform_or_interpreter_incompatible_wheels_are_unknown(
    monkeypatch, tag, requires_python
):
    _registry(
        monkeypatch,
        {
            "1.0": (
                _wheel(["somewhere.py"]),
                _file("1.0", tag=tag, requires_python=requires_python),
            )
        },
    )

    assert wheel_modules.fetch_distribution_modules("sample") == {
        "status": wheel_modules.STATUS_UNSUPPORTED
    }


def test_pinned_release_without_its_metadata_is_unknown(monkeypatch):
    body = _wheel(["latest.py"])
    item = {**_file("2.0"), "size": len(body)}
    _registry(
        monkeypatch,
        {"2.0": (body, item)},
        data={"info": {"version": "2.0"}, "urls": [item]},
    )

    assert wheel_modules.fetch_distribution_modules("sample", specifier="==1.0") == {
        "status": wheel_modules.STATUS_UNSUPPORTED
    }


def test_artifact_from_different_version_is_not_pinned_inventory_proof(monkeypatch):
    _registry(
        monkeypatch,
        {"1.0": (_wheel(["wrong_version.py"]), _file("2.0"))},
    )

    assert wheel_modules.fetch_distribution_modules("sample", specifier="==1.0") == {
        "status": wheel_modules.STATUS_UNSUPPORTED
    }


@pytest.mark.parametrize("entry_count", [0, 1, 3, 0xFFFF])
def test_inconsistent_zip_entry_count_is_not_complete_proof(monkeypatch, entry_count):
    body = bytearray(_wheel(["visible/__init__.py", "hidden/__init__.py"]))
    end = body.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", body, end + 8, entry_count, entry_count)
    _registry(monkeypatch, {"1.0": (bytes(body), _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample") == {
        "status": wheel_modules.STATUS_UNREADABLE
    }


@pytest.mark.parametrize(
    "offset,fmt,value",
    [
        (4, "H", 1),  # multivolume archive
        (6, "H", 1),  # index on a different volume
        (8, "H", 0),  # disk count differs from total count
        (12, "I", 0xFFFFFFFF),  # ZIP64
        (16, "I", 0xFFFFFFFF),  # ZIP64
        (12, "I", 0),  # directory does not end at EOCD
        (20, "H", 100),  # comment goes past end of range
    ],
)
def test_unsupported_or_out_of_bounds_end_record_is_unknown(
    monkeypatch, offset, fmt, value
):
    body = bytearray(_wheel(["sample.py"]))
    end = body.rfind(b"PK\x05\x06")
    struct.pack_into("<" + fmt, body, end + offset, value)
    _registry(monkeypatch, {"1.0": (bytes(body), _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample") == {
        "status": wheel_modules.STATUS_UNREADABLE
    }


def test_eocd_signature_in_comment_does_not_hide_real_inventory(monkeypatch):
    false_record = b"PK\x05\x06" + bytes(18)
    body = _wheel(["real_provider/__init__.py"], comment=false_record)
    _registry(monkeypatch, {"1.0": (body, _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample")["modules"] == [
        "real_provider"
    ]


def test_trailing_bytes_are_not_accepted_as_wheel_inventory(monkeypatch):
    body = _wheel(["sample.py"]) + b"unexpected trailing bytes"
    _registry(monkeypatch, {"1.0": (body, _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample") == {
        "status": wheel_modules.STATUS_UNREADABLE
    }


@pytest.mark.parametrize("field_offset", [30, 32])
def test_truncated_extra_or_comment_entry_is_rejected(monkeypatch, field_offset):
    body = bytearray(_wheel(["sample.py"]))
    directory = body.find(b"PK\x01\x02")
    struct.pack_into("<H", body, directory + field_offset, 1000)
    _registry(monkeypatch, {"1.0": (bytes(body), _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample") == {
        "status": wheel_modules.STATUS_UNREADABLE
    }


@pytest.mark.parametrize(
    "offset,fmt,value",
    [
        (8, "H", 1),  # encrypted entry
        (8, "H", 0x40),  # strong encryption
        (8, "H", 0x2000),  # masked/encrypted header metadata
        (10, "H", 99),  # unknown compression method
        (20, "I", 0xFFFFFFFF),  # ZIP64 compressed size
        (20, "I", 1_000_000),  # compressed payload would extend into/beyond index
        (24, "I", 0xFFFFFFFF),  # ZIP64 uncompressed size
        (34, "H", 1),  # local record on another volume
        (42, "I", 0xFFFFFFFF),  # ZIP64 local record offset
    ],
)
def test_unsupported_entry_metadata_cannot_prove_provider(
    monkeypatch, offset, fmt, value
):
    body = bytearray(_wheel(["sample.py"]))
    directory = body.find(b"PK\x01\x02")
    struct.pack_into("<" + fmt, body, directory + offset, value)
    _registry(monkeypatch, {"1.0": (bytes(body), _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample", specifier="==1.0") == {
        "status": wheel_modules.STATUS_UNREADABLE
    }


@pytest.mark.parametrize("name", ["../escape.py", "/absolute.py", "pkg/../escape.py"])
def test_unsafe_archive_paths_are_unknown(monkeypatch, name):
    body = _wheel([name])
    _registry(monkeypatch, {"1.0": (body, _file("1.0"))})

    assert wheel_modules.fetch_distribution_modules("sample") == {
        "status": wheel_modules.STATUS_UNREADABLE
    }


def test_large_index_uses_bounded_second_range(monkeypatch):
    body = _wheel([f"pkg/module_{number:04}_{'x' * 80}.py" for number in range(900)])
    requests = _registry(monkeypatch, {"1.0": (body, _file("1.0"))})

    result = wheel_modules.fetch_distribution_modules("sample")

    assert result["modules"] == ["pkg"]
    assert len([request for request in requests if request[1] is not None]) == 2
    assert all(
        byte_range[1] - byte_range[0] + 1 <= max_bytes
        for _url, byte_range, max_bytes in requests
        if byte_range is not None
    )


@pytest.mark.parametrize(
    "redirect_url",
    [
        "http://files.pythonhosted.org/insecure.whl",
        "https://127.0.0.1/private",
        "https://evil.example/wheel.whl",
        "https://pypi.org/unexpected-cross-host",
        "https://files.pythonhosted.org:8443/wheel.whl",
    ],
)
def test_redirect_to_untrusted_destination_is_rejected_before_following(redirect_url):
    handler = wheel_modules._TrustedRedirectHandler()
    request = wheel_modules.urllib.request.Request(
        "https://files.pythonhosted.org/packages/wheel.whl"
    )

    with pytest.raises(wheel_modules.LookupUnavailable):
        handler.redirect_request(request, None, 302, "found", {}, redirect_url)


def test_same_host_https_redirect_is_allowed():
    handler = wheel_modules._TrustedRedirectHandler()
    request = wheel_modules.urllib.request.Request("https://pypi.org/pypi/Sample/json")

    redirected = handler.redirect_request(
        request, None, 301, "found", {}, "https://pypi.org/pypi/sample/json"
    )

    assert redirected.full_url == "https://pypi.org/pypi/sample/json"


class _RangeResponse:
    status = 206

    def __init__(self, content_range, body=b"0123456789"):
        self.headers = {"Content-Range": content_range}
        self.body = body

    def read(self, count):
        return self.body[:count]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.mark.parametrize("content_range", ["", "bytes 10-19/100", "bytes 0-9/9"])
def test_incorrect_http_range_is_not_inventory_proof(monkeypatch, content_range):
    monkeypatch.setattr(
        wheel_modules,
        "_urlopen",
        lambda _request, timeout: _RangeResponse(content_range),
    )

    with pytest.raises(wheel_modules.LookupUnavailable):
        wheel_modules._http_get(
            "https://files.pythonhosted.org/sample.whl",
            max_bytes=10,
            byte_range=(0, 9),
        )


def test_correct_http_range_remains_bounded(monkeypatch):
    monkeypatch.setattr(
        wheel_modules,
        "_urlopen",
        lambda _request, timeout: _RangeResponse("bytes 0-9/100"),
    )

    assert (
        wheel_modules._http_get(
            "https://files.pythonhosted.org/sample.whl",
            max_bytes=10,
            byte_range=(0, 9),
        )
        == b"0123456789"
    )


def test_http_range_total_must_match_declared_wheel_size(monkeypatch):
    monkeypatch.setattr(
        wheel_modules,
        "_urlopen",
        lambda _request, timeout: _RangeResponse("bytes 0-9/101"),
    )

    with pytest.raises(wheel_modules.LookupUnavailable):
        wheel_modules._http_get(
            "https://files.pythonhosted.org/sample.whl",
            max_bytes=10,
            byte_range=(0, 9),
            expected_size=100,
        )
