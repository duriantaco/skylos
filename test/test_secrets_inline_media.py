import base64
import hashlib
import json
import random
import struct
import zlib

import pytest

from skylos.rules.secret_shapes import inline_png_payload_spans
from skylos.rules.secrets import scan_ctx


def _chunk(kind, payload):
    data = kind + payload
    return struct.pack(">I", len(payload)) + data + struct.pack(">I", zlib.crc32(data))


def _png(*, seed=1, width=17, metadata=b"", corrupt=False, extra_raster=b""):
    height = 16
    generator = random.Random(seed)
    rows = b"".join(b"\0" + generator.randbytes(width * 3) for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    pixels = _chunk(b"IDAT", zlib.compress(rows + extra_raster))
    if corrupt:
        pixels = pixels[:-4] + b"\0" * 4
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + metadata
        + pixels
        + _chunk(b"IEND", b"")
    )


def _as_data_uri(data):
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")


def _scan(fields):
    return scan_ctx({
        "relpath": "preview.json",
        "lines": [json.dumps(fields) + "\n"],
        "tree": None,
    })


def test_complete_inline_png_has_no_generic_findings():
    assert _scan({"preview": _as_data_uri(_png())}) == []


@pytest.mark.parametrize(
    "data",
    [
        _png()[:-25],
        _png(corrupt=True),
        _png(extra_raster=b"unexpected extra raster data"),
        _png(metadata=_chunk(b"tEXt", b"Comment\0fixture metadata")),
    ],
    ids=["truncated", "bad-crc", "invalid-raster-size", "metadata"],
)
def test_incomplete_or_unclassified_png_receives_no_container_proof(data):
    assert inline_png_payload_spans(json.dumps({"preview": _as_data_uri(data)})) == []


def test_incomplete_image_still_gets_scanned():
    assert any(
        finding.get("provider") == "generic"
        for finding in _scan({"preview": _as_data_uri(_png(seed=10, width=24)[:-32])})
    )


def test_image_does_not_hide_credential_on_same_line():
    material = hashlib.sha256(b"unissued-inline-image-control").hexdigest()
    token = "ghp_" + material[:36]
    providers = {
        finding.get("provider")
        for finding in _scan({"preview": _as_data_uri(_png()), "api_key": token})
    }
    assert providers == {"github"}


def test_generic_pass_retains_explicitly_credential_labeled_image_value():
    assert any(
        finding.get("provider") == "generic"
        for finding in _scan({"api_token": _as_data_uri(_png())})
    )
