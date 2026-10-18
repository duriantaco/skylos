"""P401 reports reads whose source size is not bounded.

HTTP responses, HTTPError bodies, uploads, archive members and opaque streams
can all allocate input-sized data. A receiver name or shadowed opener cannot
prove safety. Proven in-memory buffer read() remains quiet.
"""

import ast
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from skylos.rules.quality.performance import PerformanceRule


def _p401_lines(source):
    tree = ast.parse(source)
    rule = PerformanceRule()
    lines = []
    with TemporaryDirectory() as directory:
        context = {
            "filename": str(Path(directory) / "sample.py"),
            "project_root": directory,
        }
        for node in ast.walk(tree):
            for finding in rule.visit_node(node, context) or []:
                if finding["rule_id"] == "SKY-P401":
                    lines.append(finding["line"])
    return sorted(lines)


# --- proven not to be a file ------------------------------------------------

HTTP_ERROR_BODY = """
from urllib import error, request

def post(req):
    try:
        with request.urlopen(req) as resp:
            body = resp.read()
    except error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(detail) from e
    return body
"""

TUPLE_UNPACKED_RESULT = """
def grab(camera_factory):
    cap = camera_factory(0)
    ok, frame = cap.read()
    return ok, frame
"""

AWAITED_TUPLE_UNPACKED_RESULT = """
async def grab(cam):
    ok, frame = await cam.read()
    return frame
"""

LOCAL_IN_MEMORY_BUFFERS = """
import io
from io import StringIO

def copy(data, text):
    payload = io.BytesIO(data)
    rendered = StringIO(text)
    return payload.read(), rendered.read(), io.BytesIO(data).read()
"""


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(LOCAL_IN_MEMORY_BUFFERS, id="local-in-memory-buffers"),
    ],
)
def test_read_proven_not_from_a_file_is_not_reported(source):
    assert _p401_lines(source) == []


# --- unproven receivers: still reported --------------------------------------

UPLOADS_ARCHIVES_AND_HELPERS = """
import tarfile

def handle(request, tar, m):
    doc = request.files["doc"].read()
    upload = request.files["other"]
    body = upload.read()
    member = tar.extractfile(m).read()
    return doc, body, member


def load_config(input_file):
    return input_file.read()


def open_log(path):
    return open(path)


def tail(path):
    fh = open_log(path)
    return fh.read()
"""

OPAQUE_CALL_RESULTS = """
def grab(sock, client):
    payload = client.get("/x").raw.read()
    data = sock.makefile().read()
    return payload, data
"""

UNTYPED_REQUEST_PARAMETER = """
def handler(request, upload):
    return request.read() + upload.read()
"""

NON_IO_ANNOTATION = """
def handler(f: "UploadFile"):
    return f.read()
"""

LOOP_AND_COMPREHENSION_TARGETS = """
def drain(handles):
    out = [h.read() for h in handles]
    for f in handles:
        out.append(f.read())
    return out
"""

REBOUND_TO_UNKNOWN = """
def load(path, fetch):
    f = open(path)
    f.close()
    f = fetch(path)
    return f.read()
"""

STDIN_AND_PROCESS_PIPES = """
import sys

def drain(proc):
    return sys.stdin.read() + proc.stdout.read()
"""

EXCEPTION_NAME_REBOUND = """
def load(path):
    try:
        err = None
        raise OSError(path)
    except OSError as err:
        pass
    err = open(path)
    return err.read()
"""


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(HTTP_ERROR_BODY, [7, 9], id="http-error-and-response"),
        pytest.param(
            UPLOADS_ARCHIVES_AND_HELPERS, [5, 7, 8, 13, 22], id="uploads-archives"
        ),
        pytest.param(OPAQUE_CALL_RESULTS, [3, 4], id="opaque-call-results"),
        pytest.param(UNTYPED_REQUEST_PARAMETER, [3, 3], id="untyped-parameters"),
        pytest.param(NON_IO_ANNOTATION, [3], id="non-io-annotation"),
        pytest.param(LOOP_AND_COMPREHENSION_TARGETS, [3, 5], id="loop-targets"),
        pytest.param(REBOUND_TO_UNKNOWN, [6], id="rebound-to-unknown"),
        pytest.param(STDIN_AND_PROCESS_PIPES, [5, 5], id="stdin-and-pipes"),
        pytest.param(EXCEPTION_NAME_REBOUND, [9], id="exception-name-rebound"),
        # Unpacking the result does not show what the receiver is.
        pytest.param(TUPLE_UNPACKED_RESULT, [4], id="tuple-unpacked"),
        pytest.param(AWAITED_TUPLE_UNPACKED_RESULT, [3], id="awaited-tuple-unpacked"),
    ],
)
def test_read_of_unproven_receiver_is_reported(source, lines):
    assert _p401_lines(source) == lines


FILE_OBJECTS = """
import codecs
import gzip
import io
import os
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import IO, TextIO


def a(path):
    f = open(path)
    return f.read()


def b(path):
    with open(path, "rb") as fh, open(path) as other:
        return fh.read() + other.readlines()


def c(path):
    return open(path).read()


def d(path):
    with Path(path).open() as handle:
        return handle.read()


def e(path):
    return io.open(path).read() + codecs.open(path).read() + gzip.open(path).read()


def f(fd):
    return os.fdopen(fd).read()


def g():
    with tempfile.NamedTemporaryFile() as tmp:
        return tmp.read()


def h(stream: TextIO, raw: "IO[bytes]"):
    return stream.read() + raw.read()


def i(path):
    with ExitStack() as stack:
        src = stack.enter_context(open(path))
        return src.read()


def j(archive, name):
    return archive.open(name).read()


class Reader:
    def __init__(self, path):
        self._fh = open(path)

    def all(self):
        return self._fh.read()


def k(path):
    def inner():
        return outer_file.read()

    outer_file = open(path)
    return inner()


async def m(aiofiles, path):
    async with aiofiles.open(path) as af:
        return await af.read()
"""


def test_reads_with_file_evidence_are_reported():
    assert _p401_lines(FILE_OBJECTS) == [
        14,  # f = open(path)
        19,  # with open(...) as fh / other: read + readlines
        19,
        23,  # open(path).read()
        28,  # with Path(path).open() as handle
        32,  # io.open / codecs.open / gzip.open
        32,
        32,
        36,  # os.fdopen(fd)
        41,  # tempfile.NamedTemporaryFile
        45,  # stream: TextIO, raw: "IO[bytes]"
        45,
        51,  # stack.enter_context(open(path))
        55,  # archive.open(name)
        63,  # self._fh = open(path) in __init__
        68,  # closure over an opened file
        76,  # async with aiofiles.open(...) as af
    ]


def test_untyped_file_parameters_are_reported():
    source = """
def process(f, fp, size):
    head = f.read(size)
    return head + f.read() + fp.readlines()
"""
    assert _p401_lines(source) == [4, 4]


def test_opened_file_is_reported_whatever_its_name():
    source = """
def a(path):
    stream = open(path)
    return stream.read()
"""
    assert _p401_lines(source) == [4]


def test_shadowed_open_is_not_file_evidence():
    source = """
def open(url):
    return fetch(url)

def run(url):
    resp = open(url)
    return resp.read()
"""
    assert _p401_lines(source) == [7]


def test_many_reads_in_one_scope_stay_fast():
    source = "def big(paths):\n" + "".join(
        f"    f{i} = open(paths[{i}])\n    d{i} = f{i}.read()\n" for i in range(1500)
    )
    started = time.perf_counter()
    assert len(_p401_lines(source)) == 1500
    assert time.perf_counter() - started < 5
