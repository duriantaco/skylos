"""A proved OpenCV frame API is not a whole-stream read contract."""

import ast
import textwrap

import pytest

from skylos.rules.quality.performance import PerformanceRule


def _read_lines(tmp_path, source, extra_files=None):
    source = textwrap.dedent(source)
    for name, contents in (extra_files or {}).items():
        (tmp_path / name).write_text(contents)
    tree = ast.parse(source)
    rule = PerformanceRule()
    context = {"filename": str(tmp_path / "sample.py"), "project_root": str(tmp_path)}
    findings = []
    for node in ast.walk(tree):
        findings.extend(rule.visit_node(node, context) or [])
    return [item["line"] for item in findings if item["rule_id"] == "SKY-P401"]


@pytest.mark.parametrize("source", [
    """
    import cv2
    def frames(source):
        cap = cv2.VideoCapture(source)
        while cap.isOpened():
            ok, frame = cap.read()
            if not ok:
                break
            yield frame
        cap.release()
    """,
    """
    from cv2 import VideoCapture as Capture
    def frame(source):
        capture = Capture(source)
        alias = capture
        return alias.read()
    """,
    """
    import cv2 as video
    def frame(source, fallback):
        capture = None
        capture = video.VideoCapture(source)
        if not capture.isOpened():
            capture.release()
            capture = video.VideoCapture(fallback)
        ok, image = capture.read()
        return image
    """,
    """
    import cv2
    cap = cv2.VideoCapture(0)
    def frames():
        while True:
            ok, image = cap.read()
            if ok:
                yield image
    """,
])
def test_proved_video_capture_reads_one_frame(tmp_path, source):
    assert _read_lines(tmp_path, source) == []


@pytest.mark.parametrize("source", [
    """
    def frame(camera_factory):
        cap = camera_factory(0)
        ok, image = cap.read()
        return image
    """,
    """
    import cv2
    def frame(source, stream):
        cap = cv2.VideoCapture(source)
        cap = stream
        return cap.read()
    """,
    """
    import cv2
    def frame(source, stream):
        cap = cv2.VideoCapture(source)
        alias = cap
        alias = stream
        return cap.read()
    """,
    """
    import cv2
    def frame(source, mutate):
        cap = cv2.VideoCapture(source)
        mutate(cap)
        return cap.read()
    """,
    """
    import cv2
    def frame(source, stream):
        cap = cv2.VideoCapture(source)
        cap.read = stream.read
        return cap.read()
    """,
    """
    from cv2 import VideoCapture
    def frame(source, mutate):
        mutate(VideoCapture)
        cap = VideoCapture(source)
        return cap.read()
    """,
    """
    import cv2
    def frame(source, cv2):
        cap = cv2.VideoCapture(source)
        return cap.read()
    """,
    """
    import cv2
    cv2.VideoCapture = lambda source: open(source)
    def frame(source):
        cap = cv2.VideoCapture(source)
        return cap.read()
    """,
    """
    import cv2
    __import__("cv2").VideoCapture = lambda source: open(source)
    cap = cv2.VideoCapture("input")
    data = cap.read()
    """,
    """
    import cv2
    import importlib
    namespace = importlib.import_module("cv2").__dict__
    namespace["VideoCapture"] = open
    cap = cv2.VideoCapture("input")
    data = cap.read()
    """,
    """
    import cv2
    def frame(source):
        cap = cv2.VideoCapture(source)
        try:
            operation()
        except Exception as cap:
            return cap.read()
    """,
    """
    import cv2
    class Camera:
        def __init__(self, source):
            self.cap = cv2.VideoCapture(source)
        def frame(self):
            return self.cap.read()
    """,
    """
    def contents(path):
        with open(path) as stream:
            data = stream.read()
        return data
    """,
])
def test_unknown_or_mutated_read_contract_stays_reported(tmp_path, source):
    assert _read_lines(tmp_path, source)


def test_local_cv2_provider_does_not_prove_the_external_api(tmp_path):
    assert _read_lines(tmp_path, """
        import cv2
        cap = cv2.VideoCapture("input")
        data = cap.read()
    """, {"cv2.py": "VideoCapture = open\n"})


def test_snapshot_reader_cannot_borrow_head_provider_absence(tmp_path):
    source = "import cv2\ncap = cv2.VideoCapture(0)\nvalue = cap.read()\n"
    tree = ast.parse(source)
    context = {"filename": str(tmp_path / "sample.py"), "project_root": str(tmp_path), "receiver_source_reader": lambda path: None}
    rule = PerformanceRule()
    findings = [item for node in ast.walk(tree) for item in rule.visit_node(node, context) or []]
    assert any(item["rule_id"] == "SKY-P401" for item in findings)
