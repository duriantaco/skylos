"""Static analysis input. Tests never import this module."""

from pathlib import Path

from flask import Flask, request

app = Flask(__name__)


@app.get("/document")
def document():
    root = Path("/srv/documents")
    name = request.args["document"]
    return (root / name).read_bytes()


def callback(path):
    return Path(path).read_text()


def write_status():
    Path("/tmp/build.status").write_text("ready")


def create_status():
    with open("/tmp/build.status", "x") as stream:
        stream.write("ready")
