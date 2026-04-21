import os
from pathlib import Path

from flask import Flask, request


app = Flask(__name__)
UPLOAD_DIR = Path("/srv/uploads")


@app.post("/upload")
def upload_file():
    upload = request.files["file"]
    filename = upload.filename
    target = UPLOAD_DIR / filename
    with open(target, "wb") as handle:
        handle.write(upload.read())
    return "ok"


@app.post("/upload-safe")
def upload_safe():
    upload = request.files["file"]
    safe_name = os.path.basename(upload.filename)
    target = UPLOAD_DIR / safe_name
    with open(target, "wb") as handle:
        handle.write(upload.read())
    return "ok"
