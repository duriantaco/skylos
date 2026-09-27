import os

from flask import Flask, request

app = Flask(__name__)

BASE_DIR = "/srv/app/uploads"


@app.route("/uploads")
def read_upload():
    safe_name = os.path.basename(request.args.get("name", ""))
    path = os.path.join(BASE_DIR, safe_name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
