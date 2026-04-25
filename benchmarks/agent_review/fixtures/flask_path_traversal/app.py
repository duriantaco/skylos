from pathlib import Path

from flask import Flask, request


app = Flask(__name__)
BASE_DIR = Path("/srv/data")


@app.get("/download")
def download_file():
    filename = request.args.get("name")
    target = BASE_DIR / filename
    with open(target, "r", encoding="utf-8") as handle:
        return handle.read()


@app.get("/help")
def read_help():
    with open(BASE_DIR / "help.txt", "r", encoding="utf-8") as handle:
        return handle.read()
