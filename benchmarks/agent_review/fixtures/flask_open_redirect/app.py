from urllib.parse import urlparse

from flask import Flask, redirect, request


app = Flask(__name__)


@app.get("/go")
def bounce():
    target = request.args.get("next", "/")
    return redirect(target)


@app.get("/safe-go")
def bounce_safe():
    target = request.args.get("next", "/")
    if urlparse(target).netloc:
        target = "/"
    return redirect(target)
