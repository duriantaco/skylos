from flask import Flask, request
import requests


app = Flask(__name__)


@app.get("/avatar")
def fetch_avatar():
    target = request.args.get("url")
    return requests.get(target, timeout=2).text


@app.get("/health")
def fetch_health():
    return requests.get("https://status.internal.local/health", timeout=2).text
