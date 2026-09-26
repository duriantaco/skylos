import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/status")
def fetch_host():
    host = request.args.get("host", "")
    return requests.get(f"https://{host}/status", timeout=3).text
