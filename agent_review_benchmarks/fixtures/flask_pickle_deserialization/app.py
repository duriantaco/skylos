import base64
import json
import pickle

from flask import Flask, request


app = Flask(__name__)


@app.post("/restore-session")
def restore_session():
    payload = request.get_json(force=True)["payload"]
    raw = base64.b64decode(payload)
    session = pickle.loads(raw)
    return {"keys": sorted(session)}


@app.post("/restore-session-safe")
def restore_session_safe():
    payload = request.get_json(force=True)["payload"]
    session = json.loads(payload)
    return {"keys": sorted(session)}
