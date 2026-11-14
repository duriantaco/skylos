from flask import Flask, request

app = Flask(__name__)


class SessionStore:
    def __init__(self):
        self._session_replacements = {}

    def handle(self):
        sid = request.args["sid"]
        return self._session_replacements.get(sid)


store = SessionStore()


@app.route("/lookup")
def lookup():
    return str(store.handle())
