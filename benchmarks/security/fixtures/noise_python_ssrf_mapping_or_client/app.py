import httpx
from flask import Flask, request

app = Flask(__name__)


class Relay:
    def __init__(self, live):
        self._client_pool = {}
        if live:
            self._client_pool = httpx.Client()

    def send(self):
        target = request.args["target"]
        return self._client_pool.get(target)


relay = Relay(True)


@app.route("/send")
def send():
    return str(relay.send())
