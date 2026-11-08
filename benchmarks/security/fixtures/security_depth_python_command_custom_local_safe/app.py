import subprocess
from flask import Flask, request
app = Flask(__name__)
class DataSink:
    def run(self, text, shell=False):
        return text
@app.post("/run")
def run():
    subprocess = DataSink()
    return subprocess.run(request.data.decode(), shell=True)
