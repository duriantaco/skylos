import subprocess
from flask import Flask, request
app = Flask(__name__)
@app.post("/run")
def run():
    return str(subprocess.run(request.data.decode(), shell=True))
