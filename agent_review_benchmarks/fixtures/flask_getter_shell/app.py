from flask import Flask, request
import subprocess


app = Flask(__name__)


@app.get("/tool")
def run_tool():
    cmd = request.args.get("cmd")
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


@app.get("/safe-tool")
def run_safe():
    cmd = request.args.get("cmd", "pwd")
    return subprocess.run(
        ["/bin/echo", cmd],
        check=False,
        capture_output=True,
        text=True,
    )
