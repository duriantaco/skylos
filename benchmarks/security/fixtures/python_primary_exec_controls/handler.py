from flask import Flask, request

app = Flask(__name__)


@app.post("/preview")
def preview():
    text = request.form["expression"]
    exec(compile(text, "preview", "exec"), {})
