import html

from flask import Flask, render_template_string, request


app = Flask(__name__)


@app.get("/profile")
def profile():
    name = request.args.get("name")
    return render_template_string(f"<div>{name}</div>")


@app.get("/safe-profile")
def safe_profile():
    name = request.args.get("name")
    safe_name = html.escape(name)
    return render_template_string("<div>{{ name }}</div>", name=safe_name)
