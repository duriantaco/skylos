from flask import Flask

app = Flask(__name__)


@app.route("/admin")
def admin_dashboard():
    return {"ok": True}
