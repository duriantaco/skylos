from flask import Flask

app = Flask(__name__)


def tenant_admin_required(handler):
    return handler


@app.route("/admin")
@tenant_admin_required
def admin_dashboard():
    return {"ok": True}
