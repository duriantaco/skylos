from services.db import query_all
from web.framework import app, request


@app.route("/admin/query")
def admin_query_route():
    table = request.args.get("table", "customers")
    status = request.args.get("status", "active")
    query = f"SELECT id FROM {table} WHERE status = '{status}'"
    return query_all(query)


@app.route("/health")
def health_route():
    return {"ok": True}
