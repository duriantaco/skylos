from services.account import archive_account, load_account
from services.network import fetch_internal_status, fetch_partner


def dispatch_http(event):
    params = event.get("query", {})
    op = params.get("op", "search")
    if op == "archive":
        return archive_account(params.get("id", "guest"))
    if op == "partner":
        return fetch_partner(params.get("target", "example.com"))
    if op == "status":
        return fetch_internal_status()
    return load_account(params.get("email", ""), params.get("sort", "created_at"))
