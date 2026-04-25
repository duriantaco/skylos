from flask import redirect, request


def login():
    next_url = request.args.get("next", "/")
    if not next_url.startswith("/"):
        next_url = "/"
    return redirect(next_url)
