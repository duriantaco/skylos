from flask import redirect, request


def login():
    next_url = request.args.get("next", "/")
    if next_url not in ("/", "/dashboard"):
        next_url = "/"
    return redirect(next_url)
