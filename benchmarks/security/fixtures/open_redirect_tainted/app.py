from flask import redirect, request


def login():
    return redirect(request.args.get("next", "/"))
