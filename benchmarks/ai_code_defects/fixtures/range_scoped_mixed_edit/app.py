def existing_helper(value):
    return value.strip()


def handle_login(request):
    token = validate_token(request.headers["Authorization"])
    return token


def handle_profile(request):
    raw = request.args["bio"]
    safe = sanitize_input(raw)
    return existing_helper(safe)


def future_handler(payload):
    pass
