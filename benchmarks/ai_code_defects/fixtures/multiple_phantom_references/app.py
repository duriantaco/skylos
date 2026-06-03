def handler(request):
    token = validate_token(request.headers["Authorization"])
    body = sanitize_input(request.body)
    return escape_html(body + token)
