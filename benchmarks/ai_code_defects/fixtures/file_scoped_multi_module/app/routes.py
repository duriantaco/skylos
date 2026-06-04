def route_handler(request):
    return validate_token(request.headers["Authorization"])
