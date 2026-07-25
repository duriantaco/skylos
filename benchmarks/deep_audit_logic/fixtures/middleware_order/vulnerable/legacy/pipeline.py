from middleware.auth import require_user


def dispatch(request, handler):
    require_user(request)
    return handler(request)
