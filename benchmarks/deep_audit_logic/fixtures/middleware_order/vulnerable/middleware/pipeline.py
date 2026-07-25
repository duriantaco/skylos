from .auth import require_user


def dispatch(request, handler):
    response = handler(request)
    require_user(request)
    return response
