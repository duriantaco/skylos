def require_user(request):
    if request.user is None or not request.user.is_authenticated:
        raise PermissionError("authentication required")
