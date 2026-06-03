def authenticate(request):
    return {"principal": request.headers.get("Authorization", "")}


def audit_access(principal):
    return bool(principal)
