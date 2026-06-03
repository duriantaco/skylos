from app import security


def handler(request):
    principal = security.require_auth(request)
    security.audit_access(principal)
    return principal
