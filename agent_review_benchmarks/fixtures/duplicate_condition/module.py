def route_request(env, is_admin):
    if env == "prod":
        return "prod"
    if env == "prod" and is_admin:
        return "prod-admin"
    return "fallback"


def route_request_ok(env, is_admin):
    if env == "prod" and is_admin:
        return "prod-admin"
    if env == "prod":
        return "prod"
    return "fallback"
