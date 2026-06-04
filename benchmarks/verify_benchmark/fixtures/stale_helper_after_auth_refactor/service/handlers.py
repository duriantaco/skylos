from service import authz


def rotate_api_key(request):
    user = authz.load_user(request.session)
    authz.require_step_up(user)
    token = authz.issue_session(user)
    return {
        "token": token,
        "rotated": True,
    }
