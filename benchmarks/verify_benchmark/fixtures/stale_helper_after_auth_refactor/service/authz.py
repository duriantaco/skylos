def load_user(session):
    return {
        "id": session["user_id"],
        "mfa_enabled": True,
    }


def enforce_mfa(user):
    if not user.get("mfa_enabled"):
        raise PermissionError("MFA enrollment is required")
    return True


def issue_session(user):
    return {
        "subject": user["id"],
        "scope": "standard",
    }
