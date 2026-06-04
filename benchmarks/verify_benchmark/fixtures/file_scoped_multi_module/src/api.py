def create_admin_report(request):
    user = request["user"]
    require_admin(user)
    return {
        "status": "queued",
        "user": user["id"],
    }
