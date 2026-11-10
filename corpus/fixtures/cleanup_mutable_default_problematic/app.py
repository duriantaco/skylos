def register_badge(user_id: str, grants: dict[str, bool] = {}) -> dict[str, bool]:
    grants[user_id] = True
    return grants.copy()
