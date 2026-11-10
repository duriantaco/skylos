def register_badge(
    user_id: str, grants: dict[str, bool] | None = None
) -> dict[str, bool]:
    if grants is None:
        grants = {}
    grants[user_id] = True
    return grants.copy()
