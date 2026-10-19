from typing import Any

__all__ = ["load_user", "typed_helper"]


def load_user(user_id, include_deleted: bool):
    return {"id": str(user_id), "include_deleted": include_deleted}


def typed_helper(user_id: str) -> dict[str, Any]:
    return {"id": user_id}
