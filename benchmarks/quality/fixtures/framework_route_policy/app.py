from fastapi import APIRouter, Depends

router = APIRouter()


def require_admin() -> bool:
    return True


@router.post("/users")
def create_user(payload: dict) -> dict:
    return payload


@router.get("/users", response_model=list[str])
def list_users() -> list[str]:
    return []


@router.post("/admin")
def create_admin(payload: dict, user: bool = Depends(require_admin)) -> dict:
    return payload
