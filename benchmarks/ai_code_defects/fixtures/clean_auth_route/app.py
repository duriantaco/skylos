from fastapi import Depends, FastAPI

app = FastAPI()


def require_admin() -> str:
    return "admin"


@app.post("/admin/users")
def create_user(payload: dict, current_user: str = Depends(require_admin)) -> dict:
    return {"created_by": current_user, "payload": payload}
