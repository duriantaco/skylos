from fastapi import FastAPI

app = FastAPI()


@app.post("/admin/users")
def create_user(payload: dict) -> dict:
    return {"created": payload}
