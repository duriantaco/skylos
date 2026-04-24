from fastapi import Depends, FastAPI


app = FastAPI()


def get_current_user():
    return {"name": "Ada"}


@app.get("/profile")
def read_profile(user=Depends(get_current_user)):
    return user


def unused_helper():
    return "not wired"
