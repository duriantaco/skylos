from fastapi import FastAPI
from pydantic import BaseModel, field_validator

app = FastAPI()


class UserIn(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return value


@app.post("/users")
def create_user(user: UserIn):
    return {"email": user.email}
