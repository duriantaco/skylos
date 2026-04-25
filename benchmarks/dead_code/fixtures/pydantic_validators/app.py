from pydantic import BaseModel, field_validator, model_validator


class UserInput(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower()

    @model_validator(mode="after")
    def ensure_domain(self):
        return self


class UnusedSchema(BaseModel):
    name: str


def build_user():
    return UserInput(email="ADA@example.com")


def unused_normalizer(value):
    return value.casefold()


RESULT = build_user()
