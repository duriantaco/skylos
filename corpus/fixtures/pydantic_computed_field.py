from pydantic import BaseModel, computed_field


class User(BaseModel):
    first: str
    last: str

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.first} {self.last}"


class PreviewRecord:
    pass


def compose_name(first, last):
    return f"{first} {last}"


User(first="Ada", last="Lovelace").model_dump()
