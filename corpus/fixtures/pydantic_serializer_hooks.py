from pydantic import BaseModel, field_serializer, model_serializer


class User(BaseModel):
    name: str

    @field_serializer("name")
    def serialize_name(self, value):
        return value

    @model_serializer(mode="wrap")
    def serialize_model(self, handler):
        return handler(self)


class SerializationDraft:
    pass


def serialize_title(value):
    return value


def serialize_snapshot():
    return {}


User(name="Ada").model_dump()
